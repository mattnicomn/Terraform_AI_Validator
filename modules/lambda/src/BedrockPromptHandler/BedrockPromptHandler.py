import json
import boto3
import uuid
import datetime
import rsa
import jwt
from botocore.signers import CloudFrontSigner
from botocore.exceptions import ClientError


CORS_HEADERS = {
    'Access-Control-Allow-Origin': 'https://d11k4vck88gnf5.cloudfront.net',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET',
    'Access-Control-Allow-Credentials': 'true',
    'Content-Type': 'application/json'
}

# CloudFront Settings
cloudfront_key_id = "K3PMISK1CK6HYH"  # Replace with your CloudFront Key ID
content_url = "https://d11k4vck88gnf5.cloudfront.net/index.html"  # Replace with your content URL

# Cognito Settings
cognito_region = 'us-east-1'
cognito_user_pool_id = 'us-east-1_qsT1OnMXw'  # Replace with your actual user pool ID
cognito_app_client_id = '7ccfli4ti56r33as43qp6imat2'

def get_req_parts(event):
    """
    Return (method, headers_dict, body_str) handling both REST v1 and HTTP API v2.
    """
    # headers normalized to lower-case keys for easier lookups
    headers = { (k.lower() if k else k): v for k, v in (event.get('headers') or {}).items() }

    # HTTP API v2
    if 'requestContext' in event and 'http' in event['requestContext']:
        method = event['requestContext']['http'].get('method', '')
        body = event.get('body')
        if event.get('isBase64Encoded'):
            # if body is base64 for v2
            import base64
            body = base64.b64decode(body or '').decode('utf-8', errors='replace')
        return method, headers, body

    # REST API v1 (Lambda proxy)
    method = event.get('httpMethod', '')
    body = event.get('body')
    return method, headers, body

# Initialize the SSM client for Parameter Store
ssm_client = boto3.client('ssm', region_name='us-east-1')


def lambda_handler(event, context):
    try:
        print("===== DEBUGGING INFORMATION =====")
        print("Complete event:", json.dumps(event))
        print("=== LAMBDA VERSION CHECK: Using NEW Bedrock implementation ===")

        # Extract method/headers/body for v1 or v2
        method, headers, raw_body = get_req_parts(event)

        # CORS preflight: reply with headers
        if method.upper() == 'OPTIONS':
            return {
                'statusCode': 204,
                'headers': CORS_HEADERS,
                'body': ''
            }

        # ---- Auth (Bearer <jwt>) ----
        auth_header = headers.get('authorization')
        token = None
        if auth_header:
            token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        skip_validation = False  # set True only for local testing

        if not token and not skip_validation:
            print("Authorization token is missing")
            return generate_error_response("Missing or invalid Authorization token", 401)

        if not skip_validation and token:
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                print("Decoded token (no signature verification):", json.dumps(decoded))
            except Exception as e:
                print(f"Token parse error: {str(e)}")
                return generate_error_response(f"Invalid token format: {str(e)}", 401)

        # ---- Body / prompt ----
        try:
            body_json = json.loads(raw_body or '{}')
        except Exception as e:
            print(f"Invalid JSON: {e}; raw: {raw_body}")
            return generate_error_response("Invalid JSON in request body", 400)

        prompt = body_json.get('prompt', '').strip()
        if not prompt:
            return generate_error_response("Missing 'prompt' parameter in the request body.", 400)

        # ---- Call Bedrock, build response ----
        response_text = invoke_bedrock_agent(prompt)
        signed_url = generate_signed_url(content_url)

        return {
            'statusCode': 200,
            'headers': CORS_HEADERS,
            'body': json.dumps({
                'response': response_text,
                'cloudfront_signed_url': signed_url
            })
        }

    except Exception as e:
        print(f"Unhandled error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return generate_error_response(f"Error occurred: {str(e)}")


def get_token_from_event(event):
    """Extract the JWT token from the Authorization header with enhanced logging"""
    # Debug headers
    if 'headers' in event and event['headers']:
        headers = event['headers']
        print("Available headers:", list(headers.keys()))
        
        # Check for both cases of 'Authorization'
        auth_header = headers.get('Authorization') or headers.get('authorization')
        if auth_header:
            print(f"Found auth header: {auth_header[:15]}...")
            if auth_header.startswith('Bearer '):
                return auth_header[7:]  # Remove 'Bearer ' prefix
            else:
                print("Auth header doesn't start with 'Bearer '")
                return auth_header  # Try to use it anyway
        else:
            print("No 'Authorization' header found")
    else:
        print("No headers in event")
    
    # As a fallback, check if token is directly in the event
    if 'token' in event:
        print("Found token directly in event")
        return event['token']
    
    return None

# Generate error response for Lambda
def generate_error_response(message, status_code=500):
    return {
        'statusCode': status_code,
        'headers': CORS_HEADERS,
        'body': json.dumps({
            'error': message
        })
    }

# Retrieve the private key from Parameter Store
def get_private_key():
    try:
        response = ssm_client.get_parameter(
            Name='private_key.pem',  # The parameter name you set earlier
            WithDecryption=True
        )
        return response['Parameter']['Value']
    except ClientError as e:
        raise Exception(f"Failed to retrieve private key from Parameter Store: {str(e)}")

# Generate CloudFront Signed URL
def rsa_signer(message):
    try:
        private_key = get_private_key()

        # Ensure private_key is in bytes before loading it
        if isinstance(private_key, str):  # If it's a string, convert it to bytes
            private_key = private_key.encode('utf-8')

        private_key_obj = rsa.PrivateKey.load_pkcs1(private_key)

        # Ensure that message is encoded properly as bytes
        if isinstance(message, str):  # If it's a string, convert it to bytes
            message = message.encode('utf-8')

        # Sign the message
        return rsa.sign(message, private_key_obj, 'SHA-1')
    except Exception as e:
        raise Exception(f"Error signing the CloudFront URL: {str(e)}")

def generate_signed_url(url):
    try:
        cf_signer = CloudFrontSigner(cloudfront_key_id, rsa_signer)

        # Set expiration time for URL (1 hour from now)
        expires = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

        # Generate the signed URL
        signed_url = cf_signer.generate_presigned_url(url, date_less_than=expires)
        return signed_url
    except Exception as e:
        raise Exception(f"Error generating signed URL: {str(e)}")

# Invoke Bedrock agent with improved error handling
def invoke_bedrock_agent(prompt):
    try:
        client = boto3.client('bedrock-agent-runtime', region_name='us-east-1')

        print(f"Invoking Bedrock agent with agentId: NNKUTQQWKP, agentAliasId: GVM7ZZPOOM")
        
        response = client.invoke_agent(
            agentId="NNKUTQQWKP",       # <- Replace with your agent ID
            agentAliasId="GVM7ZZPOOM",  # <- Replace with your agent alias ID
            sessionId=str(uuid.uuid4()),
            inputText=prompt
        )

        print("Bedrock agent response received")
        
        # Process the response with improved error handling
        response_text = ""
        completion_events = []
        
        try:
            for event in response['completion']:
                completion_events.append(event)
                print(f"Event type: {type(event)}, Event keys: {list(event.keys()) if isinstance(event, dict) else 'Not a dict'}")
                
                if 'chunk' in event:
                    chunk_data = event['chunk']
                    if 'bytes' in chunk_data:
                        try:
                            chunk_text = chunk_data['bytes'].decode('utf-8')
                            response_text += chunk_text
                            print(f"Added chunk: {chunk_text[:100]}...")
                        except Exception as decode_error:
                            print(f"Error decoding chunk bytes: {decode_error}")
                    else:
                        print(f"No 'bytes' in chunk: {chunk_data}")
                elif 'trace' in event:
                    # Handle trace events (these contain debugging info)
                    print(f"Trace event: {event['trace']}")
                elif 'returnControl' in event:
                    # Handle return control events
                    print(f"Return control event: {event['returnControl']}")
                else:
                    print(f"Unknown event type: {event}")

        except Exception as stream_error:
            print(f"Error processing event stream: {stream_error}")
            print(f"Completion events so far: {completion_events}")
            raise

        if not response_text:
            print("Warning: No response text extracted from Bedrock agent")
            response_text = "No response generated by the agent"

        print(f"Final response text length: {len(response_text)}")
        return response_text
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        print(f"Bedrock ClientError - Code: {error_code}, Message: {error_message}")
        
        # Provide more specific error handling
        if error_code == 'dependencyFailedException':
            raise Exception(f"Bedrock agent dependency failure: {error_message}. This usually indicates an issue with the agent's action groups or knowledge bases.")
        elif error_code == 'ValidationException':
            raise Exception(f"Bedrock validation error: {error_message}. Check your agent ID and alias ID.")
        elif error_code == 'AccessDeniedException':
            raise Exception(f"Bedrock access denied: {error_message}. Check your Lambda's IAM permissions.")
        else:
            raise Exception(f"Bedrock error ({error_code}): {error_message}")
    except Exception as e:
        print(f"Unexpected error invoking Bedrock agent: {str(e)}")
        print(f"Error type: {type(e)}")
        raise Exception(f"Error invoking Bedrock agent: {str(e)}")