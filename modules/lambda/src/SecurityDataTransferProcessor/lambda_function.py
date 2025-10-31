import boto3
import json
import uuid
import datetime
import re
import traceback
from botocore.exceptions import ClientError

# Global variables for configuration
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:253881689673:SecurityDataTransferAlerts"
SOURCE_BUCKETS = "securitydatatransfers3source"
DESTINATION_BUCKETS = "securitydatatransfers3destination"
RESULTS_BUCKET = "securitydatatransfers3results"

# PII entity types to detect
PII_ENTITY_TYPES = [
    'BANK_ACCOUNT_NUMBER', 'CREDIT_DEBIT_NUMBER', 'CREDIT_DEBIT_CVV',
    'CREDIT_DEBIT_EXPIRY', 'PIN', 'EMAIL', 'ADDRESS', 'NAME', 'PHONE',
    'SSN', 'DATE_TIME', 'PASSPORT_NUMBER', 'DRIVER_ID', 'URL', 'AGE'
]

# PHI regex patterns
PHI_PATTERNS = {
    'medical_record_number': r'\b[A-Z]{2}\d{6}\b',
    'health_insurance_claim_number': r'\b\d{9}[A-Z]\b',
    'diagnosis_code': r'\b[A-Z]\d{2}(?:\.\d{1,2})?\b',  # ICD-10 format
    'npi_number': r'\b\d{10}\b',
    'prescription_information': r'(?i)\brx\s*#?\s*\d+\b',
}

# Initialize AWS clients with exception handling
try:
    s3_client = boto3.client('s3', region_name='us-east-1')
    comprehend_client = boto3.client('comprehend')
    sns_client = boto3.client('sns')
except Exception as e:
    print(f"Error initializing AWS clients: {str(e)}")
    # Create dummy clients to prevent function from failing completely
    # These will raise errors if used, but allow the function to initialize
    s3_client = None
    comprehend_client = None
    sns_client = None

def format_bedrock_response(status_code, content, action_group, api_path, http_method):
    """
    Format response for Bedrock Agent. IMPORTANT: apiPath and httpMethod
    MUST echo what the agent sent in the request, or you get a mismatch error.
    """
    # Normalize content into application/json shape
    if status_code == 200 and not isinstance(content, str):
        app_json = content
    else:
        app_json = {"message": content if isinstance(content, str) else json.dumps(content)}

    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group or "SecurityDataTransferAPI",
            "apiPath": api_path or "",
            "httpMethod": (http_method or "").upper(),
            "httpStatusCode": status_code,
            "responseBody": {
                "application/json": app_json,          # <— note the slash; Bedrock accepts either form,
                "applicationJson": app_json            #     keep both for compatibility
            }
        }
    }


def format_bedrock_error(status_code, message, *, action_group, api_path, http_method):
    return format_bedrock_response(
        status_code,
        {"error": message},
        action_group=action_group,
        api_path=api_path,
        http_method=http_method
    )


def safe_json_loads(json_str, default=None):
    """Safely parse JSON string with error handling"""
    if not json_str:
        return default if default is not None else {}
    
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {str(e)}, content: {json_str[:100]}...")
        return default if default is not None else {}



def lambda_handler(event, context):
    """Main Lambda handler with comprehensive error handling"""
    try:
        print(f"Received event: {json.dumps(event)}")
        
        # Check if AWS clients were initialized successfully
        if None in (s3_client, comprehend_client, sns_client):
            return format_bedrock_response(500, 'AWS service clients failed to initialize')
        
        # Handle direct API Gateway or test invocations
        if 'operation' in event:
            operation = event.get('operation')
            # Original operation-based routing
            if operation == 'scanFile':
                return scan_file(event)
            elif operation == 'transferFile':
                return transfer_file(event)
            elif operation == 'getClassificationReport':
                return get_classification_report(event)
            elif operation == 'scanBucket':
                return scan_bucket(event)
            else:
                return format_bedrock_response(400, 'Unsupported operation')
        
            # Handle Bedrock Agent Action Group invocations
        elif 'actionGroup' in event and 'apiPath' in event:
            try:
                # Extract and ECHO these back in every response
                action_group = event.get('actionGroup')
                api_path     = event.get('apiPath')
                http_method  = (event.get('httpMethod') or "").upper()

                # Basic validation – if missing, fail in the Agent-compliant format
                if not api_path or not http_method:
                    return format_bedrock_error(
                        400,
                        "Missing apiPath or httpMethod in request",
                        action_group=action_group,
                        api_path=api_path,
                        http_method=http_method
                    )

                # Normalize params from either list or dict formats
                raw_params = event.get('parameters', [])
                if isinstance(raw_params, list):
                    params = {p['name']: p.get('value') for p in raw_params if isinstance(p, dict) and 'name' in p}
                elif isinstance(raw_params, dict):
                    params = raw_params
                else:
                    params = {}

                # Route by path + method
                if api_path == '/scan-file' and http_method == 'POST':
                    scan_event = {
                        'bucketName': params.get('bucketName'),
                        'objectKey': params.get('objectKey')
                    }
                    result = scan_file(scan_event)
                    return format_bedrock_response(
                        200, result,
                        action_group=action_group, api_path=api_path, http_method=http_method
                    )

                elif api_path == '/transfer-file' and http_method == 'POST':
                    # Bedrock may send requestBody as a stringified JSON
                    body_raw = event.get('requestBody') or "{}"
                    body = safe_json_loads(body_raw, {})
                    transfer_event = {
                        'sourceBucket': body.get('sourceBucket'),
                        'sourceKey': body.get('sourceKey'),
                        'destinationBucket': body.get('destinationBucket'),
                        'destinationKey': body.get('destinationKey')
                    }
                    result = transfer_file(transfer_event)
                    return format_bedrock_response(
                        200, result,
                        action_group=action_group, api_path=api_path, http_method=http_method
                    )

                elif api_path == '/classification-report' and http_method == 'GET':
                    report_event = {
                        'scanId': params.get('scanId')
                    }
                    result = get_classification_report(report_event)
                    return format_bedrock_response(
                        200, result,
                        action_group=action_group, api_path=api_path, http_method=http_method
                    )
                elif path == '/scan-bucket' and method in ('POST', 'GET'):
                    # Parameters may come in as list of {name, value} or a dict
                    raw_params = event.get('parameters', [])
                    params = {}
                    if isinstance(raw_params, list):
                        params = {p['name']: p.get('value') for p in raw_params if 'name' in p}
                    elif isinstance(raw_params, dict):
                        params = raw_params

                    # Also accept JSON body with same fields (POST)
                    body = safe_json_loads(event.get('requestBody', '{}'), {})
                    bucket_name = params.get('bucketName') or body.get('bucketName')
                    prefix = params.get('prefix') or body.get('prefix')
                    max_keys = body.get('maxKeys')
                    try:
                        if isinstance(max_keys, str) and max_keys.isdigit():
                            max_keys = int(max_keys)
                    except:
                        max_keys = None

                    scan_req = {'bucketName': bucket_name, 'prefix': prefix, 'maxKeys': max_keys}
                    result = scan_bucket(scan_req)
                    return format_bedrock_response(200, result, action_group, path, method)

                else:
                    return format_bedrock_error(
                        400,
                        f"Unsupported operation: {api_path} {http_method}",
                        action_group=action_group, api_path=api_path, http_method=http_method
                    )

            except Exception as e:
                print(f"Error processing Bedrock Agent request: {str(e)}")
                traceback.print_exc()
                return format_bedrock_error(
                    500,
                    f"Error processing request: {str(e)}",
                    action_group=event.get('actionGroup'),
                    api_path=event.get('apiPath'),
                    http_method=(event.get('httpMethod') or "").upper()
                )
            
    except Exception as e:
        print(f"Unhandled exception in lambda_handler: {str(e)}")
        traceback.print_exc()
        return format_bedrock_response(500, f'Unhandled error: {str(e)}')

def scan_file(event):
    """Scan a file for security issues with comprehensive error handling"""
    try:
        bucket_name = event.get('bucketName')
        object_key = event.get('objectKey')
        
        if not bucket_name or not object_key:
            return {
                'error': 'Missing required parameters: bucketName and objectKey are required',
                'errorCode': 'MISSING_PARAMETERS'
            }
        
        # Get the file content
        try:
            response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
            content = response['Body'].read().decode('utf-8')
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'NoSuchKey':
                return {
                    'error': f'File not found: {object_key}',
                    'errorCode': 'FILE_NOT_FOUND'
                }
            elif error_code == 'AccessDenied':
                return {
                    'error': f'Access denied to file: {object_key}',
                    'errorCode': 'ACCESS_DENIED'
                }
            else:
                print(f"S3 error: {str(e)}")
                return {
                    'error': f'Error accessing file: {str(e)}',
                    'errorCode': 'S3_ERROR'
                }
        except UnicodeDecodeError as e:
            return {
                'error': f'File encoding not supported: {str(e)}',
                'errorCode': 'UNSUPPORTED_ENCODING'
            }
        except Exception as e:
            print(f"Error reading file: {str(e)}")
            return {
                'error': f'Error reading file: {str(e)}',
                'errorCode': 'FILE_READ_ERROR'
            }
        
        # Initialize findings with empty lists to prevent NoneType errors
        pii_findings = []
        phi_findings = []
        fedramp_findings = []
        
        # Scan for PII using Comprehend
        try:
            pii_findings = detect_pii(content)
        except Exception as e:
            print(f"Error in PII detection: {str(e)}")
            # Continue with empty findings rather than failing completely
        
        # Scan for PHI using regex patterns
        try:
            phi_findings = detect_phi(content)
        except Exception as e:
            print(f"Error in PHI detection: {str(e)}")
            # Continue with empty findings rather than failing completely
        
        # Scan for FedRAMP compliance issues
        try:
            fedramp_findings = check_fedramp_compliance(content)
        except Exception as e:
            print(f"Error in FedRAMP compliance check: {str(e)}")
            # Continue with empty findings rather than failing completely
        
        # Determine classification based on findings
        try:
            classification_type, security_issues = classify_data(pii_findings, phi_findings, fedramp_findings)
        except Exception as e:
            print(f"Error classifying data: {str(e)}")
            # Default to most restrictive classification if classification fails
            classification_type = 'Type3'
            security_issues = [{
                'issueType': 'Error',
                'severity': 'High',
                'description': f"Error during classification: {str(e)}",
                'location': 'N/A'
            }]
        
        # Create a unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan result object
        scan_result = {
            'scanId': scan_id,
            'bucketName': bucket_name,
            'objectKey': object_key,
            'timestamp': datetime.datetime.now().isoformat(),
            'classificationType': classification_type,
            'securityIssues': security_issues,
            'piiFindings': pii_findings,
            'phiFindings': phi_findings,
            'fedrampFindings': fedramp_findings,
            'transferAllowed': classification_type != 'Type3'
        }
        
        # Store the scan result in a dedicated bucket/folder
        try:
            s3_client.put_object(
                Bucket=RESULTS_BUCKET,
                Key=f'scan-results/{scan_id}.json',
                Body=json.dumps(scan_result),
                ContentType='application/json'
            )
        except Exception as e:
            print(f"Error storing scan results: {str(e)}")
            # Don't fail the function if we can't store results
        
        # Send notification if Type3 data is found
        if classification_type == 'Type3':
            try:
                send_notification(scan_result)
            except Exception as e:
                print(f"Error sending notification: {str(e)}")
                # Don't fail the function if notification fails
        
        # Return the response in the format matching the API schema
        return {
            'scanId': scan_id,
            'classificationType': classification_type,
            'securityIssues': security_issues,
            'transferAllowed': classification_type != 'Type3'
        }
        
    except Exception as e:
        print(f"Unhandled exception in scan_file: {str(e)}")
        traceback.print_exc()
        return {
            'error': f'Error scanning file: {str(e)}',
            'errorCode': 'SCAN_ERROR'
        }

def scan_bucket(event):
    """
    Scan all (or a subset) of objects in an S3 bucket.
    Input event supports:
      - bucketName  (required)
      - prefix      (optional, limit to a folder)
      - maxKeys     (optional, cap total scanned objects)
    Returns a summary + per-object results.
    """
    bucket_name = event.get('bucketName')
    prefix = event.get('prefix', '')
    max_keys = event.get('maxKeys')  # int or None

    if not bucket_name:
        return {
            'error': 'Missing required parameter: bucketName',
            'errorCode': 'MISSING_PARAMETERS'
        }

    results = []
    errors = []
    total_scanned = 0

    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        page_iter = paginator.paginate(Bucket=bucket_name, Prefix=prefix) if prefix else paginator.paginate(Bucket=bucket_name)

        for page in page_iter:
            for obj in page.get('Contents', []):
                key = obj['Key']
                # obey limit if provided
                if isinstance(max_keys, int) and total_scanned >= max_keys:
                    break

                # Skip "folders"
                if key.endswith('/'):
                    continue

                scan_event = {'bucketName': bucket_name, 'objectKey': key}
                try:
                    scan_result = scan_file(scan_event)
                    # tag ‘objectKey’ onto result for clarity
                    if isinstance(scan_result, dict):
                        scan_result['objectKey'] = key
                    results.append(scan_result)
                except Exception as e:
                    errors.append({'objectKey': key, 'error': str(e)})
                total_scanned += 1

            if isinstance(max_keys, int) and total_scanned >= max_keys:
                break

        summary = {
            'bucket': bucket_name,
            'prefix': prefix or '',
            'totalObjectsScanned': total_scanned,
            'totalSucceeded': len([r for r in results if isinstance(r, dict) and 'error' not in r]),
            'totalFailed': len(errors),
        }

        # Optionally store a summary artifact
        try:
            manifest = {
                'summary': summary,
                'results': results[:1000],   # avoid huge payloads
                'errors': errors[:1000]
            }
            s3_client.put_object(
                Bucket=RESULTS_BUCKET,
                Key=f'scan-results/bucket-scan-{uuid.uuid4()}.json',
                Body=json.dumps(manifest),
                ContentType='application/json'
            )
        except Exception as e:
            print(f"Warning: failed to write bucket-scan manifest: {e}")

        # Return compact payload (summary + counts + first N details)
        return {
            'summary': summary,
            'errors': errors[:100],
            'sampleResults': results[:100]
        }

    except Exception as e:
        print(f"Unhandled exception in scan_bucket: {str(e)}")
        traceback.print_exc()
        return {
            'error': f'Error scanning bucket: {str(e)}',
            'errorCode': 'BUCKET_SCAN_ERROR'
        }

def transfer_file(event):
    """Transfer a file between buckets with comprehensive error handling"""
    try:
        source_bucket = event.get('sourceBucket')
        source_key = event.get('sourceKey')
        destination_bucket = event.get('destinationBucket')
        destination_key = event.get('destinationKey') or source_key
        
        if not source_bucket or not source_key or not destination_bucket:
            return {
                'error': 'Missing required parameters for file transfer',
                'errorCode': 'MISSING_PARAMETERS'
            }
        
        # First scan the file
        try:
            scan_event = {
                'bucketName': source_bucket,
                'objectKey': source_key
            }
            scan_result = scan_file(scan_event)
            
            # Check if scan_result is an error response
            if isinstance(scan_result, dict) and 'error' in scan_result:
                return {
                    'transferId': str(uuid.uuid4()),
                    'success': False,
                    'message': f'Scan failed: {scan_result.get("error", "Unknown error")}',
                    'scanId': None
                }
        except Exception as e:
            print(f"Error during pre-transfer scan: {str(e)}")
            return {
                'transferId': str(uuid.uuid4()),
                'success': False,
                'message': f'Pre-transfer scan failed: {str(e)}',
                'scanId': None
            }
        
        # If Type3 data, block transfer
        if not scan_result.get('transferAllowed', True):
            transfer_result = {
                'transferId': str(uuid.uuid4()),
                'success': False,
                'message': 'Transfer blocked due to Type3 data detection',
                'scanId': scan_result.get('scanId')
            }
            
            try:
                send_notification({
                    'type': 'TRANSFER_BLOCKED',
                    'reason': 'Type3 data detected',
                    'sourceBucket': source_bucket,
                    'sourceKey': source_key,
                    'destinationBucket': destination_bucket,
                    'scanId': scan_result.get('scanId')
                })
            except Exception as e:
                print(f"Error sending notification for blocked transfer: {str(e)}")
                # Don't fail if notification fails
            
            return transfer_result
        
        # Proceed with transfer
        try:
            # Copy the object
            copy_source = {'Bucket': source_bucket, 'Key': source_key}
            s3_client.copy_object(
                CopySource=copy_source,
                Bucket=destination_bucket,
                Key=destination_key
            )
            
            # Apply tags based on classification
            classification_type = scan_result.get('classificationType')
            
            tags = {
                'Type1_Data': 'true' if classification_type == 'Type1' else 'false',
                'Type2_Data': 'true' if classification_type == 'Type2' else 'false',
                'Type3_Data': 'false',  # Type3 would be blocked
                'DataClassification': get_classification_label(classification_type),
                'ContainsPII': 'true' if any(scan_result.get('piiFindings', [])) else 'false',
                'ContainsPHI': 'true' if any(scan_result.get('phiFindings', [])) else 'false',
                'FedRAMPCompliant': 'true' if not any(scan_result.get('fedrampFindings', [])) else 'false',
                'LastScanned': datetime.datetime.now().isoformat(),
                'ScanId': scan_result.get('scanId', '')
            }
            
            try:
                tag_set = [{'Key': k, 'Value': v} for k, v in tags.items()]
                s3_client.put_object_tagging(
                    Bucket=destination_bucket,
                    Key=destination_key,
                    Tagging={'TagSet': tag_set}
                )
            except Exception as e:
                print(f"Error applying tags: {str(e)}")
                # Don't fail the transfer if tagging fails
            
            transfer_result = {
                'transferId': str(uuid.uuid4()),
                'success': True,
                'message': f'Transfer completed successfully. Classification: {classification_type}',
                'scanId': scan_result.get('scanId'),
                'appliedTags': tags
            }
            
            return transfer_result
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = f"S3 error ({error_code}): {str(e)}"
            print(error_message)
            return {
                'transferId': str(uuid.uuid4()),
                'success': False,
                'message': f'Transfer failed: {error_message}',
                'scanId': scan_result.get('scanId')
            }
        except Exception as e:
            print(f"Error during transfer: {str(e)}")
            return {
                'transferId': str(uuid.uuid4()),
                'success': False,
                'message': f'Transfer failed: {str(e)}',
                'scanId': scan_result.get('scanId')
            }
            
    except Exception as e:
        print(f"Unhandled exception in transfer_file: {str(e)}")
        traceback.print_exc()
        return {
            'error': f'Error transferring file: {str(e)}',
            'errorCode': 'TRANSFER_ERROR'
        }

def get_classification_report(event):
    """Get classification report with comprehensive error handling"""
    try:
        scan_id = event.get('scanId')
        
        if not scan_id:
            return {
                'error': 'Missing required scan ID',
                'errorCode': 'MISSING_SCAN_ID'
            }
        
        try:
            # Get the scan result from the results bucket
            response = s3_client.get_object(
                Bucket=RESULTS_BUCKET,
                Key=f'scan-results/{scan_id}.json'
            )
            scan_result_json = response['Body'].read().decode('utf-8')
            scan_result = safe_json_loads(scan_result_json)
            if not scan_result:
                return {
                    'error': 'Error parsing scan result data',
                    'errorCode': 'PARSE_ERROR'
                }
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'NoSuchKey':
                return {
                    'error': f'Scan report not found for ID: {scan_id}',
                    'errorCode': 'REPORT_NOT_FOUND'
                }
            else:
                print(f"S3 error retrieving scan result: {str(e)}")
                return {
                    'error': f'Error retrieving scan result: {str(e)}',
                    'errorCode': 'S3_ERROR'
                }
        except Exception as e:
            print(f"Error retrieving scan result: {str(e)}")
            return {
                'error': f'Error retrieving classification report: {str(e)}',
                'errorCode': 'RETRIEVAL_ERROR'
            }
        
        # Format a detailed classification report
        detailed_findings = []
        
        # Process PII findings
        try:
            for finding in scan_result.get('piiFindings', []):
                detailed_findings.append({
                    'findingType': 'PII',
                    'entityType': finding.get('Type'),
                    'location': f"Score: {finding.get('Score')}",
                    'context': 'Redacted for security',
                    'complianceStandard': 'FedRAMP, GDPR, CCPA'
                })
        except Exception as e:
            print(f"Error processing PII findings: {str(e)}")
            # Continue with other findings
        
        # Process PHI findings
        try:
            for finding in scan_result.get('phiFindings', []):
                detailed_findings.append({
                    'findingType': 'PHI',
                    'entityType': finding.get('type'),
                    'location': finding.get('location', 'N/A'),
                    'context': 'Redacted for security',
                    'complianceStandard': 'HIPAA, FedRAMP'
                })
        except Exception as e:
            print(f"Error processing PHI findings: {str(e)}")
            # Continue with other findings
        
        # Process FedRAMP findings
        try:
            for finding in scan_result.get('fedrampFindings', []):
                detailed_findings.append({
                    'findingType': 'FedRAMP',
                    'entityType': finding.get('type'),
                    'location': finding.get('location', 'N/A'),
                    'context': finding.get('description', 'N/A'),
                    'complianceStandard': 'FedRAMP'
                })
        except Exception as e:
            print(f"Error processing FedRAMP findings: {str(e)}")
            # Continue with other findings
            
        # Create the full report
        report = {
            'scanId': scan_id,
            'scanDate': scan_result.get('timestamp'),
            'bucketName': scan_result.get('bucketName'),
            'objectKey': scan_result.get('objectKey'),
            'classificationType': scan_result.get('classificationType'),
            'classificationLabel': get_classification_label(scan_result.get('classificationType')),
            'transferAllowed': scan_result.get('transferAllowed', False),
            'securityIssuesCount': len(scan_result.get('securityIssues', [])),
            'piiFindings': len(scan_result.get('piiFindings', [])),
            'phiFindings': len(scan_result.get('phiFindings', [])),
            'fedrampFindings': len(scan_result.get('fedrampFindings', [])),
            'detailedFindings': detailed_findings,
            'remediationSteps': get_remediation_steps(scan_result.get('classificationType'), 
                                                   scan_result.get('securityIssues', []))
        }
        
        return report
        
    except Exception as e:
        print(f"Unhandled exception in get_classification_report: {str(e)}")
        traceback.print_exc()
        return {
            'error': f'Error generating classification report: {str(e)}',
            'errorCode': 'REPORT_ERROR'
        }

def detect_pii(content):
    """Detect PII in content using AWS Comprehend"""
    if not content or len(content) == 0:
        return []

    # Truncate content if it exceeds Comprehend limits (100KB)
    max_bytes = 99000  # Slightly less than 100KB to be safe
    content_bytes = content.encode('utf-8')
    if len(content_bytes) > max_bytes:
        content = content_bytes[:max_bytes].decode('utf-8', errors='replace')
        print(f"Content truncated to {max_bytes} bytes for PII detection")
    
    try:
        response = comprehend_client.detect_pii_entities(
            Text=content,
            LanguageCode='en'
        )
        
        pii_findings = []
        for entity in response.get('Entities', []):
            # Only include entities with a type in our allowed list
            if entity['Type'] in PII_ENTITY_TYPES:
                pii_findings.append({
                    'Type': entity['Type'],
                    'Score': entity['Score'],
                    'BeginOffset': entity['BeginOffset'],
                    'EndOffset': entity['EndOffset']
                })
        
        return pii_findings
    except Exception as e:
        print(f"Error in PII detection: {str(e)}")
        raise

def detect_phi(content):
    """Detect PHI in content using regex patterns"""
    if not content or len(content) == 0:
        return []
    
    phi_findings = []
    
    for phi_type, pattern in PHI_PATTERNS.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            start, end = match.span()
            phi_findings.append({
                'type': phi_type,
                'match': match.group(),
                'location': f"Characters {start}-{end}",
                'context': get_safe_context(content, start, end)
            })
    
    return phi_findings

def check_fedramp_compliance(content):
    """Check for FedRAMP compliance issues in content"""
    if not content or len(content) == 0:
        return []
    
    # Define patterns for potential FedRAMP compliance issues
    fedramp_patterns = {
        'unencrypted_credentials': r'(?i)(password|secret|api_?key|token|auth)[_\s]*=\s*[\'"][^\'"]+[\'"]',
        'aws_access_key': r'(?i)(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'aws_secret_key': r'(?i)[^A-Za-z0-9/+=][A-Za-z0-9/+=]{40}[^A-Za-z0-9/+=]',
        'ipv4_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'public_url': r'(?i)https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
        'sensitive_environments': r'(?i)(prod|production|staging)\s+environment'
    }
    
    findings = []
    
    for issue_type, pattern in fedramp_patterns.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            start, end = match.span()
            findings.append({
                'type': issue_type,
                'location': f"Characters {start}-{end}",
                'description': f"Potential {issue_type.replace('_', ' ')} found",
                'severity': get_fedramp_severity(issue_type)
            })
    
    return findings

def get_safe_context(content, start, end, context_chars=20):
    """Get a safe redacted context around a match"""
    # Calculate context boundaries
    context_start = max(0, start - context_chars)
    context_end = min(len(content), end + context_chars)
    
    # Get context before and after the match
    before = content[context_start:start]
    match = "[REDACTED]"  # Redact the actual match
    after = content[end:context_end]
    
    return before + match + after

def get_fedramp_severity(issue_type):
    """Get severity level for FedRAMP issue types"""
    high_severity = ['unencrypted_credentials', 'aws_access_key', 'aws_secret_key']
    medium_severity = ['ipv4_address', 'sensitive_environments']
    
    if issue_type in high_severity:
        return 'High'
    elif issue_type in medium_severity:
        return 'Medium'
    else:
        return 'Low'

def classify_data(pii_findings, phi_findings, fedramp_findings):
    """Classify data based on findings"""
    security_issues = []
    
    # Process PII findings
    for finding in pii_findings:
        entity_type = finding.get('Type')
        score = finding.get('Score', 0)
        
        # High-risk PII types that should be treated as Type3
        high_risk_pii = ['SSN', 'CREDIT_DEBIT_NUMBER', 'BANK_ACCOUNT_NUMBER', 
                          'CREDIT_DEBIT_CVV', 'PIN', 'PASSPORT_NUMBER']
        
        if entity_type in high_risk_pii:
            security_issues.append({
                'issueType': 'High-Risk PII',
                'severity': 'High',
                'description': f"Found {entity_type} (confidence: {score:.2f})",
                'location': f"Characters {finding.get('BeginOffset')}-{finding.get('EndOffset')}"
            })
        else:
            security_issues.append({
                'issueType': 'PII',
                'severity': 'Medium',
                'description': f"Found {entity_type} (confidence: {score:.2f})",
                'location': f"Characters {finding.get('BeginOffset')}-{finding.get('EndOffset')}"
            })
    
    # Process PHI findings
    for finding in phi_findings:
        security_issues.append({
            'issueType': 'PHI',
            'severity': 'High',
            'description': f"Found PHI ({finding.get('type')})",
            'location': finding.get('location', 'N/A')
        })
    
    # Process FedRAMP findings
    for finding in fedramp_findings:
        security_issues.append({
            'issueType': 'FedRAMP',
            'severity': finding.get('severity', 'Medium'),
            'description': finding.get('description', 'Unknown compliance issue'),
            'location': finding.get('location', 'N/A')
        })
    
    # Determine classification type based on findings
    classification_type = 'Type1'  # Default - public data
    
    # Check for high severity issues that would make it Type3
    high_severity_issues = [issue for issue in security_issues if issue['severity'] == 'High']
    medium_severity_issues = [issue for issue in security_issues if issue['severity'] == 'Medium']
    
    # If we have any high severity issues, it's Type3
    if high_severity_issues:
        classification_type = 'Type3'  # Restricted data
    # If we have medium severity issues but no high, it's Type2
    elif medium_severity_issues:
        classification_type = 'Type2'  # Sensitive data
    # Otherwise it's Type1
    else:
        classification_type = 'Type1'  # Public data
    
    return classification_type, security_issues

def get_classification_label(classification_type):
    """Get a human-readable label for a classification type"""
    labels = {
        'Type1': 'Public Data',
        'Type2': 'Sensitive Data',
        'Type3': 'Restricted Data'
    }
    return labels.get(classification_type, 'Unknown')

def get_remediation_steps(classification_type, security_issues):
    """Get remediation steps based on classification and issues"""
    if not security_issues:
        return ['No security issues found, no remediation needed.']
    
    # Common remediation steps
    steps = []
    
    # Add steps based on classification type
    if classification_type == 'Type3':
        steps.append('This data contains highly sensitive information and should not be transferred without proper authorization.')
        steps.append('Review and redact all PII/PHI before any transfer.')
        steps.append('Encrypt all data at rest and in transit.')
        steps.append('Implement access controls to restrict data access.')
    elif classification_type == 'Type2':
        steps.append('This data contains sensitive information that requires careful handling.')
        steps.append('Consider encrypting the data during transfer.')
        steps.append('Implement proper access controls for the destination.')
    else:  # Type1
        steps.append('While classified as public data, always follow organizational data handling policies.')
    
    # Add specific steps based on issue types
    issue_types = [issue['issueType'] for issue in security_issues]
    if 'High-Risk PII' in issue_types:
        steps.append('Redact or encrypt all high-risk PII (SSN, credit card numbers, bank account numbers, etc.) before transfer.')
    if 'PHI' in issue_types:
        steps.append('Ensure compliance with HIPAA requirements for PHI data.')
    if 'FedRAMP' in issue_types:
        steps.append('Ensure the destination environment meets FedRAMP compliance requirements.')
    
    return steps

def send_notification(content):
    """Send an SNS notification with error handling"""
    try:
        # Format the notification message
        if isinstance(content, dict):
            # If this is a scan result or other structured data
            if 'scanId' in content:
                message = (
                    f"Security alert: Type3 data detected in scan {content.get('scanId')}\n"
                    f"Bucket: {content.get('bucketName')}\n"
                    f"Object: {content.get('objectKey')}\n"
                    f"Timestamp: {content.get('timestamp')}\n"
                    f"Security issues: {len(content.get('securityIssues', []))}\n"
                    f"Transfer allowed: {content.get('transferAllowed', False)}"
                )
            # If this is a transfer blocked notification
            elif 'type' in content and content['type'] == 'TRANSFER_BLOCKED':
                message = (
                    f"Transfer blocked: {content.get('reason')}\n"
                    f"Source bucket: {content.get('sourceBucket')}\n"
                    f"Source key: {content.get('sourceKey')}\n"
                    f"Destination bucket: {content.get('destinationBucket')}\n"
                    f"Scan ID: {content.get('scanId')}"
                )
            # Generic structured content
            else:
                message = json.dumps(content)
        else:
            # String content
            message = str(content)
            
        # Send the notification
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject='Security Data Transfer Alert'
        )
        
        print(f"Notification sent: {response['MessageId']}")
        return True
        
    except Exception as e:
        print(f"Error sending notification: {str(e)}")
        return False