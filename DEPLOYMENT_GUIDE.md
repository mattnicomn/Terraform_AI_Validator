# Deployment Guide - Updated Infrastructure

## Overview
This guide covers deploying the updated Terraform infrastructure with all discovered CloudFront and S3 resources properly configured.

## Prerequisites

### 1. AWS Credentials
Ensure your AWS credentials are configured:
```bash
aws configure
# or set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_DEFAULT_REGION="us-east-1"
```

### 2. Required Assets
Create an `assets` directory in the project root with the following files:

```bash
mkdir -p assets
```

Required files:
- `assets/logo.png` - Company logo (40x40px or 320x80px recommended)
- `assets/favicon.ico` - Browser icon (16x16px or 32x32px)
- `assets/profile.png` - Profile photo (84x84px recommended)
- `assets/resume.pdf` - Resume PDF file

### 3. CloudFront Key Pair (Optional but Recommended)
If you want to use CloudFront signed URLs:

```bash
# Generate RSA key pair
openssl genrsa -out cloudfront_private_key.pem 2048
openssl rsa -pubout -in cloudfront_private_key.pem -out cloudfront_public_key.pem
```

## Configuration

### 1. Update terraform.tfvars

Create or update `terraform.tfvars` with your values:

```hcl
# Region
region = "us-east-1"

# Project metadata
project = "security-data-transfer"
env     = "prod"
owner   = "platform"

# Frontend CORS
frontend_allowed_origin = "https://d11k4vck88gnf5.cloudfront.net"

# Lambda code sources
processor_s3_bucket = "your-lambda-code-bucket"
processor_s3_key    = "SecurityDataTransferProcessor.zip"

prompt_s3_bucket = "your-lambda-code-bucket"
prompt_s3_key    = "BedrockPromptHandler.zip"

# Bedrock configuration
bedrock_model_id        = "anthropic.claude-3-haiku-20240307-v1:0"
bedrock_agent_id        = "NNKUTQQWKP"
bedrock_agent_alias_id  = "GVM7ZZPOOM"
enable_bedrock_agent    = true

# CloudFront signed URLs (optional)
# cloudfront_public_key_pem  = file("cloudfront_public_key.pem")
# cloudfront_private_key_pem = file("cloudfront_private_key.pem")

# KMS encryption (optional)
# log_group_kms_key_id = "your-kms-key-id"
# ssm_kms_key_id       = "your-kms-key-id"
```

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Review Changes

```bash
terraform plan -out=tfplan
```

Review the plan carefully, especially:
- New CloudFront public key and key group resources
- SSM parameter for CloudFront private key
- S3 object uploads for frontend assets
- Updated Lambda environment variables

## Deployment Steps

### Step 1: Deploy Infrastructure

```bash
terraform apply tfplan
```

### Step 2: Verify CloudFront Distribution

```bash
# Get CloudFront domain
terraform output cloudfront_url

# Test access
curl -I $(terraform output -raw cloudfront_url)
```

### Step 3: Upload Lambda Code

If you haven't already, package and upload your Lambda functions:

```bash
# Package BedrockPromptHandler
cd modules/lambda/src/BedrockPromptHandler
zip -r BedrockPromptHandler.zip .
aws s3 cp BedrockPromptHandler.zip s3://your-lambda-code-bucket/

# Package SecurityDataTransferProcessor
cd ../SecurityDataTransferProcessor
zip -r SecurityDataTransferProcessor.zip .
aws s3 cp SecurityDataTransferProcessor.zip s3://your-lambda-code-bucket/
```

### Step 4: Update Lambda Functions

```bash
# Trigger Lambda update
terraform apply -target=module.lambda_prompt -target=module.lambda_processor
```

### Step 5: Test the Application

1. Open the CloudFront URL in your browser
2. Click "Login with Cognito"
3. Authenticate with your Cognito credentials
4. Test the Bedrock prompt functionality

## Post-Deployment Verification

### 1. Check CloudFront Distribution

```bash
aws cloudfront get-distribution --id $(terraform output -raw cloudfront_distribution_id)
```

### 2. Verify S3 Assets

```bash
aws s3 ls s3://$(terraform output -raw s3_frontend)/assets/
```

Expected output:
```
favicon.ico
logo.png
profile.png
resume.pdf
```

### 3. Test Lambda Functions

```bash
# Test BedrockPromptHandler
aws lambda invoke \
  --function-name $(terraform output -raw lambda_prompt) \
  --payload '{"prompt":"Hello"}' \
  response.json

cat response.json
```

### 4. Verify SSM Parameters

```bash
aws ssm get-parameter --name /cloudfront/private_key.pem --with-decryption
```

## Troubleshooting

### Issue: Assets Not Found (404)

**Solution**: Ensure assets are uploaded to S3:
```bash
aws s3 sync assets/ s3://$(terraform output -raw s3_frontend)/assets/
```

### Issue: CloudFront Access Denied

**Solution**: Check S3 bucket policy allows CloudFront OAC:
```bash
aws s3api get-bucket-policy --bucket $(terraform output -raw s3_frontend)
```

### Issue: Lambda Can't Access SSM Parameter

**Solution**: Verify IAM permissions:
```bash
aws iam get-role-policy \
  --role-name BedrockPromptHandler-role-461wkeeg \
  --policy-name LambdaSSMCloudFrontKeyAccess
```

### Issue: Cognito Authentication Fails

**Solution**: Verify callback URLs match:
```bash
aws cognito-idp describe-user-pool-client \
  --user-pool-id us-east-1_qsT1OnMXw \
  --client-id 7ccfli4ti56r33as43qp6imat2
```

## Rollback Procedure

If you need to rollback:

```bash
# Destroy specific resources
terraform destroy -target=module.cloudfront
terraform destroy -target=aws_s3_object.frontend_assets

# Or full rollback
terraform destroy
```

## Maintenance

### Update Frontend Assets

```bash
# Update a single asset
aws s3 cp assets/logo.png s3://$(terraform output -raw s3_frontend)/assets/logo.png

# Invalidate CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id $(terraform output -raw cloudfront_distribution_id) \
  --paths "/assets/*"
```

### Rotate CloudFront Keys

```bash
# Generate new key pair
openssl genrsa -out cloudfront_private_key_new.pem 2048
openssl rsa -pubout -in cloudfront_private_key_new.pem -out cloudfront_public_key_new.pem

# Update terraform.tfvars with new keys
# Apply changes
terraform apply
```

### Update Lambda Code

```bash
# Upload new code
aws s3 cp BedrockPromptHandler.zip s3://your-lambda-code-bucket/

# Update function
aws lambda update-function-code \
  --function-name $(terraform output -raw lambda_prompt) \
  --s3-bucket your-lambda-code-bucket \
  --s3-key BedrockPromptHandler.zip
```

## Security Best Practices

1. **Enable KMS encryption** for CloudWatch Logs and SSM parameters
2. **Rotate CloudFront keys** annually
3. **Enable CloudFront access logging** for audit trails
4. **Use AWS Secrets Manager** for sensitive configuration (alternative to SSM)
5. **Enable S3 versioning** for critical buckets
6. **Implement CloudWatch alarms** for Lambda errors and API Gateway 4xx/5xx
7. **Review IAM policies** regularly for least privilege

## Cost Optimization

1. **CloudFront**: Using SNI-only SSL saves ~$600/month
2. **S3**: Implement lifecycle policies for old assets
3. **Lambda**: Right-size memory allocation based on CloudWatch metrics
4. **CloudWatch Logs**: Set appropriate retention periods (currently 30 days)

## Next Steps

1. Implement the placeholder API endpoints:
   - `/api/presign-upload` - For S3 presigned URL generation
   - `/api/logs` - For application logs and updates

2. Add CloudWatch dashboards for monitoring

3. Implement automated backups for critical S3 buckets

4. Set up CloudWatch alarms for:
   - Lambda errors
   - API Gateway 4xx/5xx errors
   - CloudFront error rates

5. Consider adding a custom domain with ACM certificate
