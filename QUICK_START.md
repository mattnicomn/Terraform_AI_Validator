# Quick Start Guide

## Step 1: Add Your Assets

Place these files in the `assets/` directory:

```
assets/
├── logo.png           ← Your company logo (40x40px or 320x80px)
├── favicon.ico        ← Browser icon (16x16px or 32x32px)
├── profile.png        ← Your profile photo (84x84px)
└── resume.pdf         ← Your resume PDF
```

### Quick Asset Creation Tips:

**Don't have assets ready?** Use these temporary placeholders:

1. **Logo & Profile**: Create a simple colored square with your initials
   - Use Canva, Figma, or even PowerPoint
   - Export as PNG with transparent background

2. **Favicon**: Convert your logo to ICO format
   - Use https://favicon.io or https://realfavicongenerator.net

3. **Resume**: Export from Word/Google Docs as PDF

## Step 2: Configure Variables

Create `terraform.tfvars` in the root directory:

```hcl
# Basic Configuration
region  = "us-east-1"
project = "security-data-transfer"
env     = "prod"

# Lambda Code (update with your S3 bucket)
processor_s3_bucket = "your-lambda-code-bucket"
processor_s3_key    = "SecurityDataTransferProcessor.zip"
prompt_s3_bucket    = "your-lambda-code-bucket"
prompt_s3_key       = "BedrockPromptHandler.zip"

# Bedrock (already configured with discovered values)
bedrock_agent_id       = "NNKUTQQWKP"
bedrock_agent_alias_id = "GVM7ZZPOOM"
```

## Step 3: Deploy

```bash
# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Apply changes
terraform apply
```

## Step 4: Verify

```bash
# Get your CloudFront URL
terraform output cloudfront_url

# Open in browser
start $(terraform output -raw cloudfront_url)  # Windows
# or
open $(terraform output -raw cloudfront_url)   # Mac/Linux
```

## Current Directory Structure

```
Terraform_AI_Validator/
├── assets/                    ← ADD YOUR FILES HERE
│   ├── README.md
│   ├── .gitkeep
│   ├── logo.png              ← ADD THIS
│   ├── favicon.ico           ← ADD THIS
│   ├── profile.png           ← ADD THIS
│   └── resume.pdf            ← ADD THIS
├── modules/
│   ├── api_gateway/
│   ├── bedrock/
│   ├── cloudfront/
│   ├── cognito/
│   ├── iam/
│   ├── lambda/
│   ├── lambda_sd_transfer/
│   ├── s3/
│   └── sns_alerts/
├── openapi/
├── main.tf
├── variables.tf
├── terraform.tfvars          ← CREATE THIS
├── s3_assets_upload.tf       ← Handles asset uploads
├── ssm_parameters.tf         ← CloudFront key management
└── README.md

```

## What Happens When You Apply?

1. **S3 Buckets** created (source, destination, results, frontend, quarantine)
2. **CloudFront Distribution** created with your domain
3. **Lambda Functions** deployed (BedrockPromptHandler, SecurityDataTransferProcessor)
4. **API Gateway** configured with routes
5. **Cognito** user pool and client configured
6. **Assets uploaded** from `assets/` to S3 automatically
7. **Frontend accessible** via CloudFront URL

## Troubleshooting

### "Assets not found"
Make sure files are in the `assets/` directory:
```bash
ls assets/
# Should show: logo.png, favicon.ico, profile.png, resume.pdf
```

### "Lambda code not found"
Upload your Lambda code to S3 first:
```bash
cd modules/lambda/src/BedrockPromptHandler
zip -r BedrockPromptHandler.zip .
aws s3 cp BedrockPromptHandler.zip s3://your-bucket/
```

### "Permission denied"
Check your AWS credentials:
```bash
aws sts get-caller-identity
```

## Next Steps

After successful deployment:

1. ✅ Test the CloudFront URL
2. ✅ Login with Cognito credentials
3. ✅ Test Bedrock prompt functionality
4. ✅ Review CloudWatch logs
5. ✅ Set up monitoring and alarms

## Need Help?

- See **DEPLOYMENT_GUIDE.md** for detailed instructions
- See **CLOUDFRONT_RESOURCES_INVENTORY.md** for resource details
- See **AWS_SERVICES_AUDIT.md** for security recommendations
