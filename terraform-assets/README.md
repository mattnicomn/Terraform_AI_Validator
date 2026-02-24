# US Mission Hero - Terraform Assets Management

This directory contains a clean, standalone Terraform configuration for managing your US Mission Hero frontend assets.

## What This Manages

✅ **S3 Bucket:** `bedrockfrontend`  
✅ **Assets:**
- index.html (US Mission Hero branding)
- assets/logo.png (your logo)
- assets/US-Mission-Hero.png (your logo)
- assets/profile.png (your logo)
- assets/resume.pdf (your resume)

✅ **CloudFront:** References existing distribution (data source only)

## What This Doesn't Manage

These resources already exist and work fine:
- ❌ Lambda functions
- ❌ API Gateway
- ❌ Cognito
- ❌ Bedrock Agent
- ❌ SNS Topics

## Quick Start

### 1. Initialize Terraform

```powershell
cd terraform-assets
terraform init
```

### 2. Review What Will Be Created

```powershell
terraform plan
```

### 3. Apply Configuration

```powershell
terraform apply
```

Type `yes` when prompted.

### 4. View Outputs

```powershell
terraform output
```

## Common Commands

### Deploy/Update Assets
```powershell
terraform apply
```

### Destroy Everything
```powershell
terraform destroy
```

**Warning:** This will delete your S3 bucket and all assets!

### View Current State
```powershell
terraform show
```

### List Managed Resources
```powershell
terraform state list
```

### Refresh State
```powershell
terraform refresh
```

### Format Code
```powershell
terraform fmt
```

### Validate Configuration
```powershell
terraform validate
```

## Updating Assets

### Update Logo
1. Replace `../assets/US Mission Hero.png`
2. Run: `terraform apply`

### Update Resume
1. Replace `../assets/Resume - Matthew Nico.pdf`
2. Run: `terraform apply`

### Update HTML
1. Edit `../modules/s3/index_Final.html`
2. Run: `terraform apply`

## Invalidate CloudFront Cache

After deploying changes, invalidate CloudFront cache:

```powershell
aws cloudfront create-invalidation `
  --distribution-id $(terraform output -raw cloudfront_id) `
  --paths "/*"
```

Or use the helper script:

```powershell
# From terraform-assets directory
$distId = terraform output -raw cloudfront_id
aws cloudfront create-invalidation --distribution-id $distId --paths "/*"
```

## Configuration

Edit `terraform.tfvars` to customize:

```hcl
# AWS Configuration
region = "us-east-1"

# Project Information
project     = "US Mission Hero"
environment = "prod"
owner       = "Platform Team"

# S3 Bucket
bucket_name   = "bedrockfrontend"
allow_destroy = true  # Set to false in production

# CloudFront
cloudfront_distribution_id = "EOK4YOONDZGMT"

# Features
enable_versioning = false  # Set to true for file versioning
```

## Importing Existing Resources

If the S3 bucket already exists (it does), import it:

```powershell
terraform import aws_s3_bucket.frontend bedrockfrontend
```

Then run:
```powershell
terraform plan
```

Terraform will show what needs to be updated.

## Troubleshooting

### "Bucket already exists"
The bucket exists from manual deployment. Import it:
```powershell
terraform import aws_s3_bucket.frontend bedrockfrontend
```

### "Access Denied"
Check AWS credentials:
```powershell
aws sts get-caller-identity
aws configure
```

### "File not found"
Ensure you're in the `terraform-assets` directory and parent directories have the assets:
```powershell
cd terraform-assets
Test-Path ../assets/US Mission Hero.png
Test-Path ../modules/s3/index_Final.html
```

### Changes not visible on site
Invalidate CloudFront cache:
```powershell
$distId = terraform output -raw cloudfront_id
aws cloudfront create-invalidation --distribution-id $distId --paths "/*"
```

## File Structure

```
terraform-assets/
├── main.tf              # Main Terraform configuration
├── variables.tf         # Variable definitions
├── terraform.tfvars     # Your variable values
├── README.md            # This file
└── .terraform/          # Terraform working directory (created by init)
```

## State Management

Terraform state is stored locally in:
- `terraform.tfstate` - Current state
- `terraform.tfstate.backup` - Previous state

**Important:** Don't delete these files! They track what Terraform manages.

For team collaboration, consider using remote state:
- S3 backend
- Terraform Cloud
- Other remote backends

## Safety Features

### Prevent Accidental Deletion
Set in `terraform.tfvars`:
```hcl
allow_destroy = false
```

This prevents `terraform destroy` from deleting the bucket.

### Enable Versioning
Set in `terraform.tfvars`:
```hcl
enable_versioning = true
```

This keeps previous versions of your files.

## Next Steps

1. ✅ Initialize: `terraform init`
2. ✅ Plan: `terraform plan`
3. ✅ Apply: `terraform apply`
4. ✅ Test: Open https://d11k4vck88gnf5.cloudfront.net
5. ✅ Update: Modify assets and `terraform apply`
6. ✅ Destroy: `terraform destroy` (when needed)

## Support

- **Terraform Docs:** https://www.terraform.io/docs
- **AWS Provider:** https://registry.terraform.io/providers/hashicorp/aws/latest/docs
- **Your Site:** https://d11k4vck88gnf5.cloudfront.net

## Version Info

- Terraform: >= 1.7.0
- AWS Provider: >= 5.80
- Region: us-east-1
