# CloudFront & S3 Resources Inventory

## CloudFront Distribution
- **Domain**: `d11k4vck88gnf5.cloudfront.net`
- **Key Pair ID**: `K3PMISK1CK6HYH`
- **Purpose**: Frontend hosting with signed URLs for secure content delivery

## S3 Buckets

### Frontend Bucket: `bedrockfrontend`
- **Purpose**: Static website hosting
- **Region**: us-east-1
- **Access**: Via CloudFront OAC (Origin Access Control)

## Required Assets in S3

### Root Level
- `index.html` - Main application file (already exists in modules/s3/)
- `index_Final.html` - Alternative/updated version (already exists in modules/s3/)

### /assets/ Directory
The following assets are referenced in the HTML but need to be uploaded:

1. **favicon.ico** - Browser tab icon
   - Path: `/assets/favicon.ico`
   - Referenced in: Both HTML files

2. **logo.png** - Company/brand logo
   - Path: `/assets/logo.png`
   - Referenced in: Both HTML files
   - Used as: Main logo and fallback image
   - Dimensions: 40x40px (index.html), 320x80px (index_Final.html)

3. **profile.png** - Profile photo
   - Path: `/assets/profile.png`
   - Referenced in: index.html (About section)
   - Dimensions: 84x84px
   - Fallback: logo.png if not found

4. **resume.pdf** - Downloadable resume
   - Path: `/assets/resume.pdf`
   - Referenced in: index.html (About section)
   - Purpose: Download link for resume

## API Endpoints Referenced

### Primary API Gateway
- **URL**: `https://9heajy0ej8.execute-api.us-east-1.amazonaws.com/BedrockPromptHandler`
- **Method**: POST
- **Auth**: Bearer token (Cognito JWT)
- **Purpose**: Bedrock agent invocation

### Placeholder APIs (TODO - Not yet implemented)
- **Presign Upload**: `https://d11k4vck88gnf5.cloudfront.net/api/presign-upload`
  - Purpose: Generate S3 presigned URLs for file uploads
  - Status: Needs implementation

- **Logs API**: `https://d11k4vck88gnf5.cloudfront.net/api/logs`
  - Purpose: Store/retrieve application logs and updates
  - Status: Needs implementation

## Cognito Configuration

### User Pool
- **ID**: `us-east-1_qsT1OnMXw`
- **Region**: us-east-1
- **Domain**: `https://us-east-1qst1onmxw.auth.us-east-1.amazoncognito.com`

### App Client
- **ID**: `7ccfli4ti56r33as43qp6imat2`
- **Callback URL**: `https://d11k4vck88gnf5.cloudfront.net/index.html`
- **Auth Flow**: Authorization Code Grant with PKCE

## Bedrock Agent Configuration

### Agent Details (from Lambda)
- **Agent ID**: `NNKUTQQWKP`
- **Agent Alias ID**: `GVM7ZZPOOM`
- **Region**: us-east-1

## CloudFront Signed URLs

### Configuration
- **Key ID**: `K3PMISK1CK6HYH`
- **Private Key Location**: AWS Systems Manager Parameter Store
  - Parameter Name: `private_key.pem`
  - Encryption: Enabled
- **Expiration**: 1 hour from generation
- **Signing Algorithm**: RSA with SHA-1

## CORS Configuration

### Allowed Origins
- `https://d11k4vck88gnf5.cloudfront.net`

### Allowed Methods
- OPTIONS
- POST
- GET

### Allowed Headers
- Content-Type
- Authorization

## Action Items

### High Priority
1. ✅ Update Terraform to include CloudFront public key configuration
2. ✅ Add SSM parameter for CloudFront private key
3. ⚠️ Upload missing assets to S3:
   - favicon.ico
   - logo.png
   - profile.png
   - resume.pdf

### Medium Priority
4. ⚠️ Implement presign-upload API endpoint
5. ⚠️ Implement logs API endpoint
6. ✅ Update Lambda environment variables with correct IDs

### Low Priority
7. Consider migrating from SHA-1 to SHA-256 for CloudFront signing
8. Add CloudWatch alarms for CloudFront 4xx/5xx errors
9. Implement CloudFront access logging

## Security Considerations

1. **Private Key Management**: Currently stored in SSM Parameter Store (good practice)
2. **CORS**: Restricted to specific CloudFront domain (good)
3. **Authentication**: Using Cognito JWT tokens (good)
4. **Signed URLs**: 1-hour expiration (reasonable for most use cases)

## Cost Optimization

1. **CloudFront**: Using SNI-only SSL (cost-effective)
2. **S3**: Consider lifecycle policies for old assets
3. **Lambda**: Review memory allocation for BedrockPromptHandler
