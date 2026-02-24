# AWS Services Audit & Updates

## Date: February 24, 2026

## AWS Services Inventory

### Compute & Serverless
- **AWS Lambda** (2 functions)
  - SecurityDataTransferProcessor - PII/PHI scanning and file transfer
  - BedrockPromptHandler - AI prompt processing
  
### Storage
- **Amazon S3** (5 buckets)
  - Source bucket - incoming files
  - Destination bucket - processed files
  - Results bucket - scan results
  - Frontend bucket - web UI hosting
  - Quarantine bucket - suspicious files

### Networking & Content Delivery
- **Amazon CloudFront** - CDN for frontend distribution
- **Amazon API Gateway (HTTP API)** - RESTful API endpoints

### Security & Identity
- **Amazon Cognito** - User authentication and authorization
- **AWS IAM** - Roles and policies for service permissions
- **AWS KMS** - Encryption key management (optional)

### AI/ML
- **Amazon Bedrock** - AI agent with action groups
- **Amazon Comprehend** - PII/PHI detection

### Monitoring & Notifications
- **Amazon CloudWatch Logs** - Centralized logging
- **Amazon SNS** - Alert notifications

## Security Updates Applied

### 1. CloudFront TLS Configuration
**Issue**: Using deprecated TLSv1 protocol
**Fix**: Updated to TLSv1.2_2021 with SNI-only support
**Impact**: Improved security posture, reduced costs (SNI vs VIP)

### 2. S3 Encryption Enhancement
**Issue**: Only AES256 encryption available
**Fix**: Added support for AWS KMS encryption with optional key specification
**Impact**: Enhanced security with audit trails and key rotation capabilities

### 3. IAM Least Privilege
**Issue**: Overly permissive `kms:*` and `ssm:*` permissions
**Fix**: Restricted to specific actions (kms:Decrypt, kms:DescribeKey) with service conditions
**Impact**: Reduced attack surface, improved compliance

### 4. CloudWatch Logs Encryption
**Issue**: Logs not encrypted at rest
**Fix**: Added optional KMS encryption for log groups
**Impact**: Enhanced data protection for sensitive logs

### 5. Bedrock Agent Enhancements
**Issue**: Missing guardrails and prompt override configurations
**Fix**: Added support for Bedrock guardrails and prompt override
**Impact**: Better control over AI responses, enhanced security

### 6. Module Dependency Fix
**Issue**: Circular dependency in S3 module (quarantine bucket)
**Fix**: Moved quarantine bucket to main configuration
**Impact**: Cleaner module structure, resolved dependency issues

## Version Updates

### Terraform
- **Previous**: >= 1.6.0
- **Updated**: >= 1.7.0
- **Reason**: Access to latest features and bug fixes

### AWS Provider
- **Previous**: >= 5.60
- **Updated**: >= 5.80
- **Reason**: Latest Bedrock agent features, security patches

### Archive Provider
- **Added**: >= 2.4
- **Reason**: Required for Lambda deployment packaging

## Recommendations

### High Priority
1. Enable KMS encryption for S3 buckets containing sensitive data
2. Enable KMS encryption for CloudWatch Logs
3. Configure Bedrock guardrails for production workloads
4. Review and restrict S3 bucket policies to specific principals

### Medium Priority
1. Enable S3 versioning for critical buckets (source, destination)
2. Implement S3 lifecycle policies for cost optimization
3. Add CloudWatch alarms for Lambda errors and API Gateway 4xx/5xx
4. Configure API Gateway throttling and rate limiting

### Low Priority
1. Consider using CloudFront custom domain with ACM certificate
2. Implement S3 access logging for audit trails
3. Add tags for cost allocation and resource management
4. Document disaster recovery procedures

## Cost Optimization Opportunities

1. **CloudFront**: Changed from VIP to SNI-only SSL (~$600/month savings per distribution)
2. **S3**: Consider Intelligent-Tiering for infrequently accessed data
3. **Lambda**: Review memory allocation and timeout settings
4. **CloudWatch Logs**: Implement retention policies (currently 30 days)

## Compliance Considerations

### FedRAMP
- KMS encryption now available for data at rest
- CloudWatch Logs encryption available
- IAM policies follow least privilege principle

### HIPAA
- Bedrock guardrails can help prevent PHI leakage
- Enhanced encryption options for sensitive data
- Audit trail improvements with KMS

## Next Steps

1. Update `terraform.tfvars` with new optional variables
2. Run `terraform plan` to review changes
3. Test in non-production environment first
4. Update documentation and runbooks
5. Schedule maintenance window for production deployment
