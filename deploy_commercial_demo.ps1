# Deploy Commercial Bedrock & S3 Demo Update
# This script uploads the updated commercial demo to S3 and invalidates CloudFront cache

$S3_BUCKET = "bedrockfrontend"
$CLOUDFRONT_DIST_ID = "EOK4YOONDZGMT"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Deploying Commercial Demo Update" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Upload the updated commercial demo
Write-Host "Uploading commercial/bedrock-s3-demo.html..." -ForegroundColor Yellow
aws s3 cp modules/s3/commercial/bedrock-s3-demo.html s3://$S3_BUCKET/commercial/bedrock-s3-demo.html --content-type "text/html"

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Commercial demo uploaded successfully" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to upload commercial demo" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Invalidate CloudFront cache
Write-Host "Invalidating CloudFront cache..." -ForegroundColor Yellow
$INVALIDATION_OUTPUT = aws cloudfront create-invalidation --distribution-id $CLOUDFRONT_DIST_ID --paths "/commercial/bedrock-s3-demo.html" --query 'Invalidation.Id' --output text

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ CloudFront invalidation created: $INVALIDATION_OUTPUT" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to create CloudFront invalidation" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Updated commercial demo is now live at:" -ForegroundColor White
Write-Host "https://d11k4vck88gnf5.cloudfront.net/commercial/bedrock-s3-demo.html" -ForegroundColor Cyan
Write-Host ""
Write-Host "CloudFront Invalidation ID: $INVALIDATION_OUTPUT" -ForegroundColor White
Write-Host "Note: Cache invalidation may take 5-10 minutes to complete." -ForegroundColor Yellow
