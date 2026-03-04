#!/usr/bin/env pwsh
# Phase 2 Website Overhaul Deployment
# Deploys remaining government documentation pages and updated main site

$ErrorActionPreference = "Stop"

$S3_BUCKET = "bedrockfrontend"
$CLOUDFRONT_ID = "EOK4YOONDZGMT"
$WEBSITE_URL = "https://d11k4vck88gnf5.cloudfront.net"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Phase 2 Website Overhaul Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Upload government documentation pages
Write-Host "Step 1: Uploading government documentation pages..." -ForegroundColor Yellow
try {
    aws s3 cp modules/s3/government/docs/fedramp-fisma.html s3://$S3_BUCKET/government/docs/fedramp-fisma.html --content-type "text/html"
    Write-Host "  - Uploaded fedramp-fisma.html" -ForegroundColor Green
    
    aws s3 cp modules/s3/government/docs/scca-saca.html s3://$S3_BUCKET/government/docs/scca-saca.html --content-type "text/html"
    Write-Host "  - Uploaded scca-saca.html" -ForegroundColor Green
    
    aws s3 cp modules/s3/government/docs/dod-dhs-solutions.html s3://$S3_BUCKET/government/docs/dod-dhs-solutions.html --content-type "text/html"
    Write-Host "  - Uploaded dod-dhs-solutions.html" -ForegroundColor Green
    
    aws s3 cp modules/s3/government/docs/rmf-nist.html s3://$S3_BUCKET/government/docs/rmf-nist.html --content-type "text/html"
    Write-Host "  - Uploaded rmf-nist.html" -ForegroundColor Green
    
    aws s3 cp modules/s3/government/docs/gold-ami.html s3://$S3_BUCKET/government/docs/gold-ami.html --content-type "text/html"
    Write-Host "  - Uploaded gold-ami.html" -ForegroundColor Green
} catch {
    Write-Host "  X Failed to upload documentation pages" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 2: Upload updated main website
Write-Host "Step 2: Uploading updated main website..." -ForegroundColor Yellow
try {
    aws s3 cp modules/s3/index_Enhanced.html s3://$S3_BUCKET/index.html --content-type "text/html"
    Write-Host "  - Uploaded index.html with new documentation links" -ForegroundColor Green
} catch {
    Write-Host "  X Failed to upload main website" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 3: Invalidate CloudFront cache
Write-Host "Step 3: Invalidating CloudFront cache..." -ForegroundColor Yellow
try {
    $invalidation = aws cloudfront create-invalidation `
        --distribution-id $CLOUDFRONT_ID `
        --paths "/*" `
        --output json | ConvertFrom-Json
    
    Write-Host "  - CloudFront invalidation created" -ForegroundColor Green
    Write-Host "  - Invalidation ID: $($invalidation.Invalidation.Id)" -ForegroundColor Gray
    Write-Host "  - Status: $($invalidation.Invalidation.Status)" -ForegroundColor Gray
} catch {
    Write-Host "  ! Warning: Could not invalidate CloudFront cache" -ForegroundColor Yellow
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Phase 2 Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Deployed Documentation Pages:" -ForegroundColor White
Write-Host "  - /government/docs/fedramp-fisma.html" -ForegroundColor Green
Write-Host "  - /government/docs/scca-saca.html" -ForegroundColor Green
Write-Host "  - /government/docs/dod-dhs-solutions.html" -ForegroundColor Green
Write-Host "  - /government/docs/rmf-nist.html" -ForegroundColor Green
Write-Host "  - /government/docs/gold-ami.html" -ForegroundColor Green
Write-Host "  - /index.html (updated with documentation links)" -ForegroundColor Green
Write-Host ""
Write-Host "All Government Solutions Now Have:" -ForegroundColor White
Write-Host "  - Comprehensive documentation pages" -ForegroundColor Cyan
Write-Host "  - Working 'Docs' buttons on main site" -ForegroundColor Cyan
Write-Host "  - Contact page integration" -ForegroundColor Cyan
Write-Host "  - Consistent dark theme styling" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test URLs:" -ForegroundColor White
Write-Host "  Main Site: $WEBSITE_URL" -ForegroundColor Cyan
Write-Host "  FedRAMP/FISMA: $WEBSITE_URL/government/docs/fedramp-fisma.html" -ForegroundColor Cyan
Write-Host "  SCCA/SACA: $WEBSITE_URL/government/docs/scca-saca.html" -ForegroundColor Cyan
Write-Host "  DoD/DHS: $WEBSITE_URL/government/docs/dod-dhs-solutions.html" -ForegroundColor Cyan
Write-Host "  RMF/NIST: $WEBSITE_URL/government/docs/rmf-nist.html" -ForegroundColor Cyan
Write-Host "  Gold AMI: $WEBSITE_URL/government/docs/gold-ami.html" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: CloudFront cache invalidation may take 5-15 minutes." -ForegroundColor Yellow
Write-Host "Hard refresh (Ctrl+Shift+R) to see changes immediately." -ForegroundColor Yellow
Write-Host ""
