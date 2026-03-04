#!/usr/bin/env pwsh
# Phase 1 Website Overhaul Deployment
# Deploys new pages, CSS, and updated main site

$ErrorActionPreference = "Stop"

$S3_BUCKET = "bedrockfrontend"
$CLOUDFRONT_ID = "EOK4YOONDZGMT"
$WEBSITE_URL = "https://d11k4vck88gnf5.cloudfront.net"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Phase 1 Website Overhaul Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Upload global CSS
Write-Host "Step 1: Uploading global CSS theme..." -ForegroundColor Yellow
try {
    aws s3 cp modules/s3/css/theme.css s3://$S3_BUCKET/css/theme.css --content-type "text/css"
    Write-Host "  - Uploaded theme.css" -ForegroundColor Green
} catch {
    Write-Host "  X Failed to upload CSS" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 2: Upload contact page
Write-Host "Step 2: Uploading contact page..." -ForegroundColor Yellow
try {
    aws s3 cp modules/s3/contact.html s3://$S3_BUCKET/contact.html --content-type "text/html"
    Write-Host "  - Uploaded contact.html" -ForegroundColor Green
} catch {
    Write-Host "  X Failed to upload contact page" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 3: Upload government documentation
Write-Host "Step 3: Uploading government documentation..." -ForegroundColor Yellow
try {
    aws s3 cp modules/s3/government/docs/security-data-transfer.html s3://$S3_BUCKET/government/docs/security-data-transfer.html --content-type "text/html"
    Write-Host "  - Uploaded security-data-transfer.html (docs)" -ForegroundColor Green
} catch {
    Write-Host "  X Failed to upload government docs" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 4: Upload government demo
Write-Host "Step 4: Uploading government demo..." -ForegroundColor Yellow
try {
    aws s3 cp modules/s3/government/demo/security-data-transfer.html s3://$S3_BUCKET/government/demo/security-data-transfer.html --content-type "text/html"
    Write-Host "  - Uploaded security-data-transfer.html (demo)" -ForegroundColor Green
} catch {
    Write-Host "  X Failed to upload government demo" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 5: Upload updated main website
Write-Host "Step 5: Uploading updated main website..." -ForegroundColor Yellow
try {
    aws s3 cp modules/s3/index_Enhanced.html s3://$S3_BUCKET/index.html --content-type "text/html"
    Write-Host "  - Uploaded index.html" -ForegroundColor Green
} catch {
    Write-Host "  X Failed to upload main website" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 6: Invalidate CloudFront cache
Write-Host "Step 6: Invalidating CloudFront cache..." -ForegroundColor Yellow
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
Write-Host "Phase 1 Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Deployed Files:" -ForegroundColor White
Write-Host "  - /css/theme.css (global styling)" -ForegroundColor Green
Write-Host "  - /contact.html (contact page)" -ForegroundColor Green
Write-Host "  - /government/docs/security-data-transfer.html" -ForegroundColor Green
Write-Host "  - /government/demo/security-data-transfer.html" -ForegroundColor Green
Write-Host "  - /index.html (updated with new links)" -ForegroundColor Green
Write-Host ""
Write-Host "New Features:" -ForegroundColor White
Write-Host "  - Unified dark theme across all pages" -ForegroundColor Cyan
Write-Host "  - Professional contact page with forms" -ForegroundColor Cyan
Write-Host "  - Security Data Transfer documentation" -ForegroundColor Cyan
Write-Host "  - Interactive Security Data Transfer demo" -ForegroundColor Cyan
Write-Host "  - Replaced alert() popups with real links" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test URLs:" -ForegroundColor White
Write-Host "  Main Site: $WEBSITE_URL" -ForegroundColor Cyan
Write-Host "  Contact: $WEBSITE_URL/contact.html" -ForegroundColor Cyan
Write-Host "  Docs: $WEBSITE_URL/government/docs/security-data-transfer.html" -ForegroundColor Cyan
Write-Host "  Demo: $WEBSITE_URL/government/demo/security-data-transfer.html" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: CloudFront cache invalidation may take 5-15 minutes." -ForegroundColor Yellow
Write-Host "Hard refresh (Ctrl+Shift+R) to see changes immediately." -ForegroundColor Yellow
Write-Host ""
