#!/usr/bin/env pwsh
# Complete Website Deployment Script
# Deploys HTML + All Assets to S3 and Invalidates CloudFront

$ErrorActionPreference = "Stop"

$S3_BUCKET = "bedrockfrontend"
$CLOUDFRONT_ID = "EOK4YOONDZGMT"
$WEBSITE_URL = "https://d11k4vck88gnf5.cloudfront.net"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "US Mission Hero - Complete Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Backup current website
Write-Host "Step 1: Backing up current website..." -ForegroundColor Yellow
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = "modules/s3/index_backup_$timestamp.html"

try {
    if (Test-Path "modules/s3/index_Enhanced.html") {
        Copy-Item "modules/s3/index_Enhanced.html" $backupFile
        Write-Host "Success: Backup created at $backupFile" -ForegroundColor Green
    }
} catch {
    Write-Host "Warning: Could not create backup" -ForegroundColor Yellow
}
Write-Host ""

# Step 2: Verify files
Write-Host "Step 2: Verifying files..." -ForegroundColor Yellow
if (-not (Test-Path "modules/s3/index_Enhanced.html")) {
    Write-Host "Error: Enhanced website file not found!" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "assets")) {
    Write-Host "Error: Assets folder not found!" -ForegroundColor Red
    exit 1
}
Write-Host "Success: All files found" -ForegroundColor Green
Write-Host ""

# Step 3: Upload HTML
Write-Host "Step 3: Uploading website HTML..." -ForegroundColor Yellow
try {
    aws s3 cp modules/s3/index_Enhanced.html s3://$S3_BUCKET/index.html --content-type "text/html"
    Write-Host "Success: HTML uploaded to S3" -ForegroundColor Green
} catch {
    Write-Host "Error: Failed to upload HTML" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 4: Upload Assets
Write-Host "Step 4: Uploading assets folder..." -ForegroundColor Yellow
try {
    # Upload all files in assets folder
    aws s3 sync assets/ s3://$S3_BUCKET/assets/ --delete --exclude ".gitkeep" --exclude "README.md"
    Write-Host "Success: Assets uploaded to S3" -ForegroundColor Green
    Write-Host "  - US-Mission-Hero.png" -ForegroundColor Gray
    Write-Host "  - Resume - Ernest.pdf" -ForegroundColor Gray
    Write-Host "  - Resume - Matthew Nico.pdf" -ForegroundColor Gray
} catch {
    Write-Host "Error: Failed to upload assets" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 5: Invalidate CloudFront
Write-Host "Step 5: Invalidating CloudFront cache..." -ForegroundColor Yellow
try {
    $invalidation = aws cloudfront create-invalidation `
        --distribution-id $CLOUDFRONT_ID `
        --paths "/*" `
        --output json | ConvertFrom-Json
    
    Write-Host "Success: CloudFront invalidation created" -ForegroundColor Green
    Write-Host "  Invalidation ID: $($invalidation.Invalidation.Id)" -ForegroundColor Gray
    Write-Host "  Status: $($invalidation.Invalidation.Status)" -ForegroundColor Gray
} catch {
    Write-Host "Warning: Could not invalidate CloudFront cache" -ForegroundColor Yellow
    Write-Host "You may need to wait or manually invalidate" -ForegroundColor Yellow
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Your website is now live at:" -ForegroundColor White
Write-Host $WEBSITE_URL -ForegroundColor Cyan
Write-Host ""
Write-Host "Deployed:" -ForegroundColor White
Write-Host "  ✓ Enhanced website with improved About section" -ForegroundColor Green
Write-Host "  ✓ Larger header logo (70px)" -ForegroundColor Green
Write-Host "  ✓ Hero section logo (140px)" -ForegroundColor Green
Write-Host "  ✓ Fixed Updates page error" -ForegroundColor Green
Write-Host "  ✓ Working email buttons (Schedule Demo, Capabilities)" -ForegroundColor Green
Write-Host "  ✓ All assets (logo, resumes)" -ForegroundColor Green
Write-Host ""
Write-Host "Note: CloudFront cache invalidation may take 5-15 minutes." -ForegroundColor Yellow
Write-Host "If you do not see changes immediately, try:" -ForegroundColor Yellow
Write-Host "  - Hard refresh: Ctrl+Shift+R (Windows) or Cmd+Shift+R (Mac)" -ForegroundColor Gray
Write-Host "  - Clear browser cache" -ForegroundColor Gray
Write-Host "  - Wait a few minutes for CloudFront to update" -ForegroundColor Gray
Write-Host ""
Write-Host "Backup saved to: $backupFile" -ForegroundColor Gray
Write-Host ""
