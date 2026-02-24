#!/usr/bin/env pwsh
# Repository Cleanup Script
# Removes temporary files, backups, and obsolete documentation

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Repository Cleanup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$removed = 0

# Obsolete deployment scripts
$scripts = @(
    "create_enhanced_website.ps1",
    "deploy_assets_manually.ps1",
    "deploy_enhanced_website.ps1",
    "deploy_enhanced_website_fixed.ps1",
    "convert_resume_to_pdf.ps1",
    "extract_resume_text.ps1",
    "fix_terraform.ps1"
)

Write-Host "Removing obsolete scripts..." -ForegroundColor Yellow
foreach ($file in $scripts) {
    if (Test-Path $file) {
        Remove-Item $file -Force
        Write-Host "  - Removed $file" -ForegroundColor Gray
        $removed++
    }
}

# Temporary image
if (Test-Path "ChatGPT Image Nov 1, 2025, 08_57_58 AM.png") {
    Remove-Item "ChatGPT Image Nov 1, 2025, 08_57_58 AM.png" -Force
    Write-Host "  - Removed temporary image" -ForegroundColor Gray
    $removed++
}

# Backup Terraform files
$backups = @(
    "api_gateway_http.tf.backup",
    "locals.tf.backup",
    "main.tf.backup",
    "variables.tf.backup",
    "terraform_minimal.tfvars",
    "terraform_variables.tfvars"
)

Write-Host "Removing backup Terraform files..." -ForegroundColor Yellow
foreach ($file in $backups) {
    if (Test-Path $file) {
        Remove-Item $file -Force
        Write-Host "  - Removed $file" -ForegroundColor Gray
        $removed++
    }
}

# Old HTML backups (keep only the most recent)
$htmlBackups = @(
    "modules/s3/index_backup_20260224_130908.html",
    "modules/s3/index_backup_20260224_132636.html",
    "modules/s3/index_backup_20260224_132905.html",
    "modules/s3/index_backup_20260224_135247.html",
    "modules/s3/index_Final.html",
    "modules/s3/index_V2_Enhanced.html",
    "modules/s3/index.html"
)

Write-Host "Removing old HTML backups..." -ForegroundColor Yellow
foreach ($file in $htmlBackups) {
    if (Test-Path $file) {
        Remove-Item $file -Force
        Write-Host "  - Removed $file" -ForegroundColor Gray
        $removed++
    }
}

# Temporary documentation
$docs = @(
    "ABOUT_SECTION_ENHANCEMENT.md",
    "ASSET_PLACEMENT_GUIDE.md",
    "AWS_FOUNDERS_PROGRAM_CONTENT.md",
    "CHANGES_SUMMARY.md",
    "DEPLOYMENT_CHECKLIST.md",
    "DEPLOYMENT_GUIDE.md",
    "DEPLOYMENT_READY.md",
    "DEPLOYMENT_SUCCESS.md",
    "ENHANCED_WEBSITE_README.md",
    "ERNEST_INFO_TEMPLATE.md",
    "FIX_ERRORS.md",
    "NEXT_STEPS_V2_ENHANCEMENT.md",
    "QUICK_DEPLOY.md",
    "QUICK_START.md",
    "README_ASSETS.md",
    "README_DEPLOYMENT.md",
    "SIMPLE_DEPLOYMENT.md",
    "TERRAFORM_FINAL_SOLUTION.md",
    "TERRAFORM_FIX_GUIDE.md",
    "TERRAFORM_FIXED_SUMMARY.md",
    "TERRAFORM_READY.md",
    "TERRAFORM_SIMPLE_GUIDE.md",
    "UPDATED_ASSETS_GUIDE.md",
    "UPDATES_SUMMARY.md",
    "WEBSITE_ENHANCEMENT_PLAN.md",
    "WEBSITE_ENHANCEMENT_V2_PLAN.md",
    "WEBSITE_PREVIEW.md"
)

Write-Host "Removing temporary documentation..." -ForegroundColor Yellow
foreach ($file in $docs) {
    if (Test-Path $file) {
        Remove-Item $file -Force
        Write-Host "  - Removed $file" -ForegroundColor Gray
        $removed++
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Cleanup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Removed $removed files" -ForegroundColor White
Write-Host ""
Write-Host "Kept essential files:" -ForegroundColor White
Write-Host "  - deploy_complete_website.ps1 (main deployment script)" -ForegroundColor Green
Write-Host "  - modules/s3/index_Enhanced.html (active website)" -ForegroundColor Green
Write-Host "  - modules/s3/index_backup_20260224_140928.html (latest backup)" -ForegroundColor Green
Write-Host "  - AWS_SERVICES_AUDIT.md (infrastructure documentation)" -ForegroundColor Green
Write-Host "  - CLOUDFRONT_RESOURCES_INVENTORY.md (infrastructure documentation)" -ForegroundColor Green
Write-Host "  - CO_FOUNDERS_PROFILE.md (company information)" -ForegroundColor Green
Write-Host "  - ENHANCED_WEBSITE_GUIDE.md (website documentation)" -ForegroundColor Green
Write-Host "  - README.md (main documentation)" -ForegroundColor Green
Write-Host ""
