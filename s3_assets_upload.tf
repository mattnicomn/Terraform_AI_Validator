# S3 Objects for Frontend Assets
# Upload static assets to the frontend bucket

locals {
  assets_dir = "${path.module}/assets"
  
  # Define assets to upload
  frontend_assets = {
    "index.html"       = { source = "${path.module}/modules/s3/index_Final.html", content_type = "text/html" }
    "assets/logo.png"  = { source = "${local.assets_dir}/logo.png", content_type = "image/png" }
    "assets/favicon.ico" = { source = "${local.assets_dir}/favicon.ico", content_type = "image/x-icon" }
    "assets/profile.png" = { source = "${local.assets_dir}/profile.png", content_type = "image/png" }
    "assets/resume.pdf"  = { source = "${local.assets_dir}/resume.pdf", content_type = "application/pdf" }
  }
}

# Upload frontend assets to S3
resource "aws_s3_object" "frontend_assets" {
  for_each = {
    for k, v in local.frontend_assets : k => v
    if fileexists(v.source)
  }

  bucket       = module.s3_frontend.bucket_id
  key          = each.key
  source       = each.value.source
  content_type = each.value.content_type
  etag         = filemd5(each.value.source)

  # Cache control for assets
  cache_control = startswith(each.key, "assets/") ? "public, max-age=31536000, immutable" : "public, max-age=3600"

  tags = merge(local.common_tags, {
    Name = each.key
  })
}

# Output instructions for missing assets
output "missing_assets_instructions" {
  value = <<-EOT
    
    IMPORTANT: Upload the following assets to complete the frontend setup:
    
    1. Create an 'assets' directory in the project root
    2. Add the following files:
       - assets/logo.png (40x40px or 320x80px, PNG format)
       - assets/favicon.ico (16x16px or 32x32px, ICO format)
       - assets/profile.png (84x84px, PNG format)
       - assets/resume.pdf (Your resume in PDF format)
    
    3. Run 'terraform apply' again to upload the assets
    
    Alternatively, upload directly to S3:
    aws s3 cp assets/ s3://${module.s3_frontend.bucket_id}/assets/ --recursive
    
  EOT
}
