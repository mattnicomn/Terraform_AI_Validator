# S3 Objects for Frontend Assets
# Upload static assets to the frontend bucket

locals {
  assets_dir = "${path.module}/assets"
  
  # Check if PDF resume exists
  resume_pdf_exists = fileexists("${path.module}/assets/Resume - Matthew Nico.pdf")
  
  # Define assets to upload - using actual files from assets directory
  frontend_assets = merge(
    {
      "index.html"              = { source = "${path.module}/modules/s3/index_Final.html", content_type = "text/html" }
      "assets/logo.png"         = { source = "${local.assets_dir}/US Mission Hero.png", content_type = "image/png" }
      "assets/US-Mission-Hero.png" = { source = "${local.assets_dir}/US Mission Hero.png", content_type = "image/png" }
      "assets/profile.png"      = { source = "${local.assets_dir}/US Mission Hero.png", content_type = "image/png" }
    },
    # Conditionally add resume if PDF exists
    local.resume_pdf_exists ? {
      "assets/resume.pdf" = { source = "${local.assets_dir}/Resume - Matthew Nico.pdf", content_type = "application/pdf" }
    } : {}
  )
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

# Generate favicon from logo using ImageMagick or similar
# Commented out because it requires bash which doesn't work on Windows
# Create favicon.ico manually or use an online tool like https://favicon.io
#
# resource "null_resource" "generate_favicon" {
#   triggers = {
#     logo_hash = fileexists("${path.module}/assets/US Mission Hero.png") ? filemd5("${path.module}/assets/US Mission Hero.png") : ""
#   }
#
#   provisioner "local-exec" {
#     command = <<-EOT
#       # Try to generate favicon using ImageMagick if available
#       if command -v magick &> /dev/null || command -v convert &> /dev/null; then
#         if command -v magick &> /dev/null; then
#           magick "${path.module}/assets/US Mission Hero.png" -resize 32x32 "${path.module}/assets/favicon.ico" 2>/dev/null || echo "Favicon generation skipped"
#         else
#           convert "${path.module}/assets/US Mission Hero.png" -resize 32x32 "${path.module}/assets/favicon.ico" 2>/dev/null || echo "Favicon generation skipped"
#         fi
#       else
#         echo "ImageMagick not found. Please install it or manually create favicon.ico"
#       fi
#     EOT
#     interpreter = ["bash", "-c"]
#   }
# }

# Upload favicon if it exists (either generated or manually created)
resource "aws_s3_object" "favicon" {
  count = fileexists("${path.module}/assets/favicon.ico") ? 1 : 0

  bucket       = module.s3_frontend.bucket_id
  key          = "assets/favicon.ico"
  source       = "${path.module}/assets/favicon.ico"
  content_type = "image/x-icon"
  cache_control = "public, max-age=31536000, immutable"

  tags = merge(local.common_tags, {
    Name = "favicon.ico"
  })
}

# Output instructions for missing assets
output "assets_status" {
  value = <<-EOT
    
    ✅ Assets Configuration Status:
    
    Logo: US Mission Hero.png → Uploaded as:
      - assets/logo.png
      - assets/US-Mission-Hero.png  
      - assets/profile.png
    
    Resume: ${fileexists("${path.module}/assets/Resume - Matthew Nico.pdf") ? "✅ PDF Found - Will be uploaded" : "⚠️  PDF Not Found"}
    
    Favicon: ${fileexists("${path.module}/assets/favicon.ico") ? "✅ Found" : "⚠️  Missing - Create manually or logo will be used"}
    
    ${fileexists("${path.module}/assets/Resume - Matthew Nico.pdf") ? "" : "📋 TODO: Convert resume to PDF\n    Run: .\\convert_resume_to_pdf.ps1\n    Or manually: File > Save As > PDF in Word\n"}
    🌐 After deployment, your site will be available at:
       https://d11k4vck88gnf5.cloudfront.net
    
    🎨 Branding: US Mission Hero
    📄 Site Title: US Mission Hero • Security Data Transfer
    
  EOT
}
