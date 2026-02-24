# Cleanup old files from S3 bucket
# This removes files that are no longer needed

# Data source to list all objects in the bucket
data "aws_s3_objects" "frontend_bucket" {
  bucket = module.s3_frontend.bucket_id
}

# Define files to keep (whitelist approach)
locals {
  files_to_keep = [
    "index.html",
    "assets/logo.png",
    "assets/US-Mission-Hero.png",
    "assets/profile.png",
    "assets/favicon.ico",
    "assets/resume.pdf",
  ]
  
  # Files that should be deleted (anything not in the keep list)
  # This will be calculated after we know what's in the bucket
}

# Note: Terraform doesn't have a built-in way to delete objects not managed by it
# We'll use a null_resource with AWS CLI to clean up

resource "null_resource" "cleanup_old_s3_files" {
  triggers = {
    # Run cleanup whenever assets change
    assets_hash = md5(jsonencode([
      for k, v in local.frontend_assets : k
    ]))
  }

  provisioner "local-exec" {
    command = <<-EOT
      # List all objects in the bucket
      echo "Checking S3 bucket for old files..."
      
      # Get list of all objects
      aws s3 ls s3://${module.s3_frontend.bucket_id}/ --recursive | awk '{print $4}' > /tmp/s3_current_files.txt || true
      
      # Define files to keep
      cat > /tmp/s3_keep_files.txt <<EOF
index.html
assets/logo.png
assets/US-Mission-Hero.png
assets/profile.png
assets/favicon.ico
assets/resume.pdf
EOF
      
      # Find files to delete (in bucket but not in keep list)
      if [ -f /tmp/s3_current_files.txt ]; then
        while IFS= read -r file; do
          if ! grep -Fxq "$file" /tmp/s3_keep_files.txt; then
            echo "Deleting old file: $file"
            aws s3 rm "s3://${module.s3_frontend.bucket_id}/$file" || echo "Failed to delete $file"
          fi
        done < /tmp/s3_current_files.txt
      fi
      
      # Cleanup temp files
      rm -f /tmp/s3_current_files.txt /tmp/s3_keep_files.txt
      
      echo "S3 cleanup complete!"
    EOT
    interpreter = ["bash", "-c"]
  }

  depends_on = [
    aws_s3_object.frontend_assets
  ]
}

# Windows-compatible version using PowerShell
resource "null_resource" "cleanup_old_s3_files_windows" {
  count = substr(pathexpand("~"), 0, 1) == "C" ? 1 : 0

  triggers = {
    assets_hash = md5(jsonencode([
      for k, v in local.frontend_assets : k
    ]))
  }

  provisioner "local-exec" {
    command = <<-EOT
      Write-Host "Checking S3 bucket for old files..."
      
      # Get list of all objects
      $currentFiles = aws s3 ls s3://${module.s3_frontend.bucket_id}/ --recursive | ForEach-Object {
        $parts = $_ -split '\s+', 4
        if ($parts.Length -ge 4) { $parts[3] }
      }
      
      # Define files to keep
      $keepFiles = @(
        "index.html",
        "assets/logo.png",
        "assets/US-Mission-Hero.png",
        "assets/profile.png",
        "assets/favicon.ico",
        "assets/resume.pdf"
      )
      
      # Delete files not in keep list
      foreach ($file in $currentFiles) {
        if ($file -and $keepFiles -notcontains $file) {
          Write-Host "Deleting old file: $file"
          aws s3 rm "s3://${module.s3_frontend.bucket_id}/$file"
        }
      }
      
      Write-Host "S3 cleanup complete!"
    EOT
    interpreter = ["PowerShell", "-Command"]
  }

  depends_on = [
    aws_s3_object.frontend_assets
  ]
}

output "s3_cleanup_info" {
  value = <<-EOT
    
    🧹 S3 Bucket Cleanup:
    
    Files that will be kept:
    - index.html
    - assets/logo.png (US Mission Hero.png)
    - assets/US-Mission-Hero.png
    - assets/profile.png (US Mission Hero.png)
    - assets/favicon.ico (if exists)
    - assets/resume.pdf (when converted)
    
    All other files will be removed from the bucket.
    
    To manually clean up the bucket:
    aws s3 ls s3://${module.s3_frontend.bucket_id}/ --recursive
    
  EOT
}
