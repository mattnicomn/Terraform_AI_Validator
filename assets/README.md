# Frontend Assets

This directory contains static assets that will be uploaded to the S3 frontend bucket and served via CloudFront.

## Required Files

Place the following files in this directory:

### 1. logo.png
- **Purpose**: Company/brand logo displayed in the header
- **Recommended Size**: 40x40px (small) or 320x80px (large)
- **Format**: PNG with transparent background
- **Usage**: Main logo and fallback image for profile

### 2. favicon.ico
- **Purpose**: Browser tab icon
- **Recommended Size**: 16x16px or 32x32px (multi-size ICO preferred)
- **Format**: ICO format
- **Usage**: Browser tab and bookmarks

### 3. profile.png
- **Purpose**: Profile photo in the About section
- **Recommended Size**: 84x84px
- **Format**: PNG
- **Usage**: About page header
- **Fallback**: If missing, logo.png is used

### 4. resume.pdf
- **Purpose**: Downloadable resume
- **Format**: PDF
- **Usage**: Download link in About section

## File Structure

```
assets/
├── README.md          (this file)
├── logo.png           (add your logo here)
├── favicon.ico        (add your favicon here)
├── profile.png        (add your profile photo here)
└── resume.pdf         (add your resume here)
```

## After Adding Files

Once you've added all the files, run:

```bash
terraform apply
```

The `s3_assets_upload.tf` configuration will automatically upload these files to your S3 bucket with proper cache headers.

## Manual Upload (Alternative)

If you prefer to upload manually:

```bash
# Upload all assets at once
aws s3 sync assets/ s3://bedrockfrontend/assets/ \
  --exclude "README.md" \
  --cache-control "public, max-age=31536000, immutable"

# Upload index.html separately
aws s3 cp modules/s3/index_Final.html s3://bedrockfrontend/index.html \
  --content-type "text/html" \
  --cache-control "public, max-age=3600"
```

## Invalidate CloudFront Cache

After uploading new assets, invalidate the CloudFront cache:

```bash
aws cloudfront create-invalidation \
  --distribution-id $(terraform output -raw cloudfront_distribution_id) \
  --paths "/assets/*" "/index.html"
```

## Image Optimization Tips

### For logo.png:
- Use PNG-8 if possible (smaller file size)
- Optimize with tools like TinyPNG or ImageOptim
- Keep file size under 50KB

### For favicon.ico:
- Create multi-size ICO (16x16, 32x32, 48x48)
- Use online tools like favicon.io or RealFaviconGenerator

### For profile.png:
- Use square aspect ratio
- Optimize for web (72 DPI)
- Keep file size under 100KB

### For resume.pdf:
- Keep file size under 2MB
- Use PDF/A format for long-term archival
- Ensure text is selectable (not scanned image)
