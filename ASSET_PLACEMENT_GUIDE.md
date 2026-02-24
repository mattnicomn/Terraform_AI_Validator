# Asset Placement Guide

## Where to Put Your Files

```
📁 Terraform_AI_Validator/          ← You are here (project root)
│
├── 📁 assets/                       ← PUT YOUR FILES IN THIS FOLDER
│   │
│   ├── 📄 README.md                 ✅ Already exists
│   ├── 📄 .gitkeep                  ✅ Already exists
│   │
│   ├── 🖼️  logo.png                 ⚠️  ADD THIS FILE
│   ├── 🎨 favicon.ico               ⚠️  ADD THIS FILE
│   ├── 👤 profile.png               ⚠️  ADD THIS FILE
│   └── 📋 resume.pdf                ⚠️  ADD THIS FILE
│
├── 📁 modules/
├── 📁 openapi/
├── 📄 main.tf
├── 📄 variables.tf
└── 📄 s3_assets_upload.tf          ← This file uploads assets to S3
```

## Step-by-Step Instructions

### Option 1: Using File Explorer (Windows)

1. Open File Explorer
2. Navigate to: `C:\Users\mattn\OneDrive\Desktop\Terraform_AI_Validator\assets`
3. Copy your 4 files into this folder:
   - logo.png
   - favicon.ico
   - profile.png
   - resume.pdf

### Option 2: Using Command Line

```powershell
# Navigate to the assets directory
cd C:\Users\mattn\OneDrive\Desktop\Terraform_AI_Validator\assets

# Copy files from wherever they are
# Example: if files are on your Desktop
copy C:\Users\mattn\Desktop\logo.png .
copy C:\Users\mattn\Desktop\favicon.ico .
copy C:\Users\mattn\Desktop\profile.png .
copy C:\Users\mattn\Desktop\resume.pdf .

# Verify files are there
dir
```

### Option 3: Drag and Drop

1. Open the `assets` folder in File Explorer
2. Drag and drop your 4 files into the folder

## Verify Files Are in Place

Run this command to check:

```powershell
dir assets
```

You should see:
```
Directory: C:\Users\mattn\OneDrive\Desktop\Terraform_AI_Validator\assets

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        2/24/2026   X:XX XX              XX .gitkeep
-a----        2/24/2026   X:XX XX            XXXX README.md
-a----        2/24/2026   X:XX XX            XXXX favicon.ico
-a----        2/24/2026   X:XX XX            XXXX logo.png
-a----        2/24/2026   X:XX XX            XXXX profile.png
-a----        2/24/2026   X:XX XX            XXXX resume.pdf
```

## What Happens After You Add Files?

When you run `terraform apply`, the `s3_assets_upload.tf` configuration will:

1. ✅ Detect the files in the `assets/` directory
2. ✅ Upload them to S3 bucket: `bedrockfrontend`
3. ✅ Set proper content types (image/png, application/pdf, etc.)
4. ✅ Configure cache headers for optimal performance
5. ✅ Make them accessible via CloudFront

## File Requirements

### logo.png
- **Format**: PNG
- **Size**: 40x40px (small) or 320x80px (large)
- **Background**: Transparent preferred
- **Max file size**: 50KB recommended

### favicon.ico
- **Format**: ICO (multi-size preferred)
- **Sizes**: 16x16, 32x32, 48x48
- **Max file size**: 10KB recommended

### profile.png
- **Format**: PNG
- **Size**: 84x84px (square)
- **Background**: Any (will be displayed with rounded corners)
- **Max file size**: 100KB recommended

### resume.pdf
- **Format**: PDF
- **Max file size**: 2MB recommended
- **Text**: Should be selectable (not scanned image)

## Don't Have These Files Yet?

### Quick Placeholders

**For logo.png and profile.png:**
1. Open Paint or any image editor
2. Create a 100x100px image
3. Add your initials or a solid color
4. Save as PNG

**For favicon.ico:**
1. Use your logo.png
2. Go to https://favicon.io/favicon-converter/
3. Upload logo.png
4. Download the generated favicon.ico

**For resume.pdf:**
1. Create a simple document in Word/Google Docs
2. Export as PDF
3. Save to the assets folder

## After Adding Files

Run these commands:

```powershell
# Check files are there
dir assets

# Initialize Terraform (if not done already)
terraform init

# Preview what will be created
terraform plan

# Apply the changes
terraform apply
```

## Accessing Your Files After Deployment

Your files will be available at:

- **Logo**: `https://d11k4vck88gnf5.cloudfront.net/assets/logo.png`
- **Favicon**: `https://d11k4vck88gnf5.cloudfront.net/assets/favicon.ico`
- **Profile**: `https://d11k4vck88gnf5.cloudfront.net/assets/profile.png`
- **Resume**: `https://d11k4vck88gnf5.cloudfront.net/assets/resume.pdf`

## Need Help?

If you're stuck, check:
- **QUICK_START.md** - Simple deployment guide
- **DEPLOYMENT_GUIDE.md** - Detailed deployment instructions
- **assets/README.md** - Asset specifications
