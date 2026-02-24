# 📁 Where to Add Your Assets

## Simple Answer

**Put these 4 files in the `assets` folder:**

```
assets/
├── logo.png       ← Your logo
├── favicon.ico    ← Browser icon
├── profile.png    ← Your photo
└── resume.pdf     ← Your resume
```

## Full Path

```
C:\Users\mattn\OneDrive\Desktop\Terraform_AI_Validator\assets\
```

## Quick Commands

```powershell
# Navigate to assets folder
cd assets

# Check what's there
dir

# Copy your files here (example)
copy C:\path\to\your\logo.png .
copy C:\path\to\your\favicon.ico .
copy C:\path\to\your\profile.png .
copy C:\path\to\your\resume.pdf .
```

## What Happens Next?

When you run `terraform apply`, these files automatically upload to S3 and become available on your CloudFront website at:

- `https://d11k4vck88gnf5.cloudfront.net/assets/logo.png`
- `https://d11k4vck88gnf5.cloudfront.net/assets/favicon.ico`
- `https://d11k4vck88gnf5.cloudfront.net/assets/profile.png`
- `https://d11k4vck88gnf5.cloudfront.net/assets/resume.pdf`

## That's It!

Once the files are in the `assets` folder, Terraform handles everything else automatically.

---

For more details, see:
- **ASSET_PLACEMENT_GUIDE.md** - Detailed instructions with examples
- **QUICK_START.md** - Complete deployment guide
- **assets/README.md** - File specifications and requirements
