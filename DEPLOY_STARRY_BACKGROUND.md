# Deploy Starry Background to Main Index Page

## Issue
The main index page (https://d11k4vck88gnf5.cloudfront.net/) and all its tabs (#/home, #/government, #/commercial, #/about, #/updates) are showing a dark background instead of the starry background.

## Root Cause
The file `modules/s3/index_Enhanced.html` has the starry background configured correctly, but:
1. It needs to be deployed to S3 as `index.html` (not `index_Enhanced.html`)
2. Missing CSS variables (`--panel`, `--card`, etc.) have been added
3. CloudFront cache needs to be invalidated

## Changes Made
✅ Added missing CSS variables to index_Enhanced.html:
- `--panel: #0f1419`
- `--card: #111827`
- `--gov-accent: #3b82f6`
- `--commercial-accent: #10b981`
- `--success`, `--danger`, `--warning`, `--info`
- `--shadow-lg`

✅ Starry background CSS is already configured:
```css
body {
  background: linear-gradient(135deg, var(--bg-dark) 0%, var(--bg-dark-secondary) 100%);
  background-image: url('/assets/starry-bg.png');
  background-size: cover;
  background-position: center;
  background-repeat: no-repeat;
  background-attachment: fixed;
}
```

## Deployment Steps

### Step 1: Upload index.html to S3

The file needs to be uploaded as `index.html` (not `index_Enhanced.html`):

```powershell
# Upload the updated index file
aws s3 cp modules/s3/index_Enhanced.html s3://bedrockfrontend/index.html --content-type "text/html"

# Verify the starry background image exists
aws s3 ls s3://bedrockfrontend/assets/starry-bg.png

# If starry-bg.png doesn't exist, upload it
aws s3 cp assets/starry-bg.png s3://bedrockfrontend/assets/starry-bg.png --content-type "image/png"
```

### Step 2: Invalidate CloudFront Cache

```powershell
# Invalidate the index page and assets
aws cloudfront create-invalidation --distribution-id EOK4YOONDZGMT --paths "/index.html" "/assets/starry-bg.png" "/"

# Or invalidate everything (recommended)
aws cloudfront create-invalidation --distribution-id EOK4YOONDZGMT --paths "/*"
```

### Step 3: Wait for Invalidation

CloudFront invalidation typically takes 1-2 minutes. Check status:

```powershell
aws cloudfront list-invalidations --distribution-id EOK4YOONDZGMT
```

### Step 4: Clear Browser Cache

After CloudFront invalidation completes:
- **Windows**: Press `Ctrl + F5` for hard refresh
- **Mac**: Press `Cmd + Shift + R` for hard refresh

Or clear browser cache completely:
- Chrome: Settings → Privacy and security → Clear browsing data
- Firefox: Settings → Privacy & Security → Clear Data
- Edge: Settings → Privacy, search, and services → Clear browsing data

## Verification

After deployment, check these URLs:

1. **Main page**: https://d11k4vck88gnf5.cloudfront.net/
   - ✅ Should show starry background

2. **Home tab**: https://d11k4vck88gnf5.cloudfront.net/index.html#/home
   - ✅ Should show starry background

3. **Government tab**: https://d11k4vck88gnf5.cloudfront.net/index.html#/government
   - ✅ Should show starry background

4. **Commercial tab**: https://d11k4vck88gnf5.cloudfront.net/index.html#/commercial
   - ✅ Should show starry background

5. **About tab**: https://d11k4vck88gnf5.cloudfront.net/index.html#/about
   - ✅ Should show starry background

6. **Updates tab**: https://d11k4vck88gnf5.cloudfront.net/index.html#/updates
   - ✅ Should show starry background

## Expected Result

All pages will have:
- ✅ Beautiful starry cosmos background
- ✅ Semi-transparent dark overlay (rgba(0,0,0,0.5))
- ✅ Content with proper z-index layering
- ✅ Smooth transitions between tabs
- ✅ Consistent look with all subpages

## Troubleshooting

### If starry background still doesn't show:

1. **Check if file was uploaded correctly**:
   ```powershell
   aws s3 ls s3://bedrockfrontend/index.html
   aws s3 ls s3://bedrockfrontend/assets/starry-bg.png
   ```

2. **Check CloudFront distribution**:
   ```powershell
   aws cloudfront get-distribution --id EOK4YOONDZGMT
   ```

3. **Test direct S3 URL** (if bucket is public):
   - https://bedrockfrontend.s3.amazonaws.com/index.html
   - https://bedrockfrontend.s3.amazonaws.com/assets/starry-bg.png

4. **Check browser console** (F12):
   - Look for 404 errors on starry-bg.png
   - Check if CSS is loading correctly
   - Verify no JavaScript errors

5. **Try incognito/private browsing**:
   - This bypasses all browser cache
   - If it works here, it's a cache issue

6. **Check file permissions**:
   ```powershell
   aws s3api get-object-acl --bucket bedrockfrontend --key index.html
   aws s3api get-object-acl --bucket bedrockfrontend --key assets/starry-bg.png
   ```

### If you see a dark background but no stars:

1. **Verify starry-bg.png exists and is accessible**:
   - Open https://d11k4vck88gnf5.cloudfront.net/assets/starry-bg.png directly
   - Should show the starry background image

2. **Check CSS in browser DevTools**:
   - Right-click on page → Inspect
   - Look at the `<body>` element
   - Check if `background-image: url('/assets/starry-bg.png')` is present
   - Check if it's being overridden by other CSS

3. **Verify file path is correct**:
   - The CSS uses `/assets/starry-bg.png` (absolute path)
   - Make sure the file is at `s3://bedrockfrontend/assets/starry-bg.png`

## Alternative: Quick Test

If you want to test immediately without waiting for CloudFront:

1. **Get the S3 website endpoint** (if static website hosting is enabled):
   ```powershell
   aws s3api get-bucket-website --bucket bedrockfrontend
   ```

2. **Access directly via S3 website URL**:
   - Format: `http://bedrockfrontend.s3-website-<region>.amazonaws.com/`
   - This bypasses CloudFront cache

## Summary

The starry background is now properly configured in `index_Enhanced.html`. Once you:
1. Upload it as `index.html` to S3
2. Invalidate CloudFront cache
3. Clear your browser cache

You'll see the beautiful starry cosmos background on all tabs of the main page, creating a consistent and professional look across your entire website! 🌟
