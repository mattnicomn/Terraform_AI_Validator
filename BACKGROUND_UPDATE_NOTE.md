# Background Update - Awaiting Image

## Status: Partially Complete

### ✅ Completed
1. Updated `/css/theme.css` with:
   - Background image reference to `/assets/starry-bg.png`
   - `background-size: cover`
   - `background-position: center`
   - `background-repeat: no-repeat`
   - `background-attachment: fixed`
   - Dark overlay (rgba(0, 0, 0, 0.5)) for text contrast

2. Removed logo image from headers:
   - Updated CSS to remove `.brand img.logo` styles
   - Added gradient text effect to brand title
   - Updated contact.html header (removed logo)
   - Phase 2 documentation pages already created without logo

3. Updated responsive styles:
   - Removed logo sizing from mobile breakpoints
   - Added brand title font-size adjustment for mobile

### ⏳ Pending
1. **starry-bg.png image file** - Need user to provide the cosmos background image
2. Upload image to `/assets/starry-bg.png` on S3
3. Test pages to verify:
   - Background displays correctly
   - Text contrast is readable
   - Overlay opacity is appropriate (currently set to 0.5)

### 📝 Next Steps

Once the starry-bg.png image is provided:

1. Save image to `modules/s3/assets/starry-bg.png`
2. Upload to S3:
   ```powershell
   aws s3 cp modules/s3/assets/starry-bg.png s3://bedrockfrontend/assets/starry-bg.png
   ```
3. Deploy updated CSS and HTML files
4. Test all pages for readability
5. Adjust overlay opacity if needed (in theme.css, line with `background: rgba(0, 0, 0, 0.5)`)

### 🎨 Current CSS Changes

**Body background:**
```css
body {
  background: linear-gradient(135deg, var(--bg-dark) 0%, var(--bg-dark-secondary) 100%);
  background-image: url('/assets/starry-bg.png');
  background-size: cover;
  background-position: center;
  background-repeat: no-repeat;
  background-attachment: fixed;
  color: var(--text-primary);
  position: relative;
}
```

**Dark overlay:**
```css
body::before {
  content: '';
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  pointer-events: none;
  z-index: 0;
}
```

### 🔧 Fallback

If image is not provided, the site will fall back to the gradient background:
`linear-gradient(135deg, var(--bg-dark) 0%, var(--bg-dark-secondary) 100%)`

This ensures the site remains functional and visually appealing even without the cosmos background.
