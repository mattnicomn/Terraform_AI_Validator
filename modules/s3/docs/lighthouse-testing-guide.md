# Lighthouse Performance Testing Guide

## Quick Start

This guide will help you run Lighthouse performance audits to validate the Phase 6 optimizations.

---

## Method 1: Chrome DevTools (Recommended for Quick Testing)

### Steps:

1. **Open your website** in Google Chrome
2. **Open DevTools**: Press `F12` or `Ctrl+Shift+I` (Windows/Linux) or `Cmd+Option+I` (Mac)
3. **Go to Lighthouse tab**: Click the "Lighthouse" tab in DevTools
4. **Configure audit**:
   - ✅ Check "Performance"
   - ✅ Check "Accessibility" (optional but recommended)
   - Select "Desktop" or "Mobile"
   - Select "Navigation" mode
5. **Click "Analyze page load"**
6. **Wait for results** (30-60 seconds)

### What to Look For:

| Metric | Target | Status |
|--------|--------|--------|
| Performance Score | > 90 | 🎯 |
| First Contentful Paint (FCP) | < 1.8s | 🎯 |
| Largest Contentful Paint (LCP) | < 2.5s | 🎯 |
| Total Blocking Time (TBT) | < 300ms | 🎯 |
| Cumulative Layout Shift (CLS) | < 0.1 | 🎯 |

### Expected Passes:

- ✅ Eliminate render-blocking resources
- ✅ Properly size images
- ✅ Defer offscreen images
- ✅ Minify CSS
- ✅ Minify JavaScript
- ✅ Uses efficient cache policy
- ✅ Preconnect to required origins

---

## Method 2: Lighthouse CLI (For Detailed Reports)

### Installation:

```bash
npm install -g lighthouse
```

### Run Audit:

```bash
# Basic audit
lighthouse https://your-site.com --view

# Mobile audit with full report
lighthouse https://your-site.com --preset=mobile --output=html --output-path=./lighthouse-mobile.html --view

# Desktop audit
lighthouse https://your-site.com --preset=desktop --output=html --output-path=./lighthouse-desktop.html --view

# Both performance and accessibility
lighthouse https://your-site.com --only-categories=performance,accessibility --view
```

### Advanced Options:

```bash
# Simulate slow 3G connection
lighthouse https://your-site.com --throttling.rttMs=300 --throttling.throughputKbps=700 --view

# Disable throttling (test on actual connection)
lighthouse https://your-site.com --throttling-method=provided --view

# Multiple runs for average
lighthouse https://your-site.com --runs=5 --view
```

---

## Method 3: PageSpeed Insights (Google's Online Tool)

### Steps:

1. **Visit**: https://pagespeed.web.dev/
2. **Enter your URL**: Type your website URL
3. **Click "Analyze"**
4. **Wait for results** (30-60 seconds)
5. **Review both Mobile and Desktop tabs**

### Benefits:

- No installation required
- Tests from Google's servers (real-world conditions)
- Provides Field Data (real user metrics) if available
- Shows Core Web Vitals status

---

## Method 4: Lighthouse CI (For Continuous Monitoring)

### Setup:

```bash
# Install Lighthouse CI
npm install -g @lhci/cli

# Create config file
cat > lighthouserc.json << EOF
{
  "ci": {
    "collect": {
      "url": ["http://localhost:8080"],
      "numberOfRuns": 3
    },
    "assert": {
      "assertions": {
        "categories:performance": ["error", {"minScore": 0.9}],
        "first-contentful-paint": ["error", {"maxNumericValue": 1800}],
        "largest-contentful-paint": ["error", {"maxNumericValue": 2500}],
        "total-blocking-time": ["error", {"maxNumericValue": 300}],
        "cumulative-layout-shift": ["error", {"maxNumericValue": 0.1}]
      }
    }
  }
}
EOF

# Run Lighthouse CI
lhci autorun
```

---

## Testing Checklist

### Before Testing:

- [ ] Deploy website to production or staging server
- [ ] Clear browser cache
- [ ] Close unnecessary browser tabs
- [ ] Disable browser extensions (or use Incognito mode)
- [ ] Ensure stable internet connection

### Pages to Test:

- [ ] Main page: `index_Enhanced.html`
- [ ] Contact page: `contact.html`
- [ ] Sample documentation page: `government/docs/gold-ami.html`
- [ ] Sample demo page: `commercial/bedrock-s3-demo.html`

### Test Scenarios:

- [ ] Desktop (1920x1080)
- [ ] Tablet (768x1024)
- [ ] Mobile (375x667)
- [ ] Slow 3G connection
- [ ] Fast 3G connection
- [ ] 4G connection

---

## Interpreting Results

### Performance Score Breakdown:

| Score | Rating | Action |
|-------|--------|--------|
| 90-100 | ✅ Good | Maintain current optimizations |
| 50-89 | ⚠️ Needs Improvement | Review opportunities section |
| 0-49 | ❌ Poor | Implement recommended fixes |

### Core Web Vitals:

**First Contentful Paint (FCP)**:
- Good: < 1.8s
- Needs Improvement: 1.8s - 3.0s
- Poor: > 3.0s

**Largest Contentful Paint (LCP)**:
- Good: < 2.5s
- Needs Improvement: 2.5s - 4.0s
- Poor: > 4.0s

**Total Blocking Time (TBT)**:
- Good: < 300ms
- Needs Improvement: 300ms - 600ms
- Poor: > 600ms

**Cumulative Layout Shift (CLS)**:
- Good: < 0.1
- Needs Improvement: 0.1 - 0.25
- Poor: > 0.25

---

## Common Issues and Fixes

### Issue: Performance Score < 90

**Possible Causes**:
- Server response time too slow
- Large images not optimized
- Too many HTTP requests
- Render-blocking resources

**Check**:
1. Network tab in DevTools
2. Lighthouse "Opportunities" section
3. Server response time (TTFB)

### Issue: FCP > 1.8s

**Possible Causes**:
- Critical CSS not inlined
- Render-blocking resources
- Slow server response

**Verify**:
- Critical CSS is in `<style>` tag
- Scripts have `defer` attribute
- Resource hints are present

### Issue: LCP > 2.5s

**Possible Causes**:
- Large hero image not preloaded
- Slow image loading
- Render-blocking resources

**Verify**:
- Hero images have `<link rel="preload">`
- Images have `width` and `height` attributes
- CloudFront CDN is working

### Issue: TBT > 300ms

**Possible Causes**:
- Large JavaScript files
- JavaScript not deferred
- Too much JavaScript execution

**Verify**:
- All scripts use `defer` attribute
- JavaScript files are minified (.min.js)
- No blocking scripts in `<head>`

### Issue: CLS > 0.1

**Possible Causes**:
- Images without dimensions
- Dynamic content insertion
- Web fonts causing layout shift

**Verify**:
- All images have `width` and `height` attributes
- Critical CSS includes font styles
- No content injected above the fold

---

## Network Tab Validation

### What to Check:

1. **Critical CSS**:
   - Should be inline (no HTTP request)
   - Look for `<style>` tag in HTML source

2. **Full Stylesheet**:
   - `theme.min.css` should load with low priority
   - Should not block rendering
   - Should be cached (304 on reload)

3. **JavaScript**:
   - All `.min.js` files should be loaded
   - Should have `defer` attribute
   - Should not block initial render

4. **Images**:
   - Hero images should load immediately
   - Below-the-fold images should lazy load
   - Should have proper dimensions

5. **Resource Hints**:
   - CloudFront connection should establish early
   - Preloaded assets should have "Highest" priority

---

## Sample Lighthouse Report Interpretation

### Good Report Example:

```
Performance: 95
FCP: 1.2s
LCP: 1.8s
TBT: 150ms
CLS: 0.05

Opportunities:
✅ Eliminate render-blocking resources (0ms saved)
✅ Properly size images (0 KB saved)
✅ Defer offscreen images (0 KB saved)
✅ Minify CSS (0 KB saved)
✅ Minify JavaScript (0 KB saved)

Diagnostics:
✅ Minimize main-thread work (1.5s)
✅ Reduce JavaScript execution time (0.8s)
✅ Avoid enormous network payloads (150 KB)
```

### Report Needing Improvement:

```
Performance: 75
FCP: 2.5s
LCP: 3.2s
TBT: 450ms
CLS: 0.15

Opportunities:
⚠️ Eliminate render-blocking resources (500ms saved)
⚠️ Properly size images (200 KB saved)
⚠️ Defer offscreen images (150 KB saved)

Action Required:
1. Check if critical CSS is inlined
2. Verify image lazy loading is working
3. Check if scripts have defer attribute
```

---

## Automated Testing Script

Save this as `test-performance.sh`:

```bash
#!/bin/bash

# Test Performance Script
echo "Running Lighthouse Performance Tests..."

# Test main pages
lighthouse https://your-site.com/index_Enhanced.html \
  --preset=mobile \
  --output=html \
  --output-path=./reports/lighthouse-index-mobile.html

lighthouse https://your-site.com/index_Enhanced.html \
  --preset=desktop \
  --output=html \
  --output-path=./reports/lighthouse-index-desktop.html

lighthouse https://your-site.com/contact.html \
  --preset=mobile \
  --output=html \
  --output-path=./reports/lighthouse-contact-mobile.html

echo "Reports generated in ./reports/ directory"
echo "Open the HTML files to view results"
```

Make executable and run:

```bash
chmod +x test-performance.sh
./test-performance.sh
```

---

## Continuous Monitoring

### Set Up Alerts:

1. **Google Search Console**:
   - Monitor Core Web Vitals
   - Get alerts for performance issues
   - Track real user metrics

2. **Lighthouse CI**:
   - Run on every deployment
   - Fail builds if performance drops
   - Track performance over time

3. **Real User Monitoring (RUM)**:
   - Track actual user experience
   - Identify performance issues by region
   - Monitor performance trends

---

## Expected Results Summary

Based on Phase 6 optimizations, you should see:

### Performance Improvements:

- ✅ Performance Score: 90-100
- ✅ FCP: 1.0s - 1.5s (improved by 200-500ms)
- ✅ LCP: 1.5s - 2.0s (improved by 200-500ms)
- ✅ TBT: 100ms - 200ms (improved by 100-300ms)
- ✅ CLS: 0.01 - 0.05 (minimal layout shift)

### Optimization Passes:

- ✅ Eliminate render-blocking resources
- ✅ Properly size images
- ✅ Defer offscreen images
- ✅ Minify CSS
- ✅ Minify JavaScript
- ✅ Uses efficient cache policy
- ✅ Preconnect to required origins
- ✅ Preload key requests

---

## Questions or Issues?

If Lighthouse scores are lower than expected:

1. **Check deployment**: Ensure all optimized files are deployed
2. **Check server**: Verify server response time (TTFB < 600ms)
3. **Check network**: Test on different network conditions
4. **Check browser**: Use latest Chrome version
5. **Review report**: Check "Opportunities" and "Diagnostics" sections

---

**Last Updated**: 2025-02-24  
**Related Documentation**: phase6-validation-report.md
