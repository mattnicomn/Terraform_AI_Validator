# Design Document: Website Organization Improvements

## Overview

This design document outlines the technical approach for improving and organizing the US Mission Hero website. The project focuses on creating consistent styling, improving user experience, enhancing accessibility, and optimizing performance across all pages without adding new features or modifying backend functionality.

### Goals

- Establish a unified design system with consistent styling across all pages
- Create reusable HTML components for navigation, footer, and common UI elements
- Implement responsive design for mobile, tablet, and desktop viewports
- Enhance accessibility to meet WCAG 2.1 AA standards
- Optimize performance for fast page loads
- Maintain existing functionality while improving code organization

### Scope

The project encompasses:
- 1 main index page (index_Enhanced.html)
- 1 contact page (contact.html)
- 6 government documentation pages
- 2 demo pages (government and commercial)
- 1 global CSS file (theme.css)
- JavaScript enhancements for interactivity

### Non-Goals

- Adding new features or functionality
- Modifying backend APIs or authentication
- Changing content or copy
- Redesigning the visual brand identity

## Architecture

### High-Level Structure


```
┌─────────────────────────────────────────────────────────────┐
│                     US Mission Hero Website                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Global CSS (theme.css)                    │
│  • CSS Variables (colors, spacing, typography)               │
│  • Base Styles (reset, typography, layout)                   │
│  • Component Styles (buttons, cards, forms)                  │
│  • Utility Classes (spacing, display, responsive)            │
│  • Responsive Breakpoints (mobile, tablet, desktop)          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Page Templates                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Main Index  │  │Documentation │  │  Demo Pages  │      │
│  │    Page      │  │    Pages     │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐                                            │
│  │Contact Page  │                                            │
│  └──────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Reusable Components                        │
│  • Navigation Header (with mobile menu)                      │
│  • Footer (with links and copyright)                         │
│  • Breadcrumb Navigation                                     │
│  • Loading Spinners                                          │
│  • Form Validation Messages                                  │
│  • Toast Notifications                                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   JavaScript Modules                         │
│  • Form Validation (validation.js)                           │
│  • Mobile Menu Toggle (navigation.js)                        │
│  • Loading State Management (loading.js)                     │
│  • Smooth Scroll (scroll.js)                                 │
│  • Toast Notifications (toast.js)                            │
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Mobile-First**: Design for mobile devices first, then enhance for larger screens
2. **Progressive Enhancement**: Core content accessible without JavaScript
3. **Component-Based**: Reusable components with consistent styling
4. **Accessibility-First**: WCAG 2.1 AA compliance built into every component
5. **Performance-Optimized**: Minimal HTTP requests, lazy loading, efficient CSS

### File Organization

```
modules/s3/
├── index_Enhanced.html          # Main landing page
├── contact.html                 # Contact page
├── css/
│   └── theme.css                # Global stylesheet (enhanced)
├── js/
│   ├── common.js                # Shared utilities
│   ├── navigation.js            # Mobile menu and navigation
│   ├── validation.js            # Form validation
│   ├── loading.js               # Loading state management
│   └── toast.js                 # Toast notifications
├── government/
│   ├── docs/
│   │   ├── security-data-transfer.html
│   │   ├── fedramp-fisma.html
│   │   ├── scca-saca.html
│   │   ├── dod-dhs-solutions.html
│   │   ├── rmf-nist.html
│   │   └── gold-ami.html
│   └── demo/
│       └── security-data-transfer.html
├── commercial/
│   └── bedrock-s3-demo.html
└── assets/
    └── (images, icons, etc.)
```


## Components and Interfaces

### 1. Navigation Header Component

The navigation header provides consistent site-wide navigation with responsive mobile menu support.

**Structure:**
```html
<header class="site-header" role="banner">
  <div class="container header-content">
    <!-- Brand Section -->
    <div class="brand">
      <img src="/assets/US-Mission-Hero.png" alt="US Mission Hero Logo" class="brand-logo" />
      <div class="brand-text">
        <div class="brand-title">US Mission Hero</div>
        <div class="brand-tagline">Secure Cloud Solutions for Government & Commercial</div>
      </div>
    </div>
    
    <!-- Mobile Menu Toggle -->
    <button class="mobile-menu-toggle" aria-label="Toggle navigation menu" aria-expanded="false">
      <span class="hamburger-icon"></span>
    </button>
    
    <!-- Navigation Links -->
    <nav class="nav-menu" role="navigation" aria-label="Main navigation">
      <a href="/" class="nav-link" aria-current="page">Home</a>
      <a href="/#government" class="nav-link">Government Solutions</a>
      <a href="/#commercial" class="nav-link">Commercial Solutions</a>
      <a href="/#about" class="nav-link">About</a>
      <a href="/contact.html" class="nav-link">Contact</a>
    </nav>
  </div>
</header>
```

**CSS Classes:**
- `.site-header`: Sticky header with backdrop blur
- `.header-content`: Flex container for header elements
- `.brand`: Logo and text container
- `.mobile-menu-toggle`: Hamburger button (hidden on desktop)
- `.nav-menu`: Navigation links container
- `.nav-link`: Individual navigation links
- `.nav-link[aria-current="page"]`: Active page indicator

**Responsive Behavior:**
- Desktop (≥1024px): Horizontal navigation, logo on left, links on right
- Tablet (768px-1023px): Horizontal navigation, may wrap
- Mobile (<768px): Hamburger menu, full-screen overlay navigation

**Accessibility Features:**
- Semantic HTML5 elements (`<header>`, `<nav>`)
- ARIA labels and roles
- Keyboard navigation support (Tab, Enter, Escape)
- Focus indicators
- Skip-to-content link

### 2. Footer Component

The footer provides consistent site-wide links, copyright information, and social media links.

**Structure:**
```html
<footer class="site-footer" role="contentinfo">
  <div class="container footer-content">
    <!-- Company Info -->
    <div class="footer-section">
      <h3>US Mission Hero</h3>
      <p>Delivering secure, compliant cloud solutions for government agencies and commercial enterprises.</p>
    </div>
    
    <!-- Solutions Links -->
    <div class="footer-section">
      <h3>Solutions</h3>
      <ul class="footer-links">
        <li><a href="/#government">Government Solutions</a></li>
        <li><a href="/#commercial">Commercial Solutions</a></li>
      </ul>
    </div>
    
    <!-- Company Links -->
    <div class="footer-section">
      <h3>Company</h3>
      <ul class="footer-links">
        <li><a href="/#about">About Us</a></li>
        <li><a href="/contact.html">Contact</a></li>
        <li><a href="https://github.com/mattnicomn" target="_blank" rel="noopener">GitHub</a></li>
      </ul>
    </div>
  </div>
  
  <!-- Copyright -->
  <div class="footer-bottom">
    <p>&copy; <span id="current-year"></span> US Mission Hero. All rights reserved.</p>
  </div>
</footer>
```

**CSS Classes:**
- `.site-footer`: Footer container with border and padding
- `.footer-content`: Grid layout for footer sections
- `.footer-section`: Individual footer column
- `.footer-links`: Unstyled list for links
- `.footer-bottom`: Copyright section with centered text

**Responsive Behavior:**
- Desktop: 3-column grid layout
- Tablet: 2-column grid layout
- Mobile: Single column, stacked vertically


### 3. Breadcrumb Navigation Component

Breadcrumb navigation for documentation pages showing hierarchical location.

**Structure:**
```html
<nav class="breadcrumb" aria-label="Breadcrumb">
  <ol class="breadcrumb-list">
    <li class="breadcrumb-item"><a href="/">Home</a></li>
    <li class="breadcrumb-item"><a href="/#government">Government Solutions</a></li>
    <li class="breadcrumb-item" aria-current="page">Security Data Transfer API</li>
  </ol>
</nav>
```

**CSS Classes:**
- `.breadcrumb`: Container with appropriate spacing
- `.breadcrumb-list`: Horizontal list with separators
- `.breadcrumb-item`: Individual breadcrumb items
- `.breadcrumb-item[aria-current="page"]`: Current page (not a link)

**Responsive Behavior:**
- Desktop: Full breadcrumb path displayed
- Mobile: Truncate middle items if needed, show "... > Current Page"

### 4. Loading Spinner Component

Visual feedback during asynchronous operations.

**Structure:**
```html
<div class="loading-spinner" role="status" aria-live="polite">
  <div class="spinner-icon"></div>
  <span class="sr-only">Loading...</span>
</div>
```

**CSS Classes:**
- `.loading-spinner`: Container for spinner
- `.spinner-icon`: Animated spinner (CSS animation)
- `.sr-only`: Screen reader only text

**Animation:**
- Rotating circle with CSS keyframes
- Duration: 1s, infinite loop
- Respects `prefers-reduced-motion`

### 5. Form Validation Component

Real-time form validation with accessible error messages.

**Structure:**
```html
<div class="form-group">
  <label for="email" class="form-label">Email *</label>
  <input 
    type="email" 
    id="email" 
    class="form-input" 
    aria-required="true"
    aria-invalid="false"
    aria-describedby="email-error"
  />
  <div id="email-error" class="form-error" role="alert" aria-live="polite">
    <!-- Error message appears here -->
  </div>
</div>
```

**CSS Classes:**
- `.form-group`: Container for label, input, and error
- `.form-label`: Label styling
- `.form-input`: Input field styling
- `.form-input.is-invalid`: Error state styling (red border)
- `.form-input.is-valid`: Valid state styling (green border)
- `.form-error`: Error message styling (red text)

**Validation States:**
- Default: Neutral styling
- Invalid: Red border, error icon, error message
- Valid: Green border, checkmark icon
- Disabled: Reduced opacity, no interaction

### 6. Toast Notification Component

Temporary notification messages for user feedback.

**Structure:**
```html
<div class="toast toast-success" role="alert" aria-live="polite" aria-atomic="true">
  <div class="toast-icon">✓</div>
  <div class="toast-message">Operation completed successfully</div>
  <button class="toast-close" aria-label="Close notification">×</button>
</div>
```

**CSS Classes:**
- `.toast`: Base toast styling
- `.toast-success`: Success variant (green)
- `.toast-error`: Error variant (red)
- `.toast-warning`: Warning variant (yellow)
- `.toast-info`: Info variant (blue)
- `.toast-icon`: Icon container
- `.toast-message`: Message text
- `.toast-close`: Close button

**Behavior:**
- Appears at bottom center of viewport
- Auto-dismisses after 3 seconds
- Can be manually dismissed
- Stacks multiple toasts vertically
- Slide-in animation from bottom


## Data Models

### CSS Variable Schema

The design system uses CSS custom properties for consistent theming.

```css
:root {
  /* Brand Colors */
  --brand-primary: #3b82f6;        /* Blue - Government */
  --brand-secondary: #10b981;      /* Green - Commercial */
  --brand-gold: #f59e0b;           /* Gold - Accent */
  
  /* Background Colors */
  --bg-dark: #0a0e1a;              /* Primary background */
  --bg-dark-secondary: #1a1f2e;    /* Secondary background */
  --bg-card: #1e293b;              /* Card background */
  --bg-card-hover: #2d3748;        /* Card hover state */
  
  /* Text Colors */
  --text-primary: #f1f5f9;         /* Primary text */
  --text-secondary: #94a3b8;       /* Secondary text */
  --text-muted: #64748b;           /* Muted text */
  
  /* UI Colors */
  --border: #334155;               /* Default border */
  --border-light: #475569;         /* Light border */
  --focus: #60a5fa;                /* Focus indicator */
  --success: #10b981;              /* Success state */
  --warning: #f59e0b;              /* Warning state */
  --danger: #ef4444;               /* Error state */
  --info: #3b82f6;                 /* Info state */
  
  /* Shadows */
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.3);
  --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.4);
  --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.5);
  --shadow-xl: 0 20px 25px rgba(0, 0, 0, 0.6);
  
  /* Spacing Scale */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 32px;
  --space-2xl: 48px;
  --space-3xl: 64px;
  
  /* Typography Scale */
  --font-size-xs: 0.75rem;         /* 12px */
  --font-size-sm: 0.875rem;        /* 14px */
  --font-size-base: 1rem;          /* 16px */
  --font-size-lg: 1.125rem;        /* 18px */
  --font-size-xl: 1.25rem;         /* 20px */
  --font-size-2xl: 1.5rem;         /* 24px */
  --font-size-3xl: 1.875rem;       /* 30px */
  --font-size-4xl: 2.25rem;        /* 36px */
  --font-size-5xl: 3rem;           /* 48px */
  
  /* Font Weights */
  --font-weight-normal: 400;
  --font-weight-medium: 500;
  --font-weight-semibold: 600;
  --font-weight-bold: 700;
  
  /* Line Heights */
  --line-height-tight: 1.2;
  --line-height-normal: 1.6;
  --line-height-relaxed: 1.8;
  
  /* Border Radius */
  --radius-sm: 6px;
  --radius-md: 8px;
  --radius-lg: 12px;
  --radius-xl: 16px;
  --radius-full: 9999px;
  
  /* Transitions */
  --transition-fast: 0.15s ease-in-out;
  --transition-base: 0.2s ease-in-out;
  --transition-slow: 0.3s ease-in-out;
  
  /* Breakpoints (for reference in media queries) */
  --breakpoint-mobile: 768px;
  --breakpoint-tablet: 1024px;
  --breakpoint-desktop: 1200px;
}
```

### Component State Model

Components follow a consistent state model:

```typescript
interface ComponentState {
  default: CSSProperties;      // Default/idle state
  hover?: CSSProperties;       // Mouse hover state
  focus?: CSSProperties;       // Keyboard focus state
  active?: CSSProperties;      // Active/pressed state
  disabled?: CSSProperties;    // Disabled state
  loading?: CSSProperties;     // Loading state
  error?: CSSProperties;       // Error state
  success?: CSSProperties;     // Success state
}
```

### Page Template Model

All pages follow a consistent structure:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>[Page Title] - US Mission Hero</title>
  <meta name="description" content="[Page Description]">
  <link rel="stylesheet" href="/css/theme.css">
  <!-- Page-specific styles if needed -->
</head>
<body>
  <!-- Skip to content link -->
  <a href="#main-content" class="skip-link">Skip to main content</a>
  
  <!-- Navigation Header Component -->
  <header class="site-header">...</header>
  
  <!-- Main Content -->
  <main id="main-content" class="container">
    <!-- Page-specific content -->
  </main>
  
  <!-- Footer Component -->
  <footer class="site-footer">...</footer>
  
  <!-- JavaScript -->
  <script src="/js/common.js"></script>
  <!-- Page-specific scripts if needed -->
</body>
</html>
```


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property Reflection

After analyzing all acceptance criteria, I identified several areas where properties can be consolidated:

**Consolidation Decisions:**
1. **CSS Consistency Properties (1.2-1.7)**: These all verify that CSS variables and classes are used consistently. They can be combined into broader properties about CSS variable usage and class consistency.

2. **Component Consistency Properties (2.1, 3.1)**: Navigation and footer consistency can be verified with a single property about component HTML structure.

3. **Responsive Behavior Properties (4.1-4.8, 18.1-18.7)**: Multiple properties about responsive behavior at different breakpoints can be consolidated into properties about media query application and layout adaptation.

4. **Accessibility Properties (5.1-5.10)**: While each is important, some can be combined (e.g., ARIA attributes, semantic HTML usage).

5. **Form Validation Properties (10.1-10.8)**: These describe a cohesive validation system that can be tested with fewer, more comprehensive properties.

6. **Page Structure Properties (13.1-13.7, 16.1-16.7, 17.1-17.7)**: Template consistency can be verified with properties about structural elements rather than individual page types.

The following properties represent the consolidated, non-redundant set that provides comprehensive coverage:

### Property 1: CSS Variable Usage

*For any* page in the website, all color values, spacing values, and typography values should be defined using CSS custom properties from theme.css rather than hardcoded values.

**Validates: Requirements 1.2, 1.3, 1.4, 1.5, 1.7, 19.1, 19.2, 19.5, 19.6, 19.7, 20.2, 20.3, 20.5**

### Property 2: Inline Style Elimination

*For any* HTML element across all pages, inline style attributes should not override CSS custom properties or global CSS classes defined in theme.css.

**Validates: Requirements 1.6**

### Property 3: Component HTML Consistency

*For any* two pages on the website, the HTML structure of the navigation header and footer components should be identical (same elements, classes, and hierarchy).

**Validates: Requirements 2.1, 3.1**

### Property 4: Navigation Active State

*For any* page on the website, exactly one navigation link should have the aria-current="page" attribute, and it should correspond to the current page's section.

**Validates: Requirements 2.3**

### Property 5: Keyboard Navigation Completeness

*For any* interactive element (buttons, links, form inputs) on any page, the element should be reachable and operable using only keyboard navigation (Tab, Enter, Space, Escape).

**Validates: Requirements 2.4, 5.2, 18.7**

### Property 6: Responsive Layout Adaptation

*For any* page at viewport width less than 768px, all multi-column grid layouts should collapse to single-column layouts, and the navigation should display a hamburger menu.

**Validates: Requirements 4.1, 4.3, 18.1**

### Property 7: Touch Target Sizing

*For any* interactive element on any page at mobile viewport widths (<768px), the element's clickable area should be at least 44x44 pixels.

**Validates: Requirements 4.5, 11.6**

### Property 8: Viewport Overflow Prevention

*For any* page at any viewport width, the page content should not cause horizontal scrolling (body width should not exceed viewport width).

**Validates: Requirements 4.6**

### Property 9: ARIA Attribute Completeness

*For any* interactive element, form input, or custom component on any page, appropriate ARIA attributes (aria-label, aria-labelledby, aria-describedby, or role) should be present.

**Validates: Requirements 5.1, 5.9, 6.5, 9.7, 10.7**

### Property 10: Semantic HTML Usage

*For any* page on the website, the page structure should use semantic HTML5 elements (header, nav, main, footer, article, section) rather than generic div elements for major structural components.

**Validates: Requirements 5.4**

### Property 11: Image Alt Text Completeness

*For any* img element on any page, the element should have an alt attribute with descriptive text (or empty string for decorative images).

**Validates: Requirements 5.5**


### Property 12: Color Contrast Compliance

*For any* text element on any page, the contrast ratio between the text color and its background color should be at least 4.5:1 for normal text or 3:1 for large text (18px+ or 14px+ bold).

**Validates: Requirements 5.6, 11.4**

### Property 13: Focus Indicator Visibility

*For any* interactive element on any page, when the element receives keyboard focus, a visible focus indicator (outline or border) should appear with sufficient contrast against the background.

**Validates: Requirements 5.3**

### Property 14: Heading Hierarchy Correctness

*For any* page on the website, heading elements (h1-h6) should follow a logical hierarchy without skipping levels (e.g., h1 → h2 → h3, not h1 → h3).

**Validates: Requirements 5.8, 7.1, 16.4**

### Property 15: Form Label Association

*For any* form input element on any page, the input should have an associated label element (via for/id attributes) or an aria-label attribute.

**Validates: Requirements 5.10**

### Property 16: Breadcrumb Structure Correctness

*For any* documentation page, if breadcrumb navigation is present, it should contain at least two items (Home and current page), with all items except the last being clickable links.

**Validates: Requirements 6.2, 6.3**

### Property 17: Typography Scale Consistency

*For any* text element across all pages, the font-size value should be one of the predefined values from the typography scale (0.75rem, 0.875rem, 1rem, 1.125rem, 1.25rem, 1.5rem, 1.875rem, 2.25rem, 3rem).

**Validates: Requirements 7.6, 20.2**

### Property 18: Color Coding Consistency

*For any* government-related content section, the primary accent color should be blue (--brand-primary), and for any commercial-related content section, the primary accent color should be green (--brand-secondary).

**Validates: Requirements 7.7, 19.3, 19.4**

### Property 19: Image Lazy Loading

*For any* image element that is not in the initial viewport (below the fold), the img element should have the loading="lazy" attribute.

**Validates: Requirements 8.2**

### Property 20: Script Deferral

*For any* script element that is not critical for initial page render, the script tag should have either the defer or async attribute.

**Validates: Requirements 8.6**

### Property 21: Loading State Button Disabling

*For any* button that triggers an asynchronous operation, when the operation is in progress, the button should be disabled (disabled attribute or aria-disabled="true") and display a loading indicator.

**Validates: Requirements 9.3**

### Property 22: Operation Feedback Consistency

*For any* asynchronous operation (form submission, API call), when the operation completes, a feedback message (success or error) should be displayed using consistent styling (toast notification or inline message).

**Validates: Requirements 9.4, 9.5**

### Property 23: Form Validation Real-Time Feedback

*For any* form input with validation rules, when the user modifies the input value, validation should occur and visual feedback (error or success styling) should update within 500ms.

**Validates: Requirements 10.2, 10.8**

### Property 24: Form Validation Error Placement

*For any* form input with a validation error, the error message should be displayed adjacent to the input field (immediately below or to the right) and associated via aria-describedby.

**Validates: Requirements 10.1, 10.4**

### Property 25: Form Submission Prevention

*For any* form with validation rules, if any required field is invalid or empty, the form submission should be prevented (preventDefault) and focus should move to the first invalid field.

**Validates: Requirements 10.5**

### Property 26: Transition Duration Consistency

*For any* CSS transition or animation on interactive elements (hover, focus, active states), the transition duration should be between 0.15s and 0.4s.

**Validates: Requirements 12.2**

### Property 27: Reduced Motion Respect

*For any* page on the website, when the user's system has prefers-reduced-motion: reduce set, all animations and transitions should be disabled or significantly reduced.

**Validates: Requirements 12.6**

### Property 28: Smooth Scroll Behavior

*For any* anchor link that navigates to a section on the same page, clicking the link should trigger smooth scrolling behavior rather than instant jumping.

**Validates: Requirements 12.4**

### Property 29: Page Structure Consistency

*For any* page on the website, the page should have exactly one header element, exactly one main element, and exactly one footer element, in that order.

**Validates: Requirements 13.1**

### Property 30: Container Width Consistency

*For any* container element (class="container") across all pages, the max-width should be 1200px and horizontal padding should be 24px.

**Validates: Requirements 13.2**


### Property 31: Responsive Image Implementation

*For any* image that has multiple size variants, the img element should use srcset and sizes attributes to provide appropriate images for different viewport widths.

**Validates: Requirements 14.3**

### Property 32: SVG Optimization

*For any* SVG file used on the website, the file should not contain unnecessary metadata elements (e.g., editor-specific data, comments) that increase file size.

**Validates: Requirements 14.4**

### Property 33: CSS Vendor Prefix Presence

*For any* CSS property that requires vendor prefixes for cross-browser compatibility (e.g., backdrop-filter, appearance), the appropriate prefixes (-webkit-, -moz-, -ms-) should be present.

**Validates: Requirements 15.2**

### Property 34: CSS Feature Fallbacks

*For any* modern CSS feature that lacks universal browser support (e.g., CSS Grid, backdrop-filter), a fallback style should be defined for older browsers.

**Validates: Requirements 15.4**

### Property 35: JavaScript Graceful Degradation

*For any* page on the website, when JavaScript is disabled, the core content and navigation should remain accessible and functional (no blank pages or broken layouts).

**Validates: Requirements 15.6**

### Property 36: Documentation Template Consistency

*For any* two documentation pages, the page structure should be identical: page hero, overview section, features section, architecture section, use cases section, and CTA section.

**Validates: Requirements 16.1**

### Property 37: Demo Template Consistency

*For any* two demo pages, the page structure should be identical: page hero, demo sections with form inputs, result display areas, and information sections.

**Validates: Requirements 17.1**

### Property 38: Mobile Menu State Management

*For any* page at mobile viewport width (<768px), when the hamburger menu is clicked, the navigation menu should expand, the hamburger icon should change to a close icon, and body scrolling should be prevented.

**Validates: Requirements 18.2, 18.3, 18.6**

### Property 39: Mobile Menu Auto-Close

*For any* page at mobile viewport width (<768px), when a navigation link in the expanded mobile menu is clicked, the menu should automatically close and body scrolling should be restored.

**Validates: Requirements 18.4**

### Property 40: Font Family Consistency

*For any* text element across all pages, the font-family should use the system font stack defined in theme.css: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif.

**Validates: Requirements 20.1, 20.7**

### Property 41: Font Weight Consistency

*For any* text element across all pages, the font-weight value should be one of the predefined weights: 400 (normal), 500 (medium), 600 (semibold), or 700 (bold).

**Validates: Requirements 20.4**


## Error Handling

### Client-Side Error Handling

**Form Validation Errors:**
- Display field-specific error messages below each invalid input
- Use red border and error icon to indicate invalid state
- Prevent form submission until all errors are resolved
- Announce errors to screen readers via aria-live regions

**Network Errors:**
- Display user-friendly error messages for failed API calls
- Provide retry options for transient failures
- Log errors to console for debugging
- Show toast notifications for error feedback

**JavaScript Errors:**
- Implement global error handler to catch unhandled exceptions
- Log errors to console with stack traces
- Display generic error message to users
- Ensure page remains functional despite errors (graceful degradation)

**Image Loading Errors:**
- Provide fallback images for broken image links
- Use onerror attribute to handle image load failures
- Display placeholder or alt text when images fail to load

### Error Message Guidelines

**Characteristics of Good Error Messages:**
1. **Specific**: Clearly identify what went wrong
2. **Actionable**: Tell users how to fix the problem
3. **Polite**: Use friendly, non-technical language
4. **Visible**: Display prominently near the source of the error
5. **Accessible**: Announced to screen readers

**Examples:**

```javascript
// Good error messages
"Please enter a valid email address (e.g., name@example.com)"
"Password must be at least 8 characters long"
"Unable to submit form. Please check your internet connection and try again."

// Bad error messages
"Invalid input"
"Error 400"
"Something went wrong"
```

### Error Recovery Strategies

**Form Errors:**
1. Preserve user input when validation fails
2. Focus on first invalid field
3. Allow users to correct errors without losing data
4. Provide inline help text for complex fields

**Network Errors:**
1. Implement exponential backoff for retries
2. Cache form data locally to prevent data loss
3. Provide offline mode indicators
4. Queue operations for retry when connection restored

**Browser Compatibility Errors:**
1. Detect unsupported features before use
2. Provide fallback implementations
3. Display upgrade prompts for very old browsers
4. Ensure core functionality works without modern features


## Testing Strategy

### Dual Testing Approach

This project requires both unit testing and property-based testing to ensure comprehensive coverage:

**Unit Tests:**
- Verify specific examples and edge cases
- Test integration points between components
- Validate error conditions and boundary cases
- Focus on concrete scenarios with known inputs/outputs

**Property-Based Tests:**
- Verify universal properties across all inputs
- Test with randomized data to find edge cases
- Ensure properties hold for entire input domains
- Complement unit tests with broader coverage

Both testing approaches are necessary and complementary. Unit tests catch specific bugs, while property tests verify general correctness.

### Property-Based Testing Configuration

**Library Selection:**
- **JavaScript/Node.js**: Use `fast-check` library for property-based testing
- **Installation**: `npm install --save-dev fast-check`

**Test Configuration:**
- Minimum 100 iterations per property test (due to randomization)
- Each property test must reference its design document property
- Tag format: `Feature: website-organization-improvements, Property {number}: {property_text}`

**Example Property Test:**

```javascript
const fc = require('fast-check');

// Feature: website-organization-improvements, Property 1: CSS Variable Usage
test('all pages use CSS variables for colors', () => {
  fc.assert(
    fc.property(
      fc.constantFrom(...getAllPagePaths()),
      (pagePath) => {
        const html = fs.readFileSync(pagePath, 'utf-8');
        const inlineStyles = extractInlineStyles(html);
        const hardcodedColors = inlineStyles.filter(style => 
          /color:\s*#[0-9a-f]{3,6}/i.test(style) ||
          /background:\s*#[0-9a-f]{3,6}/i.test(style)
        );
        return hardcodedColors.length === 0;
      }
    ),
    { numRuns: 100 }
  );
});
```

### Unit Testing Strategy

**Test Categories:**

1. **Component Rendering Tests**
   - Verify components render with correct HTML structure
   - Test component props and state changes
   - Validate accessibility attributes

2. **Responsive Behavior Tests**
   - Test layout changes at specific breakpoints (768px, 1024px)
   - Verify mobile menu toggle functionality
   - Check touch target sizes on mobile

3. **Form Validation Tests**
   - Test validation rules for each input type
   - Verify error message display
   - Test form submission prevention with invalid data

4. **Accessibility Tests**
   - Verify ARIA attributes are present
   - Test keyboard navigation flows
   - Check color contrast ratios
   - Validate heading hierarchy

5. **Performance Tests**
   - Verify lazy loading implementation
   - Check script defer/async attributes
   - Validate image optimization

**Example Unit Test:**

```javascript
// Test: Navigation component has correct structure
test('navigation header contains all required links', () => {
  const html = fs.readFileSync('modules/s3/index_Enhanced.html', 'utf-8');
  const $ = cheerio.load(html);
  
  const navLinks = $('.nav-menu .nav-link');
  expect(navLinks.length).toBe(5);
  
  const linkTexts = navLinks.map((i, el) => $(el).text()).get();
  expect(linkTexts).toEqual(['Home', 'Government Solutions', 'Commercial Solutions', 'About', 'Contact']);
});
```

### Visual Regression Testing

**Tools:**
- Use Percy or Chromatic for visual regression testing
- Capture screenshots at multiple viewport sizes
- Compare against baseline images
- Flag visual changes for review

**Viewport Sizes to Test:**
- Mobile: 375px, 414px
- Tablet: 768px, 1024px
- Desktop: 1280px, 1920px

### Accessibility Testing

**Automated Tools:**
- axe-core for automated accessibility testing
- Pa11y for command-line accessibility testing
- Lighthouse for accessibility audits

**Manual Testing:**
- Keyboard navigation testing (Tab, Shift+Tab, Enter, Escape)
- Screen reader testing (NVDA, JAWS, VoiceOver)
- Color contrast verification
- Focus indicator visibility

**Example Accessibility Test:**

```javascript
const { AxePuppeteer } = require('@axe-core/puppeteer');

test('page has no accessibility violations', async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto('http://localhost:8000/index_Enhanced.html');
  
  const results = await new AxePuppeteer(page).analyze();
  expect(results.violations).toHaveLength(0);
  
  await browser.close();
});
```

### Performance Testing

**Metrics to Track:**
- First Contentful Paint (FCP) < 1.8s
- Largest Contentful Paint (LCP) < 2.5s
- Time to Interactive (TTI) < 3.8s
- Cumulative Layout Shift (CLS) < 0.1
- Total Blocking Time (TBT) < 300ms

**Tools:**
- Lighthouse for performance audits
- WebPageTest for detailed performance analysis
- Chrome DevTools Performance panel

### Cross-Browser Testing

**Browsers to Test:**
- Chrome (latest 2 versions)
- Firefox (latest 2 versions)
- Safari (latest 2 versions)
- Edge (latest 2 versions)

**Testing Approach:**
- Use BrowserStack or Sauce Labs for cross-browser testing
- Test on real devices when possible
- Verify layout, functionality, and performance

### Test Coverage Goals

**Minimum Coverage Targets:**
- Unit test coverage: 80% of JavaScript code
- Property test coverage: All 41 correctness properties
- Accessibility test coverage: All pages and components
- Visual regression coverage: All pages at 3+ viewport sizes
- Cross-browser coverage: All supported browsers


## Implementation Details

### CSS Architecture

**File Structure:**

```css
/* theme.css structure */

/* 1. CSS Variables (Design Tokens) */
:root { /* color, spacing, typography variables */ }

/* 2. CSS Reset */
*, *::before, *::after { box-sizing: border-box; }
/* normalize styles */

/* 3. Base Styles */
html, body { /* base typography, colors */ }
h1, h2, h3, h4, h5, h6 { /* heading styles */ }
p, ul, ol { /* text styles */ }
a { /* link styles */ }

/* 4. Layout Components */
.container { /* max-width, padding */ }
.grid { /* grid layouts */ }
.flex { /* flex layouts */ }

/* 5. UI Components */
.btn { /* button base styles */ }
.btn-primary, .btn-secondary { /* button variants */ }
.card { /* card component */ }
.badge { /* badge component */ }
.form-input, .form-label { /* form components */ }

/* 6. Navigation Components */
.site-header { /* header styles */ }
.nav-menu { /* navigation styles */ }
.mobile-menu-toggle { /* mobile menu button */ }

/* 7. Footer Components */
.site-footer { /* footer styles */ }
.footer-content { /* footer layout */ }

/* 8. Utility Classes */
.hidden { display: none !important; }
.sr-only { /* screen reader only */ }
.text-center { text-align: center; }
/* spacing utilities */

/* 9. Responsive Breakpoints */
@media (max-width: 768px) { /* mobile styles */ }
@media (min-width: 769px) and (max-width: 1023px) { /* tablet styles */ }
@media (min-width: 1024px) { /* desktop styles */ }

/* 10. Accessibility */
@media (prefers-reduced-motion: reduce) { /* reduced motion styles */ }
@media (prefers-color-scheme: light) { /* light mode overrides */ }

/* 11. Print Styles */
@media print { /* print-specific styles */ }
```

**Naming Conventions:**
- Use BEM (Block Element Modifier) for component classes
- Use kebab-case for class names
- Prefix utility classes with purpose (e.g., `.text-`, `.bg-`, `.mt-`)
- Use semantic names over presentational names

**CSS Best Practices:**
- Use CSS custom properties for all theme values
- Avoid !important except for utility classes
- Use relative units (rem, em, %) over absolute units (px)
- Group related properties together
- Add comments for complex selectors

### JavaScript Architecture

**Module Structure:**

```javascript
// common.js - Shared utilities
const utils = {
  // DOM helpers
  $: (selector) => document.querySelector(selector),
  $$: (selector) => document.querySelectorAll(selector),
  
  // Event helpers
  on: (element, event, handler) => element.addEventListener(event, handler),
  off: (element, event, handler) => element.removeEventListener(event, handler),
  
  // Class helpers
  addClass: (element, className) => element.classList.add(className),
  removeClass: (element, className) => element.classList.remove(className),
  toggleClass: (element, className) => element.classList.toggle(className),
  
  // Attribute helpers
  setAttr: (element, attr, value) => element.setAttribute(attr, value),
  getAttr: (element, attr) => element.getAttribute(attr),
  
  // Debounce helper
  debounce: (func, wait) => {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = utils;
}
```

```javascript
// navigation.js - Mobile menu and navigation
class Navigation {
  constructor() {
    this.header = utils.$('.site-header');
    this.menuToggle = utils.$('.mobile-menu-toggle');
    this.navMenu = utils.$('.nav-menu');
    this.navLinks = utils.$$('.nav-link');
    this.isOpen = false;
    
    this.init();
  }
  
  init() {
    if (this.menuToggle) {
      utils.on(this.menuToggle, 'click', () => this.toggleMenu());
    }
    
    this.navLinks.forEach(link => {
      utils.on(link, 'click', () => this.closeMenu());
    });
    
    // Close menu on Escape key
    utils.on(document, 'keydown', (e) => {
      if (e.key === 'Escape' && this.isOpen) {
        this.closeMenu();
      }
    });
    
    // Set active link based on current page
    this.setActiveLink();
  }
  
  toggleMenu() {
    this.isOpen ? this.closeMenu() : this.openMenu();
  }
  
  openMenu() {
    this.isOpen = true;
    utils.addClass(this.navMenu, 'is-open');
    utils.setAttr(this.menuToggle, 'aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
  }
  
  closeMenu() {
    this.isOpen = false;
    utils.removeClass(this.navMenu, 'is-open');
    utils.setAttr(this.menuToggle, 'aria-expanded', 'false');
    document.body.style.overflow = '';
  }
  
  setActiveLink() {
    const currentPath = window.location.pathname;
    const currentHash = window.location.hash;
    
    this.navLinks.forEach(link => {
      const href = link.getAttribute('href');
      if (href === currentPath || href === currentHash) {
        utils.setAttr(link, 'aria-current', 'page');
      }
    });
  }
}

// Initialize on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new Navigation());
} else {
  new Navigation();
}
```

```javascript
// validation.js - Form validation
class FormValidator {
  constructor(form) {
    this.form = form;
    this.inputs = form.querySelectorAll('input, textarea, select');
    this.errors = new Map();
    
    this.init();
  }
  
  init() {
    this.inputs.forEach(input => {
      // Real-time validation on input
      utils.on(input, 'input', utils.debounce(() => {
        this.validateField(input);
      }, 300));
      
      // Validation on blur
      utils.on(input, 'blur', () => {
        this.validateField(input);
      });
    });
    
    // Prevent submission if invalid
    utils.on(this.form, 'submit', (e) => {
      if (!this.validateForm()) {
        e.preventDefault();
        this.focusFirstError();
      }
    });
  }
  
  validateField(input) {
    const value = input.value.trim();
    const type = input.type;
    const required = input.hasAttribute('required');
    let error = null;
    
    // Required validation
    if (required && !value) {
      error = 'This field is required';
    }
    
    // Type-specific validation
    if (value && !error) {
      if (type === 'email' && !this.isValidEmail(value)) {
        error = 'Please enter a valid email address';
      } else if (type === 'url' && !this.isValidUrl(value)) {
        error = 'Please enter a valid URL';
      }
    }
    
    // Custom validation
    const pattern = input.getAttribute('pattern');
    if (value && pattern && !new RegExp(pattern).test(value)) {
      error = input.getAttribute('title') || 'Invalid format';
    }
    
    this.setFieldError(input, error);
    return !error;
  }
  
  validateForm() {
    let isValid = true;
    this.inputs.forEach(input => {
      if (!this.validateField(input)) {
        isValid = false;
      }
    });
    return isValid;
  }
  
  setFieldError(input, error) {
    const errorId = `${input.id}-error`;
    let errorElement = utils.$(`#${errorId}`);
    
    if (error) {
      // Add error state
      utils.addClass(input, 'is-invalid');
      utils.removeClass(input, 'is-valid');
      utils.setAttr(input, 'aria-invalid', 'true');
      
      // Create or update error message
      if (!errorElement) {
        errorElement = document.createElement('div');
        errorElement.id = errorId;
        errorElement.className = 'form-error';
        errorElement.setAttribute('role', 'alert');
        errorElement.setAttribute('aria-live', 'polite');
        input.parentNode.appendChild(errorElement);
      }
      errorElement.textContent = error;
      utils.setAttr(input, 'aria-describedby', errorId);
      
      this.errors.set(input, error);
    } else {
      // Remove error state
      utils.removeClass(input, 'is-invalid');
      utils.addClass(input, 'is-valid');
      utils.setAttr(input, 'aria-invalid', 'false');
      
      if (errorElement) {
        errorElement.textContent = '';
      }
      
      this.errors.delete(input);
    }
  }
  
  focusFirstError() {
    const firstInvalidInput = this.form.querySelector('.is-invalid');
    if (firstInvalidInput) {
      firstInvalidInput.focus();
    }
  }
  
  isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }
  
  isValidUrl(url) {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }
}

// Initialize all forms
document.querySelectorAll('form[data-validate]').forEach(form => {
  new FormValidator(form);
});
```


```javascript
// loading.js - Loading state management
class LoadingManager {
  static show(button, message = 'Loading...') {
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    
    // Store original content
    button.dataset.originalContent = button.innerHTML;
    
    // Add loading spinner
    button.innerHTML = `
      <span class="loading-spinner" role="status" aria-live="polite">
        <span class="spinner-icon"></span>
        <span class="sr-only">${message}</span>
      </span>
    `;
  }
  
  static hide(button) {
    button.disabled = false;
    button.setAttribute('aria-busy', 'false');
    
    // Restore original content
    if (button.dataset.originalContent) {
      button.innerHTML = button.dataset.originalContent;
      delete button.dataset.originalContent;
    }
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = LoadingManager;
}
```

```javascript
// toast.js - Toast notifications
class Toast {
  static show(message, type = 'info', duration = 3000) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'polite');
    toast.setAttribute('aria-atomic', 'true');
    
    const icons = {
      success: '✓',
      error: '✗',
      warning: '⚠',
      info: 'ℹ'
    };
    
    toast.innerHTML = `
      <div class="toast-icon">${icons[type] || icons.info}</div>
      <div class="toast-message">${message}</div>
      <button class="toast-close" aria-label="Close notification">×</button>
    `;
    
    document.body.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => toast.classList.add('toast-show'), 10);
    
    // Close button handler
    const closeBtn = toast.querySelector('.toast-close');
    closeBtn.addEventListener('click', () => this.hide(toast));
    
    // Auto-dismiss
    if (duration > 0) {
      setTimeout(() => this.hide(toast), duration);
    }
    
    return toast;
  }
  
  static hide(toast) {
    toast.classList.remove('toast-show');
    toast.classList.add('toast-hide');
    
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 300);
  }
  
  static success(message, duration) {
    return this.show(message, 'success', duration);
  }
  
  static error(message, duration) {
    return this.show(message, 'error', duration);
  }
  
  static warning(message, duration) {
    return this.show(message, 'warning', duration);
  }
  
  static info(message, duration) {
    return this.show(message, 'info', duration);
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Toast;
}
```

```javascript
// scroll.js - Smooth scrolling
class SmoothScroll {
  constructor() {
    this.init();
  }
  
  init() {
    // Handle anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', (e) => {
        const href = anchor.getAttribute('href');
        
        // Skip if href is just "#"
        if (href === '#') return;
        
        const target = document.querySelector(href);
        if (target) {
          e.preventDefault();
          this.scrollTo(target);
        }
      });
    });
  }
  
  scrollTo(element, offset = 80) {
    const elementPosition = element.getBoundingClientRect().top;
    const offsetPosition = elementPosition + window.pageYOffset - offset;
    
    window.scrollTo({
      top: offsetPosition,
      behavior: 'smooth'
    });
    
    // Set focus for accessibility
    element.setAttribute('tabindex', '-1');
    element.focus();
  }
}

// Initialize on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new SmoothScroll());
} else {
  new SmoothScroll();
}
```

### Responsive Design Strategy

**Breakpoint System:**

```css
/* Mobile First Approach */

/* Base styles (mobile, <768px) */
.container {
  max-width: 100%;
  padding: 0 16px;
}

.grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 16px;
}

/* Tablet (768px - 1023px) */
@media (min-width: 768px) {
  .container {
    padding: 0 24px;
  }
  
  .grid-2 {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .grid-3 {
    grid-template-columns: repeat(2, 1fr);
  }
}

/* Desktop (1024px+) */
@media (min-width: 1024px) {
  .container {
    max-width: 1200px;
    margin: 0 auto;
  }
  
  .grid-3 {
    grid-template-columns: repeat(3, 1fr);
  }
}

/* Large Desktop (1200px+) */
@media (min-width: 1200px) {
  .grid-4 {
    grid-template-columns: repeat(4, 1fr);
  }
}
```

**Mobile Menu Implementation:**

```css
/* Mobile menu styles */
.mobile-menu-toggle {
  display: none;
  background: none;
  border: none;
  cursor: pointer;
  padding: 8px;
}

.hamburger-icon {
  display: block;
  width: 24px;
  height: 2px;
  background: var(--text-primary);
  position: relative;
}

.hamburger-icon::before,
.hamburger-icon::after {
  content: '';
  display: block;
  width: 24px;
  height: 2px;
  background: var(--text-primary);
  position: absolute;
  transition: transform 0.3s ease;
}

.hamburger-icon::before {
  top: -8px;
}

.hamburger-icon::after {
  top: 8px;
}

/* Mobile menu open state */
.mobile-menu-toggle[aria-expanded="true"] .hamburger-icon {
  background: transparent;
}

.mobile-menu-toggle[aria-expanded="true"] .hamburger-icon::before {
  transform: rotate(45deg);
  top: 0;
}

.mobile-menu-toggle[aria-expanded="true"] .hamburger-icon::after {
  transform: rotate(-45deg);
  top: 0;
}

/* Mobile breakpoint */
@media (max-width: 767px) {
  .mobile-menu-toggle {
    display: block;
  }
  
  .nav-menu {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: var(--bg-dark);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 24px;
    transform: translateX(-100%);
    transition: transform 0.3s ease;
    z-index: 1000;
  }
  
  .nav-menu.is-open {
    transform: translateX(0);
  }
  
  .nav-link {
    font-size: 1.5rem;
    padding: 16px;
  }
}
```


### Accessibility Implementation

**Skip to Content Link:**

```html
<a href="#main-content" class="skip-link">Skip to main content</a>
```

```css
.skip-link {
  position: absolute;
  top: -40px;
  left: 0;
  background: var(--brand-primary);
  color: white;
  padding: 8px 16px;
  text-decoration: none;
  z-index: 10000;
  transition: top 0.2s;
}

.skip-link:focus {
  top: 0;
}
```

**Focus Indicators:**

```css
/* Global focus styles */
*:focus {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}

/* Custom focus for buttons */
.btn:focus {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
  box-shadow: 0 0 0 4px rgba(96, 165, 250, 0.2);
}

/* Focus visible (keyboard only) */
*:focus:not(:focus-visible) {
  outline: none;
}

*:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
```

**Screen Reader Only Content:**

```css
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}

.sr-only-focusable:focus {
  position: static;
  width: auto;
  height: auto;
  padding: inherit;
  margin: inherit;
  overflow: visible;
  clip: auto;
  white-space: normal;
}
```

**ARIA Live Regions:**

```html
<!-- For dynamic content updates -->
<div aria-live="polite" aria-atomic="true" class="sr-only" id="status-message"></div>

<script>
// Announce status to screen readers
function announceStatus(message) {
  const statusEl = document.getElementById('status-message');
  statusEl.textContent = message;
  
  // Clear after announcement
  setTimeout(() => {
    statusEl.textContent = '';
  }, 1000);
}
</script>
```

**Reduced Motion Support:**

```css
/* Respect user's motion preferences */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

### Performance Optimization

**Critical CSS Inlining:**

```html
<head>
  <!-- Inline critical CSS for above-the-fold content -->
  <style>
    /* Critical styles: layout, typography, colors */
    :root { /* CSS variables */ }
    body { /* base styles */ }
    .site-header { /* header styles */ }
    .hero { /* hero section styles */ }
  </style>
  
  <!-- Load full stylesheet asynchronously -->
  <link rel="preload" href="/css/theme.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
  <noscript><link rel="stylesheet" href="/css/theme.css"></noscript>
</head>
```

**Image Optimization:**

```html
<!-- Responsive images with srcset -->
<img 
  src="/assets/hero-800.webp"
  srcset="
    /assets/hero-400.webp 400w,
    /assets/hero-800.webp 800w,
    /assets/hero-1200.webp 1200w,
    /assets/hero-1600.webp 1600w
  "
  sizes="(max-width: 768px) 100vw, (max-width: 1024px) 80vw, 1200px"
  alt="US Mission Hero"
  loading="lazy"
  width="1200"
  height="600"
/>

<!-- Fallback for browsers without WebP support -->
<picture>
  <source srcset="/assets/hero.webp" type="image/webp">
  <source srcset="/assets/hero.jpg" type="image/jpeg">
  <img src="/assets/hero.jpg" alt="US Mission Hero" loading="lazy">
</picture>
```

**Script Loading Strategy:**

```html
<!-- Defer non-critical scripts -->
<script src="/js/common.js" defer></script>
<script src="/js/navigation.js" defer></script>
<script src="/js/validation.js" defer></script>

<!-- Async for independent scripts -->
<script src="/js/analytics.js" async></script>

<!-- Inline critical scripts -->
<script>
  // Critical functionality that must run immediately
  // (e.g., feature detection, polyfills)
</script>
```

**Resource Hints:**

```html
<head>
  <!-- DNS prefetch for external domains -->
  <link rel="dns-prefetch" href="https://d11k4vck88gnf5.cloudfront.net">
  
  <!-- Preconnect for critical resources -->
  <link rel="preconnect" href="https://d11k4vck88gnf5.cloudfront.net">
  
  <!-- Preload critical assets -->
  <link rel="preload" href="/css/theme.css" as="style">
  <link rel="preload" href="/js/common.js" as="script">
  <link rel="preload" href="/assets/US-Mission-Hero.png" as="image">
</head>
```

**Lazy Loading Implementation:**

```javascript
// Lazy load images below the fold
if ('IntersectionObserver' in window) {
  const imageObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const img = entry.target;
        img.src = img.dataset.src;
        img.classList.remove('lazy');
        observer.unobserve(img);
      }
    });
  });
  
  document.querySelectorAll('img.lazy').forEach(img => {
    imageObserver.observe(img);
  });
} else {
  // Fallback for browsers without IntersectionObserver
  document.querySelectorAll('img.lazy').forEach(img => {
    img.src = img.dataset.src;
  });
}
```


## Migration Strategy

### Phase 1: Global CSS Enhancement (Priority: High)

**Objective:** Expand theme.css with comprehensive design system.

**Tasks:**
1. Add missing CSS variables for all colors, spacing, and typography
2. Create utility classes for common patterns (spacing, display, text alignment)
3. Define component styles (buttons, cards, forms, badges)
4. Add responsive breakpoints with mobile-first approach
5. Implement accessibility styles (focus indicators, reduced motion)

**Validation:**
- All CSS variables are defined and documented
- No hardcoded color or spacing values in component styles
- Utility classes cover common use cases
- Responsive breakpoints work at 768px, 1024px, 1200px

### Phase 2: Component Extraction (Priority: High)

**Objective:** Create reusable HTML components for navigation and footer.

**Tasks:**
1. Standardize navigation header HTML across all pages
2. Standardize footer HTML across all pages
3. Add mobile menu functionality to navigation
4. Ensure consistent branding (logo, tagline) in all headers
5. Add skip-to-content links to all pages

**Validation:**
- Navigation HTML is identical across all pages
- Footer HTML is identical across all pages
- Mobile menu works on all pages at <768px viewport
- Skip links are present and functional

### Phase 3: Page Template Updates (Priority: Medium)

**Objective:** Update all pages to use consistent structure and components.

**Pages to Update:**
- index_Enhanced.html (main page)
- contact.html
- government/docs/*.html (6 documentation pages)
- government/demo/security-data-transfer.html
- commercial/bedrock-s3-demo.html

**Tasks for Each Page:**
1. Replace header with standardized navigation component
2. Replace footer with standardized footer component
3. Add skip-to-content link
4. Update CSS class names to use theme.css classes
5. Remove inline styles
6. Add breadcrumb navigation (documentation pages only)
7. Ensure semantic HTML structure (header, main, footer)
8. Add ARIA attributes for accessibility

**Validation:**
- All pages use theme.css as primary stylesheet
- No inline styles that override theme.css
- All pages have consistent header/footer
- Semantic HTML structure is correct

### Phase 4: JavaScript Enhancements (Priority: Medium)

**Objective:** Add JavaScript modules for interactivity.

**Tasks:**
1. Create common.js with utility functions
2. Create navigation.js for mobile menu
3. Create validation.js for form validation
4. Create loading.js for loading states
5. Create toast.js for notifications
6. Create scroll.js for smooth scrolling
7. Update existing pages to use new modules

**Validation:**
- Mobile menu works on all pages
- Form validation works on contact page
- Loading states work on demo pages
- Toast notifications work for user feedback
- Smooth scrolling works for anchor links

### Phase 5: Accessibility Improvements (Priority: High)

**Objective:** Ensure WCAG 2.1 AA compliance across all pages.

**Tasks:**
1. Add ARIA labels to all interactive elements
2. Ensure keyboard navigation works for all components
3. Add visible focus indicators
4. Verify color contrast ratios (4.5:1 minimum)
5. Add alt text to all images
6. Ensure heading hierarchy is correct
7. Add form labels and error messages
8. Test with screen readers

**Validation:**
- All interactive elements are keyboard accessible
- Focus indicators are visible
- Color contrast meets WCAG AA standards
- All images have alt text
- Heading hierarchy is logical
- Forms have proper labels and error handling
- Screen reader testing passes

### Phase 6: Performance Optimization (Priority: Medium)

**Objective:** Optimize page load performance.

**Tasks:**
1. Optimize images (compress, convert to WebP)
2. Add lazy loading to below-the-fold images
3. Implement responsive images with srcset
4. Minify CSS and JavaScript for production
5. Add resource hints (preconnect, dns-prefetch)
6. Defer non-critical JavaScript
7. Inline critical CSS

**Validation:**
- Lighthouse performance score > 90
- First Contentful Paint < 1.8s
- Largest Contentful Paint < 2.5s
- Total Blocking Time < 300ms
- Cumulative Layout Shift < 0.1

### Phase 7: Testing and Validation (Priority: High)

**Objective:** Comprehensive testing across browsers and devices.

**Tasks:**
1. Write unit tests for JavaScript modules
2. Write property-based tests for correctness properties
3. Run accessibility audits (axe, Pa11y, Lighthouse)
4. Test on multiple browsers (Chrome, Firefox, Safari, Edge)
5. Test on multiple devices (mobile, tablet, desktop)
6. Run visual regression tests
7. Validate HTML and CSS against W3C standards

**Validation:**
- All unit tests pass
- All property tests pass (100+ iterations each)
- No accessibility violations
- Works in all supported browsers
- Responsive design works on all devices
- HTML and CSS validate

### Rollback Strategy

**If Issues Arise:**
1. Keep backup copies of all original files
2. Use version control (Git) for all changes
3. Test changes in staging environment before production
4. Have rollback plan for each phase
5. Monitor error logs after deployment

**Rollback Steps:**
1. Identify problematic changes
2. Revert to previous version using Git
3. Test reverted version
4. Deploy reverted version to production
5. Investigate and fix issues
6. Re-deploy when fixed

### Success Criteria

**Phase Completion Criteria:**
- All tasks completed and validated
- All tests passing
- No regressions in functionality
- Performance metrics met
- Accessibility standards met
- Cross-browser compatibility verified

**Project Completion Criteria:**
- All 20 requirements satisfied
- All 41 correctness properties verified
- Lighthouse scores: Performance > 90, Accessibility = 100, Best Practices > 90, SEO > 90
- Zero critical or high-severity accessibility violations
- Works in Chrome, Firefox, Safari, Edge (latest 2 versions)
- Responsive design works on mobile (375px+), tablet (768px+), desktop (1024px+)


## Summary

This design document provides a comprehensive technical approach for improving and organizing the US Mission Hero website. The design focuses on:

**Key Improvements:**
1. **Unified Design System**: CSS variables and utility classes for consistent styling
2. **Reusable Components**: Standardized navigation, footer, breadcrumbs, and UI elements
3. **Responsive Design**: Mobile-first approach with breakpoints at 768px, 1024px, 1200px
4. **Accessibility**: WCAG 2.1 AA compliance with ARIA attributes, keyboard navigation, and screen reader support
5. **Performance**: Optimized images, lazy loading, deferred scripts, and critical CSS inlining
6. **Maintainability**: Modular JavaScript, consistent naming conventions, and clear documentation

**Implementation Approach:**
- 7 phases with clear priorities and validation criteria
- Mobile-first responsive design strategy
- Component-based architecture for reusability
- Comprehensive testing strategy (unit tests + property-based tests)
- Rollback strategy for risk mitigation

**Expected Outcomes:**
- Consistent user experience across all pages
- Improved accessibility for users with disabilities
- Faster page load times and better performance
- Easier maintenance and future enhancements
- Better SEO and search engine visibility
- Compliance with web standards and best practices

**Next Steps:**
1. Review and approve this design document
2. Create detailed task list from migration strategy
3. Set up development environment and testing infrastructure
4. Begin Phase 1: Global CSS Enhancement
5. Iterate through phases with continuous testing and validation

This design provides clear guidance for implementation while maintaining flexibility for adjustments based on testing and feedback.

