/**
 * Lazy Loading Module
 * Provides IntersectionObserver fallback for browsers that don't support native lazy loading
 * 
 * Usage: This script automatically initializes on page load
 */

(function() {
  'use strict';

  /**
   * Check if browser supports native lazy loading
   */
  function supportsNativeLazyLoading() {
    return 'loading' in HTMLImageElement.prototype;
  }

  /**
   * Initialize lazy loading with IntersectionObserver fallback
   */
  function initLazyLoading() {
    // If browser supports native lazy loading, no fallback needed
    if (supportsNativeLazyLoading()) {
      console.log('[LazyLoad] Native lazy loading supported');
      return;
    }

    console.log('[LazyLoad] Using IntersectionObserver fallback');

    // Get all images with loading="lazy" attribute
    const lazyImages = document.querySelectorAll('img[loading="lazy"]');

    if (lazyImages.length === 0) {
      return;
    }

    // Check if IntersectionObserver is supported
    if ('IntersectionObserver' in window) {
      // Create intersection observer
      const imageObserver = new IntersectionObserver(function(entries, observer) {
        entries.forEach(function(entry) {
          if (entry.isIntersecting) {
            const img = entry.target;
            
            // Load the image by ensuring src is set
            if (img.dataset.src) {
              img.src = img.dataset.src;
            }
            
            // If srcset is present, ensure it's applied
            if (img.dataset.srcset) {
              img.srcset = img.dataset.srcset;
            }
            
            // Remove loading attribute to prevent any issues
            img.removeAttribute('loading');
            
            // Add loaded class for styling if needed
            img.classList.add('lazy-loaded');
            
            // Stop observing this image
            observer.unobserve(img);
          }
        });
      }, {
        // Load images slightly before they enter viewport
        rootMargin: '50px 0px',
        threshold: 0.01
      });

      // Observe each lazy image
      lazyImages.forEach(function(img) {
        imageObserver.observe(img);
      });
    } else {
      // Fallback for browsers without IntersectionObserver
      // Load all images immediately
      console.log('[LazyLoad] IntersectionObserver not supported, loading all images');
      lazyImages.forEach(function(img) {
        if (img.dataset.src) {
          img.src = img.dataset.src;
        }
        if (img.dataset.srcset) {
          img.srcset = img.dataset.srcset;
        }
        img.removeAttribute('loading');
        img.classList.add('lazy-loaded');
      });
    }
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initLazyLoading);
  } else {
    // DOM is already loaded
    initLazyLoading();
  }
})();
