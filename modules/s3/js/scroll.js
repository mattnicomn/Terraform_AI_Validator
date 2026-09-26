/**
 * Smooth Scroll Module
 * Provides smooth scrolling for anchor links with accessibility support
 * @requires common.js
 */

(function() {
  'use strict';

  /**
   * SmoothScroll class for managing smooth scrolling behavior
   */
  class SmoothScroll {
    /**
     * Initialize smooth scroll
     * @param {Object} options - Configuration options
     * @param {number} options.offset - Offset from top in pixels (default: 80 for fixed header)
     * @param {number} options.duration - Scroll duration in milliseconds (default: 800)
     */
    constructor(options = {}) {
      this.offset = options.offset || 80;
      this.duration = options.duration || 800;
      this.init();
    }

    /**
     * Initialize event listeners for anchor links
     */
    init() {
      // Find all anchor links that point to IDs on the same page
      const anchorLinks = Common.$$('a[href^="#"]:not([href="#"])');
      
      anchorLinks.forEach(link => {
        Common.on(link, 'click', (e) => {
          const targetId = link.getAttribute('href').substring(1);
          const targetElement = document.getElementById(targetId);
          
          if (targetElement) {
            e.preventDefault();
            this.scrollTo(targetElement);
          }
        });
      });
    }

    /**
     * Scroll to a target element smoothly
     * @param {HTMLElement|string} target - Target element or selector
     * @param {number} customOffset - Optional custom offset (overrides default)
     */
    scrollTo(target, customOffset = null) {
      const element = typeof target === 'string' ? Common.$(target) : target;
      
      if (!element) {
        console.warn('SmoothScroll.scrollTo: Target element not found');
        return;
      }

      // Calculate target position
      const elementPosition = element.getBoundingClientRect().top + window.pageYOffset;
      const offsetPosition = elementPosition - (customOffset !== null ? customOffset : this.offset);

      // Perform smooth scroll
      window.scrollTo({
        top: offsetPosition,
        behavior: 'smooth'
      });

      // Set focus on target element for accessibility
      // Add tabindex if element is not naturally focusable
      if (!element.hasAttribute('tabindex')) {
        element.setAttribute('tabindex', '-1');
      }
      
      // Focus after scroll completes
      setTimeout(() => {
        element.focus({ preventScroll: true });
        
        // Remove tabindex if we added it
        if (element.getAttribute('tabindex') === '-1') {
          element.removeAttribute('tabindex');
        }
      }, this.duration);
    }

    /**
     * Scroll to top of page
     */
    scrollToTop() {
      window.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    }
  }

  // Auto-initialize smooth scroll
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      window.SmoothScroll = new SmoothScroll();
    });
  } else {
    window.SmoothScroll = new SmoothScroll();
  }

  // Export class for manual initialization
  window.SmoothScrollClass = SmoothScroll;

})();
