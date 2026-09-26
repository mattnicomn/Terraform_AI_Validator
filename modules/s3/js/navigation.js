/**
 * Navigation Module
 * Handles mobile menu toggle, active link management, and keyboard navigation
 * @requires common.js
 */

(function() {
  'use strict';

  /**
   * Navigation class for managing site navigation behavior
   */
  class Navigation {
    /**
     * Initialize navigation with DOM elements and event listeners
     */
    constructor() {
      this.menuToggle = Common.$('.mobile-menu-toggle');
      this.navMenu = Common.$('.nav-menu');
      this.navLinks = Common.$$('.nav-link');
      this.body = document.body;
      
      if (!this.menuToggle || !this.navMenu) {
        console.warn('Navigation: Required elements not found');
        return;
      }

      this.isOpen = false;
      this.init();
    }

    /**
     * Initialize event listeners
     */
    init() {
      // Mobile menu toggle
      Common.on(this.menuToggle, 'click', () => this.toggleMenu());

      // Close menu on Escape key
      Common.on(document, 'keydown', (e) => {
        if (e.key === 'Escape' && this.isOpen) {
          this.closeMenu();
        }
      });

      // Close menu when clicking nav links
      this.navLinks.forEach(link => {
        Common.on(link, 'click', () => {
          if (this.isOpen) {
            this.closeMenu();
          }
        });
      });

      // Close menu when clicking outside
      Common.on(document, 'click', (e) => {
        if (this.isOpen && 
            !this.navMenu.contains(e.target) && 
            !this.menuToggle.contains(e.target)) {
          this.closeMenu();
        }
      });

      // Set active link based on current page
      this.setActiveLink();
    }

    /**
     * Toggle mobile menu open/closed
     */
    toggleMenu() {
      if (this.isOpen) {
        this.closeMenu();
      } else {
        this.openMenu();
      }
    }

    /**
     * Open mobile menu
     */
    openMenu() {
      this.isOpen = true;
      Common.addClass(this.navMenu, 'is-open');
      Common.addClass(this.body, 'menu-open');
      Common.setAttr(this.menuToggle, 'aria-expanded', 'true');
      
      // Focus first nav link for accessibility
      const firstLink = this.navLinks[0];
      if (firstLink) {
        firstLink.focus();
      }
    }

    /**
     * Close mobile menu
     */
    closeMenu() {
      this.isOpen = false;
      Common.removeClass(this.navMenu, 'is-open');
      Common.removeClass(this.body, 'menu-open');
      Common.setAttr(this.menuToggle, 'aria-expanded', 'false');
    }

    /**
     * Set active link based on current page URL
     */
    setActiveLink() {
      const currentPath = window.location.pathname;
      
      this.navLinks.forEach(link => {
        const linkPath = link.getAttribute('href');
        
        // Remove any existing aria-current
        Common.removeAttr(link, 'aria-current');
        Common.removeClass(link, 'active');
        
        // Check if link matches current page
        if (linkPath === currentPath || 
            (currentPath === '/' && linkPath === '/') ||
            (currentPath.includes('/index') && linkPath === '/') ||
            (linkPath !== '/' && currentPath.startsWith(linkPath))) {
          Common.setAttr(link, 'aria-current', 'page');
          Common.addClass(link, 'active');
        }
      });
    }
  }

  // Initialize navigation when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      window.Navigation = new Navigation();
    });
  } else {
    window.Navigation = new Navigation();
  }

})();
