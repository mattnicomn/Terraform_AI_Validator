/**
 * Loading State Management Module
 * Manages button loading states with spinner and disabled state
 * @requires common.js
 */

(function() {
  'use strict';

  /**
   * LoadingManager class for managing button loading states
   */
  class LoadingManager {
    /**
     * Show loading state on a button
     * @param {HTMLButtonElement|string} button - Button element or selector
     * @param {string} loadingText - Optional text to show while loading (default: original text)
     * @returns {boolean} - True if loading state was applied
     * 
     * @example
     * LoadingManager.show('#submit-btn');
     * LoadingManager.show(buttonElement, 'Processing...');
     */
    static show(button, loadingText = null) {
      const btn = typeof button === 'string' ? Common.$(button) : button;
      
      if (!btn) {
        console.warn('LoadingManager.show: Button not found');
        return false;
      }

      // Store original state if not already stored
      if (!btn.dataset.originalContent) {
        btn.dataset.originalContent = btn.innerHTML;
        btn.dataset.originalDisabled = btn.disabled;
      }

      // Create loading spinner HTML
      const spinnerHTML = '<span class="loading-spinner" aria-hidden="true"></span>';
      const text = loadingText || btn.dataset.originalContent;

      // Update button content
      btn.innerHTML = `${spinnerHTML} ${text}`;
      
      // Disable button and update ARIA
      btn.disabled = true;
      Common.setAttr(btn, 'aria-busy', 'true');
      Common.addClass(btn, 'is-loading');

      return true;
    }

    /**
     * Hide loading state and restore button
     * @param {HTMLButtonElement|string} button - Button element or selector
     * @returns {boolean} - True if loading state was removed
     * 
     * @example
     * LoadingManager.hide('#submit-btn');
     * LoadingManager.hide(buttonElement);
     */
    static hide(button) {
      const btn = typeof button === 'string' ? Common.$(button) : button;
      
      if (!btn) {
        console.warn('LoadingManager.hide: Button not found');
        return false;
      }

      // Restore original content
      if (btn.dataset.originalContent) {
        btn.innerHTML = btn.dataset.originalContent;
        
        // Restore original disabled state
        btn.disabled = btn.dataset.originalDisabled === 'true';
        
        // Clean up stored data
        delete btn.dataset.originalContent;
        delete btn.dataset.originalDisabled;
      }

      // Remove loading attributes
      Common.removeAttr(btn, 'aria-busy');
      Common.removeClass(btn, 'is-loading');

      return true;
    }

    /**
     * Toggle loading state on a button
     * @param {HTMLButtonElement|string} button - Button element or selector
     * @param {boolean} isLoading - Whether to show or hide loading state
     * @param {string} loadingText - Optional text to show while loading
     * @returns {boolean} - True if state was changed
     * 
     * @example
     * LoadingManager.toggle('#submit-btn', true, 'Submitting...');
     * LoadingManager.toggle(buttonElement, false);
     */
    static toggle(button, isLoading, loadingText = null) {
      if (isLoading) {
        return LoadingManager.show(button, loadingText);
      } else {
        return LoadingManager.hide(button);
      }
    }
  }

  // Export to window
  window.LoadingManager = LoadingManager;

})();
