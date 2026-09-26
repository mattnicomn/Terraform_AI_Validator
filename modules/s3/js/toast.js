/**
 * Toast Notification Module
 * Displays temporary notification messages with different types
 * @requires common.js
 */

(function() {
  'use strict';

  /**
   * Toast class for displaying notification messages
   */
  class Toast {
    /**
     * Show a toast notification
     * @param {string} message - The message to display
     * @param {string} type - Toast type: 'success', 'error', 'warning', 'info' (default: 'info')
     * @param {number} duration - Duration in milliseconds (default: 5000, 0 = no auto-dismiss)
     * @returns {HTMLElement} - The toast element
     * 
     * @example
     * Toast.show('Operation completed successfully', 'success');
     * Toast.show('An error occurred', 'error', 0); // No auto-dismiss
     */
    static show(message, type = 'info', duration = 5000) {
      // Validate type
      const validTypes = ['success', 'error', 'warning', 'info'];
      if (!validTypes.includes(type)) {
        console.warn(`Toast.show: Invalid type "${type}". Using "info" instead.`);
        type = 'info';
      }

      // Get or create toast container
      let container = Common.$('.toast-container');
      if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        container.setAttribute('aria-live', 'polite');
        container.setAttribute('aria-atomic', 'true');
        document.body.appendChild(container);
      }

      // Create toast element
      const toast = document.createElement('div');
      toast.className = `toast toast-${type}`;
      toast.setAttribute('role', 'alert');
      
      // Get icon for toast type
      const icon = Toast.getIcon(type);
      
      // Create toast HTML
      toast.innerHTML = `
        <div class="toast-icon" aria-hidden="true">${icon}</div>
        <div class="toast-message">${message}</div>
        <button class="toast-close" aria-label="Close notification">
          <span aria-hidden="true">&times;</span>
        </button>
      `;

      // Add to container
      container.appendChild(toast);

      // Trigger animation
      setTimeout(() => {
        Common.addClass(toast, 'toast-show');
      }, 10);

      // Setup close button
      const closeBtn = toast.querySelector('.toast-close');
      Common.on(closeBtn, 'click', () => {
        Toast.hide(toast);
      });

      // Auto-dismiss if duration is set
      if (duration > 0) {
        setTimeout(() => {
          Toast.hide(toast);
        }, duration);
      }

      return toast;
    }

    /**
     * Hide a toast notification
     * @param {HTMLElement} toast - The toast element to hide
     * 
     * @example
     * const toast = Toast.show('Message');
     * Toast.hide(toast);
     */
    static hide(toast) {
      if (!toast) return;

      // Remove show class to trigger exit animation
      Common.removeClass(toast, 'toast-show');

      // Remove from DOM after animation
      setTimeout(() => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }

        // Remove container if empty
        const container = Common.$('.toast-container');
        if (container && container.children.length === 0) {
          container.parentNode.removeChild(container);
        }
      }, 300); // Match CSS transition duration
    }

    /**
     * Get icon HTML for toast type
     * @param {string} type - Toast type
     * @returns {string} - Icon HTML
     */
    static getIcon(type) {
      const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
      };
      return icons[type] || icons.info;
    }

    /**
     * Show success toast
     * @param {string} message - The message to display
     * @param {number} duration - Duration in milliseconds (default: 5000)
     * @returns {HTMLElement} - The toast element
     * 
     * @example
     * Toast.success('Changes saved successfully');
     */
    static success(message, duration = 5000) {
      return Toast.show(message, 'success', duration);
    }

    /**
     * Show error toast
     * @param {string} message - The message to display
     * @param {number} duration - Duration in milliseconds (default: 5000)
     * @returns {HTMLElement} - The toast element
     * 
     * @example
     * Toast.error('Failed to save changes');
     */
    static error(message, duration = 5000) {
      return Toast.show(message, 'error', duration);
    }

    /**
     * Show warning toast
     * @param {string} message - The message to display
     * @param {number} duration - Duration in milliseconds (default: 5000)
     * @returns {HTMLElement} - The toast element
     * 
     * @example
     * Toast.warning('Please review your input');
     */
    static warning(message, duration = 5000) {
      return Toast.show(message, 'warning', duration);
    }

    /**
     * Show info toast
     * @param {string} message - The message to display
     * @param {number} duration - Duration in milliseconds (default: 5000)
     * @returns {HTMLElement} - The toast element
     * 
     * @example
     * Toast.info('Processing your request...');
     */
    static info(message, duration = 5000) {
      return Toast.show(message, 'info', duration);
    }
  }

  // Export to window
  window.Toast = Toast;

})();
