/**
 * Form Validation Module
 * Provides real-time form validation with accessibility support
 * @requires common.js
 */

(function() {
  'use strict';

  /**
   * FormValidator class for managing form validation
   */
  class FormValidator {
    /**
     * Initialize form validator
     * @param {HTMLFormElement} form - The form element to validate
     */
    constructor(form) {
      if (!form) {
        console.warn('FormValidator: Form element is required');
        return;
      }

      this.form = form;
      this.inputs = Common.$$('input, textarea, select', form);
      this.init();
    }

    /**
     * Initialize event listeners
     */
    init() {
      // Validate on input (debounced for performance)
      this.inputs.forEach(input => {
        const debouncedValidate = Common.debounce(() => {
          this.validateField(input);
        }, 300);

        Common.on(input, 'input', debouncedValidate);
        
        // Also validate on blur for immediate feedback
        Common.on(input, 'blur', () => {
          this.validateField(input);
        });
      });

      // Validate entire form on submit
      Common.on(this.form, 'submit', (e) => {
        if (!this.validateForm()) {
          e.preventDefault();
          this.focusFirstError();
        }
      });
    }

    /**
     * Validate a single field
     * @param {HTMLInputElement} field - The field to validate
     * @returns {boolean} - True if valid, false otherwise
     */
    validateField(field) {
      const value = field.value.trim();
      const type = field.type;
      const required = field.hasAttribute('required');
      let isValid = true;
      let errorMessage = '';

      // Check required fields
      if (required && !value) {
        isValid = false;
        errorMessage = 'This field is required';
      }
      // Email validation
      else if (type === 'email' && value) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
          isValid = false;
          errorMessage = 'Please enter a valid email address';
        }
      }
      // URL validation
      else if (type === 'url' && value) {
        try {
          new URL(value);
        } catch {
          isValid = false;
          errorMessage = 'Please enter a valid URL';
        }
      }
      // Pattern validation
      else if (field.hasAttribute('pattern') && value) {
        const pattern = new RegExp(field.getAttribute('pattern'));
        if (!pattern.test(value)) {
          isValid = false;
          errorMessage = field.getAttribute('title') || 'Please match the requested format';
        }
      }
      // Min length validation
      else if (field.hasAttribute('minlength') && value) {
        const minLength = parseInt(field.getAttribute('minlength'));
        if (value.length < minLength) {
          isValid = false;
          errorMessage = `Please enter at least ${minLength} characters`;
        }
      }
      // Max length validation
      else if (field.hasAttribute('maxlength') && value) {
        const maxLength = parseInt(field.getAttribute('maxlength'));
        if (value.length > maxLength) {
          isValid = false;
          errorMessage = `Please enter no more than ${maxLength} characters`;
        }
      }

      // Update field state
      if (isValid) {
        this.clearFieldError(field);
      } else {
        this.setFieldError(field, errorMessage);
      }

      return isValid;
    }

    /**
     * Validate entire form
     * @returns {boolean} - True if all fields are valid, false otherwise
     */
    validateForm() {
      let isValid = true;

      this.inputs.forEach(input => {
        if (!this.validateField(input)) {
          isValid = false;
        }
      });

      return isValid;
    }

    /**
     * Set error state on a field
     * @param {HTMLInputElement} field - The field with error
     * @param {string} message - The error message
     */
    setFieldError(field, message) {
      const formGroup = field.closest('.form-group');
      if (!formGroup) return;

      // Add error classes
      Common.addClass(field, 'is-invalid');
      Common.removeClass(field, 'is-valid');
      Common.setAttr(field, 'aria-invalid', 'true');

      // Get or create error message element
      let errorElement = formGroup.querySelector('.form-error');
      if (!errorElement) {
        errorElement = document.createElement('div');
        errorElement.className = 'form-error';
        errorElement.id = `${field.id || field.name}-error`;
        formGroup.appendChild(errorElement);
      }

      // Set error message
      errorElement.textContent = message;
      errorElement.style.display = 'block';

      // Associate error with input
      Common.setAttr(field, 'aria-describedby', errorElement.id);
    }

    /**
     * Clear error state from a field
     * @param {HTMLInputElement} field - The field to clear
     */
    clearFieldError(field) {
      const formGroup = field.closest('.form-group');
      if (!formGroup) return;

      // Remove error classes
      Common.removeClass(field, 'is-invalid');
      
      // Add valid class if field has value
      if (field.value.trim()) {
        Common.addClass(field, 'is-valid');
      } else {
        Common.removeClass(field, 'is-valid');
      }
      
      Common.setAttr(field, 'aria-invalid', 'false');

      // Hide error message
      const errorElement = formGroup.querySelector('.form-error');
      if (errorElement) {
        errorElement.style.display = 'none';
        errorElement.textContent = '';
      }

      // Remove aria-describedby if no error
      Common.removeAttr(field, 'aria-describedby');
    }

    /**
     * Focus the first field with an error
     */
    focusFirstError() {
      const firstError = Common.$('.is-invalid', this.form);
      if (firstError) {
        firstError.focus();
        
        // Scroll to error if needed
        const rect = firstError.getBoundingClientRect();
        if (rect.top < 0 || rect.bottom > window.innerHeight) {
          firstError.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }
    }
  }

  // Auto-initialize forms with data-validate attribute
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initValidation);
  } else {
    initValidation();
  }

  function initValidation() {
    const forms = Common.$$('[data-validate]');
    forms.forEach(form => {
      new FormValidator(form);
    });
  }

  // Export for manual initialization
  window.FormValidator = FormValidator;

})();
