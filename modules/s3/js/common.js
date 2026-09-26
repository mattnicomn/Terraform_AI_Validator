/**
 * Common Utility Module
 * 
 * Provides common utility functions used across the US Mission Hero website.
 * Includes DOM manipulation helpers, event handling, and debounce utility.
 * 
 * @module common
 */

// ============================================================================
// DOM Selector Functions
// ============================================================================

/**
 * Select a single element from the DOM
 * Shorthand for document.querySelector
 * 
 * @param {string} selector - CSS selector string
 * @returns {Element|null} The first matching element or null if not found
 * 
 * @example
 * const header = $('.site-header');
 * const button = $('#submit-btn');
 */
const $ = (selector) => document.querySelector(selector);

/**
 * Select multiple elements from the DOM
 * Shorthand for document.querySelectorAll, returns an array
 * 
 * @param {string} selector - CSS selector string
 * @returns {Array<Element>} Array of matching elements (empty array if none found)
 * 
 * @example
 * const links = $$('.nav-link');
 * const inputs = $$('input[required]');
 */
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

// ============================================================================
// Event Listener Helpers
// ============================================================================

/**
 * Add an event listener to an element
 * Safely handles null/undefined elements
 * 
 * @param {Element|null} element - The element to attach the listener to
 * @param {string} event - The event type (e.g., 'click', 'input')
 * @param {Function} handler - The event handler function
 * 
 * @example
 * const button = $('#submit-btn');
 * on(button, 'click', () => console.log('Clicked!'));
 */
const on = (element, event, handler) => element?.addEventListener(event, handler);

/**
 * Remove an event listener from an element
 * Safely handles null/undefined elements
 * 
 * @param {Element|null} element - The element to remove the listener from
 * @param {string} event - The event type (e.g., 'click', 'input')
 * @param {Function} handler - The event handler function to remove
 * 
 * @example
 * const button = $('#submit-btn');
 * const handleClick = () => console.log('Clicked!');
 * on(button, 'click', handleClick);
 * off(button, 'click', handleClick);
 */
const off = (element, event, handler) => element?.removeEventListener(event, handler);

// ============================================================================
// Class Manipulation Helpers
// ============================================================================

/**
 * Add a class to an element
 * Safely handles null/undefined elements
 * 
 * @param {Element|null} element - The element to add the class to
 * @param {string} className - The class name to add
 * 
 * @example
 * const menu = $('.nav-menu');
 * addClass(menu, 'is-open');
 */
const addClass = (element, className) => element?.classList.add(className);

/**
 * Remove a class from an element
 * Safely handles null/undefined elements
 * 
 * @param {Element|null} element - The element to remove the class from
 * @param {string} className - The class name to remove
 * 
 * @example
 * const menu = $('.nav-menu');
 * removeClass(menu, 'is-open');
 */
const removeClass = (element, className) => element?.classList.remove(className);

/**
 * Toggle a class on an element
 * Safely handles null/undefined elements
 * 
 * @param {Element|null} element - The element to toggle the class on
 * @param {string} className - The class name to toggle
 * @returns {boolean|undefined} True if class was added, false if removed, undefined if element is null
 * 
 * @example
 * const menu = $('.nav-menu');
 * toggleClass(menu, 'is-open');
 */
const toggleClass = (element, className) => element?.classList.toggle(className);

/**
 * Check if an element has a class
 * Safely handles null/undefined elements
 * 
 * @param {Element|null} element - The element to check
 * @param {string} className - The class name to check for
 * @returns {boolean} True if element has the class, false otherwise
 * 
 * @example
 * const menu = $('.nav-menu');
 * if (hasClass(menu, 'is-open')) {
 *   console.log('Menu is open');
 * }
 */
const hasClass = (element, className) => element?.classList.contains(className) || false;

// ============================================================================
// Attribute Helpers
// ============================================================================

/**
 * Set an attribute on an element
 * Safely handles null/undefined elements
 * 
 * @param {Element|null} element - The element to set the attribute on
 * @param {string} name - The attribute name
 * @param {string} value - The attribute value
 * 
 * @example
 * const button = $('#menu-toggle');
 * setAttr(button, 'aria-expanded', 'true');
 */
const setAttr = (element, name, value) => element?.setAttribute(name, value);

/**
 * Get an attribute value from an element
 * Safely handles null/undefined elements
 * 
 * @param {Element|null} element - The element to get the attribute from
 * @param {string} name - The attribute name
 * @returns {string|null} The attribute value or null if not found
 * 
 * @example
 * const button = $('#menu-toggle');
 * const expanded = getAttr(button, 'aria-expanded');
 */
const getAttr = (element, name) => element?.getAttribute(name);

/**
 * Remove an attribute from an element
 * Safely handles null/undefined elements
 * 
 * @param {Element|null} element - The element to remove the attribute from
 * @param {string} name - The attribute name to remove
 * 
 * @example
 * const input = $('#email');
 * removeAttr(input, 'disabled');
 */
const removeAttr = (element, name) => element?.removeAttribute(name);

// ============================================================================
// Debounce Utility
// ============================================================================

/**
 * Create a debounced function that delays execution until after a specified delay
 * Useful for input validation, search, and resize handlers to avoid excessive calls
 * 
 * @param {Function} func - The function to debounce
 * @param {number} [delay=300] - The delay in milliseconds (default: 300ms)
 * @returns {Function} The debounced function
 * 
 * @example
 * // Debounce input validation
 * const validateEmail = (value) => {
 *   console.log('Validating:', value);
 * };
 * 
 * const debouncedValidate = debounce(validateEmail, 500);
 * 
 * const input = $('#email');
 * on(input, 'input', (e) => debouncedValidate(e.target.value));
 * 
 * @example
 * // Debounce window resize handler
 * const handleResize = () => {
 *   console.log('Window resized:', window.innerWidth);
 * };
 * 
 * on(window, 'resize', debounce(handleResize, 250));
 */
const debounce = (func, delay = 300) => {
  let timeoutId;
  return function(...args) {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func.apply(this, args), delay);
  };
};

// ============================================================================
// Exports
// ============================================================================

// Export functions for use in other modules
// If using ES6 modules, uncomment the following:
// export { $, $$, on, off, addClass, removeClass, toggleClass, hasClass, setAttr, getAttr, removeAttr, debounce };

// For browser global usage (attach to window object)
if (typeof window !== 'undefined') {
  window.Common = {
    $,
    $$,
    on,
    off,
    addClass,
    removeClass,
    toggleClass,
    hasClass,
    setAttr,
    getAttr,
    removeAttr,
    debounce
  };
}
