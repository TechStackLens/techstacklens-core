/**
 * TechStackLens - Main JavaScript
 * 
 * This file contains common JavaScript functions used across the application.
 */

// Initialize Bootstrap tooltips and popovers when the document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Add active class to current page in navbar
    highlightCurrentPage();
    
    // Initialize any collapsible elements
    initializeCollapsibles();
});

/**
 * Highlights the current page in the navigation menu
 */
function highlightCurrentPage() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    
    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPath || 
            (href !== '/' && currentPath.startsWith(href))) {
            link.classList.add('active');
        }
    });
}

/**
 * Initializes collapsible elements
 */
function initializeCollapsibles() {
    const collapsibles = document.querySelectorAll('.collapse-toggle');
    
    collapsibles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const target = document.querySelector(this.getAttribute('data-target'));
            if (target) {
                target.classList.toggle('show');
                
                // Toggle icon if present
                const icon = this.querySelector('i.fa-chevron-down, i.fa-chevron-up');
                if (icon) {
                    icon.classList.toggle('fa-chevron-down');
                    icon.classList.toggle('fa-chevron-up');
                }
            }
        });
    });
}

/**
 * Shows a confirmation dialog
 * @param {string} message - The message to display
 * @param {function} confirmCallback - Function to call if confirmed
 */
function confirmAction(message, confirmCallback) {
    if (confirm(message)) {
        confirmCallback();
    }
}

/**
 * Formats timestamps in human-readable format
 * @param {string} timestamp - ISO timestamp string
 * @returns {string} Formatted date/time
 */
function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch (e) {
        console.error('Error formatting timestamp:', e);
        return timestamp;
    }
}

/**
 * Handles form submission with confirmation
 * @param {HTMLFormElement} form - The form element
 * @param {string} confirmMessage - Confirmation message
 */
function submitWithConfirmation(form, confirmMessage) {
    form.addEventListener('submit', function(event) {
        event.preventDefault();
        
        confirmAction(confirmMessage, function() {
            form.submit();
        });
    });
}

/**
 * Shows an alert message that auto-dismisses
 * @param {string} message - Message to display
 * @param {string} type - Alert type (success, danger, warning, info)
 * @param {number} duration - Duration in milliseconds
 */
function showAlert(message, type = 'info', duration = 3000) {
    // Create alert element
    const alertEl = document.createElement('div');
    alertEl.className = `alert alert-${type} alert-dismissible fade show`;
    alertEl.setAttribute('role', 'alert');
    
    // Add message
    alertEl.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    // Add to document
    const container = document.querySelector('.container');
    container.insertBefore(alertEl, container.firstChild);
    
    // Auto-dismiss after duration
    if (duration > 0) {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alertEl);
            bsAlert.close();
        }, duration);
    }
}

/**
 * Copies text to clipboard
 * @param {string} text - Text to copy
 * @param {function} callback - Optional callback after copying
 */
function copyToClipboard(text, callback) {
    navigator.clipboard.writeText(text)
        .then(() => {
            if (callback) callback(true);
        })
        .catch(err => {
            console.error('Failed to copy text: ', err);
            if (callback) callback(false, err);
        });
}
