/**
 * File name: ui.js
 * Author: Alex Biddle
 *
 * Description:
 *      This file provides funcitons for the user interface of 
 *      the client code that handles error, sucess or informative
 *      pop up messages
 */


import { ERROR_CODES, RESPONSE_STATUSES } from "https://pascal/capstone/html/src/constants.js";



/**
 * Safely show a status message in a DOM element identified by ID.
 *
 * @param {string} elementId - ID of the DOM element that will display the message.
 * @param {string} message - The message text to display.
 * @param {string} type - "error" | "success" | "info".
 * @returns {void}
 */
export function showStatusMessage(elementId, message, type = "info") {

    // Look up the target element by ID.
    const element = document.getElementById(elementId);

    // If the element is not found, there is nothing to do.
    if (!element) {
        return;
    }

    // Remove any previous status classes.
    element.classList.remove("status-error", "status-success", "status-info");

    // Error message
    if (type === "error") {
        element.classList.add("status-error");
        alert(message);

    // Success message
    } else if (type === "success") {
        element.classList.add("status-success");

    // Satus message
    } else {
        element.classList.add("status-info");
    }

    // Use safeSetText to avoid interpreting any HTML in the message.
    element.textContent = message;
}



/**
 * Clear a status message in a DOM element identified by ID.
 *
 * @param {string} elementId - ID of the DOM element that will be cleared.
 * @returns {void}
 */
export function clearStatusMessage(elementId) {

    // Look up the target element.
    const element = document.getElementById(elementId);

    // If not found, there is nothing to clear.
    if (!element) {
        return;
    }

    // Clear status-related classes.
    element.classList.remove("status-error", "status-success", "status-info");

    // Clear any existing text content.
    element.textContent = "";
}



/**
 * Simple navigation helper to move between HTML pages.
 *
 * @param {string} relativePath - e.g., "vault.html" or "index.html".
 * @returns {void}
 */
export function navigateTo(relativePath) {
    try {

        // Otherwise use full Pascal path
        window.location.href = `https://pascal/capstone/html/${relativePath}`;

    } catch (err) {
        console.error("navigateTo failed:", err);
        alert("Navigation error: " + err.message);
    }
}


/**
 * Show an error alert based on error code or response status
 * 
 * @param {string} errorCode - Error code from ERROR_CODES or response status
 * @param {string} context - Additional context (e.g., "login", "signup", "vault")
 * @returns {void}
 */
export function showErrorAlert(errorCode, context = "") {
    let message = "";

    switch (errorCode) {
        // Authentication & User Errors
        case ERROR_CODES.AUTH_FAILED:
        case RESPONSE_STATUSES.AUTHENTICATION_FAILED:
            message = "Invalid username or password.";
            break;

        case ERROR_CODES.INVALID_USERNAME:
            message = "Invalid username.";
            break;

        case ERROR_CODES.INVALID_ACCOUNT:
        case RESPONSE_STATUSES.INVALID_ACCOUNT:
            message = "Account not found.";
            break;

        case ERROR_CODES.USER_EXISTS:
        case RESPONSE_STATUSES.USER_ACCOUNT_EXISTS:
            message = "Username already exists.";
            break;

        // Input Validation Errors
        case ERROR_CODES.INVALID_LENGTH:
            message = "Password must meet minimum requirements.";
            break;

        case ERROR_CODES.MISSING_FIELDS:
            message = "All fields are required.";
            break;

        case ERROR_CODES.INVALID_TYPE:
            message = "Invalid input.";
            break;

        case ERROR_CODES.MALFORMED_JSON:
            message = "Invalid data format.";
            break;

        case ERROR_CODES.UNKNOWN_FIELDS:
            message = "Unknown fields detected.";
            break;

        // Session & Security Errors
        case ERROR_CODES.SESSION_EXPIRED:
            message = "Session expired. Please log in again.";
            break;

        case ERROR_CODES.SESSION_NOT_FOUND:
            message = "Session not found. Please log in.";
            break;

        case ERROR_CODES.INVALID_TIMESTAMP:
            message = "Invalid timestamp.";
            break;

        case ERROR_CODES.REPLAY_DETECTED:
            message = "Security error detected.";
            break;

        // Cryptographic Errors
        case ERROR_CODES.INVALID_CHECKSUM:
        case RESPONSE_STATUSES.INVALID_CHECKSUM:
        case ERROR_CODES.SECURE_REQUEST_CHECKSUM_ERROR:
            message = "Data integrity check failed.";
            break;

        case ERROR_CODES.SECURE_REQUEST_DECRYPTION_ERROR:
            message = "Decryption failed.";
            break;

        case ERROR_CODES.SECURE_REQUEST_NONCE_ERROR:
            message = "Security error.";
            break;

        // Protocol & Request Errors
        case ERROR_CODES.INVALID_PROTOCOL:
            message = "Protocol version mismatch. Please refresh.";
            break;

        case ERROR_CODES.INVALID_REQUEST:
        case ERROR_CODES.INVALID_REQUEST_TYPE:
            message = "Invalid request.";
            break;

        case ERROR_CODES.INVALID_PACKET_STRUCTURE:
            message = "Invalid packet structure.";
            break;

        case ERROR_CODES.INVALID_RESPONSE_STATUS:
            message = "Invalid server response.";
            break;

        case ERROR_CODES.INVALID_CONTENT_TYPE:
            message = "Invalid content type.";
            break;

        // Session-Specific Errors
        case ERROR_CODES.SECURE_REQUEST_SESSION_ERROR:
            message = "Session error. Please log in again.";
            break;

        case ERROR_CODES.SECURE_REQUEST_USERNAME_MISMATCH:
            message = "Username mismatch. Please log in again.";
            break;

        // Server Errors
        case ERROR_CODES.NOT_FOUND:
            message = "Resource not found.";
            break;

        case ERROR_CODES.RATE_LIMITED:
            message = "Too many requests. Please wait.";
            break;

        case RESPONSE_STATUSES.FAILURE:
            message = "Operation failed.";
            break;

        // Default
        default:
            message = `Error: ${errorCode}`;
            break;
    }

    // Add context if provided
    if (context) {
        message = `[${context.toUpperCase()}] ${message}`;
    }

    // Display the alert
    alert(message);
}



/**
 * Validate form inputs and show appropriate alerts
 * 
 * @param {string} username - Username input
 * @param {string} password - Password input
 * @param {string} context - Context ("login" or "signup")
 * @returns {boolean} - True if validation passes, false otherwise
 */
export function validateAndAlert(username, password, context = "login") {
    
    // Check for empty username
    if (!username || username.trim() === "") {
        alert("Username is required.");
        return false;
    }

    // Check for empty password
    if (!password || password.trim() === "") {
        alert("Password is required.");
        return false;
    }

    // Check password length (minimum 8 characters for signup)
    if (context === "signup" && password.length < 8) {
        alert("Password must be at least 8 characters.");
        return false;
    }

    // Check username length (reasonable limits)
    if (username.length < 3) {
        alert("Username must be at least 3 characters.");
        return false;
    }

    if (username.length > 50) {
        alert("Username must be less than 50 characters.");
        return false;
    }

    // Check for invalid characters in username
    // letters, numbers, underscore, period, @ sign, hyphen
    const usernameRegex = /^[a-zA-Z0-9_.@-]+$/;
    if (!usernameRegex.test(username)) {
        alert("Username can only contain letters, numbers, underscores, periods, at signs and hyphens.");
        return false;
    }

    return true;
}

export function initializePasswordToggles() {

    const buttons = document.querySelectorAll("button.password-toggle[data-toggle-password]");

    buttons.forEach((btn) => {

        btn.addEventListener("click", () => {

            const selector = btn.getAttribute("data-toggle-password");
            if (!selector) return;

            const input = document.querySelector(selector);
            if (!input) return;

            const isHidden = (input.getAttribute("type") === "password");
            input.setAttribute("type", isHidden ? "text" : "password");

            btn.setAttribute("aria-pressed", isHidden ? "true" : "false");
            btn.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
        });
    });
}

// Auto-run on any page that imports ui.js (safe no-op if no toggles exist)
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
        initializePasswordToggles();
    });
} else {
    initializePasswordToggles();
}
