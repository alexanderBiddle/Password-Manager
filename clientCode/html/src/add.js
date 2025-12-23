/**
 * File name: add.js
 * Author: Alex Biddle
 *
 * Description:
 *      Page module for add.html. Contains all the javascript to handle
 *      the add.html services for adding a new entry account
 */

import { showStatusMessage, clearStatusMessage, navigateTo, showErrorAlert } from "https://pascal/capstone/html/src/ui.js";
import { sanitizePassword } from "https://pascal/capstone/html/src/sanitization.js";
import { REQUEST_TYPES, RESPONSE_STATUSES } from "https://pascal/capstone/html/src/constants.js";
import { encryptVaultField } from "https://pascal/capstone/html/src/encryption/vault_encryption.js";
import { buildClientSecureRequestPacket } from "https://pascal/capstone/html/src/handshake/client_secure_request.js";
import { runServerSecureResponse } from "https://pascal/capstone/html/src/handshake/server_secure_response.js";
import { fourWaySessionState } from "https://pascal/capstone/html/src/handshake/session_state.js";
import { ensureSecureSessionOrRedirect, requireVaultKeyBytes, sanitizeWebsite, sanitizeAccountField, handleLogout} from "https://pascal/capstone/html/src/vault_api.js";


/**
 * Generates a cryptographically secure random password using the Web Crypto API.
 * Ensures the password contains at least one uppercase letter, one lowercase
 * letter, one digit, and one symbol. 
 *
 * @param {number} length - Desired password length (minimum enforced is 12)
 * @ensures Returns password random password with uppercase, lowercase, numeric, and symbolic characters
 * @returns {string} - Securely generated password
 */
export function generateSecurePassword(length = 20) {

    // Validate the requested password length
    if (typeof length !== "number" || length < 12) {
        length = 20;
    }

     // Define allowed characters
    const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER = "abcdefghijklmnopqrstuvwxyz";
    const DIGITS = "0123456789";
    const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?";

    // Combined character pool
    const ALL = UPPER + LOWER + DIGITS + SYMBOLS;

    // Create a unit8 array
    const bytes = new Uint8Array(length);

    // Fill the byte array with random values
    crypto.getRandomValues(bytes);

    // Array to build the password characters
    const chars = [];

    // Ensure that at least one character from each required group is used
    chars.push(UPPER[bytes[0] % UPPER.length]);
    chars.push(LOWER[bytes[1] % LOWER.length]);
    chars.push(DIGITS[bytes[2] % DIGITS.length]);
    chars.push(SYMBOLS[bytes[3] % SYMBOLS.length]);

    // Fill remaining characters from the full character pool
    for (let i = 4; i < length; i++) {
        const idx = bytes[i] % ALL.length;
        chars.push(ALL[idx]);
    }

    // Use the fisher–Yates shuffle to remove positional bias
    for (let i = chars.length - 1; i > 0; i--) {
        const j = bytes[i % bytes.length] % (i + 1);
        const tmp = chars[i];
        chars[i] = chars[j];
        chars[j] = tmp;
    }

    // Join characters into a single password string
    const password = chars.join("");

    // Create another password if the current 9containing whitespace
    if (/\s/.test(password)) {
        return generateSecurePassword(length);
    }

    return password;
}



/**
 * Handles submission of the "Add Account" vault form.
 * Performs session validation, input sanitization, client-side encryption,
 * packet construction, and secure communication with the server via the
 * Four-Way Handshake protocol.
 *
 * @param {Event} event - Form submission event
 * @ensures Vault fields are sanitized and encrypted
 * @returns {Promise<void>}
 */
export async function handleAddFormSubmit(event) {

    // Prevent default browser form submission behavior
    event.preventDefault();

    // Ensure the client has an active secure session
    if (!(await ensureSecureSessionOrRedirect())) {
        return;
    }

    // Clear any previous status messages
    clearStatusMessage("add-status");

    // Retrieve the in-memory vault key (must exist)
    const vaultKeyBytes = requireVaultKeyBytes("add-status");
    if (!vaultKeyBytes) {
        return;
    }

    // Lookup required form input elements
    const siteInput = document.getElementById("site");
    const usernameInput = document.getElementById("username-entry");
    const emailInput = document.getElementById("email-entry");
    const passwordInput = document.getElementById("password-entry");

    // Validate form input integrity
    if (!siteInput || !usernameInput || !emailInput || !passwordInput) {
        showStatusMessage("add-status", "Add form is not filled.", "error");
        return;
    }

    // Extract raw user input values
    const rawWebsite = siteInput.value || "";
    const rawAccountUsername = usernameInput.value || "";
    const rawAccountEmail = emailInput.value || "";
    const rawPassword = passwordInput.value || "";

    try {

        // Sanitize user inputs to prevent injection and malformed data
        const website = sanitizeWebsite(rawWebsite);
        const accountUsername = sanitizeAccountField(rawAccountUsername, "account_username");
        const accountEmail = sanitizeAccountField(rawAccountEmail.length ? rawAccountEmail : accountUsername, "account_email");
        const accountPassword = sanitizePassword(rawPassword);

        // Encrypt all vault fields using the derived vault key
        const websiteCt = await encryptVaultField(website, vaultKeyBytes);
        const accountUsernameCt = await encryptVaultField(accountUsername, vaultKeyBytes);
        const accountEmailCt = await encryptVaultField(accountEmail, vaultKeyBytes);
        const accountPasswordCt = await encryptVaultField(accountPassword, vaultKeyBytes);

        // Construct encrypted vault payload
        const payload = {
            website: websiteCt,
            account_username: accountUsernameCt,
            account_email: accountEmailCt,
            account_password: accountPasswordCt
        };

        // Build a secure Four-Way Handshake request packet
        const requestPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.VAULT_ADD_ACCOUNT, payload, fourWaySessionState);

        // Send the request and await secure server response
        const secureResult = await runServerSecureResponse(requestPacket, fourWaySessionState);

        // Handle errors
        if (secureResult && typeof secureResult === "object" && "ok" in secureResult) {
            if (!secureResult.ok) {
                const statusCode = secureResult.status ?? "unknown";
                showStatusMessage("add-status", `Failed to add account (HTTP ${statusCode}).`, "error");
                return;
            }
        }

        // Handle server-initiated logout
        if (secureResult && secureResult.kind === "logout") {
            showStatusMessage("add-status", "Session was closed by the server.", "error");
            navigateTo("index.html");
            return;
        }

        // Parse the response fields
        const { responseStatus, payload: responsePayload } = secureResult || {};

        // Check for protocol-level failure
        if (responseStatus !== RESPONSE_STATUSES.SUCCESS) {
            if (responsePayload && typeof responsePayload.application_code === "string") {
                showErrorAlert(responsePayload.application_code, "vault");
            }

            // Display server-provided message
            const msg = (responsePayload && typeof responsePayload.message === "string")? responsePayload.message: "Server reported an error adding account.";
            showStatusMessage("add-status", msg, "error");
            return;
        }

        // Indicate success and redirect to vault page
        showStatusMessage("add-status", "Account added successfully. Redirecting to vault...", "success");
        navigateTo("vault.html");

    } catch (err) {
        console.error("handleAddFormSubmit error:", err);
        showStatusMessage("add-status", "Unexpected error adding account.", "error");
    }
}



/**
 * Initializes all event listeners and UI hooks for add.html.
 * Binds logout, form submission, and password generation behavior.
 *
 * @ensures All required UI controls are wired correctly
 * @returns {Promise<void>}
 */
export async function initializeAddPage() {

    // Bind logout button behavior
    const btnLogout = document.getElementById("btn-logout");
    if (btnLogout) {
        btnLogout.addEventListener("click", () => {
            void handleLogout();
        });
    }

    // Bind add-account form submission
    const addForm = document.getElementById("add-form");
    if (addForm) {
        addForm.addEventListener("submit", (event) => {
            void handleAddFormSubmit(event);
        });
    }

    // Bind password generation button
    const btnGenerate = document.getElementById("generate-password");
    if (btnGenerate) {

        btnGenerate.addEventListener("click", () => {
            
            // Generate a strong password
            const newPassword = generateSecurePassword(20);

            // Populate password field
            const passwordInput = document.getElementById("password-entry");
            if (passwordInput) {
                passwordInput.value = newPassword;
            }

            showStatusMessage("add-status", "Strong password generated!", "success");
        });
    }
}



/**
 * Ensures the add page logic only runs when the expected DOM
 * structure is present.
 */
document.addEventListener("DOMContentLoaded", () => {
    try {
        if (document.getElementById("add-form")) {
            void initializeAddPage();
        }
    } catch (e) {
        console.error("add.js DOMContentLoaded error:", e);
    }
});
