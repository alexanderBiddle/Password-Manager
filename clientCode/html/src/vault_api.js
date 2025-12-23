/**
 * File name: vault_api.js
 * Author: Alex Biddle
 *
 * Description:
 *      Shared security-guard and vault helper for the other javascript files
 */

import { showStatusMessage, navigateTo } from "https://pascal/capstone/html/src/ui.js";
import { sanitizeSafeTextField } from "https://pascal/capstone/html/src/sanitization.js";
import { HANDSHAKE_STATES, AES_KEY_LENGTH_BYTES, REQUEST_TYPES } from "https://pascal/capstone/html/src/constants.js";
import { fourWaySessionState } from "https://pascal/capstone/html/src/handshake/session_state.js";
import { deriveVaultKey } from "https://pascal/capstone/html/src/encryption/vault_encryption.js";
import { buildClientSecureRequestPacket } from "https://pascal/capstone/html/src/handshake/client_secure_request.js";
import { runServerSecureResponse } from "https://pascal/capstone/html/src/handshake/server_secure_response.js";



/**
 * Checks for obvious HTML/script injection patterns.
 *
 * @param {string} value - Input string to validate
 * @param {string} label - Logical field name for error reporting
 * @ensures Throws if suspicious patterns are detected
 */
export function assertNoInjectionPatterns(value, label) {

    // Type check: must be string
    if (typeof value !== "string") {
        throw new Error(`assertNoInjectionPatterns: ${label} must be a string`);
    }

    // Disallow angle brackets to reduce risk of HTML/script injection
    if (/[<>]/.test(value)) {
        throw new Error(`assertNoInjectionPatterns: ${label} contains forbidden characters`);
    }

    // Disallow "script" keyword as very simple defense-in-depth
    if (/script/i.test(value)) {
        throw new Error(`assertNoInjectionPatterns: ${label} contains disallowed keyword`);
    }
}



/**
 * Sanitizes website input using the shared safe-text sanitizer
 * and applies a client-side length constraint.
 *
 * @param {string} rawWebsite - Raw user-provided website value
 * @returns {string} - Sanitized website string
 */
export function sanitizeWebsite(rawWebsite) {

    // Use shared safe-text sanitizer (strips dangerous chars / trims length)
    const cleaned = sanitizeSafeTextField(rawWebsite);

    // Simple length check; server performs deeper validation.
    if (cleaned.length > 256) {
        throw new Error("sanitizeWebsite: website exceeds maximum length");
    }

    return cleaned;
}



/**
 * Sanitizes account-related fields and applies 
 * additional injection pattern checks.
 *
 * @param {string} rawValue - Raw user input
 * @param {string} label - Field label for error context
 * @returns {string} - Sanitized field value
 */
export function sanitizeAccountField(rawValue, label) {

    // First apply safe-text sanitization
    const cleaned = sanitizeSafeTextField(rawValue);

    // Extra defense-in-depth label-specific assertions
    assertNoInjectionPatterns(cleaned, label);

    return cleaned;
}



/**
 * Ensures that a valid AES vault key is present in memory.
 * This is required for all vault encryption/decryption operations.
 *
 * @param {string} statusElementId - Optional DOM element ID for error display
 * @returns {Uint8Array|null} - Vault key bytes or null on failure
 */
export function requireVaultKeyBytes(statusElementId) {

    // Retrieve vault key from session state
    const vaultKeyBytes = fourWaySessionState.getVaultKeyBytes?.();

    // Validate key type and length
    if (!(vaultKeyBytes instanceof Uint8Array) || vaultKeyBytes.length !== AES_KEY_LENGTH_BYTES) {
        console.error("requireVaultKeyBytes: vault key missing or invalid in session");
        if (statusElementId) {
            showStatusMessage(statusElementId, "Vault key missing. Please log out and log in again.", "error");
        }
        return null;
    }

    return vaultKeyBytes;
}



/**
 * Restores the vault key if it is expected but not currently
 * loaded into memory.
 *
 * @ensures Vault key is derived and restored when possible
 */
export async function ensureVaultKeyReady() {

    // Check if vault key already exists
    if (fourWaySessionState.getVaultKeyBytes()) {
        return;
    }

    // Create a new vault key
    if (fourWaySessionState.isVaultKeyExpected()) {

        // Retrieve cached password
        const password = sessionStorage.getItem("cipherSafeLastPassword");
        if (!password) {throw new Error("Vault key required but password not available");}

        // Retrieve vault salt
        const vaultSaltBytes = fourWaySessionState.getVaultSaltBytes();

        if (!(vaultSaltBytes instanceof Uint8Array)) {
            throw new Error("Vault salt missing during vault restore");
        }

        // Derive vault key using Argon2id
        const vaultKeyBytes = await deriveVaultKey(password, vaultSaltBytes);

        // Restore into session state
        fourWaySessionState.restoreVaultKeyBytes(vaultKeyBytes);
    }
}



/**
 * Central security gate for all authenticated pages.
 * Verifies handshake state, TTL, AES/RSA readiness, and
 * restores wrapped session state when possible.
 *
 * @returns {Promise<boolean>} - True if session is valid, false otherwise
 */
export async function ensureSecureSessionOrRedirect() {

    // Determine if the browser believes the user is logged in
    const loggedInFlag = (typeof sessionStorage !== "undefined") && sessionStorage.getItem("cipherSafeLoggedIn") === "1";

    // Query handshake state and TTL from fourWaySessionState (defensive optional chaining).
    const handshakeState = fourWaySessionState.getHandshakeState?.();
    const isExpired = fourWaySessionState.isExpired?.() ?? true;

    // Validate that the user session is in a valid state
    if (loggedInFlag && !isExpired && handshakeState === HANDSHAKE_STATES.COMPLETE) {

        // Ensure AES manager is created 
        await fourWaySessionState.ensureAesManager();

        // Ensure RSA manager is present
        if (!fourWaySessionState.getClientRsaManager()) {

            console.error("ensureSecureSessionOrRedirect: RSA manager missing despite COMPLETE state.");

            // Clean up and redirect to login.
            if (typeof sessionStorage !== "undefined") {
                sessionStorage.removeItem("cipherSafeLoggedIn");
                sessionStorage.removeItem("cipherSafeUsername");
            }
            fourWaySessionState.resetSession();
            navigateTo("index.html");
            return false;
        }
        return true;
    }

    // Restore path if no valid in-memory session state
    if (fourWaySessionState.hasEncryptedSessionInStorage()) {
        try {
            const ok = await fourWaySessionState.restoreFromStorage();

            // Restore failed or expired session
            if (!ok || fourWaySessionState.isExpired?.()) {
                fourWaySessionState.clearEncryptedSessionInStorage();
                if (typeof sessionStorage !== "undefined") {
                    sessionStorage.removeItem("cipherSafeLoggedIn");
                    sessionStorage.removeItem("cipherSafeUsername");
                }
                fourWaySessionState.resetSession();
                navigateTo("index.html");
                return false;
            }

            // Successful restore – mark login flag just in case.
            if (typeof sessionStorage !== "undefined") {
                sessionStorage.setItem("cipherSafeLoggedIn", "1");
                if (!sessionStorage.getItem("cipherSafeUsername")) {
                    const u = fourWaySessionState.getUsername?.();
                    if (typeof u === "string" && u.length > 0) {
                        sessionStorage.setItem("cipherSafeUsername", u);
                    }
                }
            }
            return true;
        
        // Error trying to restore session
        } catch (err) {
            console.error("ensureSecureSessionOrRedirect: error restoring wrapped session:", err);
            fourWaySessionState.clearEncryptedSessionInStorage();
            if (typeof sessionStorage !== "undefined") {
                sessionStorage.removeItem("cipherSafeLoggedIn");
                sessionStorage.removeItem("cipherSafeUsername");
            }

            // Reset the session object
            fourWaySessionState.resetSession();

            // Navigate back to the login page
            navigateTo("index.html");
            return false;
        }
    }

    // No login flag and no wrapped session → standard redirect to login
    if (typeof sessionStorage !== "undefined") {
        sessionStorage.removeItem("cipherSafeLoggedIn");
        sessionStorage.removeItem("cipherSafeUsername");
    }

    // Reset the session state
    fourWaySessionState.resetSession();

    navigateTo("index.html");
    return false;
}



/**
 * Performs a secure logout by notifying the server
 * and clearing all client-side session state.
 */
export async function handleLogout() {
    try {

        // try to send logout packet
        if (await ensureSecureSessionOrRedirect()) {
            const payload = {};
            const requestPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.LOGOUT, payload, fourWaySessionState );
            const secureResult = await runServerSecureResponse(requestPacket, fourWaySessionState);
            if (secureResult && secureResult.kind === "logout") {
            }
        }

    // Error logging out
    } catch (err) {
        console.error("handleLogout error:", err);
    }

    // Clear all local session state
    try {
        if (typeof sessionStorage !== "undefined") {
            fourWaySessionState.clearEncryptedSessionInStorage();
            fourWaySessionState.resetSession();
            sessionStorage.removeItem("cipherSafeLoggedIn");
            sessionStorage.removeItem("cipherSafeUsername");
        }
    } catch (e) {
        console.error("handleLogout cleanup error:", e);
    }

    navigateTo("index.html");
}



/**
 * Dynamically dispatches routing to the correct page initializer
 * based on DOM presence.
 */
export async function initializeVaultModule() {

    if (document.getElementById("vault-list")) {
        const mod = await import("https://pascal/capstone/html/src/vault.js");
        await mod.initializeVaultPage();
        return;
    }

    if (document.getElementById("add-form")) {
        const mod = await import("https://pascal/capstone/html/src/add.js");
        await mod.initializeAddPage();
        return;
    }

    if (document.getElementById("update-account-form")) {
        const mod = await import("https://pascal/capstone/html/src/update_account.js");
        await mod.initializeUpdateAccountPage();
        return;
    }

    if (document.getElementById("update-master-password-form")) {
        const mod = await import("https://pascal/capstone/html/src/update_master_password.js");
        await mod.initializeMasterPasswordPage();
        return;
    }
}



/**
 * Initializes the vault DOM.
 */
export async function startup() {
    try {
        await initializeVaultModule();
    } catch (e) {
        console.error("vault_api.js startup error:", e);
    }
}

