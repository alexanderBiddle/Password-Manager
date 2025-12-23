/**
 * File name: register.js
 * Author: Alex Biddle
 *
 * Description:
 *     This file handles all the register services for a user
 */

import { showStatusMessage, clearStatusMessage, navigateTo, validateAndAlert, showErrorAlert} from "https://pascal/capstone/html/src/ui.js";
import { sanitizeUsername, sanitizePassword} from "https://pascal/capstone/html/src/sanitization.js";
import { REQUEST_TYPES, RESPONSE_STATUSES, CLIENT_SALT_LENGTH_BYTES } from "https://pascal/capstone/html/src/constants.js";
import { Argon2idEncryptionManager } from "https://pascal/capstone/html/src/encryption/argon2id_encryption.js";
import { toUtf8Bytes, encodeBase64Url, randomBytes } from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import { sendSignupClientHello } from "https://pascal/capstone/html/src/handshake/client_hello.js";
import { processServerHello } from "https://pascal/capstone/html/src/handshake/server_hello.js";
import { buildClientSecureRequestPacket } from "https://pascal/capstone/html/src/handshake/client_secure_request.js";
import { runServerSecureResponse } from "https://pascal/capstone/html/src/handshake/server_secure_response.js";
import { fourWaySessionState } from "https://pascal/capstone/html/src/handshake/session_state.js";





/**
 * Handle the signup form submit event.
 *
 * @param {SubmitEvent} event - The form submit event object.
 *
 * @returns {Promise<void>}
 */
export async function handleSignupSubmit(event) {

    // Prevent browser default form POST.
    event.preventDefault();


    // Delete old session state
    try {
        fourWaySessionState.resetSession();
    } catch (e) {
        console.warn("handleSignupSubmit: failed to reset previous session:", e);
    }

    // Clear any existing status messages.
    clearStatusMessage("signup-status");

    // Look up the username and password input elements.
    const usernameInput = document.getElementById("signup-username-input");
    const passwordInput = document.getElementById("signup-password-input");

    // Ensure the form elements exist.
    if (!usernameInput || !passwordInput) {
        showStatusMessage("signup-status", "Signup form is not correctly configured.", "error");
        return;
    }

    // Extract raw values from input
    const rawUsername = usernameInput.value || "";
    const rawPassword = passwordInput.value || "";

    // Validation of length / character checks
    if (!validateAndAlert(rawUsername, rawPassword, "signup")) {
        return;
    }

    // Enforce the stronger 12-character requirement BEFORE running crypto.
    if (rawPassword.length < 12) {
        showStatusMessage("signup-status", "Password must be at least 12 characters long.", "error");
        return;
    }

    try {
        
        // Sanitize username and password.
        const username = sanitizeUsername(rawUsername);
        const password = sanitizePassword(rawPassword);

        // Show a progress message.
        showStatusMessage("signup-status", "Performing secure signup handshake...", "info");
        
        // Send the Client Hello for SIGNUP using the wrapper helper.
        const helloTransport = await sendSignupClientHello(username, fourWaySessionState);

        // Check if an error occurred 
        if (!helloTransport || !helloTransport.ok) {
            const statusCode = helloTransport ? helloTransport.status : "unknown";
            showStatusMessage("signup-status", `Signup handshake failed (HTTP ${statusCode}).`, "error");
            return;
        }

        // Process and validate the Server Hello and update SessionState
        const helloResult = await processServerHello(helloTransport, fourWaySessionState);

        // If the Server Hello validation failed, surface it.
        if (!helloResult || !helloResult.ok) {
            const statusCode = helloResult ? helloResult.status : "unknown";
            showStatusMessage("signup-status", `Signup handshake validation failed (HTTP ${statusCode}).`, "error");
            return;
        }

        // Extract the validated Server Hello payload
        const serverHelloData = helloResult.data || {};

        // Check if the server did not accepted the signup handshake.
        if (serverHelloData.response_status !== RESPONSE_STATUSES.SUCCESS) {

            // Check if the server indicated a user already exists
            if (serverHelloData.response_status === RESPONSE_STATUSES.USER_ACCOUNT_EXISTS) {
                alert("An account with that username already exists. Please choose a different username.");
                showStatusMessage("signup-status", "An account with that username already exists. Please choose a different username.", "error");
            
            } else {

                // Show error message
                if (typeof serverHelloData.application_code === "string") {
                    showErrorAlert(serverHelloData.application_code, "signup");
                }

                const msg = typeof serverHelloData.message === "string" ? serverHelloData.message: "Signup handshake rejected by server. Please try a different username.";
                showStatusMessage("signup-status", msg, "error");
            }
            return;
        }


        // Generate a fresh client_salt using crypto-safe RNG.
        const clientSaltBytes = randomBytes(CLIENT_SALT_LENGTH_BYTES);

        // Convert password to UTF-8 bytes.
        const passwordBytes = toUtf8Bytes(password);

        // Create Argon2id manager instance.
        const argonManager = new Argon2idEncryptionManager();

        // Derive client_hash = Argon2id(password, client_salt).
        const clientHashBytes = await argonManager.hashPassword(passwordBytes, clientSaltBytes);

        // Encode client_salt and client_hash as base64url.
        const clientSaltB64u = encodeBase64Url(clientSaltBytes);
        const clientHashB64u = encodeBase64Url(clientHashBytes);

        // Build the decrypted signup payload.
        const signupPayload = {
            client_salt: clientSaltB64u,
            client_hash: clientHashB64u
        };

        // Create the client secure packet request
        const secureRequestPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.SIGNUP, signupPayload, fourWaySessionState);

        // Send the client secure packet request
        const secureResult = await runServerSecureResponse(secureRequestPacket, fourWaySessionState);

        // Check if an error occoured
        if (secureResult && typeof secureResult === "object" && "ok" in secureResult) {
            if (!secureResult.ok) {
                const statusCode = secureResult.status ?? "unknown";
                showStatusMessage("signup-status", `Secure signup failed (HTTP ${statusCode}).`, "error");
                return;
            }
        }

        // Check if a logout packet was sent
        if (secureResult && secureResult.kind === "logout") {
            showStatusMessage("signup-status", "Session was closed by the server during signup.", "error");
            navigateTo("index.html");
            return;
        }

        // Extract the payload and reponse status
        const { responseStatus: finalStatus, payload } = secureResult || {};

        // Check if the response status was a success
        if (finalStatus !== RESPONSE_STATUSES.SUCCESS) {
            
            // Show error message
            if (payload && typeof payload.application_code === "string") {
                showErrorAlert(payload.application_code, "signup");
            }

            const serverMessage = payload && typeof payload.message === "string"? payload.message: "Signup failed. Please try again with a different username.";
            showStatusMessage("signup-status", serverMessage, "error");
            return;
        }

        showStatusMessage("signup-status", "Account created successfully. Redirecting to login...", "success");
        navigateTo("index.html");

    } catch (err) {
        console.error("handleSignupSubmit error:", err);
        showStatusMessage("signup-status", "Unexpected error during signup. Please try again.", "error");
    }
}



/**
 * Initialize the signup page by wiring events and security.
 *
 * @returns {void}
 */
export function initializeSignupPage() {

    // Look up the signup form by ID.
    const signupForm = document.getElementById("signup-form");

    // If the form exists, wire up the submit handler.
    if (signupForm) {
        signupForm.addEventListener("submit", (event) => {
            void handleSignupSubmit(event);
        });
    }
}



// Initialize the signup page when DOM is ready.
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
        initializeSignupPage();
    });
} else {
    initializeSignupPage();
}