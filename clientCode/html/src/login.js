/**
 * File name: login.js
 * Author: Alex Biddle
 *
 * Description:
 *      This file implments the login service for the client and handles
 *      communicating with the server for logging in by using the four-way 
 *      handshake protocol 
 */


// Imports
import {showStatusMessage, clearStatusMessage, navigateTo, validateAndAlert, showErrorAlert} from "https://pascal/capstone/html/src/ui.js";
import {sanitizeUsername, sanitizePassword} from "https://pascal/capstone/html/src/sanitization.js";
import {REQUEST_TYPES, RESPONSE_STATUSES, HANDSHAKE_STATES} from "https://pascal/capstone/html/src/constants.js";
import {encodeBase64Url} from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import { Argon2idEncryptionManager } from "https://pascal/capstone/html/src/encryption/argon2id_encryption.js";
import { RsaEncryptionManager } from "https://pascal/capstone/html/src/encryption/rsa_encryption.js";
import { sendLoginClientHello } from "https://pascal/capstone/html/src/handshake/client_hello.js";
import { processServerHello } from "https://pascal/capstone/html/src/handshake/server_hello.js";
import { buildClientSecureRequestPacket } from "https://pascal/capstone/html/src/handshake/client_secure_request.js";
import { runServerSecureResponse } from "https://pascal/capstone/html/src/handshake/server_secure_response.js";
import {SessionState, fourWaySessionState} from "https://pascal/capstone/html/src/handshake/session_state.js";
import { deriveVaultKey } from "https://pascal/capstone/html/src/encryption/vault_encryption.js";








//=============================================================================
//  CLIENT HASH DERIVATION
//=============================================================================

/**
 * Derive the client_hash = Argon2id(password, client_salt).
 *
 * @param {string} password - the sanitized raw password input
 * @param {Uint8Array} clientSaltBytes - 16-byte salt from session_state
 * @returns {Promise<Uint8Array>} 32-byte client_hash
 */
async function deriveClientHash(password, clientSaltBytes) {

    // Create a fresh Argon2 manager (client parameters standardized project-wide)
    const argonManager = new Argon2idEncryptionManager();

    // Convert password (string) → Uint8Array UTF-8
    const passwordBytes = new TextEncoder().encode(password);

    // Derive Argon2id digest
    const clientHashBytes = await argonManager.hashPassword(passwordBytes, clientSaltBytes);

    // Validate type
    if (!(clientHashBytes instanceof Uint8Array)) {throw new Error("deriveClientHash: Argon2id hashing produced invalid output");}

    return clientHashBytes;
}



//=============================================================================
// LOGIN HANDLERS
//=============================================================================


/**
 * Handle final secure server response after Step-3 LOGIN.
 *
 * @param {object} secureResult - output of runServerSecureResponse()
 * @param {string} username - sanitized username
 * @param {SessionState} sessionState
 */
async function handleFinalLoginResponse(secureResult, username, sessionState = fourWaySessionState) {

    // Transport/HTTP failure (network or 500)
    if (secureResult && secureResult.ok === false) {
        showStatusMessage("login-status", `Secure login failed (HTTP ${secureResult.status || "?"}).`, "error");
        return;
    }

    // Server forcibly logged out instead of completing handshake
    if (secureResult && secureResult.kind === "logout") {
        showStatusMessage("login-status", "Session was closed by server during login.", "error");
        navigateTo("index.html");
        return;
    }

    // Get the response status and payload
    const finalStatus = secureResult?.responseStatus;
    const payload     = secureResult?.payload;

    // Server sent error response
    if (finalStatus !== RESPONSE_STATUSES.SUCCESS) {

        if (payload && typeof payload.application_code === "string") {
            showErrorAlert(payload.application_code, "login");
        }

        const msg = payload?.message || "Invalid username or password.";
        showStatusMessage("login-status", msg, "error");
        return;
    }

    // Server sent success status 
    try {   

        // Set the handshake state
        sessionState.setHandshakeState(HANDSHAKE_STATES.COMPLETE);

        // Set session storage data
        sessionStorage.setItem("cipherSafeLoggedIn", "1");
        sessionStorage.setItem("cipherSafeUsername", username);

        // Persist session data 
        await sessionState.generatePersistentEncryptionKey();
        await sessionState.persistToStorage();

    } catch (e) {
        console.warn("handleFinalLoginResponse: session persistence error:", e);
    }

    // Notify user and redirect to vault page
    const message = payload?.message || "Login successful. Redirecting...";
    showStatusMessage("login-status", message, "success");
    navigateTo("vault.html");
}



/**
 * Handles logging in for a user triggered by the login form.
 */
export async function handleLoginSubmit(event) {

    // Suppress HTML form submission
    event?.preventDefault?.();

    // Reset previous status messages
    clearStatusMessage("login-status");

    // Look up DOM fields
    const usernameInput = document.getElementById("login-username-input");
    const passwordInput = document.getElementById("login-password-input");

    // Ensure the login form exists correctly
    if (!usernameInput || !passwordInput) {
        showStatusMessage("login-status", "Login form misconfigured.", "error");
        return;
    }

    const rawUsername = usernameInput.value || "";
    const rawPassword = passwordInput.value || "";

    // Basic client-side validation + alerts
    if (!validateAndAlert(rawUsername, rawPassword, "login")) {
        return;
    }

    try {

        // Sanitize the username and password
        const username = sanitizeUsername(rawUsername);
        const password = sanitizePassword(rawPassword);
        
        // Reset the session object
        fourWaySessionState.resetSession();
        
        // Set the username
        fourWaySessionState.setUsername(username);

        
        let rsaManager = fourWaySessionState.getClientRsaManager();
		if (!rsaManager) {
			rsaManager = await RsaEncryptionManager.generate();
			fourWaySessionState.setClientRsaManager(rsaManager);
		}
        
        showStatusMessage("login-status", "Starting secure login handshake...", "info");
        
        // Send the hello client packet
        const helloTransport = await sendLoginClientHello(username, fourWaySessionState);
        if (!helloTransport?.ok) {
            showStatusMessage("login-status", `Handshake failed (HTTP ${helloTransport?.status || "?"}).`, "error");
            return;
        }

        // Wait for the hello server response
        const helloResult = await processServerHello(helloTransport, fourWaySessionState);

        if (!helloResult?.ok) {
            showStatusMessage("login-status", `Handshake validation failed (HTTP ${helloResult?.status || "?"}).`, "error");
            return;
        }

        const serverHelloData = helloResult.data;

        // Ensure server indicates LOGIN success at handshake stage
        if (serverHelloData.response_status !== RESPONSE_STATUSES.SUCCESS) {

            if (serverHelloData.application_code) {
                showErrorAlert(serverHelloData.application_code, "login");
            }

            const msg = serverHelloData.message || "Login handshake rejected.";
            showStatusMessage("login-status", msg, "error");
            return;
        }

        
        
        // Get the salt values 
        const clientSaltBytes = fourWaySessionState.getClientSaltBytes();
        const vaultSaltBytes  = fourWaySessionState.getVaultSaltBytes();

        try {
			if (typeof sessionStorage !== "undefined") {
		
				if (clientSaltBytes instanceof Uint8Array) {
					sessionStorage.setItem("cipherSafeClientSaltB64u", encodeBase64Url(clientSaltBytes));
				}
		
				if (vaultSaltBytes instanceof Uint8Array) {
					sessionStorage.setItem("cipherSafeVaultSaltB64u", encodeBase64Url(vaultSaltBytes));
				}
		
				// This is already assumed by ensureVaultKeyReady() during restores.
				// (If you do not store it, vault-key re-derivation cannot happen after refresh.)
				sessionStorage.setItem("cipherSafeLastPassword", password);
			}
		} catch (e) {
			console.warn("handleLoginSubmit: unable to persist salts/password:", e);
		}

        
        // Persist salts for pages that run after refresh/navigation.
        // (SessionState restore does not always repopulate these.)
        try {
            if (typeof sessionStorage !== "undefined" && clientSaltBytes instanceof Uint8Array) {
                sessionStorage.setItem("cipherSafeClientSaltB64u", encodeBase64Url(clientSaltBytes));
            }
        } catch (e) {
            console.warn("handleLoginSubmit: unable to persist client salt:", e);
        }
        
        // Validate the salts
        if (!clientSaltBytes) {throw new Error("handleLoginSubmit: missing client_salt in session after Server Hello");}
        if (!vaultSaltBytes) {throw new Error("handleLoginSubmit: missing vault_salt in session after Server Hello");}

        // Create the master password hash
        const clientHashBytes = await deriveClientHash(password, clientSaltBytes);
        if (!(clientHashBytes instanceof Uint8Array) || clientHashBytes.length !== 32) {
            throw new Error("handleLoginSubmit: derived client hash invalid");
        }

        // Create the vault key bytes
        const vaultKeyBytes = await deriveVaultKey(password, vaultSaltBytes);
        if (!(vaultKeyBytes instanceof Uint8Array) || vaultKeyBytes.length !== 32) {
            throw new Error("handleLoginSubmit: derived vault key invalid");
        }

        // Store the vault key bytes in the session object
        fourWaySessionState.setVaultKeyBytes(vaultKeyBytes);

        // Encode the hashed master password to base 64
        const clientHashB64u = encodeBase64Url(clientHashBytes);

        // Create the payload
        const loginPayload = {
            client_hash: clientHashB64u
        };

        // Build the client secure request
        const secureRequestPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.LOGIN, loginPayload, fourWaySessionState);

        // Send the secure request to the server and process the response
        const secureResult = await runServerSecureResponse(secureRequestPacket, fourWaySessionState);

        // Hanlde the server respsonse
        await handleFinalLoginResponse(secureResult, username, fourWaySessionState);

    } catch (err) {
    	
    	fourWaySessionState.resetSession()
        console.error("handleLoginSubmit: unexpected login error:", err);
        showStatusMessage("login-status", "Unexpected error during login. Please try again.", "error");
    }
}



//=============================================================================
//  PAGE AND DOM INITIALIZATION
//=============================================================================

/**
 * Bind the LOGIN form submit handler.
 */
export function initializeLoginPage() {

    // Locate the login form by its ID
    const form = document.getElementById("login-form");

    // If the form exists, attach the submit handler
    if (form) {
        form.addEventListener("submit", (e) => {
            void handleLoginSubmit(e);
        });
    }
}


// Loads the DOM before the login page
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializeLoginPage);

// DOM is already loaded; initialize the login page
} else {
    initializeLoginPage();
}
