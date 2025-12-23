/**
 * File name: update_master_password.js
 * Author: Alex Biddle
 *
 * Description:
 *      Page module for update_master_password.html.
 *      Handles master password rotation AND vault re-encryption
 *      using existing CipherSafe client functionality.
 */

import {showStatusMessage, clearStatusMessage, navigateTo, showErrorAlert} from "https://pascal/capstone/html/src/ui.js";
import { sanitizePassword } from "https://pascal/capstone/html/src/sanitization.js";
import {REQUEST_TYPES,RESPONSE_STATUSES} from "https://pascal/capstone/html/src/constants.js";
import { Argon2idEncryptionManager } from "https://pascal/capstone/html/src/encryption/argon2id_encryption.js";
import { toUtf8Bytes, encodeBase64Url} from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import { encryptVaultField, decryptVaultField, deriveVaultKey} from "https://pascal/capstone/html/src/encryption/vault_encryption.js";
import { buildClientSecureRequestPacket} from "https://pascal/capstone/html/src/handshake/client_secure_request.js";
import { runServerSecureResponse} from "https://pascal/capstone/html/src/handshake/server_secure_response.js";
import { fourWaySessionState } from "https://pascal/capstone/html/src/handshake/session_state.js";
import { ensureSecureSessionOrRedirect, ensureVaultKeyReady, handleLogout } from "https://pascal/capstone/html/src/vault_api.js";


const STATUS_ID = "update-status";


/**
 * Converts a base64url-encoded string into a Uint8Array.
 * Used to restore cryptographic salts from sessionStorage.
 *
 * @param {string} b64u - Base64URL encoded string
 *
 * @returns {Uint8Array|null} - Decoded bytes or null on failure
 */
function base64UrlToBytes(b64u) {
    
    // Reject non-string or empty input
    if (typeof b64u !== "string" || b64u.length === 0) return null;

    // Convert base64url → base64
    let b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");

    // Add padding if needed
    const pad = b64.length % 4;
    if (pad) b64 += "=".repeat(4 - pad);                 

    // Decode base64 to binary string
    const bin = atob(b64);

    // Allocate output buffer
    const out = new Uint8Array(bin.length);

    // Convert binary string to byte array
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}


/**
 * Securely updates the user's master password
 *
 * @param {string} oldPassword - User's current master password
 * @param {string} newPassword - New master password
 *
 * @ensures All vault entries are re-encrypted using the new vault key
 * @returns {Promise<void>}
 */
export async function vaultUpdateMasterPassword(oldPassword, newPassword) {

    // Enforce valid secure session
    if (!(await ensureSecureSessionOrRedirect())) {
        return;
    }
    
     // Ensure vault key exists (restore path)
	try {
		await ensureVaultKeyReady();
	} catch (e) {}
	
	// Restore salts into SessionState if they are missing (restore path)
	try {
		const storedClientSalt = sessionStorage.getItem("cipherSafeClientSaltB64u") || "";
		const storedVaultSalt = sessionStorage.getItem("cipherSafeVaultSaltB64u") || "";
		const clientSaltBytesRestored = base64UrlToBytes(storedClientSalt);
		const vaultSaltBytesRestored = base64UrlToBytes(storedVaultSalt);
	
		if (clientSaltBytesRestored instanceof Uint8Array && clientSaltBytesRestored.length === 16) {
			if (!(fourWaySessionState.getClientSaltBytes?.() instanceof Uint8Array)) {
				fourWaySessionState.setClientSaltBytes?.(clientSaltBytesRestored);
			}
		}
	
		if (vaultSaltBytesRestored instanceof Uint8Array && vaultSaltBytesRestored.length === 16) {
			if (!(fourWaySessionState.getVaultSaltBytes?.() instanceof Uint8Array)) {
				fourWaySessionState.setVaultSaltBytes?.(vaultSaltBytesRestored);
			}
		}
	} catch (e) {
		console.warn("vaultUpdateMasterPassword: unable to restore salts from sessionStorage:", e);
	}

    // Clear any previous status message
    clearStatusMessage(STATUS_ID);

    // Capture OLD vault key before anything changes
    const oldVaultKeyBytes = fourWaySessionState.getVaultKeyBytes?.();

    try {

        // Sanitize passwords
        const oldPw = sanitizePassword(oldPassword);
        const newPw = sanitizePassword(newPassword);

        // Initialize Argon2id hasher
        const argon2 = new Argon2idEncryptionManager();

        // Retrieve salts
        const clientSaltBytes = fourWaySessionState.getClientSaltBytes?.();
        const vaultSaltBytes = fourWaySessionState.getVaultSaltBytes?.();
        
        // Ensure required session data exists
        if (!(clientSaltBytes instanceof Uint8Array) || !(vaultSaltBytes instanceof Uint8Array)) {
            showStatusMessage(STATUS_ID, "Session data missing. Please log out and log in again.", "error");
            return;
        }

        // Verify old password 
        const oldPwBytes = toUtf8Bytes(oldPw);
        const oldHashBytes = await argon2.hashPassword(oldPwBytes, clientSaltBytes);
        const oldHashB64u = encodeBase64Url(oldHashBytes);

        // Create new client salt and hash 
        const newClientSaltBytes = crypto.getRandomValues(new Uint8Array(16));
        const newClientSaltB64u = encodeBase64Url(newClientSaltBytes);
        const newPwBytes = toUtf8Bytes(newPw);
        const newHashBytes = await argon2.hashPassword(newPwBytes, newClientSaltBytes);
        const newHashB64u = encodeBase64Url(newHashBytes);

        // Send master password update request 
        const payload = {
            old_client_hash: oldHashB64u,
            new_client_salt: newClientSaltB64u,
            new_client_hash: newHashB64u
        };

        // Build the secure request packet
        const requestPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.VAULT_UPDATE_MASTER_PASSWORD, payload, fourWaySessionState);

        // Send the secure response packet and procss the server response
        const secureResult = await runServerSecureResponse(requestPacket, fourWaySessionState);

        // Error
        if (secureResult && "ok" in secureResult && !secureResult.ok) {
            showStatusMessage(STATUS_ID, `Password update failed (HTTP ${secureResult.status}).`, "error");
            return;
        }

        // logout packet
        if (secureResult && secureResult.kind === "logout") {
            navigateTo("index.html");
            return;
        }

        // Extract the payload and response
        const { responseStatus, payload: responsePayload } = secureResult || {};

        // Error response
        if (responseStatus !== RESPONSE_STATUSES.SUCCESS) {
            if (responsePayload?.application_code) {
                showErrorAlert(responsePayload.application_code, "vault");
            }
            showStatusMessage(STATUS_ID, responsePayload?.message || "Master password update failed.", "error");
            return;
        }

        // Derive NEW vault key 
        const newVaultKeyBytes = await deriveVaultKey(newPw, vaultSaltBytes);

        // Fetch vault entries (reuse existing protocol) 
        showStatusMessage(STATUS_ID, "Re-encrypting vault entries...", "info");

        // Build the secure request packet
        const fetchPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.VAULT_FETCH_ACCOUNTS, {}, fourWaySessionState);

        // Send the secure response packet and procss the server response
        const fetchResult = await runServerSecureResponse(fetchPacket, fourWaySessionState);
        const accounts = fetchResult?.payload?.accounts || [];

        // Re-encrypt each vault entry
        for (const entry of accounts) {
            const websitePlain = await decryptVaultField(entry.website, oldVaultKeyBytes);
            const usernamePlain = await decryptVaultField(entry.account_username, oldVaultKeyBytes);
            const emailPlain = await decryptVaultField(entry.account_email, oldVaultKeyBytes);
            const passwordPlain = await decryptVaultField(entry.account_password, oldVaultKeyBytes);
            const newWebsiteCt = await encryptVaultField(websitePlain, newVaultKeyBytes);
            const newUsernameCt = await encryptVaultField(usernamePlain, newVaultKeyBytes);
            const newEmailCt = await encryptVaultField(emailPlain, newVaultKeyBytes);
            const newPasswordCt = await encryptVaultField(passwordPlain, newVaultKeyBytes);

            const updatePayload = {
                old_website: entry.website,
                old_account_username: entry.account_username,
                new_website: newWebsiteCt,
                new_account_username: newUsernameCt,
                new_account_email: newEmailCt,
                new_account_password: newPasswordCt
            };

            // Build the secure request packet
            const updatePacket = await buildClientSecureRequestPacket(REQUEST_TYPES.VAULT_UPDATE_ACCOUNT, updatePayload, fourWaySessionState);

            // Send the secure response packet and procss the server response
            await runServerSecureResponse(updatePacket, fourWaySessionState);
        }

        // Finalize state 
        fourWaySessionState.setClientSaltBytes?.(newClientSaltBytes);
        fourWaySessionState.setVaultKeyBytes?.(newVaultKeyBytes);
        sessionStorage.setItem("cipherSafeLastPassword", newPw);

        showStatusMessage(STATUS_ID, "Master password updated successfully.", "success");
        
        setTimeout(() => {
        	navigateTo("index.html");
        }, 1000);


    } catch (err) {
        console.error("vaultUpdateMasterPassword error:", err);
        showStatusMessage(STATUS_ID, "Unexpected error updating master password.", "error");
    }
}


/**
 * Initializes update_master_password.html by wiring
 * logout and form submission behavior.
 *
 * @returns {Promise<void>}
 */
export async function initializeMasterPasswordPage() {

    // Bind logout button
    const btnLogout = document.getElementById("btn-logout");
    if (btnLogout) {
        btnLogout.addEventListener("click", () => {
            void handleLogout();
        });
    }

    // Locate update form
    const updateForm = document.getElementById("update-master-password-form");
    if (!updateForm) return;

    // Bind submit handler
    updateForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        clearStatusMessage(STATUS_ID);

        // get input data
        const oldPwInput = document.getElementById("old-master-password");
        const newPwInput = document.getElementById("new-master-password");

        if (!oldPwInput || !newPwInput) {
            showStatusMessage(STATUS_ID, "Update form is misconfigured.", "error");
            return;
        }

        // Update the master password and all the entries
        await vaultUpdateMasterPassword(oldPwInput.value || "", newPwInput.value || "");
    });
}


// Auto-start
document.addEventListener("DOMContentLoaded", () => {
    try {
        if (document.getElementById("update-master-password-form")) {
            void initializeMasterPasswordPage();
        }
    } catch (e) {
        console.error("update_master_password.js DOMContentLoaded error:", e);
    }
});
