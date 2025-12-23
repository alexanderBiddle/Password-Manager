/**
 * File name: update_account.js
 * Author: Alex Biddle
 *
 * Description:
 *      Page module for update_account.html, performs all services for 
 *      updating an existing account
 *
 */

import { showStatusMessage, clearStatusMessage, navigateTo, showErrorAlert } from "https://pascal/capstone/html/src/ui.js";
import { sanitizePassword } from "https://pascal/capstone/html/src/sanitization.js";
import { REQUEST_TYPES, RESPONSE_STATUSES } from "https://pascal/capstone/html/src/constants.js";
import { encryptVaultField } from "https://pascal/capstone/html/src/encryption/vault_encryption.js";
import { buildClientSecureRequestPacket } from "https://pascal/capstone/html/src/handshake/client_secure_request.js";
import { runServerSecureResponse } from "https://pascal/capstone/html/src/handshake/server_secure_response.js";
import { fourWaySessionState } from "https://pascal/capstone/html/src/handshake/session_state.js";
import { ensureSecureSessionOrRedirect, requireVaultKeyBytes, sanitizeWebsite, sanitizeAccountField, handleLogout} from "https://pascal/capstone/html/src/vault_api.js";
import { generateSecurePassword } from "https://pascal/capstone/html/src/add.js";




/**
 * Updates an existing vault entry by:
 *
 * @param {string} oldWebsite - Original website identifier (plaintext)
 * @param {string} oldUsername - Original account username (plaintext)
 * @param {string} newWebsite - Updated website value
 * @param {string} newUsername- Updated username value
 * @param {string} newEmail - Updated email value
 * @param {string} newPassword - Updated password (plaintext)
 *
 * @ensures Vault entry is updated only if a valid session exists and all new fields are encrypted with the vault key
 * @returns {Promise<boolean>} - True on success, false on failure
 */
export async function vaultUpdateAccount(oldWebsite,oldUsername, newWebsite, newUsername, newEmail, newPassword) {

    // Choose the correct status element depending on page
    const STATUS_ID = document.getElementById("update-status") ? "update-status" : "vault-status";

    // Enforce secure session before proceeding
    if (!(await ensureSecureSessionOrRedirect())) {
        return false;
    }

    // Clear any prior status messages
    clearStatusMessage(STATUS_ID);

    // Retrieve the vault key from memory
    const vaultKeyBytes = requireVaultKeyBytes(STATUS_ID);
    if (!vaultKeyBytes) {
        return false;
    }

    try {
        
        // Require password to update
        if (typeof newPassword !== "string" || newPassword.trim().length === 0) {
            showStatusMessage(STATUS_ID, "Enter a new password to update this entry.", "error");
            return false;
        }

        // Sanitize plaintext fields 
        const cleanOldWebsite = sanitizeWebsite(oldWebsite);
        const cleanOldUsername = sanitizeAccountField(oldUsername, "old_account_username");
        const cleanNewWebsite = sanitizeWebsite(newWebsite);
        const cleanNewUsername = sanitizeAccountField(newUsername, "new_account_username");
        const cleanNewEmail = sanitizeAccountField(newEmail, "new_account_email");
        const cleanNewPassword = sanitizePassword(newPassword);

        // Retrieve original ciphertext keys from sessionStorage
        let oldWebsiteCt = null;
        let oldUsernameCt = null;

        // Ensure sessionStorage
        try {
            if (typeof sessionStorage !== "undefined") {
                oldWebsiteCt = sessionStorage.getItem("update_old_website_ct");
                oldUsernameCt = sessionStorage.getItem("update_old_username_ct");
            }
        } catch (e) {
            console.error("vaultUpdateAccount: unable to read ciphertext context from sessionStorage:", e);
        }

        // Fail if ciphertext context is missing
        if (!oldWebsiteCt || !oldUsernameCt) {
            showStatusMessage(
                STATUS_ID,
                "Missing original vault entry context. Please reopen the update page from your vault.",
                "error"
            );
            return false;
        }

        // Encrypt new fields with vault key
        const newWebsiteCt = await encryptVaultField(cleanNewWebsite, vaultKeyBytes);
        const newUsernameCt = await encryptVaultField(cleanNewUsername, vaultKeyBytes);
        const newEmailCt = await encryptVaultField(cleanNewEmail, vaultKeyBytes);
        const newPasswordCt = await encryptVaultField(cleanNewPassword, vaultKeyBytes);

        const payload = {
            old_website: oldWebsiteCt,
            old_account_username: oldUsernameCt,
            new_website: newWebsiteCt,
            new_account_username: newUsernameCt,
            new_account_email: newEmailCt,
            new_account_password: newPasswordCt
        };

        // Build authenticated secure request packet
        const requestPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.VAULT_UPDATE_ACCOUNT, payload, fourWaySessionState);

        // Transmit packet and await server response
        const secureResult = await runServerSecureResponse(requestPacket, fourWaySessionState);

        // Server errors
        if (secureResult && typeof secureResult === "object" && "ok" in secureResult) {
            if (!secureResult.ok) {
                const code = secureResult.status ?? "unknown";
                showStatusMessage(STATUS_ID, `Update failed (HTTP ${code}).`, "error");
                return false;
            }
        }

        // Logout handling
        if (secureResult && secureResult.kind === "logout") {
            showStatusMessage(STATUS_ID, "Session was closed by the server.", "error");
            navigateTo("index.html");
            return false;
        }

        // Extract protocol response fields
        const { responseStatus, payload: responsePayload } = secureResult || {};

        // Appplication errors
        if (responseStatus !== RESPONSE_STATUSES.SUCCESS) {
            if (responsePayload && typeof responsePayload.application_code === "string") {
                showErrorAlert(responsePayload.application_code, "vault");
            }

            const msg = (responsePayload && typeof responsePayload.message === "string") ? responsePayload.message: "Vault entry update failed.";
            showStatusMessage(STATUS_ID, msg, "error");
            return false;
        }

        // Success
        showStatusMessage(STATUS_ID, "Vault entry updated successfully.", "success");
        
        /*
        // If we're on vault page, refresh list; if we're on update page, do not.
        if (document.getElementById("vault-list")) {
            await fetchAndRenderVaultAccounts();
        }
        */
        return true;
    
    // Unexpected error
    } catch (err) {
        console.error("vaultUpdateAccount error:", err);
        let message = "Unexpected error updating vault entry.";
        if (err instanceof Error && typeof err.message === "string") {
            if (err.message.toLowerCase().includes("sanitizepassword")) {
                message = "Password must be at least 12 characters long.";
            } else {
                message = err.message;
            }
        }

        showStatusMessage(document.getElementById("update-status") ? "update-status" : "vault-status",message,"error");

        return false;
    }
}



/**
 * Initializes the update account page 
 *
 * @ensures Update page is fully wired and guarded
 * @returns {Promise<void>}
 */
export async function initializeUpdateAccountPage() {

    // Bind logout button
    const btnLogout = document.getElementById("btn-logout");
    if (btnLogout) {
        btnLogout.addEventListener("click", () => {
            void handleLogout();
        });
    }

    // Locate update form
    const updateForm = document.getElementById("update-account-form");
    if (!updateForm) return;

    // Lookup all form fields
    const oldWebsiteInput = document.getElementById("old-website");
    const oldUsernameInput = document.getElementById("old-username");
    const newWebsiteInput = document.getElementById("new-website");
    const newUsernameInput = document.getElementById("new-username");
    const newEmailInput = document.getElementById("new-email");
    const newPasswordInput = document.getElementById("new-password");

    // Validate form integrity
    if (!oldWebsiteInput || !oldUsernameInput || !newWebsiteInput || !newUsernameInput || !newEmailInput || !newPasswordInput) {
        showStatusMessage("update-status", "Update form is invalid.", "error");
        return;
    }

    // Bind generate password button
    const btnGenerate = document.getElementById("generate-password");
    if (btnGenerate) {

        btnGenerate.addEventListener("click", () => {
            
            // Generate a strong password
            const newPassword = generateSecurePassword(20);

            // Populate password field
            if (newPasswordInput) {
                newPasswordInput.value = newPassword;
            }

            showStatusMessage("update-status", "Strong password generated!", "success");
        });
    }

    // Autofill ONCE on load if coming from Vault "Update"
    let oldEmailFromStorage = "";
    try {
        const storedOldWebsite = sessionStorage.getItem("update_old_website");
        const storedOldUsername = sessionStorage.getItem("update_old_username");
        const storedOldEmail = sessionStorage.getItem("update_old_email") || "";

        if (storedOldWebsite && storedOldUsername) {
            oldWebsiteInput.value = storedOldWebsite;
            oldUsernameInput.value = storedOldUsername;
            oldEmailFromStorage = storedOldEmail;

            // Lock original identifiers
            oldWebsiteInput.readOnly = true;
            oldUsernameInput.readOnly = true;

            // Pre-fill new fields if empty
            if (!newWebsiteInput.value) newWebsiteInput.value = storedOldWebsite;
            if (!newUsernameInput.value) newUsernameInput.value = storedOldUsername;
            if (storedOldEmail && !newEmailInput.value) newEmailInput.value = storedOldEmail;
        }
    } catch (e) {}

    // Bind form submission handler
    updateForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        clearStatusMessage("update-status");
        
        // Extract current form values
        const oldWebsite = (oldWebsiteInput.value || "").trim();
        const oldUsername = (oldUsernameInput.value || "").trim();
        const newWebsiteRaw = (newWebsiteInput.value || "").trim();
        const newUsernameRaw = (newUsernameInput.value || "").trim();
        const newEmailRaw = (newEmailInput.value || "").trim();
        const newPassword = newPasswordInput.value || "";

        // Require password so password updates actually happen
        if (!newPassword) {
            showStatusMessage("update-status", "Enter a new password to update this entry.", "error");
            return;
        }

        // Blank means "keep current"
        const newWebsite = newWebsiteRaw.length ? newWebsiteRaw : oldWebsite;
        const newUsername = newUsernameRaw.length ? newUsernameRaw : oldUsername;
        const newEmail = newEmailRaw.length
        	? newEmailRaw
        	: (oldEmailFromStorage && oldEmailFromStorage.length ? oldEmailFromStorage : oldUsername);

        // Execute secure update
        const ok = await vaultUpdateAccount(oldWebsite, oldUsername, newWebsite, newUsername, newEmail, newPassword);

        // stay on page and show error
        if (!ok) {
            return; 
        }

        // Clean up context
        try {
            sessionStorage.removeItem("update_old_website");
            sessionStorage.removeItem("update_old_username");
            sessionStorage.removeItem("update_old_email");
            sessionStorage.removeItem("update_old_website_ct");
            sessionStorage.removeItem("update_old_username_ct");
            sessionStorage.removeItem("update_old_email_ct");
        } catch (e) {}

        // Redirect back to vault
        setTimeout(() => {     
            navigateTo("vault.html");
        }, 400);
    });
}

/**
 * Ensures this module only initializes when the expected
 * DOM structure is present.
 */
document.addEventListener("DOMContentLoaded", () => {
    try {
        if (document.getElementById("update-account-form")) {
            void initializeUpdateAccountPage();
        }
    } catch (e) {
        console.error("update_account.js DOMContentLoaded error:", e);
    }
});
