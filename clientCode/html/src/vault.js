/**
 * File name: vault.js
 * Author: Alex Biddle
 *
 * Description:
 *      Page module for vault.html. Contains ONLY the vault page DOM logic
 */

import { showStatusMessage, clearStatusMessage, navigateTo, showErrorAlert } from "https://pascal/capstone/html/src/ui.js";
import { sanitizePassword } from "https://pascal/capstone/html/src/sanitization.js";
import { REQUEST_TYPES, RESPONSE_STATUSES } from "https://pascal/capstone/html/src/constants.js";
import { encryptVaultField, decryptVaultField } from "https://pascal/capstone/html/src/encryption/vault_encryption.js";
import { buildClientSecureRequestPacket } from "https://pascal/capstone/html/src/handshake/client_secure_request.js";
import { runServerSecureResponse } from "https://pascal/capstone/html/src/handshake/server_secure_response.js";
import { fourWaySessionState } from "https://pascal/capstone/html/src/handshake/session_state.js";
import { ensureSecureSessionOrRedirect, requireVaultKeyBytes, sanitizeWebsite, sanitizeAccountField, handleLogout, ensureVaultKeyReady} from "https://pascal/capstone/html/src/vault_api.js";




/**
 * Securely fetches encrypted vault metadata from the server,
 * decrypts each entry client-side, and renders the vault table.
 *
 * @ensures Session is valid, vault key exists, and all decryption occurs exclusively on the client
 * @returns {Promise<void>}
 */
export async function fetchAndRenderVaultAccounts() {

    // Ensure the secure session (AES+RSA) is ready; otherwise redirect.
    if (!(await ensureSecureSessionOrRedirect())) {
        return;
    }

    // Ensure vault key is present
    const vaultKeyBytes = requireVaultKeyBytes("vault-status");
    if (!vaultKeyBytes) {
        return;
    }

    // Locate the vault list container on vault.html.
    const vaultList = document.getElementById("vault-list");
    if (!vaultList) {
        return;
    }

    // Clear previous contents before rendering.
    vaultList.innerHTML = "";

    try {
        
        // Inform the user that loading is in progress.
        showStatusMessage("vault-status", "Loading vault accounts...", "info");

        // Payload for VAULT_FETCH_ACCOUNTS is empty; all metadata is server-derived.
        const payload = {};

        // Build a secure Step-3 packet targeting VAULT_FETCH_ACCOUNTS.
        const requestPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.VAULT_FETCH_ACCOUNTS, payload, fourWaySessionState);

        // Send secure request and process the Step-4 server response.
        const secureResult = await runServerSecureResponse(requestPacket, fourWaySessionState);

        // Handle Errors
        if (secureResult && typeof secureResult === "object" && "ok" in secureResult) {
            if (!secureResult.ok) {
                const statusCode = secureResult.status ?? "unknown";
                showStatusMessage("vault-status", `Failed to fetch vault (HTTP ${statusCode}).`, "error");
                return;
            }
        }

        // Handle Server logout
        if (secureResult && secureResult.kind === "logout") {
            showStatusMessage("vault-status", "Session was closed by the server.", "error");
            navigateTo("index.html");
            return;
        }

        // Extract status and payload from the decrypted server response.
        const { responseStatus, payload: responsePayload } = secureResult || {};

        // Non-success status: show application error context.
        if (responseStatus !== RESPONSE_STATUSES.SUCCESS) {
            if (responsePayload && typeof responsePayload.application_code === "string") {
                showErrorAlert(responsePayload.application_code, "vault");
            }

            const msg = (responsePayload && typeof responsePayload.message === "string")? responsePayload.message: "Server reported an error fetching accounts.";
            showStatusMessage("vault-status", msg, "error");
            return;
        }

        // Extract accounts array from payload; default to [] if missing.
        const accounts = Array.isArray(responsePayload.accounts) ? responsePayload.accounts : [];

        // No accounts present → show a friendly empty-vault message.
        if (accounts.length === 0) {
            showStatusMessage("vault-status", "Your vault is empty. Add your first entry!", "info");
            return;
        }

        // Clear loading status once we have entries.
        clearStatusMessage("vault-status");

        // Render headings
        renderVaultHeadings(vaultList);

        // Decrypt each account row and render
        for (const entry of accounts) {
            try {
                const websitePlain = await decryptVaultField(entry.website, vaultKeyBytes);
                const accountUsernamePlain = await decryptVaultField(entry.account_username, vaultKeyBytes);
                const accountEmailPlain = await decryptVaultField(entry.account_email, vaultKeyBytes);

                renderVaultEntry(vaultList, {
                    item_id: entry.item_id,
                    websitePlain,
                    accountUsernamePlain,
                    accountEmailPlain,
                    websiteCt: entry.website,
                    accountUsernameCt: entry.account_username,
                    accountEmailCt: entry.account_email,
                    accountPasswordCt: entry.account_password
                });

            } catch (e) {
                console.error("fetchAndRenderVaultAccounts: error decrypting entry:", e, entry);
                // Skip corrupted entries but keep rendering others
            }
        }

    } catch (err) {
        console.error("fetchAndRenderVaultAccounts error:", err);
        showStatusMessage("vault-status", "Unexpected error loading vault.", "error");
    }
}



/**
 * Fetches and decrypts a single vault password on demand.
 *
 * @param {string} websiteCt         - Website ciphertext identifier
 * @param {string} accountUsernameCt - Username ciphertext identifier
 * @param {boolean} returnValue      - If true, returns password instead of alert
 * @returns {Promise<string|void>}
 */
export async function handleFetchPassword(websiteCt, accountUsernameCt, returnValue = false) {

    // Enforce secure session before any cryptographic operations.
    if (!(await ensureSecureSessionOrRedirect())) {
        return;
    }

    const vaultKeyBytes = requireVaultKeyBytes("vault-status");
    if (!vaultKeyBytes) {
        return;
    }

    try {
        // Basic type checks
        if (typeof websiteCt !== "string" || !websiteCt) {throw new Error("handleFetchPassword: website ciphertext missing");}
        if (typeof accountUsernameCt !== "string" || !accountUsernameCt) {throw new Error("handleFetchPassword: account_username ciphertext missing");}

        // Payload specifying which entry's password is requested (by ciphertext keys).
        const payload = {
            website: websiteCt,
            account_username: accountUsernameCt
        };

        // Build secure Step-3 request for VAULT_FETCH_ACCOUNT_PASSWORD.
        const requestPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.VAULT_FETCH_ACCOUNT_PASSWORD, payload, fourWaySessionState);

        // Send and process secure Step-4 response.
        const secureResult = await runServerSecureResponse(requestPacket, fourWaySessionState);

        // Handle errors
        if (secureResult && typeof secureResult === "object" && "ok" in secureResult) {
            if (!secureResult.ok) {
                const statusCode = secureResult.status ?? "unknown";
                showStatusMessage("vault-status", `Failed to fetch password (HTTP ${statusCode}).`, "error");
                return;
            }
        }

        // Handle server logout
        if (secureResult && secureResult.kind === "logout") {
            showStatusMessage("vault-status", "Session was closed by the server.", "error");
            navigateTo("index.html");
            return;
        }

        // Extract status and response payload.
        const { responseStatus, payload: responsePayload } = secureResult || {};

        // Non-success response; show application-level error messaging.
        if (responseStatus !== RESPONSE_STATUSES.SUCCESS) {
            if (responsePayload && typeof responsePayload.application_code === "string") {
                showErrorAlert(responsePayload.application_code, "vault");
            }

            const msg = (responsePayload && typeof responsePayload.message === "string")? responsePayload.message: "Server reported an error fetching password.";

            showStatusMessage("vault-status", msg, "error");
            return;
        }

        // Extract the encrypted account password and decrypt it.
        const accountPasswordCt = responsePayload.account_password || "";
        const accountPassword = await decryptVaultField(accountPasswordCt, vaultKeyBytes);
        if (returnValue) {
            return accountPassword;
        }

        alert(`Password: ${accountPassword}`);

    } catch (err) {
        console.error("handleFetchPassword error:", err);
        showStatusMessage("vault-status", "Unexpected error fetching password.", "error");
    }
}



/**
 * Securely deletes a vault entry after user confirmation.
 *
 * @param {string} websiteCt
 * @param {string} accountUsernameCt
 * @param {string} websitePlain
 * @param {string} accountUsernamePlain
 */
export async function handleDeleteAccount(websiteCt, accountUsernameCt, websitePlain, accountUsernamePlain) {

    // Enforce secure session before performing deletion.
    if (!(await ensureSecureSessionOrRedirect())) {
        return;
    }

    // Confirm with the user before deleting (using plaintext label).
    const confirmDelete = window.confirm(`Delete entry for ${websitePlain} / ${accountUsernamePlain}?`);

    if (!confirmDelete) {
        return;
    }

    try {

        // Type checking
        if (typeof websiteCt !== "string" || !websiteCt) {throw new Error("handleDeleteAccount: website ciphertext missing");}
        if (typeof accountUsernameCt !== "string" || !accountUsernameCt) {throw new Error("handleDeleteAccount: account_username ciphertext missing");}

        // Payload describing which entry to delete (ciphertext keys).
        const payload = {
            website: websiteCt,
            account_username: accountUsernameCt
        };

        // Build secure Step-3 request for VAULT_DELETE_ACCOUNT.
        const requestPacket = await buildClientSecureRequestPacket(REQUEST_TYPES.VAULT_DELETE_ACCOUNT, payload, fourWaySessionState);

        // Send and process secure Step-4 response.
        const secureResult = await runServerSecureResponse(requestPacket, fourWaySessionState);

        // Handle errors
        if (secureResult && typeof secureResult === "object" && "ok" in secureResult) {
            if (!secureResult.ok) {
                const statusCode = secureResult.status ?? "unknown";
                showStatusMessage("vault-status", `Failed to delete account (HTTP ${statusCode}).`, "error");
                return;
            }
        }

        // Handle server logout 
        if (secureResult && secureResult.kind === "logout") {
            showStatusMessage("vault-status", "Session was closed by the server.", "error");
            navigateTo("index.html");
            return;
        }

        // Extract status and payload.
        const { responseStatus, payload: responsePayload } = secureResult || {};

        // Non-success responses show meaningful error messages.
        if (responseStatus !== RESPONSE_STATUSES.SUCCESS) {
            if (responsePayload && typeof responsePayload.application_code === "string") {
                showErrorAlert(responsePayload.application_code, "vault");
            }

            const msg = (responsePayload && typeof responsePayload.message === "string") ? responsePayload.message : "Server reported an error deleting account.";

            showStatusMessage("vault-status", msg, "error");
            return;
        }

        // Success: notify user and refresh vault listing.
        showStatusMessage("vault-status", "Account deleted.", "success");
        await ensureVaultKeyReady();
        await fetchAndRenderVaultAccounts();

    } catch (err) {
        console.error("handleDeleteAccount error:", err);
        showStatusMessage("vault-status", "Unexpected error deleting account.", "error");
    }
}




function renderVaultHeadings(container) {

    const header = document.createElement("div");
    header.className = "vault-entry";
    header.dataset.header = "1"; // so search does not hide it

    header.style.setProperty("display", "grid", "important");
    header.style.setProperty("grid-template-columns", "200px 160px 220px 140px 1fr", "important");
    header.style.setProperty("align-items", "center", "important");
    header.style.setProperty("column-gap", "14px", "important");
    header.style.setProperty("padding", "8px 0", "important");
    header.style.setProperty("border-bottom", "1px solid rgba(0,0,0,0.15)", "important");
    header.style.setProperty("font-weight", "700", "important");
    header.style.setProperty("opacity", "0.85", "important");

    const makeHead = (text, alignRight = false) => {
        const el = document.createElement("div");
        el.textContent = text;
        el.style.setProperty("white-space", "nowrap", "important");
        if (alignRight) {
            el.style.setProperty("text-align", "right", "important");
        }
        return el;
    };

    header.appendChild(makeHead("Website"));
    header.appendChild(makeHead("Username"));
    header.appendChild(makeHead("Email"));
    header.appendChild(makeHead("Password"));
    header.appendChild(makeHead("Actions", true));

    container.appendChild(header);
}

export function renderVaultEntry(container, entry) {

    const website = entry.websitePlain || "";
    const accountUsername = entry.accountUsernamePlain || "";
    const accountEmail = entry.accountEmailPlain || "";

    const websiteCt = entry.websiteCt || "";
    const accountUsernameCt = entry.accountUsernameCt || "";
    const accountEmailCt = entry.accountEmailCt || "";
    const accountPasswordCt = entry.accountPasswordCt || "";

    // Row wrapper
    const row = document.createElement("div");
    row.className = "vault-entry";

    row.style.setProperty("display", "grid", "important");
    row.style.setProperty("grid-template-columns", "200px 160px 220px 150px 1fr", "important");
    row.style.setProperty("align-items", "center", "important");
    row.style.setProperty("column-gap", "14px", "important");
    row.style.setProperty("padding", "10px 0", "important");
    row.style.setProperty("width", "100%", "important");

    // Store ciphertexts on the row for future actions (defense-in-depth)
    row.dataset.websiteCt = websiteCt;
    row.dataset.accountUsernameCt = accountUsernameCt;
    row.dataset.accountEmailCt = accountEmailCt;
    row.dataset.accountPasswordCt = accountPasswordCt;

    const makeCell = (text, cls) => {
        const el = document.createElement("div");
        el.className = cls;
        el.textContent = text;
        el.style.whiteSpace = "nowrap";
        el.style.overflow = "hidden";
        el.style.textOverflow = "ellipsis";
        return el;
    };

    const websiteEl = makeCell(website, "vault-entry-website");
    const usernameEl = makeCell(accountUsername, "vault-entry-username");
    const emailEl = makeCell(accountEmail, "vault-entry-email");

    // PASSWORD CELL (starts as dots)
    const passwordEl = document.createElement("div");
    passwordEl.className = "vault-entry-password";
    passwordEl.textContent = "••••••••";
    passwordEl.style.fontFamily = "monospace";
    passwordEl.style.letterSpacing = "2px";
    passwordEl.style.setProperty("white-space", "nowrap", "important");
    passwordEl.style.setProperty("overflow", "hidden", "important");
    passwordEl.style.setProperty("text-overflow", "ellipsis", "important");
    passwordEl.style.setProperty("max-width", "320px", "important");

    // Actions column
    const actions = document.createElement("div");
    actions.className = "vault-entry-actions";
    actions.style.display = "flex";
    actions.style.justifyContent = "flex-end";
    actions.style.gap = "8px";

    const btnView = document.createElement("button");
    btnView.type = "button";
    btnView.textContent = "View Password";

    const btnCopy = document.createElement("button");
    btnCopy.type = "button";
    btnCopy.textContent = "Copy";
    btnCopy.disabled = true;

    const btnDelete = document.createElement("button");
    btnDelete.type = "button";
    btnDelete.textContent = "Delete";

    const btnUpdate = document.createElement("button");
    btnUpdate.type = "button";
    btnUpdate.textContent = "Update";

    // Make buttons fit nicely
    const styleBtn = (btn, w) => {
        btn.style.padding = "7px 10px";
        btn.style.minWidth = w;
        btn.style.fontSize = "13px";
        btn.style.whiteSpace = "nowrap";
    };
    styleBtn(btnView, "120px");
    styleBtn(btnCopy, "70px");
    styleBtn(btnDelete, "70px");
    styleBtn(btnUpdate, "70px");

    // -----------------------------
    // BUTTON: VIEW PASSWORD (TOGGLE)
    // -----------------------------
    let passwordShown = false;

    btnView.addEventListener("click", async () => {

        // If password already visible → hide it
        if (passwordShown) {
            passwordEl.textContent = "••••••••";
            btnView.textContent = "View Password";
            passwordShown = false;
            return;
        }

        // Fetch and decrypt password from server using ciphertext keys
        const password = await handleFetchPassword(websiteCt, accountUsernameCt, true);

        if (!password) {
            showStatusMessage("vault-status", "Unable to retrieve password.", "error");
            return;
        }

        // Reveal password in the table cell
        passwordEl.textContent = password;
        btnView.textContent = "Hide Password";
        passwordShown = true;

        // Enable copy button
        btnCopy.disabled = false;
        btnCopy.dataset.password = password;
    });

    // -----------------------------
    // COPY BUTTON
    // -----------------------------
    btnCopy.addEventListener("click", async () => {
        const password = btnCopy.dataset.password || "";
        if (!password) {
            showStatusMessage("vault-status", "View password first.", "error");
            return;
        }
        await navigator.clipboard.writeText(password);
        showStatusMessage("vault-status", "Password copied!", "success");
    });

    // -----------------------------
    // UPDATE BUTTON (GO TO update_account.html)
    // -----------------------------
    btnUpdate.addEventListener("click", () => {

        if (typeof sessionStorage !== "undefined") {
            // Save plaintext context (for form prefill)
            sessionStorage.setItem("update_old_website", website);
            sessionStorage.setItem("update_old_username", accountUsername);
            sessionStorage.setItem("update_old_email", accountEmail);

            // Save ciphertext context (for server update keys)
            sessionStorage.setItem("update_old_website_ct", websiteCt);
            sessionStorage.setItem("update_old_username_ct", accountUsernameCt);
            sessionStorage.setItem("update_old_email_ct", accountEmailCt);
        }

        navigateTo("update_account.html");
    });

    // -----------------------------
    // DELETE BUTTON
    // -----------------------------
    btnDelete.addEventListener("click", () => {
        void handleDeleteAccount(websiteCt, accountUsernameCt, website, accountUsername);
    });

    // Assemble row
    actions.appendChild(btnView);
    actions.appendChild(btnCopy);
    actions.appendChild(btnUpdate);
    actions.appendChild(btnDelete);

    row.appendChild(websiteEl);
    row.appendChild(usernameEl);
    row.appendChild(emailEl);
    row.appendChild(passwordEl);
    row.appendChild(actions);

    container.appendChild(row);
}

export function enableVaultSearch() {

    const searchInput = document.getElementById("search");
    const vaultList = document.getElementById("vault-list");

    if (!searchInput || !vaultList) return;

    searchInput.addEventListener("input", () => {

        const query = (searchInput.value || "").toLowerCase().trim();
        const entries = vaultList.querySelectorAll(".vault-entry");

        entries.forEach(entry => {

            // Keep header always visible + keep its grid layout
            if (entry.dataset && entry.dataset.header === "1") {
                entry.style.setProperty("display", "grid", "important");
                return;
            }

            const text = (entry.textContent || "").toLowerCase();
            const match = query.length === 0 || text.includes(query);

            if (match) {
                entry.style.setProperty("display", "grid", "important");
            } else {
                entry.style.setProperty("display", "none", "important");
            }
        });
    });
}



/**
 * Wires all vault page UI controls and triggers initial vault load.
 *
 * @ensures Vault page is fully interactive and secure
 */
export async function initializeVaultPage() {

    const btnAdd = document.getElementById("btn-add");
    if (btnAdd) {
        btnAdd.addEventListener("click", () => {
            navigateTo("add.html");
        });
    }

    const btnUpdateAccount = document.getElementById("btn-update-account");
    if (btnUpdateAccount) {
        btnUpdateAccount.addEventListener("click", () => {
            navigateTo("update_account.html");
        });
    }

    const btnUpdateMaster = document.getElementById("btn-update-master-password");
    if (btnUpdateMaster) {
        btnUpdateMaster.addEventListener("click", () => {
            navigateTo("update_master_password.html");
        });
    }

    const btnLogout = document.getElementById("btn-logout");
    if (btnLogout) {
        btnLogout.addEventListener("click", () => {
            void handleLogout();
        });
    }

    // Autofill the "current" account fields if we came from a vault row "Update" button.
    const oldWebsitePrefill = document.getElementById("old-website");
    const oldUsernamePrefill = document.getElementById("old-username");

    if (oldWebsitePrefill && oldUsernamePrefill && typeof sessionStorage !== "undefined") {
        const storedWebsite = sessionStorage.getItem("update_old_website");
        const storedUsername = sessionStorage.getItem("update_old_username");

        if (storedWebsite && storedUsername) {
            oldWebsitePrefill.value = storedWebsite;
            oldUsernamePrefill.value = storedUsername;

            // Lock identity fields to avoid updating the wrong record.
            oldWebsitePrefill.readOnly = true;
            oldUsernamePrefill.readOnly = true;
        }
    }

    enableVaultSearch();
    void fetchAndRenderVaultAccounts();
}

// Auto-start when this script is loaded on vault.html
document.addEventListener("DOMContentLoaded", () => {
    try {
        if (document.getElementById("vault-list")) {
            void initializeVaultPage();
        }
    } catch (e) {
        console.error("vault.js DOMContentLoaded error:", e);
    }
});
