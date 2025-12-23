/**
 * File name: session_state.js
 * Author: Alex Biddle
 *
 * Description:
 *   Provides an in-memory client-side session object for CipherSafe's
 *   Four-Way Handshake. Tracks username, client RSA manager, server RSA
 *   public key, AES session key, key identifier, used nonces, handshake
 *   state, and TTL. Exports a shared singleton instance
 *   fourWaySessionState used by all handshake and UI modules.
 */


// Imports
import { HANDSHAKE_STATES, SESSION_TTL_SECONDS, AES_KEY_LENGTH_BYTES, CLIENT_HASH_LENGTH_BYTES, CLIENT_SALT_LENGTH_BYTES,  VAULT_SALT_LENGTH_BYTES} from "https://pascal/capstone/html/src/constants.js";

import { sanitizeUsername, sanitizeText, deepCopy } from "https://pascal/capstone/html/src/sanitization.js";
import { encodeBase64Url, decodeBase64Url, toUtf8Bytes } from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import { AesEncryptionManager } from "https://pascal/capstone/html/src/encryption/aes_encryption.js";
import { RsaEncryptionManager } from "https://pascal/capstone/html/src/encryption/rsa_encryption.js";


// Storage key for wrapped session blob (Option B)
const WRAPPED_SESSION_STORAGE_KEY = "cipherSafeWrappedSession";


//=============================================================================
//  SESSION STATE CLASS
//=============================================================================
export class SessionState {

    // Constructor initializes a blank session.
    constructor() {

        // Store client's username (bound to handshake)
        this._username = null;

        // Store client's RSA keypair (RsaEncryptionManager instance)
        this._clientRsaManager = null;

        // Store server's RSA public key (PEM string)
        this._serverRsaPublicKeyPem = null;

        // Store raw AES session key for Step 3/4 encryption
        this._serverAesSessionKeyBytes = null;

        // Store AES manager instance (using the AES session key)
        this._aesManager = null;

        // server-assigned key identifier (string)
        this._serverKeyIdentifier = null;

        // Client salt
        this._clientSaltBytes = null;

        // Vault salt
        this._vaultSaltBytes = null;

        // Vault key bytes (derived from password + vault_salt)
        this._vaultKeyBytes = null;

        // Client hash bytes
        this._clientHashBytes = null;

        // Nonce
        this._usedNonces = new Set();

        // handshake state (none, hello, secure, complete)
        this._handshakeState = HANDSHAKE_STATES.NONE;

        // Timestamp session was established
        this._sessionCreatedAt = null;

        // TTL seconds (15 minutes)
        this._ttlSeconds = SESSION_TTL_SECONDS;

        // Encryption key used for restoring the session object
        this._persistentEncryptionKey = null;
    }



    //=============================================================================
    // GETTERS
    //=============================================================================


    // Get username
    getUsername() {
        return this._username;
    }

    // Get client RSA manager
    getClientRsaManager() {
        return this._clientRsaManager;
    }

    // Get server RSA PEM public key
    getServerRsaPublicKeyPem() {
        return this._serverRsaPublicKeyPem;
    }

    // Get AES session key (raw bytes)
    getServerAesSessionKeyBytes() {
        return this._serverAesSessionKeyBytes ? new Uint8Array(this._serverAesSessionKeyBytes) : null;
    }

    // Get AES encryption manager
    getAesManager() {
        return this._aesManager;
    }

    // Get server key identifier
    getServerKeyIdentifier() {
        return this._serverKeyIdentifier;
    }

    // Get handshake state
    getHandshakeState() {
        return this._handshakeState;
    }

    // Get session creation timestamp
    getSessionCreatedAt() {
        return this._sessionCreatedAt;
    }

    // Get TTL seconds
    getTtlSeconds() {
        return this._ttlSeconds;
    }

    // Get used nonces set
    getUsedNonces() {
        return this._usedNonces;
    }

    // Get client_salt bytes
    getClientSaltBytes() {
        return this._clientSaltBytes ? new Uint8Array(this._clientSaltBytes) : null;
    }

    // Get vault_salt bytes
    getVaultSaltBytes() {
        return this._vaultSaltBytes ? new Uint8Array(this._vaultSaltBytes) : null;
    }

    // Get vaultKey bytes
    getVaultKeyBytes() {
        return this._vaultKeyBytes ? new Uint8Array(this._vaultKeyBytes) : null;
    }



    //=============================================================================
    //  SETTERS
    //=============================================================================


    /**
     * Set username (sanitized + validated).
     *
     * @param {string} username
     */
    setUsername(username) {
        const cleaned = sanitizeUsername(username);
        this._username = cleaned;
    }



    /**
     * Set the client-side RSA manager (constructed beforehand).
     *
     * @param {RsaEncryptionManager} mgr
     */
    setClientRsaManager(mgr) {
        if (!(mgr instanceof RsaEncryptionManager)) { throw new Error("setClientRsaManager: must be an instance of RsaEncryptionManager"); }
        this._clientRsaManager = mgr;
    }



    /**
     * Set the server's RSA public key (PEM string).
     *
     * @param {string} pem
     */
    setServerRsaPublicKeyPem(pem) {
        if (typeof pem !== "string" || !pem.trim()) { throw new Error("setServerRsaPublicKeyPem: PEM must be non-empty string"); }
        this._serverRsaPublicKeyPem = pem.trim();
    }



    /**
     * Set the raw AES session key bytes.
     *
     * @param {Uint8Array} keyBytes
     */
    setServerAesSessionKeyBytes(keyBytes) {

        if (!(keyBytes instanceof Uint8Array)) { throw new Error("setServerAesSessionKeyBytes: key must be Uint8Array"); }
        if (keyBytes.length !== AES_KEY_LENGTH_BYTES) { throw new Error(`setServerAesSessionKeyBytes: AES key must be ${AES_KEY_LENGTH_BYTES} bytes`); }

        this._serverAesSessionKeyBytes = new Uint8Array(keyBytes);
        this._aesManager = null;
    }



    /**
     * Set the server key_identifier.
     *
     * @param {string} keyId
     */
    setServerKeyIdentifier(keyId) {
        const cleaned = sanitizeText(keyId);
        this._serverKeyIdentifier = cleaned;
    }



    /**
     * Set handshake state (strict validation against enum).
     *
     * @param {string} state
     */
    setHandshakeState(state) {

        if (!Object.values(HANDSHAKE_STATES).includes(state)) { throw new Error(`setHandshakeState: invalid state '${state}'`); }
        this._handshakeState = state;
    }



    /**
     * Set client salt value
     *
     * @param {Uint8Array} saltBytes
     */
    setClientSaltBytes(saltBytes) {
        if (!(saltBytes instanceof Uint8Array)) { throw new Error("setClientSaltBytes: saltBytes must be Uint8Array"); }
        if (saltBytes.length !== CLIENT_SALT_LENGTH_BYTES) { throw new Error(`setClientSaltBytes: must be ${CLIENT_SALT_LENGTH_BYTES} bytes`); }
        this._clientSaltBytes = new Uint8Array(saltBytes);
    }



    /**
     * Set vault_salt value
     *
     * @param {Uint8Array} saltBytes
     */
    setVaultSaltBytes(saltBytes) {
        if (!(saltBytes instanceof Uint8Array)) { throw new Error("setVaultSaltBytes: saltBytes must be Uint8Array"); }
        if (saltBytes.length !== VAULT_SALT_LENGTH_BYTES) { throw new Error(`setVaultSaltBytes: must be ${VAULT_SALT_LENGTH_BYTES} bytes`); }
        this._vaultSaltBytes = new Uint8Array(saltBytes);
    }



    /**
     * Set clientHashBytes value
     *
     * @param {Uint8Array} bytes
     */
    setClientHashBytes(bytes) {
        if (!(bytes instanceof Uint8Array) || bytes.length !== CLIENT_HASH_LENGTH_BYTES) { throw new Error("client_hash must be 32 bytes"); }
        this._clientHashBytes = new Uint8Array(bytes);
    }



    /**
     * Set vaultKeyBytes value
     *
     * @param {Uint8Array} bytes
     */
    setVaultKeyBytes(bytes) {
        if (!(bytes instanceof Uint8Array)) { throw new Error("vaultKeyBytes must be Uint8Array"); }
        if (bytes.length !== AES_KEY_LENGTH_BYTES) { throw new Error(`vaultKeyBytes must be ${AES_KEY_LENGTH_BYTES} bytes`); }
        this._vaultKeyBytes = new Uint8Array(bytes);
    }



    //=============================================================================
    // SESSION TRANSITION HELPERS
    //=============================================================================

    /**
     * Populate session state after SERVER_HELLO.
     */
    setAfterServerHello({ serverRsaPublicKeyPem, serverKeyIdentifier, serverAesSessionKeyBytes, sessionCreatedAtIso8601 }) {

        // type checking
        if (typeof serverRsaPublicKeyPem !== "string" || !serverRsaPublicKeyPem.trim()) {
            throw new Error("SessionState.setAfterServerHello: serverRsaPublicKeyPem must be non-empty string");
        }
        if (typeof serverKeyIdentifier !== "string" || !serverKeyIdentifier.trim()) {
            throw new Error("SessionState.setAfterServerHello: serverKeyIdentifier must be non-empty string");
        }
        if (!(serverAesSessionKeyBytes instanceof Uint8Array)) {
            throw new Error("SessionState.setAfterServerHello: serverAesSessionKeyBytes must be Uint8Array");
        }
        if (typeof sessionCreatedAtIso8601 !== "string" || !sessionCreatedAtIso8601.endsWith("Z")) {
            throw new Error("SessionState.setAfterServerHello: sessionCreatedAtIso8601 must be ISO8601Z string");
        }

        // Set session data feilds
        this._serverRsaPublicKeyPem = serverRsaPublicKeyPem;
        this._serverKeyIdentifier = serverKeyIdentifier;
        this._serverAesSessionKeyBytes = new Uint8Array(serverAesSessionKeyBytes);
        this._sessionCreatedAt = sessionCreatedAtIso8601;
        this.setHandshakeState(HANDSHAKE_STATES.HELLO);
        this._aesManager = null;
    }


    /**
     * Adds a nonce to the nonce set
     */
    addUsedNonce(nonceB64u) {
        if (typeof nonceB64u !== "string" || !nonceB64u) {
            throw new Error("SessionState.addUsedNonce: nonceB64u must be non-empty string");
        }
        this._usedNonces.add(nonceB64u);
    }


    /**
     * Ensure AES-GCM manager is initialized.
     */
    async ensureAesManager() {

        // Ensure AES session key exists
        if (!this._serverAesSessionKeyBytes) { throw new Error("ensureAesManager: AES session key not set"); }

        // create AES manager if missing
        if (!this._aesManager) {
            this._aesManager = await AesEncryptionManager.create(this._serverAesSessionKeyBytes);
        }

        return this._aesManager;
    }


    /**
     * Determine whether the session has expired.
     */
    isExpired() {
        try {

            // Check if the creation timestamp is not null
            if (!this._sessionCreatedAt) {
                return true;
            }

            // Parse ISO8601 timestamp
            const createdMs = Date.parse(this._sessionCreatedAt);

            // Invalid timestamp means expired
            if (Number.isNaN(createdMs)) {
                return true;
            }

            // Get current time
            const nowMs = Date.now();

            // Compare elapsed time to TTL
            return (nowMs - createdMs) / 1000 > this._ttlSeconds;

        } catch {
            return true;
        }
    }


    // Reset all session state and cryptographic material
    resetSession() {

        this._username = null;
        this._sessionCreatedAt = null;
        this._handshakeState = HANDSHAKE_STATES.NONE;
        this._clientSaltBytes = null;
        this._vaultSaltBytes = null;
        this._clientHashBytes = null;
        this._vaultKeyBytes = null;
        this._serverRsaPublicKeyPem = null;
        this._serverKeyIdentifier = null;
        this._clientRsaManager = null;
        this._serverAesSessionKeyBytes = null;
        this._aesManager = null;
        this._usedNonces.clear();
        this._persistentEncryptionKey = null;
    }


    // Generate AES key used to encrypt persisted session data
    async generatePersistentEncryptionKey() {

        this._persistentEncryptionKey = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }


    // Persist encrypted session state to sessionStorage
    async persistToStorage() {
        try {

            // Abort if sessionStorage unavailable
            if (typeof sessionStorage === "undefined") { return; }

            // Require completed handshake
            if (this._handshakeState !== HANDSHAKE_STATES.COMPLETE) { throw new Error("SessionState.persistToStorage: handshake must be COMPLETE before persisting"); }

             // Generate wrap key if missing
            if (!this._persistentEncryptionKey) {
                await this.generatePersistentEncryptionKey();
            }

             // Placeholder for AES session key
            let aesKeyBytes = null;

            // Get AES manager raw key
            if (this._aesManager) {
                aesKeyBytes = this._aesManager.getRawKeyBytes();
            } else if (this._serverAesSessionKeyBytes) {
                aesKeyBytes = new Uint8Array(this._serverAesSessionKeyBytes);
            } else {
                throw new Error("SessionState.persistToStorage: missing AES session key");
            }

            // Ensure RSA manager supports exporting private key
            if (!this._clientRsaManager || typeof this._clientRsaManager.exportPrivateKeyPkcs8Bytes !== "function") {
                throw new Error("SessionState.persistToStorage: RSA manager missing or incompatible");
            }
            
            // Export RSA private key
            const rsaPrivatePkcs8Bytes = await this._clientRsaManager.exportPrivateKeyPkcs8Bytes();

            // Construct plaintext payload
            const payload = {
                username: this._username,
                handshake_state: this._handshakeState,
                session_created_at: this._sessionCreatedAt,
                ttl_seconds: this._ttlSeconds,
                server_rsa_public_key_pem: this._serverRsaPublicKeyPem,
                server_key_identifier: this._serverKeyIdentifier,
                aes_key_b64u: encodeBase64Url(aesKeyBytes),
                rsa_private_pkcs8_b64u: encodeBase64Url(rsaPrivatePkcs8Bytes),
                vault_salt_b64u: this._vaultSaltBytes ? encodeBase64Url(this._vaultSaltBytes) : null,
                vault_key_b64u: this._vaultKeyBytes ? encodeBase64Url(this._vaultKeyBytes) : null
            };
            
            // Convert payload to UTF-8 bytes
            const payloadBytes = toUtf8Bytes(JSON.stringify(payload));

            // Generate random IV
            const ivBytes = crypto.getRandomValues(new Uint8Array(12));

            // Encrypt payload
            const ciphertextArrayBuffer = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: ivBytes },
                this._persistentEncryptionKey,
                payloadBytes
            );

            // Convert ciphertext to Uint8Array
            const ciphertextBytes = new Uint8Array(ciphertextArrayBuffer);

            // Create wrapped session object
            const encryptedData = {
                version: 2,
                iv_b64u: encodeBase64Url(ivBytes),
                ciphertext_b64u: encodeBase64Url(ciphertextBytes)
            };

            // Store encrypted session
            sessionStorage.setItem(WRAPPED_SESSION_STORAGE_KEY, JSON.stringify(encryptedData));
            
            // Export wrap key
            const rawWrapKey = await crypto.subtle.exportKey("raw", this._persistentEncryptionKey);
            
            // Encode wrap key
            const wrapKeyB64u = encodeBase64Url(new Uint8Array(rawWrapKey));
            
            // Store wrap key
            sessionStorage.setItem("cipherSafeWrapKey", wrapKeyB64u);

        } catch (err) {
            console.error("SessionState.persistToStorage error:", err);
        }
    }


    // Determine whether encrypted session exists in storage
    hasEncryptedSessionInStorage() {
        try {

            // Abort if sessionStorage unavailable
            if (typeof sessionStorage === "undefined") {
                return false;
            }

            // Retrieve wrapped session data
            const raw = sessionStorage.getItem(WRAPPED_SESSION_STORAGE_KEY);
            return typeof raw === "string" && raw.length > 0;

        } catch {
            return false;
        }
    }


    // Remove encrypted session and wrap key
    clearEncryptedSessionInStorage() {
        if (typeof sessionStorage !== "undefined") {
            sessionStorage.removeItem(WRAPPED_SESSION_STORAGE_KEY);
            sessionStorage.removeItem("cipherSafeWrapKey");
        }
    }


    // Restore encrypted session from storage
    async restoreFromStorage() {
        try {

            // Abort if sessionStorage unavailable
            if (typeof sessionStorage === "undefined") {
                return false;
            }
            
            // Retrieve wrap key
            const wrapKeyB64u = sessionStorage.getItem("cipherSafeWrapKey");
            if (!wrapKeyB64u) {
                return false;
            }

            // Decode wrap key
            const rawWrapKeyBytes = decodeBase64Url(wrapKeyB64u);

            // Import wrap key
            this._persistentEncryptionKey = await crypto.subtle.importKey(
                "raw",
                rawWrapKeyBytes,
                { name: "AES-GCM" },
                false,
                ["encrypt", "decrypt"]
            );

            // Retrieve encrypted payload
            const raw = sessionStorage.getItem(WRAPPED_SESSION_STORAGE_KEY);
            if (!raw) {
                return false;
            }


            // Parse JSON
            let data;
            try {
                data = JSON.parse(raw);
            } catch {
                console.error("SessionState.restoreFromStorage: corrupt wrapped blob");
                return false;
            }

            // Decode IV
            const ivBytes = decodeBase64Url(data.iv_b64u);
            
            // Decode ciphertext
            const ciphertextBytes = decodeBase64Url(data.ciphertext_b64u);

            // Decrypt payload
            const plaintextBuffer = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: ivBytes },
                this._persistentEncryptionKey,
                ciphertextBytes
            );

            // Decode plaintext JSON
            const payloadJson = new TextDecoder().decode(plaintextBuffer);
            
            // Parse payload
            const payload = JSON.parse(payloadJson);

            // Reset current session
            this.resetSession();

            // Restore core fields
            this._username = payload.username;
            this._handshakeState = payload.handshake_state;
            this._sessionCreatedAt = payload.session_created_at;
            this._ttlSeconds = payload.ttl_seconds;
            this._serverRsaPublicKeyPem = payload.server_rsa_public_key_pem;
            this._serverKeyIdentifier = payload.server_key_identifier;

            // Restore AES session key
            const aesKeyBytes = decodeBase64Url(payload.aes_key_b64u);
            this._serverAesSessionKeyBytes = aesKeyBytes;
            
            // Recreate AES manager
            this._aesManager = await AesEncryptionManager.create(aesKeyBytes);
            
             // Restore RSA private key
            const rsaPkcs8Bytes = decodeBase64Url(payload.rsa_private_pkcs8_b64u);
            this._clientRsaManager = await RsaEncryptionManager.importPrivateKeyPkcs8Bytes(
                rsaPkcs8Bytes,
                this._serverRsaPublicKeyPem
            );

            // Restore vault salt
            if (payload.vault_salt_b64u) {
                const vaultSaltBytes = decodeBase64Url(payload.vault_salt_b64u);
                this._vaultSaltBytes = new Uint8Array(vaultSaltBytes);
            }
            
            // Restore vault key
            if (payload.vault_key_b64u) {

                const vaultKeyBytes = decodeBase64Url(payload.vault_key_b64u);

                if (!(vaultKeyBytes instanceof Uint8Array)) {throw new Error("restoreFromStorage: vaultKeyBytes invalid");}
                if (vaultKeyBytes.length !== AES_KEY_LENGTH_BYTES) {throw new Error("restoreFromStorage: vaultKeyBytes wrong length");}

                this._vaultKeyBytes = new Uint8Array(vaultKeyBytes);
            }

            return true;

        } catch (err) {
            console.error("SessionState.restoreFromStorage error:", err);
            return false;
        }
    }


    // Return a safe copy of session metadata
    getFullSessionState() {
        return deepCopy({
            username: this._username,
            handshake_state: this._handshakeState,
            server_rsa_public_key_pem: this._serverRsaPublicKeyPem,
            server_key_identifier: this._serverKeyIdentifier,
            ttl_seconds: this._ttlSeconds,
            session_created_at: this._sessionCreatedAt,
            used_nonce_count: this._usedNonces.size,
            client_salt_b64u: this._clientSaltBytes ? encodeBase64Url(this._clientSaltBytes) : null,
            vault_salt_b64u: this._vaultSaltBytes ? encodeBase64Url(this._vaultSaltBytes) : null,
            vault_key_b64u: this._vaultKeyBytes ? encodeBase64Url(this._vaultKeyBytes) : null
        });
    }
}


export const fourWaySessionState = new SessionState();
