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
import {HANDSHAKE_STATES, SESSION_TTL_SECONDS, AES_KEY_LENGTH_BYTES, CLIENT_HASH_LENGTH_BYTES, CLIENT_SALT_LENGTH_BYTES, VAULT_SALT_LENGTH_BYTES} from "https://pascal/capstone/html/src/constants.js";
import {sanitizeUsername, sanitizeText, deepCopy} from "https://pascal/capstone/html/src/sanitization.js";
import { encodeBase64Url, decodeBase64Url, toUtf8Bytes} from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
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

        // Vault key bytes
        this._vaultKeyBytes = null;
        
        // Vault key has been derived
        this._vaultKeyDerived = false;
        
        // Client hashed bytes
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
        return this._serverAesSessionKeyBytes? new Uint8Array(this._serverAesSessionKeyBytes): null;
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

    // In session_state.js 
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
    
    // Vault key is derived
    isVaultKeyExpected() {
        return this._vaultKeyDerived === true;
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
        if (!(mgr instanceof RsaEncryptionManager)) {throw new Error("setClientRsaManager: must be an instance of RsaEncryptionManager");}
        this._clientRsaManager = mgr;
    }



    /**
     * Set the server's RSA public key (PEM string).
     *
     * @param {string} pem
     */
    setServerRsaPublicKeyPem(pem) {
        if (typeof pem !== "string" || !pem.trim()) {throw new Error("setServerRsaPublicKeyPem: PEM must be non-empty string");}
        this._serverRsaPublicKeyPem = pem.trim();
    }



    /**
     * Set the raw AES session key bytes.
     *
     * @param {Uint8Array} keyBytes
     */
    setServerAesSessionKeyBytes(keyBytes) {

        if (!(keyBytes instanceof Uint8Array)) {throw new Error("setServerAesSessionKeyBytes: key must be Uint8Array");}
        if (keyBytes.length !== AES_KEY_LENGTH_BYTES) {throw new Error(`setServerAesSessionKeyBytes: AES key must be ${AES_KEY_LENGTH_BYTES} bytes`);}

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

        if (!Object.values(HANDSHAKE_STATES).includes(state)) {throw new Error(`setHandshakeState: invalid state '${state}'`);}
        this._handshakeState = state;
    }



    /**
     * Set client salt value
     *
     * @param {string} state
     */
    setClientSaltBytes(saltBytes) {
        if (!(saltBytes instanceof Uint8Array)) {throw new Error("setClientSaltBytes: saltBytes must be Uint8Array");}
        if (saltBytes.length !== CLIENT_SALT_LENGTH_BYTES) {throw new Error(`setClientSaltBytes: must be ${CLIENT_SALT_LENGTH_BYTES} bytes`);}
        this._clientSaltBytes = new Uint8Array(saltBytes);
    }


    /**
     * Set vault_salt value 
     *
     * @param {Uint8Array} saltBytes
     */
    setVaultSaltBytes(saltBytes) {
        if (!(saltBytes instanceof Uint8Array)) {throw new Error("setVaultSaltBytes: saltBytes must be Uint8Array");}
        if (saltBytes.length !== VAULT_SALT_LENGTH_BYTES) {throw new Error(`setVaultSaltBytes: must be ${VAULT_SALT_LENGTH_BYTES} bytes`);}
        this._vaultSaltBytes = new Uint8Array(saltBytes);
    }


    /**
     * Set clientHashBytes value 
     *
     * @param {Uint8Array} saltBytes
     */
    setClientHashBytes(bytes) {
        if (!(bytes instanceof Uint8Array) || bytes.length !== CLIENT_HASH_LENGTH_BYTES) {throw new Error("client_hash must be 32 bytes");}
        this._clientHashBytes = new Uint8Array(bytes);
    }


    /**
     * Set vaultKeyBytes value
     *
     * @param {Uint8Array} saltBytes
     */
    setVaultKeyBytes(bytes) {
        if (!(bytes instanceof Uint8Array)) {throw new Error("vaultKeyBytes must be Uint8Array");}
        if (bytes.length !== AES_KEY_LENGTH_BYTES) {throw new Error(`vaultKeyBytes must be ${AES_KEY_LENGTH_BYTES} bytes`);}
        this._vaultKeyBytes = new Uint8Array(bytes);
        this._vaultKeyDerived = true;
    }
    
    
    /**
     * Restore the vaultKeyBytes value
     *
     * @param {Uint8Array} saltBytes
     */
    restoreVaultKeyBytes(bytes) {
        this.setVaultKeyBytes(bytes);
    }
    

    //=============================================================================
    // SESSION TRANSITION 
    //=============================================================================
   
      /**
     * Called after Server Hello (Step 2)
     *
     * Sets:
     *   - server RSA public key
     *   - server AES session key bytes
     *   - server key_identifier
     *   - handshake state → HELLO
     *   - sessionCreatedAt timestamp
     */
    setAfterServerHello({serverRsaPublicKeyPem, serverKeyIdentifier, serverAesSessionKeyBytes, sessionCreatedAtIso8601}) {

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

        this._serverRsaPublicKeyPem = serverRsaPublicKeyPem;
        this._serverKeyIdentifier = serverKeyIdentifier;
        this._serverAesSessionKeyBytes = new Uint8Array(serverAesSessionKeyBytes);
        this._sessionCreatedAt = sessionCreatedAtIso8601;
        this.setHandshakeState(HANDSHAKE_STATES.HELLO);
        this._aesManager = null;
    }
    
    

    /**
     * Add nonce to the nonce set.
     */
    addUsedNonce(nonceB64u) {
        if (typeof nonceB64u !== "string" || !nonceB64u) {
            throw new Error("SessionState.addUsedNonce: nonceB64u must be non-empty string");
        }
        this._usedNonces.add(nonceB64u);
    }


    /**
     * Create AES manager when needed.
     *
     * @returns {AesEncryptionManager}
     */
    async ensureAesManager() {

        if (!this._serverAesSessionKeyBytes) {throw new Error("ensureAesManager: AES session key not set");}
        if (!this._aesManager) {
            this._aesManager = await AesEncryptionManager.create(this._serverAesSessionKeyBytes);
        }

        return this._aesManager;
    }



    /**
     * Check whether session TTL has expired.
     *
     * @returns {boolean}
     */
    isExpired() {
        try {

            // Check that the session date time exists
            if (!this._sessionCreatedAt) {
                return true;
            }

            // Parse the datetime
            const createdMs = Date.parse(this._sessionCreatedAt);
            if (Number.isNaN(createdMs)) {
                return true;
            }

            // Verify valid session time
            const nowMs = Date.now();
            return (nowMs - createdMs) / 1000 > this._ttlSeconds;
        } catch {
            return true;
        }
    }

    
    
    /**
     * Wipe session completely.
     */
    resetSession() {
        this._username = null;
        this._sessionCreatedAt = null;
        this._handshakeState = HANDSHAKE_STATES.NONE;
        this._clientSaltBytes = null;
        this._vaultSaltBytes = null;
        this._clientHashBytes = null;
        this._vaultKeyBytes = null;
        this._vaultKeyDerived = false;
        this._serverRsaPublicKeyPem = null;
        this._serverKeyIdentifier = null;
        this._clientRsaManager = null;
        this._serverAesSessionKeyBytes = null;
        this._aesManager = null;
        this._usedNonces.clear();
        this._persistentEncryptionKey = null;
    }
    
    
	/**
	 * Generate a non-extractable AES-GCM key for wrapping the persistent
	 * session data. This key lives only in memory and is lost on full
	 * page reload / tab close.
	 *
	 * @returns {Promise<void>}
	 */
	async generatePersistentEncryptionKey() {

          
		// Create encryption key
		this._persistentEncryptionKey = await crypto.subtle.generateKey(
			{ name: "AES-GCM", length: 256 },
			true,              
			["encrypt", "decrypt"]
			);

	}
	
	

    /**
	 * Persist sensitive session state (AES key + client RSA private key) into
	 * sessionStorage by wrapping it with a non-extractable AES-GCM key
	 * generated by WebCrypto.
	 *
	 * @returns {Promise<void>}
	 */
    async persistToStorage() {
        try {
            
            // Validate parameters
            if (typeof sessionStorage === "undefined") {return;}
            if (this._handshakeState !== HANDSHAKE_STATES.COMPLETE) {throw new Error("SessionState.persistToStorage: handshake must be COMPLETE before persisting");}
        
            // Ensure we have a encryption key. If missing, generate one.
			if (!this._persistentEncryptionKey) {
				await this.generatePersistentEncryptionKey();
			}
			
			// Get the raw key bytes from the aes encryption object
			let aesKeyBytes = this._aesManager? this._aesManager.getRawKeyBytes(): this._serverAesSessionKeyBytes;
			
			// Ensure the RSA key exists
			if (!this._clientRsaManager || typeof this._clientRsaManager.exportPrivateKeyPkcs8Bytes !== "function") {
				throw new Error("SessionState.persistToStorage: RSA manager missing or incompatible");
			}
            
            // Get the private encryption rsa key
			const rsaPrivatePkcs8Bytes = await this._clientRsaManager.exportPrivateKeyPkcs8Bytes();

            // Create the session data payload to encrypt
			const payload = {
				username: this._username,
				handshake_state: this._handshakeState,
				session_created_at: this._sessionCreatedAt,
				ttl_seconds: this._ttlSeconds,
				server_rsa_public_key_pem: this._serverRsaPublicKeyPem,
				server_key_identifier: this._serverKeyIdentifier,
				aes_key_b64u: encodeBase64Url(aesKeyBytes),
				rsa_private_pkcs8_b64u: encodeBase64Url(rsaPrivatePkcs8Bytes),
                vault_salt_b64u: encodeBase64Url(this._vaultSaltBytes),
                vault_key_b64u: this._vaultKeyBytes? encodeBase64Url(this._vaultKeyBytes): null
			};
            
            // Convert the payloadto bytes
			const payloadBytes = toUtf8Bytes(JSON.stringify(payload));
	
			// Get the IV for encryption
			const ivBytes = crypto.getRandomValues(new Uint8Array(12));
            
            // Encrypt the payload
			const ciphertextArrayBuffer = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: ivBytes },
				this._persistentEncryptionKey,
				payloadBytes
			);
            
            // Create a new unit8 array with the ciphertext payload
			const ciphertextBytes = new Uint8Array(ciphertextArrayBuffer);

            // Create the encrypted data object
			const encryptedData = {
				version: 2,
				iv_b64u: encodeBase64Url(ivBytes),
				ciphertext_b64u: encodeBase64Url(ciphertextBytes)
			};
            
            // Add the encrypted session data to the session storage
			sessionStorage.setItem( WRAPPED_SESSION_STORAGE_KEY, JSON.stringify(encryptedData));
			
            // Export the key to the session storage
			const rawWrapKey = await crypto.subtle.exportKey("raw", this._persistentEncryptionKey);
			const wrapKeyB64u = encodeBase64Url(new Uint8Array(rawWrapKey));
			sessionStorage.setItem("cipherSafeWrapKey", wrapKeyB64u);
	
		} catch (err) {
			console.error("SessionState.persistToStorage error:", err);
		}
	}

    

    /**
     * Check whether there is a encrypted session data in sessionStorage.
     *
     * @returns {boolean}
     */
    hasEncryptedSessionInStorage() {
        try {
            
            // Validate that session storage exists
            if (typeof sessionStorage === "undefined") {
                return false;
            }

            // Get the key
            const raw = sessionStorage.getItem(WRAPPED_SESSION_STORAGE_KEY);

            // Ensure the key is valid
            return typeof raw === "string" && raw.length > 0;
        } catch {
            return false;
        }
    }

    /**
     * Clear any wrapped session blob that might be left in storage.
     */
    clearEncryptedSessionInStorage() {
    	
        // Remove the data from the session storage
        if (typeof sessionStorage !== "undefined") {
            sessionStorage.removeItem(WRAPPED_SESSION_STORAGE_KEY);
            sessionStorage.removeItem("cipherSafeWrapKey");
        }
    }

    /**
	 * Restore session state from encrypted data in sessionStorage using the
	 * in-memory non-extractable AES-GCM key. If the encrypted session data key 
     * is missing and restoration fails and returns false.
	 *
	 * @returns {Promise<boolean>} - true if restore succeeded, false otherwise.
	 */
    async restoreFromStorage() {
        try {
        	
            // Validate that the session storage exists
			if (typeof sessionStorage === "undefined") {
				return false;
			}
			
			const wrapKeyB64u = sessionStorage.getItem("cipherSafeWrapKey");
			if (!wrapKeyB64u) return false;
	

            // Decode the key to base64
            const rawData = decodeBase64Url(wrapKeyB64u);
					
            // Import the key
            this._persistentEncryptionKey = await crypto.subtle.importKey(
            	"raw",
				rawData,
				{ name: "AES-GCM" },
				false,
				["encrypt", "decrypt"]
			);
            
            // Retreive the raw key
			const raw = sessionStorage.getItem(WRAPPED_SESSION_STORAGE_KEY);
			
            // Check that the key exists
            if (!raw) {return false;}
	
			let data;

            // Parse the data in json format
			try {
				data = JSON.parse(raw);
			} catch {
				console.error("SessionState.restoreFromStorage: corrupt wrapped blob");
				return false;
			}
            
            // Get the encryption data drom data object
			const ivBytes = decodeBase64Url(data.iv_b64u);
			const ciphertextBytes= decodeBase64Url(data.ciphertext_b64u);
	
            // Decrypt with the AES key
			const plaintextBuffer = await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: ivBytes },
				this._persistentEncryptionKey,
				ciphertextBytes
			);
            
            // Parse the decrypted data
			const payloadJson = new TextDecoder().decode(plaintextBuffer);
			const payload = JSON.parse(payloadJson);
	
            // Clear memory to have fresh session 
			this.resetSession();  
            
            // Set session data
			this._username = payload.username;
			this._handshakeState = payload.handshake_state;
			this._sessionCreatedAt = payload.session_created_at;
			this._ttlSeconds = payload.ttl_seconds;
			this._serverRsaPublicKeyPem = payload.server_rsa_public_key_pem;
			this._serverKeyIdentifier = payload.server_key_identifier;
	
            // Decode and set the AES key and AES manager for the session
			const aesKeyBytes = decodeBase64Url(payload.aes_key_b64u);
			this._serverAesSessionKeyBytes = aesKeyBytes;
			this._aesManager = await AesEncryptionManager.create(aesKeyBytes);
	
			// Decode and set the RSA key and RSA manager for the session
			const rsaPkcs8Bytes = decodeBase64Url(payload.rsa_private_pkcs8_b64u);
			this._clientRsaManager = await RsaEncryptionManager.importPrivateKeyPkcs8Bytes(rsaPkcs8Bytes, this._serverRsaPublicKeyPem);
            
            // Decode and set the vault salt for the user
			if (payload.vault_salt_b64u) {
			
				const vaultSaltBytes = decodeBase64Url(payload.vault_salt_b64u);
			
				if (!(vaultSaltBytes instanceof Uint8Array)) {throw new Error("restoreFromStorage: vaultSaltBytes invalid");}
				if (vaultSaltBytes.length !== VAULT_SALT_LENGTH_BYTES) {throw new Error("restoreFromStorage: vaultSaltBytes wrong length");}
			
				this._vaultSaltBytes = new Uint8Array(vaultSaltBytes);
			}
			
			// Decode and set the vault key bytes for the user
            if (payload.vault_key_b64u) {

				const vaultKeyBytes = decodeBase64Url(payload.vault_key_b64u);
			
				if (!(vaultKeyBytes instanceof Uint8Array)) {throw new Error("restoreFromStorage: vaultKeyBytes invalid");}
				if (vaultKeyBytes.length !== AES_KEY_LENGTH_BYTES) {throw new Error("restoreFromStorage: vaultKeyBytes wrong length");}
			
				this._vaultKeyBytes = new Uint8Array(vaultKeyBytes);
				this._vaultKeyDerived = true;
			}

			return true;
	
		} catch (err) {
			console.error("SessionState.restoreFromStorage error:", err);
			return false;
		}
	}

    
    
    getFullSessionState() {
        return deepCopy({
            username: this._username,
            handshake_state: this._handshakeState,
            server_rsa_public_key_pem: this._serverRsaPublicKeyPem,
            server_key_identifier: this._serverKeyIdentifier,
            ttl_seconds: this._ttlSeconds,
            session_created_at: this._sessionCreatedAt,
            used_nonce_count: this._usedNonces.size,
            client_salt_b64u: this._clientSaltBytes? encodeBase64Url(this._clientSaltBytes): null,
            vault_salt_b64u: this._vaultSaltBytes? encodeBase64Url(this._vaultSaltBytes): null,
            vault_key_expected: this._vaultKeyDerived,
            vault_key_bytes: this._vaultKeyBytes
        });
    }
}




export const fourWaySessionState = new SessionState();