/**
 * File name: vault_crypto.js
 * Author: Alex Biddle
 *
 * Description:
 *   
 */


// Import
import {VAULT_SALT_LENGTH_BYTES,  AES_KEY_LENGTH_BYTES, AES_GCM_NONCE_LENGTH_BYTES} from "https://pascal/capstone/html/src/constants.js";
import {encodeBase64Url, decodeBase64Url, toUtf8Bytes, fromUtf8Bytes} from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import { AesEncryptionManager } from "https://pascal/capstone/html/src/encryption/aes_encryption.js";



/**
 * Resolve the WebCrypto SubtleCrypto interface.
 *
 * @returns {SubtleCrypto}
 */
function _getSubtleCrypto() {

    // Reference to globalThis 
    const g = typeof globalThis !== "undefined" ? globalThis : {};

    // If browser crypto.subtle exists, use it
    if (g.crypto && g.crypto.subtle) {
        return g.crypto.subtle;
    }

    // Otherwise check Node.js webcrypto fallback
    try {
        const nodeCrypto = require("crypto");
        if (nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle) {
            return nodeCrypto.webcrypto.subtle;
        }
    } catch {}
    throw new Error("vault_crypto: WebCrypto SubtleCrypto not available");
}


/**
 * Convert a password string into UTF-8 bytes.
 *
 * @param {string} password
 * @returns {Uint8Array}
 */
function _passwordToBytes(password) {

    // Ensure input is a non-empty string
    if (typeof password !== "string" || !password.length) {
        throw new Error("vault_crypto: password must be a non-empty string");
    }

    // Convert string → Uint8Array UTF-8
    return toUtf8Bytes(password);
}


/**
 * Import plaintext password bytes as a PBKDF2 base key.
 *
 * @param {Uint8Array} passwordBytes
 * @returns {CryptoKey}
 */
async function _importPasswordKey(passwordBytes) {

    // Acquire WebCrypto subtle interface
    const subtle = _getSubtleCrypto();

    // Import raw password bytes into PBKDF2 usable key
    return await subtle.importKey(
        "raw",                
        passwordBytes,       
        { name: "PBKDF2" },    
        false,                 
        ["deriveBits", "deriveKey"] 
    );
}


/**
 * Derive the vault AES-256 key:
 *
 * @param {string} password - user's master password
 * @param {Uint8Array} vaultSaltBytes - must be exactly 16 bytes
 * @returns {Promise<Uint8Array>} 32-byte vault key
 */
export async function deriveVaultKey(password, vaultSaltBytes) {

    // Ensure vaultSaltBytes is a Uint8Array
    if (!(vaultSaltBytes instanceof Uint8Array)) {throw new Error("deriveVaultKey: vaultSaltBytes must be Uint8Array");}

    // Validate correct salt length
    if (vaultSaltBytes.length !== VAULT_SALT_LENGTH_BYTES) {throw new Error("deriveVaultKey: vaultSaltBytes must be 16 bytes");}

    // Get the WebCrypto subtle interface
    const subtle = _getSubtleCrypto();

    // Convert password → bytes
    const passwordBytes = _passwordToBytes(password);

    // Import password as PBKDF2 base key
    const baseKey = await _importPasswordKey(passwordBytes);

    // Run PBKDF2(SHA-256) for 200,000 iterations
    const derivedBits = await subtle.deriveBits(
        {
            name: "PBKDF2",            
            salt: vaultSaltBytes,     
            iterations: 200000,       
            hash: "SHA-256"           
        },
        baseKey,                     
        AES_KEY_LENGTH_BYTES * 8      
    );

    // Wrap derived bits as Uint8Array
    const vaultKeyBytes = new Uint8Array(derivedBits);

    // Validate final key length
    if (vaultKeyBytes.length !== AES_KEY_LENGTH_BYTES) {
        throw new Error("deriveVaultKey: derived key must be 32 bytes");
    }

    // Return final vault key
    return vaultKeyBytes;
}


//=============================================================================
// ENCRYPT A VAULT FIELD
//=============================================================================

/**
 * Encrypt any plaintext vault field (website, username, email, password).
 *
 * @param {string} plaintext - raw field content (e.g., "gmail.com")
 * @param {Uint8Array} vaultKeyBytes - 32-byte derived vault key
 * @returns {Promise<string>} ciphertext base64url string
 */
export async function encryptVaultField(plaintext, vaultKeyBytes) {

    // Ensure plaintext is a string
    if (typeof plaintext !== "string") {
        throw new Error("encryptVaultField: plaintext must be a string");
    }

    // Ensure vaultKeyBytes is Uint8Array of correct length
    if (!(vaultKeyBytes instanceof Uint8Array) ||
        vaultKeyBytes.length !== AES_KEY_LENGTH_BYTES) {
        throw new Error("encryptVaultField: vaultKeyBytes must be 32-byte Uint8Array");
    }

    // Create AES-GCM manager from the vault key
    const aes = await AesEncryptionManager.create(vaultKeyBytes);

    // AAD (Associated Authenticated Data) – empty for vault encryption
    const aad = new Uint8Array([]);

    // Convert plaintext → UTF-8 bytes
    const plaintextBytes = toUtf8Bytes(plaintext);

    // Perform AES-GCM encryption
    const { nonce, ciphertextWithTag } = await aes.encrypt(aad, plaintextBytes);

    // Allocate buffer: nonce(12 bytes) || ciphertext+tag
    const full = new Uint8Array(nonce.length + ciphertextWithTag.length);

    // Copy nonce into front
    full.set(nonce, 0);

    // Copy ciphertext+tag after nonce
    full.set(ciphertextWithTag, nonce.length);

    // Encode as base64url string for DB/storage
    return encodeBase64Url(full);
}



/**
 * Decrypt a base64url ciphertext into plaintext.
 *
 * @param {string} ciphertextB64u - base64url nonce||ciphertext
 * @param {Uint8Array} vaultKeyBytes - 32-byte vault key
 * @returns {Promise<string>} plaintext string
 */
export async function decryptVaultField(ciphertextB64u, vaultKeyBytes) {

    // Validate parameters
    if (typeof ciphertextB64u !== "string") {throw new Error("decryptVaultField: ciphertext must be string");}
    if (!(vaultKeyBytes instanceof Uint8Array)) {throw new Error("decryptVaultField: vaultKeyBytes must be Uint8Array");}
    if (vaultKeyBytes.length !== AES_KEY_LENGTH_BYTES) {throw new Error("decryptVaultField: vaultKeyBytes must be 32 bytes");}

    // Decode base64url into bytes
    const decoded = decodeBase64Url(ciphertextB64u);

    // Ensure ciphertext long enough for nonce + GCM tag
    if (decoded.length <= AES_GCM_NONCE_LENGTH_BYTES + 16) {
        throw new Error("decryptVaultField: ciphertext too short");
    }

    // Extract the AES-GCM nonce (first 12 bytes)
    const nonce = decoded.slice(0, AES_GCM_NONCE_LENGTH_BYTES);

    // Extract ciphertext+tag remainder
    const ciphertext = decoded.slice(AES_GCM_NONCE_LENGTH_BYTES);

    // Create AES-GCM manager with vault key
    const aes = await AesEncryptionManager.create(vaultKeyBytes);

    // AAD is empty (must match encryption parameters)
    const aad = new Uint8Array([]);

    // Decrypt ciphertext → plaintext bytes
    const plaintextBytes = await aes.decrypt(aad, nonce, ciphertext);

    // Convert plaintext bytes → UTF-8 string
    return fromUtf8Bytes(plaintextBytes);
}
