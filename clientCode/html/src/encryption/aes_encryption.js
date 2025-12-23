/**
 * File name: aes_encryption.js
 * Author: Alex Biddle
 *
 * Description:
 *     
 */



// Imports
import { randomBytes, assertByteLength } from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import {AES_KEY_LENGTH_BYTES, AES_GCM_NONCE_LENGTH_BYTES} from "https://pascal/capstone/html/src/constants.js";


/**
 * Resolve a Web Crypto "subtle" implementation for AES-GCM operations.
 *
 * @returns: SubtleCrypto - A Web Crypto subtle implementation ready for AES-GCM.
 */
function _getSubtleCrypto() {

    // Attempt to resolve a global crypto object (browser or similar environments)
    const globalCrypto =
        typeof globalThis !== "undefined"? (globalThis.crypto || globalThis.msCrypto || null): null;

    // If a global crypto object exists and exposes subtle, return subtle
    if (globalCrypto && typeof globalCrypto.subtle === "object") {
        // Return the subtle crypto interface provided by the environment
        return globalCrypto.subtle;
    }

    // If we reach here, global Web Crypto is not available; try Node.js fallback
    try {
        // Dynamically require the Node.js crypto module
        const nodeCrypto = require("crypto");

        // Check if Node exposes webcrypto.subtle
        if (nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle) {
            // Return Node's subtle interface
            return nodeCrypto.webcrypto.subtle;
        }
    } catch {
        // Ignore require failures; we will handle lack of subtle below
    }

    // If neither browser Web Crypto nor Node webcrypto are available, fail hard
    throw new Error("AES-GCM requires Web Crypto API (subtle) support");
}




export class AesEncryptionManager {

    /**
     * Internal constructor; use AesEncryptionManager.create(...) instead.
     *
     * @param: CryptoKey   - Imported AES-GCM CryptoKey instance
     * @param: Uint8Array  - Raw 32-byte AES key copy for reference.
     */
    constructor(cryptoKey, rawKeyBytes) {
        
        // The raw key must be of a unit8Array
        if (!(rawKeyBytes instanceof Uint8Array)) {
            throw new Error("AesEncryptionManager: rawKeyBytes must be a Uint8Array");
        }

        // Key must be exactly 32 bytes to mirror AES_manager.py
        assertByteLength("aes_key", rawKeyBytes, AES_KEY_LENGTH_BYTES);

        // Store the CryptoKey instance used for AES-GCM encrypt/decrypt
        this._cryptoKey = cryptoKey;

        // Store a defensive copy of the raw AES key bytes
        this._rawKeyBytes = rawKeyBytes;
    }



    /**
     * Asynchronously create a new AesEncryptionManager from raw key bytes.
     *
     * @param: Uint8Array - Raw 32-byte AES-256 key.
     * @returns: Promise<AesEncryptionManager> - A fully initialized manager instance.
     */
    static async create(keyBytes) {

        // Verify that the provided keyBytes is a Uint8Array
        if (!(keyBytes instanceof Uint8Array)) {
            throw new Error("AesEncryptionManager.create: keyBytes must be a Uint8Array");
        }

        // Enforce a 32-byte AES-256 key length using helper validation
        assertByteLength("aes_key", keyBytes, AES_KEY_LENGTH_BYTES);

        // Create a defensive copy of the raw key bytes (to avoid external mutation)
        const rawKeyCopy = new Uint8Array(keyBytes);

        // Resolve the Web Crypto subtle interface for key import
        const subtle = _getSubtleCrypto();

        // Define the AES-GCM key import parameters (algorithm + usage)
        const algorithm = {name: "AES-GCM"};

        // Import the raw key bytes into a CryptoKey usable for encrypt/decrypt
        const cryptoKey = await subtle.importKey(
            "raw",
            rawKeyCopy,
            algorithm,
            false,
            ["encrypt", "decrypt"]
        );

        // Return a new manager instance bound to this CryptoKey and raw key bytes
        return new AesEncryptionManager(cryptoKey, rawKeyCopy);
    }



    /**
     * Generate a new random 32-byte AES-256 key.
     * 
     * @returns: Uint8Array - New AES-256 key bytes.
     */
    static generateKeyBytes() {

        // Delegate to randomBytes helper to get 32 random bytes
        const key = randomBytes(AES_KEY_LENGTH_BYTES);

        // Double-check length
        assertByteLength("generated_aes_key", key, AES_KEY_LENGTH_BYTES);

        // Return the generated AES-256 key bytes
        return key;
    }



    /**
     * Generate a fresh 12-byte nonce for AES-GCM IV.
     * 
     * @returns: Uint8Array - New GCM nonce bytes.
     */
    static generateNonceBytes() {

        // Get the random nonce bytes
        const nonce = randomBytes(AES_GCM_NONCE_LENGTH_BYTES);

        // Ensure nonce length is exactly 12 bytes.
        assertByteLength("aes_gcm_nonce", nonce, AES_GCM_NONCE_LENGTH_BYTES);

        // Return the generated nonce
        return nonce;
    }



    /**
     * Get a defensive copy of the raw AES key bytes.
     *
     * @returns: Uint8Array - Copy of the underlying 32-byte AES key.
    */
    getRawKeyBytes() {

        // Create a new Uint8Array with the same length as the stored key
        const copy = new Uint8Array(this._rawKeyBytes.length);

        // Copy the internal key bytes into the new array
        copy.set(this._rawKeyBytes);

        // Return the defensive copy to the caller
        return copy;
    }



    /**
     * Encrypt and authenticate plaintext using AES-256-GCM.
     *
     * @param: Uint8Array - aadBytes: Associated Authenticated Data.
     * @param: Uint8Array - plaintextBytes: Non-empty plaintext bytes to encrypt.
     * @returns: Promise<{ nonce: Uint8Array, ciphertextWithTag: Uint8Array }>
    */
    async encrypt(aadBytes, plaintextBytes) {

        // Ensure AAD is a Uint8Array
        if (!(aadBytes instanceof Uint8Array)) {
            throw new Error("AesEncryptionManager.encrypt: aadBytes must be a Uint8Array");
        }

        // Ensure plaintext is a Uint8Array
        if (!(plaintextBytes instanceof Uint8Array)) {
            throw new Error("AesEncryptionManager.encrypt: plaintextBytes must be a Uint8Array");
        }

        // Enforce non-empty plaintext, like the server
        if (plaintextBytes.length === 0) {
            throw new Error("AesEncryptionManager.encrypt: plaintext cannot be empty");
        }

        // Generate a fresh 12-byte GCM nonce for this encryption operation
        const nonce = AesEncryptionManager.generateNonceBytes();

        // Resolve the Web Crypto subtle interface
        const subtle = _getSubtleCrypto();

        // Define the AES-GCM encryption parameters
        const algorithm = {
            name: "AES-GCM",
            iv: nonce,
            additionalData: aadBytes,
            tagLength: 128
        };

        // Perform AES-GCM encryption using the CryptoKey and algorithm definition
        const ciphertextBuffer = await subtle.encrypt(algorithm, this._cryptoKey, plaintextBytes);

        // Wrap the resulting ArrayBuffer into a Uint8Array for easier handling
        const ciphertextWithTag = new Uint8Array(ciphertextBuffer);

        // Ensure the output contains at least a 16-byte GCM tag
        if (ciphertextWithTag.length < 16) {
            throw new Error("AesEncryptionManager.encrypt: ciphertext output invalid (missing GCM tag)");
        }

        // Return both nonce and ciphertextWithTag to the caller
        return {nonce, ciphertextWithTag};
    }



    /**
     * Decrypt and authenticate AES-256-GCM ciphertext.
     *
     * @param: Uint8Array - aadBytes: Associated data used during encryption.
     * @param: Uint8Array - nonceBytes: 12-byte nonce used during encryption.
     * @param: Uint8Array - ciphertextWithTagBytes: Ciphertext concatenated with tag.
     * @returns: Promise<Uint8Array> - Decrypted plaintext bytes.
    */
    async decrypt(aadBytes, nonceBytes, ciphertextWithTagBytes) {

        // Ensure AAD is a Uint8Array
        if (!(aadBytes instanceof Uint8Array)) {
            throw new Error("AesEncryptionManager.decrypt: aadBytes must be a Uint8Array");
        }

        // Ensure nonce is a Uint8Array
        if (!(nonceBytes instanceof Uint8Array)) {
            throw new Error("AesEncryptionManager.decrypt: nonceBytes must be a Uint8Array");
        }

        // Enforce the required nonce length of 12 bytes
        assertByteLength("nonce", nonceBytes, AES_GCM_NONCE_LENGTH_BYTES);

        // Ensure ciphertextWithTagBytes is a Uint8Array
        if (!(ciphertextWithTagBytes instanceof Uint8Array)) {
            throw new Error("AesEncryptionManager.decrypt: ciphertextWithTagBytes must be a Uint8Array");
        }

        // Validate that ciphertext contains at least a 16-byte authentication tag
        if (ciphertextWithTagBytes.length < 16) {
            throw new Error("AesEncryptionManager.decrypt: ciphertext must include 16-byte GCM tag");
        }

        // Resolve the Web Crypto subtle interface
        const subtle = _getSubtleCrypto();

        // Define the AES-GCM decryption parameters (must match encryption)
        const algorithm = {
            name: "AES-GCM",
            iv: nonceBytes,
            additionalData: aadBytes,
            tagLength: 128
        };

        // Perform AES-GCM decryption using the CryptoKey and provided parameters
        const plaintextBuffer = await subtle.decrypt(algorithm, this._cryptoKey, ciphertextWithTagBytes);

        // Wrap the resulting ArrayBuffer into a Uint8Array for consistency
        const plaintextBytes = new Uint8Array(plaintextBuffer);

        // Return the decrypted plaintext bytes to the caller
        return plaintextBytes;
    }
}
