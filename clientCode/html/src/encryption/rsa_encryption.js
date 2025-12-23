/**
 * File name: rsa_encryption.js
 * Author: Alex Biddle
 *
 * Description:
 *     
 */


// Imports
import { AES_KEY_LENGTH_BYTES } from "https://pascal/capstone/html/src/constants.js";


/**
 * Resolve a Web Crypto SubtleCrypto implementation for RSA operations.
 *
 * @returns: SubtleCrypto - The subtle crypto interface for RSA-OAEP.
 */
function _getSubtleCrypto() {

    // Grab a reference to globalThis if available (browser / Node / Deno)
    const globalRef = typeof globalThis !== "undefined" ? globalThis : null;

    // Initialize local variable for the crypto object
    let cryptoObj = null;

    /// Attempt to resolve a crypto provider in common environments
    if (globalRef && globalRef.crypto && globalRef.crypto.subtle) {
        cryptoObj = globalRef.crypto;
    } else {
        // Node.js-style import, if available
        try {
            // eslint-disable-next-line no-eval
            const nodeCrypto = eval("require")("crypto");
            if (nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle) {
                cryptoObj = nodeCrypto.webcrypto;
            }
        } catch (e) {
        }
    }

    // If no crypto implementation was found, throw an error
    if (!cryptoObj || !cryptoObj.subtle) {
        throw new Error("_getSubtleCrypto: No Web Crypto SubtleCrypto implementation available");
    }

    // Return the subtle crypto interface
    return cryptoObj.subtle;
}

/**
 * Convert an ArrayBuffer into a Uint8Array.
 *
 * @param: ArrayBuffer - buffer: raw buffer.
 * @returns: Uint8Array - view over the buffer.
 */
function _toUint8(buffer) {

    // Ensure the input is an ArrayBuffer
    if (!(buffer instanceof ArrayBuffer)) {
        throw new Error("_toUint8: buffer must be an ArrayBuffer");
    }

    // Wrap and return as Uint8Array
    return new Uint8Array(buffer);
}


/**
 * Convert a Uint8Array to a base64 string.
 *
 * @param: Uint8Array - bytes: raw bytes to encode.
 * @returns: string - base64 encoded text.
 */
function _bytesToBase64(bytes) {

    // Validate that bytes is a Uint8Array
    if (!(bytes instanceof Uint8Array)) {
        throw new Error("_bytesToBase64: bytes must be a Uint8Array");
    }

    // Convert bytes → binary string
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    // Encode to base64 using btoa
    return btoa(binary);
}



/**
 * Convert a PEM-formatted public key string into an ArrayBuffer (DER).
 *
 * @param: string - pemText: PEM-encoded public key.
 * @returns: ArrayBuffer - DER-encoded key.
 */
function _pemToArrayBuffer(pemText) {

    // Ensure we are working with a string
    if (typeof pemText !== "string") {
        throw new Error("_pemToArrayBuffer: pemText must be a string");
    }

    // Remove carriage returns and trim surrounding whitespace
    const cleanText = pemText.replace(/\r/g, "").trim();

    // Remove PEM headers and footers, leaving only the base64 body
    const base64Body = cleanText
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/[\n]/g, "")
        .trim();

    // Decode base64 → binary string
    const binary = atob(base64Body);

    // Convert binary string to Uint8Array
    const len = binary.length;
    const bytes = new Uint8Array(len);

    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    // Return ArrayBuffer
    return bytes.buffer;
}



/**
 * Convert a CryptoKey public key into a PEM-formatted string.
 *
 * @param: ArrayBuffer - spkiBuffer: SubjectPublicKeyInfo DER bytes.
 * @returns: string - PEM-formatted public key.
 */
function _spkiToPem(spkiBuffer) {

    // Convert buffer → Uint8Array
    const spkiBytes = _toUint8(spkiBuffer);

    // Encode to base64
    const base64 = _bytesToBase64(spkiBytes);

    // Wrap in standard PEM header/footer with 64-character line breaks
    const lines = [];
    for (let i = 0; i < base64.length; i += 64) {
        lines.push(base64.slice(i, i + 64));
    }

    // Join lines with newline separators
    const body = lines.join("\n");

    // Build the final PEM string
    return ["-----BEGIN PUBLIC KEY-----",body,"-----END PUBLIC KEY-----",""].join("\n");
}





/**
 * RsaEncryptionManager
 *
 * Manages a client-side RSA-2048 keypair for RSA-OAEP operations that are
 * compatible with the server-side RSAManager used in CipherSafe.
 */
export class RsaEncryptionManager {

    /**
     * Internal constructor; use RsaEncryptionManager.generate() to create.
     *
     * @param: CryptoKey - privateKey: RSA-OAEP private key.
     * @param: CryptoKey - publicKey: RSA-OAEP public key.
     */
    constructor(privateKey, publicKey) {

        // Store the private key CryptoKey reference
        this._privateKey = privateKey;

        // Store the public key CryptoKey reference
        this._publicKey = publicKey;
    }



    /**
     * Generate a new RSA-2048 keypair for RSA-OAEP with SHA-256.
     *
     * @returns: Promise<RsaEncryptionManager> - instance with generated keys.
     */
    static async generate() {

        // Resolve the subtle crypto interface
        const subtle = _getSubtleCrypto();

        // Define the algorithm parameters for RSA-OAEP key generation
        const algorithm = {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256"
        };

        // Generate the keypair using subtle.generateKey
        const keyPair = await subtle.generateKey(
            algorithm,
            true,
            ["encrypt", "decrypt"]
        );

        // Extract references
        const privateKey = keyPair.privateKey;
        const publicKey = keyPair.publicKey;

        // Basic sanity checks
        if (!privateKey || !publicKey) {
            throw new Error("RsaEncryptionManager.generate: Failed to generate RSA keypair");
        }

        // Create and return a new RsaEncryptionManager instance
        return new RsaEncryptionManager(privateKey, publicKey);
    }



    /**
     * Export the client's public key as a PEM-formatted string.
     *
     * @returns: Promise<string> - PEM with "BEGIN PUBLIC KEY" / "END PUBLIC KEY".
     */
    async exportPublicKeyPem() {

        // Resolve the subtle crypto interface
        const subtle = _getSubtleCrypto();

        // Export the public key in SPKI (SubjectPublicKeyInfo) DER format
        const spkiBuffer = await subtle.exportKey("spki", this._publicKey);

        // Convert SPKI DER bytes into PEM-formatted text
        return _spkiToPem(spkiBuffer);
    }




    /**
     * Decrypt arbitrary RSA-OAEP ciphertext with the client's private key.
     *
     * @param: Uint8Array - wrappedBytes: RSA-OAEP ciphertext to decrypt.
     * @param: number|undefined - expectedLength: optional expected plaintext length in bytes.
     * @returns: Promise<Uint8Array> - decrypted plaintext bytes.
     */
    async decryptWithPrivateKeyBytes(wrappedBytes) {

        // Ensure wrappedBytes is a Uint8Array
        if (!(wrappedBytes instanceof Uint8Array)) {
            throw new Error("RsaEncryptionManager.decryptWithPrivateKeyBytes: wrappedBytes must be a Uint8Array");
        }

        // Ensure wrappedBytes is not empty
        if (wrappedBytes.length === 0) {
            throw new Error("RsaEncryptionManager.decryptWithPrivateKeyBytes: wrappedBytes cannot be empty");
        }

        // Resolve the SubtleCrypto interface
        const subtle = _getSubtleCrypto();

        // Define the RSA-OAEP decryption algorithm parameters
        const algorithm = {
            name: "RSA-OAEP",
            hash: "SHA-256"
        };
        
        // Perform RSA-OAEP decryption with the client's private key
        const plainBuffer = await subtle.decrypt(
            algorithm,
            this._privateKey,
            wrappedBytes
        );

        // Wrap the resulting ArrayBuffer in a Uint8Array for convenience
        const plainBytes = new Uint8Array(plainBuffer);

        // Return the decrypted plaintext bytes
        return plainBytes;
    }



     /**
     * Decrypt a wrapped AES-256 session key using the client's private key.
     *
     * @param: Uint8Array - wrappedKeyBytes: RSA-OAEP ciphertext containing the AES key.
     * @returns: Promise<Uint8Array> - unwrapped AES key bytes (length AES_KEY_LENGTH_BYTES).
     */
    async decryptWrappedAesKey(wrappedKeyBytes) {
        
        const fullPlaintext = await this.decryptWithPrivateKeyBytes(wrappedKeyBytes);

		// Extract LAST 32 bytes of RSA-OAEP plaintext
		const aesKey = fullPlaintext.slice(fullPlaintext.length - AES_KEY_LENGTH_BYTES);
	
		if (aesKey.length !== AES_KEY_LENGTH_BYTES)
			throw new Error("Invalid AES key length after OAEP unwrap");
	
		return aesKey;
    }


 /**
     * Encrypt arbitrary data using an RSA-OAEP public key in PEM format.
     *
     * @param: Uint8Array - dataBytes: raw data to encrypt.
     * @param: string     - publicKeyPem: PEM-encoded public key.
     * @returns: Promise<Uint8Array> - RSA-OAEP ciphertext.
     */
    async encryptWithPemPublicKey(dataBytes, publicKeyPem) {

        // Validate dataBytes parameter
        if (!(dataBytes instanceof Uint8Array)) {
            throw new Error("RsaEncryptionManager.encryptWithPemPublicKey: dataBytes must be a Uint8Array");
        }

        // Validate public key PEM string
        if (typeof publicKeyPem !== "string" || !publicKeyPem.trim()) {
            throw new Error("RsaEncryptionManager.encryptWithPemPublicKey: publicKeyPem must be a non-empty string");
        }

        // Resolve the SubtleCrypto interface
        const subtle = _getSubtleCrypto();

        // Convert the PEM public key into a DER ArrayBuffer
        const derBuffer = _pemToArrayBuffer(publicKeyPem);

        // Define the RSA-OAEP algorithm parameters for key import
        const algorithm = {
            name: "RSA-OAEP",
            hash: "SHA-256"
        };

        // Import the public key for encryption
        const publicKey = await subtle.importKey(
            "spki",
            derBuffer,
            algorithm,
            false,
            ["encrypt"]
        );

        // Sanity check the imported key
        if (!publicKey) {
            throw new Error("RsaEncryptionManager.encryptWithPemPublicKey: Failed to import public key");
        }

        // Perform RSA-OAEP encryption of the dataBytes
        const ciphertextBuffer = await subtle.encrypt(algorithm, publicKey, dataBytes);

        // Wrap the ciphertext ArrayBuffer into a Uint8Array
        const ciphertextBytes = new Uint8Array(ciphertextBuffer);

        // Ensure the ciphertext is non-empty
        if (ciphertextBytes.length === 0) {
            throw new Error("RsaEncryptionManager.encryptWithPemPublicKey: encryption produced empty ciphertext");
        }

        // Return the ciphertext bytes
        return ciphertextBytes;
    }



    /**
     * Import a server public key for RSA-PSS(SHA-256) verification.
     */
    async importPssPublicKey(pemText) {
        const subtle = _getSubtleCrypto();
        const der = _pemToArrayBuffer(pemText);

        return await subtle.importKey("spki",der, { name: "RSA-PSS", hash: "SHA-256",}, false, ["verify"]);
    }


    /**
     * Verify RSA-PSS signature.
     */
    async verifyPssSignature(publicKey, payloadBytes, signatureBytes, saltLength) {
        const subtle = _getSubtleCrypto();

        return await subtle.verify({name: "RSA-PSS", saltLength,}, publicKey, signatureBytes, payloadBytes);
    }


    /**
     * Export the RSA private key as PKCS#8 bytes (Uint8Array).
     * Used for secure persistence (Option B).
     *
     * @returns {Promise<Uint8Array>}
     */
    async exportPrivateKeyPkcs8Bytes() {
        
        // Get the crypto object
        const subtle = _getSubtleCrypto();

        // Export private key in PKCS#8 DER format
        const pkcs8 = await subtle.exportKey("pkcs8", this._privateKey);

        // Convert ArrayBuffer → Uint8Array
        return new Uint8Array(pkcs8);
    }


    /**
     * Recreate a full RsaEncryptionManager from a PKCS#8 private key
     * and a server public key PEM. Used for restoring the session.
     *
     * @param {Uint8Array} pkcs8Bytes
     * @param {string}     serverPublicPem - PEM-encoded server RSA public key
     * @returns {Promise<RsaEncryptionManager>}
     */
    static async importPrivateKeyPkcs8Bytes(pkcs8Bytes, serverPublicPem) {

        // validate parameters
        if (!(pkcs8Bytes instanceof Uint8Array)) {throw new Error("importPrivateKeyPkcs8Bytes: pkcs8Bytes must be Uint8Array");}
        if (typeof serverPublicPem !== "string" || serverPublicPem.trim() === "") {throw new Error("importPrivateKeyPkcs8Bytes: serverPublicPem required");}
        
        // Get the crypto object
        const subtle = _getSubtleCrypto();

        // Import PRIVATE key from PKCS#8
        const privateKey = await subtle.importKey(
            "pkcs8",
            pkcs8Bytes,
            {name: "RSA-OAEP", hash: "SHA-256"},
            true,    
            ["decrypt"]
        );

        // Import PUBLIC key from PEM 
        const publicDer = _pemToArrayBuffer(serverPublicPem);
        const publicKey = await subtle.importKey(
            "spki",
            publicDer,
            {name: "RSA-OAEP", hash: "SHA-256"},
            true,
            ["encrypt"]
        );

        return new RsaEncryptionManager(privateKey, publicKey);
    }
}