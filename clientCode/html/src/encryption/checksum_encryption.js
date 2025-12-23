/**
 * File name: checksum_encryption.js
 * Author: Alex Biddle
 *
 * Description:
 *   SHA-256 checksum utilities for CipherSafe client-side cryptographic
 *   validation (Client Hello, Secure Request, Secure Response).
 */

// Imports
import { CHECKSUM_DIGEST_LENGTH_BYTES } from "https://pascal/capstone/html/src/constants.js";
import { assertByteLength } from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";



/**
 * Perform a constant-time comparison between two Uint8Arrays.
 *
 * @param: Uint8Array - first digest for comparison
 * @param: Uint8Array - second digest for comparison
 * @returns: boolean - true if equal, false otherwise
 */
function constantTimeEqual(a, b) {

    // Check the types of parameters a and b
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
        throw new Error("constantTimeEqual: both inputs must be Uint8Array");
    }

    // Check that both arrays are the same length
    if (a.length !== b.length) {
        return false;
    }

    let acc = 0;
    for (let i = 0; i < a.length; i++) {
        acc |= (a[i] ^ b[i]);
    }
    return acc === 0;
}



export class ChecksumEncryptionManager {

    constructor() {

        // Store the digest size as exactly 32 bytes (SHA-256)
        this._digestSize = CHECKSUM_DIGEST_LENGTH_BYTES;

        // Store the internal algorithm name for reference
        this._algorithm = "SHA-256";
    }

    /**
     * Internal helper: WebCrypto SHA-256 hashing.
     *
     * @param: Uint8Array - data to hash
     * @returns: Promise<Uint8Array> - raw 32-byte digest
     */
    async _sha256(data) {

        // Validate input type
        if (!(data instanceof Uint8Array)) {
            throw new Error("ChecksumEncryptionManager._sha256: data must be a Uint8Array");
        }

        // Perform SHA-256 hashing using WebCrypto
        const digestBuffer = await crypto.subtle.digest("SHA-256", data);

        // Convert ArrayBuffer → Uint8Array
        const digest = new Uint8Array(digestBuffer);

        // Ensure digest size is correct
        assertByteLength("checksum_digest", digest, this._digestSize);

        return digest;
    }
    
    

    /**
     * Compute a SHA-256 checksum over the given data.
     *
     * @param: Uint8Array - data to be hashed
     * @returns: Promise<Uint8Array> - raw 32-byte digest
     */
    async computeChecksum(data) {

        // Ensure input is Uint8Array
        if (!(data instanceof Uint8Array)) {
            throw new Error("ChecksumEncryptionManager.computeChecksum: data must be a Uint8Array");
        }

        // Compute SHA-256 digest
        const digest = await this._sha256(data);

        // Return digest
        return digest;
    }



    /**
     * Verify that a provided checksum matches the computed checksum for data.
     *
     * @param: Uint8Array - data to hash
     * @param: Uint8Array - expectedChecksum (must be 32 bytes)
     * @returns: Promise<boolean> - true on match, false otherwise
     */
    async verifyChecksum(data, expectedChecksum) {

        // Ensure data is Uint8Array
        if (!(data instanceof Uint8Array)) {
            throw new Error("ChecksumEncryptionManager.verifyChecksum: data must be a Uint8Array");
        }

        // Ensure expected checksum is Uint8Array
        if (!(expectedChecksum instanceof Uint8Array)) {
            throw new Error("ChecksumEncryptionManager.verifyChecksum: expectedChecksum must be a Uint8Array");
        }

        // Ensure expected length is valid
        assertByteLength("expected_checksum", expectedChecksum, this._digestSize);

        // Compute new digest for comparison
        const computed = await this.computeChecksum(data);

        // Perform constant-time comparison
        const match = constantTimeEqual(computed, expectedChecksum);

        return match;
    }
}
