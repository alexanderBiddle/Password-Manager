/**
 * File name: argon2id_encryption.js
 * Author: Alex Biddle
 *
 * Description:
 * 
 */



// Imports
import { randomBytes, assertByteLength } from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import {ARGON2ID_PARAMS, CLIENT_SALT_LENGTH_BYTES, CLIENT_HASH_LENGTH_BYTES} from "https://pascal/capstone/html/src/constants.js";




/**
 * Determine the numeric Argon2id type value for argon2-browser.
 *
 * @returns: number - Numeric type code for Argon2id.
 */
function _resolveArgon2idType() {

    // Check if argon2.ArgonType exists and has an Argon2id member
    if (argon2 && argon2.ArgonType && typeof argon2.ArgonType.Argon2id === "number") {
        return argon2.ArgonType.Argon2id;
    }

    // Return the resolved Argon2id type code
    return 2;
}



// Resolve the Argon2id numeric type once at module load time
const _ARGON2_TYPE_ID = _resolveArgon2idType();


/**
 * Perform a constant-time comparison between two Uint8Arrays.
 *
 * @param: Uint8Array - first array to compare.
 * @param: Uint8Array - second array to compare.
 * @returns: boolean - True if both arrays are equal, False otherwise.
 */
function constantTimeEqual(a, b) {

    // Check the types of parameters a and b
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
        throw new Error("constantTimeEqual: both arguments must be Uint8Array");
    }

    // If the lengths differ, we can immediately return false
    if (a.length !== b.length) {
        return false;
    }

    // Initialize a result accumulator to zero
    let result = 0;

    // Iterate over each index in the arrays
    for (let i = 0; i < a.length; i += 1) {

        // XOR the byte values and OR them into the accumulator
        result |= a[i] ^ b[i];
    }

    // Return true only if the accumulator remains zero
    return result === 0;
}



export class Argon2idEncryptionManager {

    constructor() {

        this._timeCost = ARGON2ID_PARAMS.TIME_COST;
        this._memoryCostKib = ARGON2ID_PARAMS.MEMORY_COST_KIB;
        this._parallelism = ARGON2ID_PARAMS.PARALLELISM;
        this._hashLen = ARGON2ID_PARAMS.HASH_LENGTH_BYTES;
        this._saltLen = ARGON2ID_PARAMS.SALT_LENGTH_BYTES;
    }



    /**
     * Generate a new random salt using a secure CSPRNG.
     *
     * @returns: Uint8Array - Newly generated salt bytes.
     */
    generateSaltBytes() {

        // Use randomBytes helper to generate a salt of the configured length
        const salt = randomBytes(this._saltLen);

        // Enforce that the returned salt is exactly salt_len bytes
        assertByteLength("argon2_salt", salt, CLIENT_SALT_LENGTH_BYTES);

        // Return the validated salt bytes
        return salt;
    }



    /**
     * Hash a password using Argon2id with the fixed CipherSafe parameters.
     *
     * @param: Uint8Array - passwordBytes: raw password or client-derived hash.
     * @param: Uint8Array - saltBytes: salt used for hashing (16 bytes).
     * @returns: Promise<Uint8Array> - Raw Argon2id digest bytes.
     */
    async hashPassword(passwordBytes, saltBytes) {

        // Ensure that the password input is a Uint8Array
        if (!(passwordBytes instanceof Uint8Array)) {
            throw new Error("Argon2idEncryptionManager.hashPassword: passwordBytes must be a Uint8Array");
        }

        // Ensure that the salt input is a Uint8Array
        if (!(saltBytes instanceof Uint8Array)) {
            throw new Error("Argon2idEncryptionManager.hashPassword: saltBytes must be a Uint8Array");
        }

        // Enforce that the salt has the expected length of 16 bytes
        assertByteLength("argon2_salt", saltBytes, CLIENT_SALT_LENGTH_BYTES);

        // Build the Argon2 configuration object for argon2-browser
        const config = {
            pass: passwordBytes,
            salt: saltBytes,
            time: this._timeCost,
            mem: this._memoryCostKib,
            parallelism: this._parallelism,
            hashLen: this._hashLen,
            type: _ARGON2_TYPE_ID,
            raw: true
        };

        // Execute Argon2id hashing with the configured parameters
        const result = await argon2.hash(config);

        // Extract the hash component from the result object
        let digest = result && result.hash;

        // If the hash is present as an ArrayBuffer instead of Uint8Array, wrap it
        if (digest instanceof ArrayBuffer) {
            digest = new Uint8Array(digest);
        }

        // Ensure the digest is now a Uint8Array
        if (!(digest instanceof Uint8Array)) {
            throw new Error("Argon2idEncryptionManager.hashPassword: invalid digest type returned by Argon2");
        }

        // Enforce that the digest has the expected hash length of 32 bytes
        assertByteLength("argon2_digest", digest, CLIENT_HASH_LENGTH_BYTES);

        // Create a defensive copy of the digest to avoid external mutation
        const digestCopy = new Uint8Array(digest.length);

        // Copy the digest bytes into the new array
        digestCopy.set(digest);

        // Return the defensive copy of the digest
        return digestCopy;
    }



    /**
     * Verify a password against a known Argon2id digest using constant-time comparison.
     *
     * @param: Uint8Array - passwordBytes: password input to hash and compare.
     * @param: Uint8Array - saltBytes: salt used during original hashing.
     * @param: Uint8Array - expectedHashBytes: stored Argon2id digest
     * @returns: Promise<boolean> - True if verification succeeds, False otherwise.
     */
    async verifyPassword(passwordBytes, saltBytes, expectedHashBytes) {

        // Ensure that the password input is a Uint8Array
        if (!(passwordBytes instanceof Uint8Array)) {
            throw new Error("Argon2idEncryptionManager.verifyPassword: passwordBytes must be a Uint8Array");
        }

        // Ensure that the salt input is a Uint8Array
        if (!(saltBytes instanceof Uint8Array)) {
            throw new Error("Argon2idEncryptionManager.verifyPassword: saltBytes must be a Uint8Array");
        }

        // Ensure that the expected hash input is a Uint8Array
        if (!(expectedHashBytes instanceof Uint8Array)) {
            throw new Error("Argon2idEncryptionManager.verifyPassword: expectedHashBytes must be a Uint8Array");
        }

        // Enforce the salt length requirement (16 bytes)
        assertByteLength("argon2_salt", saltBytes, CLIENT_SALT_LENGTH_BYTES);

        // Enforce the expected hash length requirement (32 bytes)
        assertByteLength("argon2_expected_hash", expectedHashBytes, CLIENT_HASH_LENGTH_BYTES);

        // Recompute the Argon2id digest for the provided password and salt
        const recomputed = await this.hashPassword(passwordBytes, saltBytes);

        // Perform a constant-time comparison between recomputed and expected digest
        const match = constantTimeEqual(recomputed, expectedHashBytes);

        // Return True only if the digests match exactly
        return match;
    }
}
