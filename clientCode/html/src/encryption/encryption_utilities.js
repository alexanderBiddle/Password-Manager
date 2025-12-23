/**
 * File name: encryption_utilities.js
 * Author: Alex Biddle
 *
 * Description:
 *     
 */




// Create a single shared TextEncoder instance for UTF-8 encoding operations
const _textEncoder = new TextEncoder();

// Create a single shared TextDecoder instance for UTF-8 decoding operations
const _textDecoder = new TextDecoder();



/**
 * Convert a JavaScript string into a UTF-8 encoded Uint8Array.
 *
 * @param: string - Input text to encode.
 * @returns: Uint8Array
 */
export function toUtf8Bytes(text) {

    // Ensure that the provided value is actually a string
    if (typeof text !== "string") {
        throw new Error("toUtf8Bytes: text must be a string");
    }

    // Use the shared TextEncoder to convert the string into UTF-8 bytes
    return _textEncoder.encode(text);
}



/**
 * Convert a UTF-8 encoded Uint8Array into a JavaScript string.
 *
 * @param: Uint8Array - UTF-8 encoded data.
 * @returns: string
 */
export function fromUtf8Bytes(bytes) {

    // Validate that the input is a Uint8Array instance
    if (!(bytes instanceof Uint8Array)) {
        throw new Error("fromUtf8Bytes: bytes must be a Uint8Array");
    }

    // Use the shared TextDecoder to convert bytes back into a string
    return _textDecoder.decode(bytes);
}



/**
 * Convert a Uint8Array into a Base64URL-encoded string.
 * 
 * @param: Uint8Array - Raw binary data to encode.
 * @returns: string
 */
export function encodeBase64Url(bytes) {

    // Ensure that we were given a Uint8Array
    if (!(bytes instanceof Uint8Array)) {
        throw new Error("encodeBase64Url: input must be a Uint8Array");
    }

    // Initialize an empty string to accumulate binary characters
    let binary = "";

    // Loop through each byte in the Uint8Array
    for (let i = 0; i < bytes.length; i += 1) {
        binary += String.fromCharCode(bytes[i]);
    }

    // Use btoa to convert the binary string into standard base64
    const base64 = btoa(binary);

    // Convert base64 to URL-safe Base64URL and remove any trailing '=' padding
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); 
}



/**
 * Decode a Base64URL-encoded string into a Uint8Array.
 *
 * @param: string - Base64URL string to decode.
 * @returns: Uint8Array
 */
export function decodeBase64Url(b64url) {

    // Ensure that the input value is a string
    if (typeof b64url !== "string") {
        throw new Error("decodeBase64Url: input must be a string");
    }

    // Trim leading and trailing whitespace from the input string
    let trimmed = b64url.trim();

    // Reject empty strings after trimming
    if (trimmed.length === 0) {
        throw new Error("decodeBase64Url: input cannot be empty");
    }

    // Ensure characters are valid Base64URL (defense in depth, mirrors server)
    if (!/^[A-Za-z0-9\-_]+$/.test(trimmed)) {
        throw new Error("decodeBase64Url: invalid base64url characters");
    }

    // Convert URL-safe characters back into standard base64 characters
    trimmed = trimmed.replace(/-/g, "+").replace(/_/g, "/");

    // Compute the remainder when the length is divided by 4
    const padLength = trimmed.length % 4;

    // If we have a remainder of 2, add two '=' padding characters
    if (padLength === 2) {
        trimmed += "==";
    }
    // If we have a remainder of 3, add one '=' padding character
    else if (padLength === 3) {
        trimmed += "=";
    }
    // If the remainder is not 0, 2, or 3, this is invalid base64 length
    else if (padLength !== 0) {
        throw new Error("decodeBase64Url: invalid base64url length");
    }

    // Declare a variable to hold the decoded binary string
    let binary;

    // Attempt to decode the base64 string into a binary string using atob
    try {
        binary = atob(trimmed);
    
    // If atob throws, the content is not valid base64
    } catch {
        throw new Error("decodeBase64Url: invalid base64 data");
    }

    // Create a new Uint8Array with the length of the binary string
    const bytes = new Uint8Array(binary.length);

    // Populate the Uint8Array with the character codes of each binary character
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }

    // Return the populated Uint8Array
    return bytes;
}



/**
 * Generate cryptographically secure random bytes of the given length.
 * 
 * @param: number - length in bytes (must be > 0).
 * @returns: Uint8Array
 */
export function randomBytes(length) {

    // Ensure the length parameter is an integer
    if (!Number.isInteger(length) || length <= 0) {
        throw new Error("randomBytes: length must be a positive integer");
    }

    // Allocate a Uint8Array buffer with the requested number of bytes
    const buffer = new Uint8Array(length);

    // Attempt to obtain a crypto object from the global environment
    const cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) ? globalThis.crypto: null;

    // If a crypto object with getRandomValues is available, use it
    if (cryptoObj && typeof cryptoObj.getRandomValues === "function") {

        // Fill the buffer with cryptographically secure random values
        cryptoObj.getRandomValues(buffer);

        // Return the securely populated buffer
        return buffer;
    }

    // If Web Crypto is not available, attempt to fall back to Node.js crypto
    try {
        // Dynamically require the crypto module (for Node-based test environments)
        const nodeCrypto = require("crypto");

        // Use Node's randomBytes method to generate secure random bytes
        const nodeBuffer = nodeCrypto.randomBytes(length);

        // Copy each byte from the Node buffer into the Uint8Array buffer
        for (let i = 0; i < length; i += 1) {
            buffer[i] = nodeBuffer[i];
        }

        // Return the filled Uint8Array
        return buffer;
    
    // If neither Web Crypto nor Node crypto are available, fail
    } catch {
        throw new Error("randomBytes: no secure random source available");
    }
}




/**
 * Concatenate multiple Uint8Array instances into a single Uint8Array.
 *
 * @param: Array<Uint8Array> - One or more Uint8Array values.
 * @returns: Uint8Array
 */
export function concatenateUint8Arrays(...arrays) {

    // If no arrays were provided, return an empty Uint8Array
    if (!arrays.length) {
        return new Uint8Array(0);
    }

    // Initialize total length of the concatenated result
    let totalLength = 0;

    // Iterate over each array to validate and sum lengths
    for (const arr of arrays) {

        // Ensure each argument is a Uint8Array
        if (!(arr instanceof Uint8Array)) {
            throw new Error("concatenateUint8Arrays: all arguments must be Uint8Array");
        }

        // Add the length of this array to the total length
        totalLength += arr.length;
    }

    // Allocate a new Uint8Array to hold all concatenated bytes
    const result = new Uint8Array(totalLength);

    // Maintain an offset index while copying bytes into the result
    let offset = 0;

    // Iterate again to copy each array's contents into the result buffer
    for (const arr of arrays) {

        // Copy the current Uint8Array into result starting at the current offset
        result.set(arr, offset);

        // Advance the offset by the number of bytes we just copied
        offset += arr.length;
    }

    // Return the fully concatenated Uint8Array
    return result;
}



/**
 * Assert that a Uint8Array has the expected length.
 *
 * @param: string     - label/name for error messages.
 * @param: Uint8Array - byte array being validated.
 * @param: number     - required length.
 * @returns: void
 */
export function assertByteLength(label, bytes, expectedLength) {

    // Validate that the label is a non-empty string
    if (typeof label !== "string" || !label.trim()) {
        throw new Error("assertByteLength: label must be a non-empty string");
    }

    // Ensure that the bytes argument is a Uint8Array
    if (!(bytes instanceof Uint8Array)) {
        throw new Error(`assertByteLength: ${label} must be a Uint8Array`);
    }

    // Validate that expectedLength is a positive integer
    if (!Number.isInteger(expectedLength) || expectedLength <= 0) {
        throw new Error("assertByteLength: expectedLength must be a positive integer");
    }

    // If the actual length does not match the expected length, raise an error
    if (bytes.length !== expectedLength) {
        throw new Error(`assertByteLength: ${label} must be ${expectedLength} bytes, got ${bytes.length}`);
    }
}
