/**
 * File name: sanitization.js
 * Author: Alex Biddle
 *
 * Description:
 *      This file contains the functions for sanitizing input from the 
 *      user and from the server to ensure types and data format
 */



import { TIMESTAMP_DRIFT_SECONDS, ISO8601Z_REGEX } from "https://pascal/capstone/html/src/constants.js";


/**
 * Clean a string by removing leading/trailing whitespace and converting
 * illegal control characters into safe equivalents.
 *
 * @param: string - raw user input
 * @returns: A sanitized string.
 */
export function sanitizeText(raw) {
    
    // Ensure input is a string
    if (typeof raw !== "string") {throw new Error("sanitizeText: value must be a string");}

    // Trim leading/trailing whitespace
    let cleaned = raw.trim();

    // Remove null bytes, control chars (except standard whitespace)
    return cleaned.replace(/[\u0000-\u001F\u007F]/g, "");
}



/**
 * Validate and sanitize a CipherSafe username.
 *
 * @param: string - raw username input
 * @returns: sanitized username
 */
export function sanitizeUsername(raw) {
    
    // Validate type and length
    if (typeof raw !== "string") {throw new Error("sanitizeUsername: username must be a string");}

    // Sanitize the text first
    const cleaned = sanitizeText(raw);


    if (cleaned.length === 0) {throw new Error("sanitizeUsername: username cannot be empty");}
    if (cleaned.length > 64) {throw new Error("sanitizeUsername: username exceeds maximum length");}

    // Sanitize the text
    return cleaned;
}



/**
 * Sanitize user text with strict injection checks. 
 *
 * @param: string - raw user input
 * @returns: sanitized text string
 */
export function sanitizeSafeTextField(raw) {
    
    // Validate type and length
    if (typeof raw !== "string") {throw new Error("sanitizeSafeTextField: value must be a string");}
    if (raw.length === 0) {throw new Error("sanitizeSafeTextField: value cannot be empty");}
    if (raw.length > 512) {throw new Error("sanitizeSafeTextField: value exceeds maximum length (512 characters)");}

    // Sanitize the text
    return sanitizeText(raw);
}



/**
 * Validate that a string is legal Base64URL.
 *
 * @param: string - candidate base64url string
 * @returns: cleaned base64url or throws an error
 */
export function validateBase64Url(value) {
    
    // Validate type
    if (typeof value !== "string") {throw new Error("validateBase64Url: value must be a string");}

    // Trim the string and validate
    const trimmed = value.trim();
    if (trimmed.length === 0) {throw new Error("validateBase64Url: empty string");}

    // Check for invalid characters
    const base64urlRegex = /^[A-Za-z0-9_\-]+={0,2}$/;
    if (!base64urlRegex.test(trimmed)) {throw new Error("validateBase64Url: invalid base64url characters");}
    if (trimmed.length > 65536) {throw new Error("validateBase64Url: exceeds 64KB limit");}

    return trimmed;
}


/**
 * Safely parse a JSON string.
 *
 * @param: string - JSON text
 * @returns: parsed JSON object
 */
export function safeParseJSON(text) {
    
    // Ensure input is a string
    if (typeof text !== "string") {throw new Error("safeParseJSON: input must be a string");}

    try {
        const obj = JSON.parse(text);
        return obj;
    } catch {
        throw new Error("safeParseJSON: malformed JSON");
    }
}



/**
 * Extract a required field from an object, ensuring type correctness.
 *
 * @param: object - the source object
 * @param: string - field name
 * @returns: field value
 */
export function requireField(obj, field) {
    
    // Ensure input is a object
    if (typeof obj !== "object" || obj === null) {throw new Error("requireField: obj must be a non-null object");}
    
    // Ensure input is a string
    if (typeof field !== "string") {throw new Error("requireField: field must be a string");}

    // Ensure the field and object are not null or empty
    if (!(field in obj)) {throw new Error(`requireField: missing required field '${field}'`);}
    const value = obj[field];
    if (value === null || value === undefined) {throw new Error(`requireField: field '${field}' cannot be null`);}

    return value;
}



/**
 * Convert a value to an integer, mirroring the server's
 *
 * @param: any - input value
 * @returns: integer
 */
export function coerceToInt(value) {
    const n = Number(value);
    if (!Number.isInteger(n)) {throw new Error("coerceToInt: value cannot be coerced to integer");}
    return n;
}



/**
 * Deep clone a JSON-serializable object.
 *
 * @param: object - any JSON-safe value
 * @returns: deep-cloned object
 */
export function deepCopy(obj) {
    try {
        return JSON.parse(JSON.stringify(obj));
    } catch {
        throw new Error("deepCopy: value must be JSON-serializable");
    }
}



/**
 * Validate and parse an ISO8601Z timestamp with ±TIMESTAMP_DRIFT_SECONDS drift.
 */
export function validateTimestamp(value, fieldName = "timestamp") {

    // Validate the type and characters 
    if (typeof value !== "string" || !ISO8601Z_REGEX.test(value)) {throw new Error(`${fieldName}: must be strict ISO8601Z format`);}
    
    // Parse the timestamp
    const parsed = Date.parse(value);
    if (Number.isNaN(parsed)) {throw new Error(`${fieldName}: timestamp not parseable`);}

    // Enforce 5 second drift time
    const driftSec = Math.abs(Date.now() - parsed) / 1000;
    if (driftSec > TIMESTAMP_DRIFT_SECONDS) {throw new Error(`${fieldName}: timestamp drift exceeds ${TIMESTAMP_DRIFT_SECONDS}s`);}

    return value;
}



/**
 * Generate a strict ISO8601Z timestamp EXACTLY matching server timestamp behavior.
 */
export function generateIso8601ZTimestamp() {
    const now = new Date();

    return (
        now.getUTCFullYear() +
        "-" +
        String(now.getUTCMonth() + 1).padStart(2, "0") +
        "-" +
        String(now.getUTCDate()).padStart(2, "0") +
        "T" +
        String(now.getUTCHours()).padStart(2, "0") +
        ":" +
        String(now.getUTCMinutes()).padStart(2, "0") +
        ":" +
        String(now.getUTCSeconds()).padStart(2, "0") +
        "Z"
    );
}



/**
 * Sanitize a user-supplied master password for signup.
 *
 * Enforces:
 *   - Non-empty, <= 512 characters (via sanitizeSafeTextField)
 *   - Minimum length of 12 characters for master passwords
 *
 * @param {string} rawPassword
 * @returns {string}
 */
export function sanitizePassword(rawPassword) {

    // Sanitize the password
    const cleaned = sanitizeSafeTextField(rawPassword);

    // Enforce a stricter minimum length for master passwords at signup.
    if (cleaned.length < 12) {
        throw new Error("sanitizePassword: password must be at least 12 characters long");
    }

    return cleaned;
}