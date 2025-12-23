/**
 * File name: packet_transit.js
 * Author: Alex Biddle
 *
 * Description:
 *    Provides a thin transport layer for sending Client Hello and
 *    Client Secure Request packets to the Flask backend. All requests
 *    are POST with JSON bodies, and responses are normalized into
 *    { ok, status, data } objects with safe JSON parsing.
 */


// Imports
import {HANDSHAKE_HELLO_PATH, HANDSHAKE_SECURE_PATH, JSON_HEADERS} from "https://pascal/capstone/html/src/constants.js";
import {sanitizeText, safeParseJSON} from "https://pascal/capstone/html/src/sanitization.js";



/**
 * Internal helper to ensure a plain object is being sent as JSON.
 *
 * @param {any} value
 */
function _assertPlainObject(value) {

    // Ensure we have a non-null object
    if (typeof value !== "object" || value === null) {throw new Error("_assertPlainObject: packet must be a non-null object");}

    // Arrays are not allowed for top-level packets
    if (Array.isArray(value)) {throw new Error("_assertPlainObject: packet must not be an array");}
}



/**
 * Internal helper to sanitize and validate a path or URL segment.
 *
 * @param {string} rawPath
 * @returns {string}
 */
function _sanitizePath(rawPath) {

    // Ensure input is a string
    if (typeof rawPath !== "string") {throw new Error("_sanitizePath: path must be a string");}

    // Trim and strip control characters
    const cleaned = sanitizeText(rawPath);

    // Basic path sanity checks (no empty string)
    if (cleaned.length === 0) {throw new Error("_sanitizePath: path must not be empty");}

    // Disallow whitespace within path
    if (/\s/.test(cleaned)) {throw new Error("_sanitizePath: path must not contain whitespace");}

    return cleaned;
}




export class PacketTransit  {

    constructor() {

        // Sanitize and store hello endpoint path
        this._helloPath = (HANDSHAKE_HELLO_PATH);

        // Sanitize and store secure endpoint path
        this._securePath = (HANDSHAKE_SECURE_PATH);
    }



    /**
     * Perform a POST request with a JSON body.
     *
     * @param: string - path
     * @param: object - packetObject
     * @returns: Promise<{ ok: boolean, status: number, data: any }>
     */
    async _postJson(path, packetObject) {

        // Sanitize the incoming path value
        const safePath = _sanitizePath(path);

        // Validate that the outgoing packet is a plain object
        _assertPlainObject(packetObject);

        // Serialize the object into JSON text
        let bodyText;
        try {
            bodyText = JSON.stringify(packetObject);
        } catch {
            throw new Error("_postJson: packetObject is not JSON-serializable");
        }

        // Build the fetch options object
        const options = {
            method: "POST",
            headers: JSON_HEADERS,
            body: bodyText
        };

        // Determine the base URL from the browser location
        let origin = "";
        if (typeof window === "object") {
            if (window.location && typeof window.location.origin === "string") {
                origin = window.location.origin;
            }
        }
              
        // Compose the full URL (origin + sanitized path)
        const url = origin + safePath;

        // Execute the HTTP request
        const response = await fetch(url, options);

        // Capture the numeric HTTP status code
        const status = response.status;

        // Prepare container for parsed JSON (if any)
        let data = null;

        // Attempt to parse the response body as JSON safely
        try {

            // Read the raw response text first
            const text = await response.text();

            // If there is no body, leave data as null
            if (text && text.trim().length > 0) {

                // Use our safe JSON parser (throws on malformed JSON)
                data = safeParseJSON(text);

                // Final sanity check: server should send objects, not arrays
                if (typeof data !== "object" || data === null || Array.isArray(data)) {
                    throw new Error("_postJson: server JSON must be an object");
                }
            }
        
        // If parsing or validation fails, treat data as null
        } catch {
            data = null;
        }

        // Determine whether HTTP status indicates success
        const ok = response.ok;

        // Return the normalized result to the caller
        return { ok, status, data };
    }



    /**
     * Send a Client Hello or Logout packet to /api/handshake/hello.
     *
     * @param: object - packetObject: already constructed JSON.
     * @returns: Promise<{ ok: boolean, status: number, data: any }>
     */
    async sendClientHello(packetObject) {

        // Delegate to the generic JSON POST helper
        return this._postJson(this._helloPath, packetObject);
    }



    /**
     * Send a Client Secure Request (Step 3) to /api/handshake/secure.
     *
     * @param: object - packetObject: already constructed JSON.
     * @returns: Promise<{ ok: boolean, status: number, data: any }>
     */
    async sendClientSecureRequest(packetObject) {

        // Delegate to the generic JSON POST helper
        return this._postJson(this._securePath, packetObject);
    }
}



// Export a default transport instance for typical app usage
export const packetTransit = new PacketTransit();
