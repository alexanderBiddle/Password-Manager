/**
 * File name: server_secure_response.js
 * Author:   Alex Biddle
 *
 * Description:
 *   Processes Step-4 of the Four-Way Handshake.
 *   Validates server ciphertext, checksum, RSA-PSS signature, decrypts
 *   AES-GCM payload, returns structured response, handles logout packets,
 *   and enforces strict session binding & timestamp drift rules.
 */




// Imports
import {PROTOCOL_VERSION, RESPONSE_STATUSES, AES_KEY_LENGTH_BYTES, AES_GCM_NONCE_LENGTH_BYTES} from "https://pascal/capstone/html/src/constants.js";
import {fourWaySessionState, SessionState} from "https://pascal/capstone/html/src/handshake/session_state.js";
import {toUtf8Bytes, fromUtf8Bytes, decodeBase64Url, concatenateUint8Arrays} from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import {ChecksumEncryptionManager} from "https://pascal/capstone/html/src/encryption/checksum_encryption.js";
import {RsaEncryptionManager} from "https://pascal/capstone/html/src/encryption/rsa_encryption.js";
import {sanitizeText, safeParseJSON, validateBase64Url, validateTimestamp} from "https://pascal/capstone/html/src/sanitization.js";
import {packetTransit} from "https://pascal/capstone/html/src/handshake/packet_transit.js";




// Create a shared checksum manager instance so we can reuse it across secure requests
const checksumManager = new ChecksumEncryptionManager();



/**
 * Ensure that a value is a non-null plain object (and not an array).
 *
 * @param: any - value
 * @returns: void
 */
function assertPlainObject(value) {

    // Check for non-null object
    if (typeof value !== "object" || value === null) {throw new Error("Server response must be a non-null object");}

    // Reject arrays as top-level packets
    if (Array.isArray(value)) {throw new Error("Server response must not be an array");}
}



/**
 * Sanitize a string field coming from the server packet.
 *
 * @param: any    - rawValue
 * @param: string - fieldName
 * @returns: string
 */
function sanitizeServerStringField(rawValue, fieldName) {

    // Ensure the value is a string
    if (typeof rawValue !== "string") {throw new Error(`Field '${fieldName}' must be a string`);}

    // Apply generic text sanitization
    return sanitizeText(rawValue);
}



/**
 * Validate that a value is a Base64URL string and return it unchanged.
 *
 * @param: string - rawB64u
 * @param: string - fieldName
 * @returns: string
 */
function sanitizeBase64UrlField(rawB64u, fieldName) {

    // Ensure the value is a string
    if (typeof rawB64u !== "string") {throw new Error(`Field '${fieldName}' must be a string`);}

    // Sanitize underlying text
    const cleaned = sanitizeText(rawB64u);

    // Apply Base64URL validation rules
    return validateBase64Url(cleaned);
}


/**
 * Verify RSA-PSS(SHA-256) signature over (server_checksum_b64u || response_status)
 *
 * @param {string} serverChecksumB64u
 * @param {string} responseStatus
 * @param {string} signatureB64u
 * @param {string} serverRsaPublicKeyPem
 * @param {RsaEncryptionManager} rsaManagerInstance
 */
async function verifyServerDigitalSignature(serverChecksumB64u, responseStatus, signatureB64u, serverRsaPublicKeyPem, rsaManagerInstance) {


    // Validate RSA manager instance
    if (!(rsaManagerInstance instanceof RsaEncryptionManager)) {throw new Error("verifyServerDigitalSignature: rsaManagerInstance must be a RsaEncryptionManager");}

    // Ensure responseStatus is a string
    if (typeof responseStatus !== "string") {throw new Error("verifyServerDigitalSignature: responseStatus must be a string");}

    // Signature must be sanitized AND Base64URL validated
    const cleanedSig = validateBase64Url(sanitizeText(signatureB64u));
    const signatureBytes = decodeBase64Url(cleanedSig);

    // signature must not be empty
    if (!(signatureBytes instanceof Uint8Array) || signatureBytes.length === 0) {throw new Error("verifyServerDigitalSignature: decoded signature is empty");}

    // Sanitize the server PEM
    const pem = sanitizeServerStringField(serverRsaPublicKeyPem, "server_rsa_public_key");

    // Import the server RSA-PSS public key via the RSA manager
    const publicKey = await rsaManagerInstance.importPssPublicKey(pem);

    // Compute saltLength = modulusBytes - hashBytes (32) - 2
    const modulusBits = publicKey.algorithm.modulusLength;
    const modulusBytes = modulusBits / 8;
    const hashBytes = 32;
    const saltLength = modulusBytes - hashBytes - 2;

    // Verify the salt length
    if (!Number.isFinite(saltLength) || saltLength <= 0) {throw new Error("verifyServerDigitalSignature: invalid computed saltLength");}


    // Build the signed payload: server_checksum_b64u || response_status
    const payloadString = `${serverChecksumB64u}${responseStatus}`;
    const payloadBytes = toUtf8Bytes(payloadString);

    // Delegate to RSA manager verify method
    const verified = await rsaManagerInstance.verifyPssSignature(publicKey, payloadBytes, signatureBytes, saltLength);

    if (!verified) {throw new Error("verifyServerDigitalSignature: RSA-PSS signature verification failed");}

}



/**
 * Detect whether a packet is a plain logout response (no ciphertext).
 */
function isLogoutPacket(packet) {

    return (typeof packet === "object" && packet !== null && typeof packet.message === "string" && typeof packet.server_ciphertext === "undefined"
    );
}



/**
 * Process a plain logout response packet, validate it, and reset session.
 */
function processLogoutPacket(packet, sessionState = fourWaySessionState) {

    // Extract and sanitize protocol_version
    const protocolVersion = sanitizeText(packet.protocol_version);
    if (protocolVersion !== PROTOCOL_VERSION) {throw new Error("Logout packet protocol_version mismatch");}

    // Extract and sanitize response_status
    const responseStatus = sanitizeText(packet.response_status);
    const allowedStatuses = Object.values(RESPONSE_STATUSES);
    if (!allowedStatuses.includes(responseStatus)) {throw new Error("Logout packet contains invalid response_status");}

    // Extract and sanitize username
    const username = sanitizeText(packet.username);
    const activeUsername = sessionState.getUsername();
    if (typeof activeUsername !== "string" || !activeUsername) {throw new Error("Logout packet received but no active username in session");}

    // Ensure logout username matches session username
    if (username !== activeUsername) {
        throw new Error("Logout packet username mismatch");
    }

    // Validate timestamp with shared sanitization helper
    const timestamp = validateTimestamp(packet.timestamp, "timestamp");

    // Sanitize the message field
    const message = sanitizeServerStringField(packet.message, "message");

    // Reset session
    sessionState.resetSession();

    return {
        kind: "logout",
        responseStatus,
        username,
        timestamp,
        message,
        rawPacket: packet
    };
}



/**
 * Ensure the packet has exactly the required Step 4 fields.
 */
function assertServerEncryptedResponseFields(packet) {

    const requiredFields = [
        "protocol_version",
        "response_status",
        "username",
        "timestamp",
        "server_checksum",
        "server_ciphertext",
        "server_digital_signature"
    ];

    const provided = Object.keys(packet);

    for (const f of requiredFields) {
        if (!provided.includes(f)) {throw new Error(`ServerEncryptedResponse missing required field '${f}'`);}
    }
    for (const f of provided) {
        if (!requiredFields.includes(f)) {throw new Error(`ServerEncryptedResponse contains unknown field '${f}'`);}
    }
}



/**
 * Process Server Encrypted Response (Handshake Step 4).
 */
export async function processServerSecureResponse(serverResponsePacket, sessionState = fourWaySessionState) {

    // Check the session state
    if (!(sessionState instanceof SessionState)) {throw new Error("processServerSecureResponse: sessionState must be a SessionState instance");}

    // Ensure response packet is a plain object
    assertPlainObject(serverResponsePacket);

    // Detect logout packets
    if (isLogoutPacket(serverResponsePacket)) {
        return processLogoutPacket(serverResponsePacket);
    }

    // Ensure packet has required Step-4 fields
    assertServerEncryptedResponseFields(serverResponsePacket);

    // Retrieve active username
    const activeUsername = sessionState.getUsername();
    if (typeof activeUsername !== "string" || !activeUsername) {throw new Error("processServerSecureResponse: no active username in session");}

    // Check for session expiry
    if (sessionState.isExpired()) {
        sessionState.resetSession();
        throw new Error("SecureResponse: session expired");
    }

    // Retrieve AES session key
    const aesKeyBytes = sessionState.getServerAesSessionKeyBytes();
    if (!(aesKeyBytes instanceof Uint8Array)) {throw new Error("processServerSecureResponse: server AES key not initialized");}
    if (aesKeyBytes.length !== AES_KEY_LENGTH_BYTES) {throw new Error("processServerSecureResponse: AES key length mismatch");}

    // protocol_version
    const protocolVersion = sanitizeText(serverResponsePacket.protocol_version);
    if (protocolVersion !== PROTOCOL_VERSION) {throw new Error("ServerEncryptedResponse protocol_version mismatch");}

    // response_status
    const responseStatus = sanitizeText(serverResponsePacket.response_status);
    const allowedStatuses = Object.values(RESPONSE_STATUSES);
    if (!allowedStatuses.includes(responseStatus)) {throw new Error("ServerEncryptedResponse contains invalid response_status");}

    // username
    const serverUsername = sanitizeText(serverResponsePacket.username);
    if (serverUsername !== activeUsername) {throw new Error("ServerEncryptedResponse username does not match active session");}

    // timestamp
    const serverTimestamp = validateTimestamp(serverResponsePacket.timestamp, "timestamp");

    // Checksums 
    const serverChecksumB64u = sanitizeBase64UrlField(serverResponsePacket.server_checksum, "server_checksum");

    // Ciphertext
    const serverCiphertextB64u = sanitizeBase64UrlField(serverResponsePacket.server_ciphertext, "server_ciphertext");

    // signature must be sanitized AND validated
    const serverDigitalSignatureB64u = validateBase64Url(sanitizeText(serverResponsePacket.server_digital_signature));

    // Decode checksum and ciphertext
    const serverChecksumBytes = decodeBase64Url(serverChecksumB64u);
    const ciphertextWithNonceBytes = decodeBase64Url(serverCiphertextB64u);
    if (!(serverChecksumBytes instanceof Uint8Array) || serverChecksumBytes.length === 0) {throw new Error("ServerEncryptedResponse checksum bytes are empty");}
    if (!(ciphertextWithNonceBytes instanceof Uint8Array) || ciphertextWithNonceBytes.length === 0) {throw new Error("ServerEncryptedResponse ciphertext bytes are empty");}

    // Must contain nonce + ciphertext+tag
    if (ciphertextWithNonceBytes.length <= AES_GCM_NONCE_LENGTH_BYTES + 16) {throw new Error("ServerEncryptedResponse ciphertext length is too short");}

    // Nonce first n bytes
    const nonceBytes = ciphertextWithNonceBytes.slice(0, AES_GCM_NONCE_LENGTH_BYTES);

    // Ciphertext-with-tag remainder
    const ciphertextBytes = ciphertextWithNonceBytes.slice(AES_GCM_NONCE_LENGTH_BYTES);

    // checksum input = ciphertext + AES key
    const checksumInput = concatenateUint8Arrays(ciphertextWithNonceBytes, aesKeyBytes);
    const checksumOk = await checksumManager.verifyChecksum(checksumInput, serverChecksumBytes);
    if (!checksumOk) {throw new Error("ServerEncryptedResponse checksum verification failed");}

    // Retrieve RSA public key
    const serverRsaPublicKeyPem = sessionState.getServerRsaPublicKeyPem();
    if (typeof serverRsaPublicKeyPem !== "string" || !serverRsaPublicKeyPem.trim()) {throw new Error("ServerEncryptedResponse: missing server RSA public key PEM in session");}

    // Get the RSA manager
    const clientRsaManager = sessionState.getClientRsaManager();
    if (!(clientRsaManager instanceof RsaEncryptionManager)) {throw new Error("ServerEncryptedResponse: missing client RsaEncryptionManager in session");}
    
    // RSA-PSS digital signature validation
    await verifyServerDigitalSignature(serverChecksumB64u, responseStatus, serverDigitalSignatureB64u, serverRsaPublicKeyPem, clientRsaManager);

    // AAD = username + timestamp
    const aadBytes = toUtf8Bytes(serverUsername + serverTimestamp);

    // Get AES manager from session state
    const aesManager = await sessionState.ensureAesManager();

    // AES-GCM decrypt the ciphertext
    const plaintextBytes = await aesManager.decrypt(aadBytes, nonceBytes, ciphertextBytes);
    if (!(plaintextBytes instanceof Uint8Array)) {throw new Error("ServerEncryptedResponse AES-GCM decrypt produced invalid plaintext");}

    // Decode the ciphertext bytes 
    const plaintextJson = fromUtf8Bytes(plaintextBytes);
    const payload = safeParseJSON(plaintextJson);

    // payload must be an object, not array
    assertPlainObject(payload);

    return {
        kind: "secure_response",
        responseStatus,
        username: serverUsername,
        timestamp: serverTimestamp,
        payload,
        rawPacket: serverResponsePacket
    };
}




/**
 * Sends Client Secure Request (Step 3) and automatically processes
 * the Server Secure Response (Step 4).
 */
export async function runServerSecureResponse(secureRequestPacket, sessionState = fourWaySessionState) {

    // Check the session state type
    if (!(sessionState instanceof SessionState)) {throw new Error("runServerSecureResponse: sessionState must be a SessionState instance");}
    
    // Step 3 → send to server
    const transport = await packetTransit.sendClientSecureRequest(secureRequestPacket);

    if (!transport.ok) {
        return transport;
    }

    // Step 4 → decrypt + verify + parse
    return await processServerSecureResponse(transport.data, sessionState);
}
