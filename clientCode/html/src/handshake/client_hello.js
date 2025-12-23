/**
 * File name: client_hello.js
 * Author: Alex Biddle
 *
 * Description:
 *     
 */


import {PROTOCOL_VERSION, REQUEST_TYPES} from "https://pascal/capstone/html/src/constants.js";
import {sanitizeUsername, generateIso8601ZTimestamp} from "https://pascal/capstone/html/src/sanitization.js";
import {toUtf8Bytes, encodeBase64Url} from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import {ChecksumEncryptionManager} from "https://pascal/capstone/html/src/encryption/checksum_encryption.js";
import {RsaEncryptionManager} from "https://pascal/capstone/html/src/encryption/rsa_encryption.js";
import {SessionState, fourWaySessionState} from "https://pascal/capstone/html/src/handshake/session_state.js";
import {packetTransit} from "https://pascal/capstone/html/src/handshake/packet_transit.js";



// Create a single checksum manager instance for computing hello checksums
const _checksumManager = new ChecksumEncryptionManager();



/**
 * Compute the SHA-256 checksum for a Client Hello payload.
 *
 * @param {object} payloadWithoutChecksum - Core Client Hello fields.
 * @returns {Promise<string>} - Base64URL-encoded checksum digest.
 */
async function _computeClientHelloChecksum(payloadWithoutChecksum) {

    // Ensure a non-null object is given for checksum calculation
    if (typeof payloadWithoutChecksum !== "object" || payloadWithoutChecksum === null) {
    	throw new Error("_computeClientHelloChecksum: payload must be a non-null object");
    }

    /// Extract username and timestamp exactly as the server expects
    const username = payloadWithoutChecksum.username;
    const timestamp = payloadWithoutChecksum.timestamp;

    if (typeof username !== "string" || typeof timestamp !== "string") {
        throw new Error("_computeClientHelloChecksum: payload must contain string username and timestamp");
    }

    // Build the binding string: username + timestamp
    const bindingString = `${username}${timestamp}`;

    // Convert to UTF-8 bytes so checksum is deterministic
    const bindingBytes = toUtf8Bytes(bindingString);

    // Compute a SHA-256 digest (32 bytes) over the binding bytes
    const digestBytes = await _checksumManager.computeChecksum(bindingBytes);

    // Encode the raw digest bytes as Base64URL for transport
    return encodeBase64Url(digestBytes);
}



/**
 * Build the Client Hello JSON packet (without sending it).
 *
 * @param {string} rawUsername
 * @param {string} requestType - One of REQUEST_TYPES.LOGIN / SIGNUP / LOGOUT, etc.
 * @param {SessionState} sessionState
 * @returns {Promise<object>} - Fully formed Client Hello packet.
 */
async function buildClientHelloPacket(rawUsername, requestType, sessionState = fourWaySessionState) {

    // Validate parameters
    if (!(sessionState instanceof SessionState)) {
        throw new Error("buildClientHelloPacket: sessionState must be a SessionState instance");
    }
    if (!Object.values(REQUEST_TYPES).includes(requestType)) {
        throw new Error(`buildClientHelloPacket: invalid request_type '${requestType}'`);
    }
    
    // Validate the username
    const sanitizedUsername = sanitizeUsername(rawUsername);

    // Persist the username into session state so later steps can bind to it
    sessionState.setUsername(sanitizedUsername);

    // Retrieve the existing client RSA manager, if any
    let clientRsa = sessionState.getClientRsaManager();

    // If no client RSA keypair yet, generate a new 2048-bit RSA-OAEP pair
    if (!clientRsa) {
        clientRsa = await RsaEncryptionManager.generate();
        sessionState.setClientRsaManager(clientRsa);
        //console.log("[ClientHello] Public key PEM (first 80 chars):", clientPublicKeyPem.slice(0, 80));
    }
    

    // Export the client's RSA public key as PEM text
    const clientPublicKeyPem = await clientRsa.exportPublicKeyPem();
    
    // Generate a strict ISO8601Z timestamp for this Client Hello
    const timestamp = generateIso8601ZTimestamp();

    // Construct the core payload that will be checksummed (no checksum yet)
    const payloadWithoutChecksum = {
        protocol_version: PROTOCOL_VERSION,
        request_type: requestType,
        username: sanitizedUsername,
        timestamp: timestamp,
        client_rsa_public_key: clientPublicKeyPem
    };

    // Compute a SHA-256 checksum over the JSON serialization
    const checksum = await _computeClientHelloChecksum(payloadWithoutChecksum);

    // Return the final packet including the checksum field
    return {
        ...payloadWithoutChecksum,
        client_checksum: checksum
    };
}



/**
 * Build and send a Client Hello packet for login or signup.
 *
 *
 * @param {string} rawUsername
 * @param {string} requestType - One of REQUEST_TYPES.LOGIN / SIGNUP.
 * @param {SessionState} sessionState - Shared handshake session state.
 * @returns {Promise<{ ok: boolean, status: number, data: any }>}
 */
export async function sendClientHello(rawUsername, requestType, sessionState = fourWaySessionState) {

    // Build the Client Hello JSON structure (including checksum)
    const clientHelloPacket = await buildClientHelloPacket(rawUsername, requestType, sessionState);

    // Send the packet to /api/handshake/hello via packet_transit.js
    const result = await packetTransit.sendClientHello(clientHelloPacket);

    // Return the normalized transport result to the caller
    return result;
}



/**
 * Helper for sending a login request packet to the server.
 *
 * @param {string} rawUsername
 * @param {SessionState} sessionState
 * @returns {Promise<{ ok: boolean, status: number, data: any }>}
 */
export async function sendLoginClientHello(rawUsername, sessionState = fourWaySessionState) {

    // Delegate to sendClientHello with REQUEST_TYPES.LOGIN
    return sendClientHello(rawUsername, REQUEST_TYPES.LOGIN, sessionState);
}



/**
 * Helper for sending a sign up request packet to the server.
 *
 * @param {string} rawUsername
 * @param {SessionState} sessionState
 * @returns {Promise<{ ok: boolean, status: number, data: any }>}
 */
export async function sendSignupClientHello(rawUsername, sessionState = fourWaySessionState) {

    // Delegate to sendClientHello with REQUEST_TYPES.SIGNUP
    return sendClientHello(rawUsername, REQUEST_TYPES.SIGNUP, sessionState);
}

