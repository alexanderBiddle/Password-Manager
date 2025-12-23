/**
 * File name: client_secure_request.js
 * Author: Alex Biddle
 *
 * Description:
 *    Builds the Step-3 Client Secure Request packet for the Four-Way Handshake.
 *    This packet uses AES-256-GCM, carries encrypted payload and metadata,
 *    and binds to the active session established during Client-Hello → Server-Hello. 
 */



// Imports
import {PROTOCOL_VERSION, REQUEST_TYPES, AES_KEY_LENGTH_BYTES} from "https://pascal/capstone/html/src/constants.js";
import {toUtf8Bytes, encodeBase64Url, concatenateUint8Arrays} from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import {ChecksumEncryptionManager} from "https://pascal/capstone/html/src/encryption/checksum_encryption.js";
import {SessionState, fourWaySessionState} from "https://pascal/capstone/html/src/handshake/session_state.js";
import {packetTransit} from "https://pascal/capstone/html/src/handshake/packet_transit.js";
import {sanitizeUsername, validateTimestamp, generateIso8601ZTimestamp} from "https://pascal/capstone/html/src/sanitization.js";




// Create a shared checksum manager instance so we can reuse it across secure requests
const _checksumManager = new ChecksumEncryptionManager();


// Ensure the session has required salts depending on request type
function ensureSaltsPresentOrThrowError(requestType, sessionState = fourWaySessionState) {

    // LOGIN secure request MUST have client_salt AND vault_salt
    if (requestType === REQUEST_TYPES.LOGIN) {
        if (!sessionState.getClientSaltBytes()) {
            throw new Error("buildClientSecureRequestPacket: missing client_salt in sessionState");
        }
        if (!sessionState.getVaultSaltBytes()) {
            throw new Error("buildClientSecureRequestPacket: missing vault_salt in sessionState");
        }
    }

    // Vault operations require vault_salt (client-side encryption requires it)
    const vaultOps = new Set([
        REQUEST_TYPES.VAULT_ADD_ACCOUNT,
        REQUEST_TYPES.VAULT_UPDATE_ACCOUNT,
        REQUEST_TYPES.VAULT_DELETE_ACCOUNT,
        REQUEST_TYPES.VAULT_FETCH_ACCOUNTS,
        REQUEST_TYPES.VAULT_FETCH_ACCOUNT_PASSWORD
    ]);

    if (vaultOps.has(requestType)) {
        if (!sessionState.getVaultSaltBytes()) {
            throw new Error(`buildClientSecureRequestPacket: vault_salt missing for request '${requestType}'`);
        }
    }
}


// Define a helper function to normalize and validate the secure request type
function validateSecureRequestType(rawRequestType) {

    // Ensure that the raw request type is a string
    if (typeof rawRequestType !== "string") {throw new Error("buildClientSecureRequestPacket: requestType must be a string");}

    // Build an array of all allowed request type values from REQUEST_TYPES
    const allowedTypes = Object.values(REQUEST_TYPES);

    // Verify that the cleaned request type is one of the allowed values
    if (!allowedTypes.includes(rawRequestType)) {throw new Error(`buildClientSecureRequestPacket: invalid requestType '${rawRequestType}'`);}

    // Return the sanitized and validated request type
    return rawRequestType;
}

// Check that the user has a active session stored for them
function ensureActiveSessionOrThrow(sessionState = fourWaySessionState) {
    if (!sessionState.getUsername()) {
        throw new Error("buildClientSecureRequestPacket: SessionState has no active username");
    }

    if (!sessionState.getServerAesSessionKeyBytes()) {
        throw new Error("buildClientSecureRequestPacket: No AES session_key established");
    }

    if (!sessionState.getServerKeyIdentifier()) {
        throw new Error("buildClientSecureRequestPacket: Missing server_rsa_key_identifier");
    }
}


// Export the main function that builds a Client Encrypted Request packet
export async function buildClientSecureRequestPacket(requestType, payloadObject, sessionState = fourWaySessionState) {
	
	// Ensure that the user has a active session object
	ensureActiveSessionOrThrow(sessionState);
	
    // Ensure that the provided sessionState is an instance of SessionState
    if (!(sessionState instanceof SessionState)) {throw new Error("buildClientSecureRequestPacket: sessionState must be a SessionState instance");}

    // Retrieve and sanitize session-bound username
    const rawSessionUsername = sessionState.getUsername();
    if (typeof rawSessionUsername !== "string") {throw new Error("buildClientSecureRequestPacket: SessionState has no active username");}
    const sanitizedUsername = sanitizeUsername(rawSessionUsername);


    // Validate the AES session key
    const aesKeyBytes = sessionState.getServerAesSessionKeyBytes();
    if (!(aesKeyBytes instanceof Uint8Array)) {throw new Error("buildClientSecureRequestPacket: AES session key in SessionState is not initialized");}
    if (aesKeyBytes.length !== AES_KEY_LENGTH_BYTES) {throw new Error("buildClientSecureRequestPacket: AES session key must be exactly 32 bytes");}


    // Validate server_key_identifier
    const rawServerKeyIdentifier = sessionState.getServerKeyIdentifier();
    if (typeof rawServerKeyIdentifier !== "string" || !rawServerKeyIdentifier.trim()) {throw new Error("buildClientSecureRequestPacket: SessionState has no server_key_identifier");}
    const sanitizedServerKeyIdentifier = rawServerKeyIdentifier.trim();


    // Normalize and validate the request type
    const cleanRequestType = validateSecureRequestType(requestType);

    // Ensure salts needed for this request are present
    ensureSaltsPresentOrThrowError(cleanRequestType, sessionState);

    // Serialize the payload object into JSON
    const payloadJsonString = JSON.stringify(payloadObject);

    // Convert JSON to UTF-8 bytes
    const payloadBytes = toUtf8Bytes(payloadJsonString);

    // Generate strict ISO8601Z timestamp and validate 
    const clientTimestampIsoRaw = generateIso8601ZTimestamp();
    const clientTimestampIso = validateTimestamp(clientTimestampIsoRaw, "timestamp");

    // Build AAD: username + timestamp
    const aadString = `${sanitizedUsername}${clientTimestampIso}`;
    const aadBytes = toUtf8Bytes(aadString);

    // Ensure that we have an AES manager instance attached to the SessionState
    const aesManager = await sessionState.ensureAesManager();

    // Perform AES-GCM encryption using the AES manager
    const encryptionResult = await aesManager.encrypt(aadBytes, payloadBytes);

    // Get the nonce and ciphertext with the tag
    const nonceBytes = encryptionResult.nonce;
    const ciphertextWithTagBytes = encryptionResult.ciphertextWithTag;
    if (!(nonceBytes instanceof Uint8Array)) {throw new Error("buildClientSecureRequestPacket: AES-GCM nonce must be a Uint8Array");}
    if (!(ciphertextWithTagBytes instanceof Uint8Array)) {throw new Error("buildClientSecureRequestPacket: AES-GCM ciphertextWithTag must be a Uint8Array");}

    // Add the nonce to the client session
    const nonceB64u = encodeBase64Url(nonceBytes);
    sessionState.addUsedNonce(nonceB64u);
    
    // Combine nonce + ciphertext + tag
    const fullCiphertextBytes = concatenateUint8Arrays(nonceBytes, ciphertextWithTagBytes);

    // Encode ciphertext (nonce + tag) as Base64URL
    const clientCiphertextB64u = encodeBase64Url(fullCiphertextBytes);

    // Compute client_checksum = SHA-256(ciphertext_bytes + AES_key)
    const checksumInputBytes = concatenateUint8Arrays(fullCiphertextBytes, aesKeyBytes);
    const checksumBytes = await _checksumManager.computeChecksum(checksumInputBytes);
    const clientChecksumB64u = encodeBase64Url(checksumBytes);

    // Encode AES session key bytes for protocol echo
    const serverAesSessionKeyB64u = encodeBase64Url(aesKeyBytes);

    // Construct the final packet
    const secureRequestPacket = {

        protocol_version: PROTOCOL_VERSION,
        request_type: cleanRequestType,
        username: sanitizedUsername,
        timestamp: clientTimestampIso,
        client_checksum: clientChecksumB64u,
        server_aes_session_key: serverAesSessionKeyB64u,
        server_key_identifier: sanitizedServerKeyIdentifier,
        client_ciphertext: clientCiphertextB64u
    };

    return secureRequestPacket;
}




// Build and send a Client Secure Request packet.
export async function sendClientSecureRequest(requestType, payloadObject, sessionState = fourWaySessionState) {
    
    // Build secure packet
    const securePacket = await buildClientSecureRequestPacket(requestType, payloadObject, sessionState);

    // POST to /api/handshake/secure
    return await packetTransit.sendClientSecureRequest(securePacket);
}




// Helper — Send LOGIN secure request (Step 3 after successful Server Hello).
export async function sendLoginSecureRequest(payloadObject, sessionState = fourWaySessionState) {
    return sendClientSecureRequest(REQUEST_TYPES.LOGIN, payloadObject, sessionState);
}




// Helper — Send SIGNUP secure request.
export async function sendSignupSecureRequest(payloadObject, sessionState = fourWaySessionState) {
    return sendClientSecureRequest(REQUEST_TYPES.SIGNUP, payloadObject, sessionState);
}




// Helper — Send request for fetching the user vault (all accounts).
export async function sendVaultFetchRequest(payloadObject, sessionState = fourWaySessionState) {
    return sendClientSecureRequest(REQUEST_TYPES.VAULT_FETCH_ACCOUNTS, payloadObject, sessionState);
}




// Helper — Send request to add a vault entry.
export async function sendVaultAddRequest(payloadObject, sessionState = fourWaySessionState) {
    return sendClientSecureRequest(REQUEST_TYPES.VAULT_ADD_ACCOUNT, payloadObject, sessionState);
}




// Helper — Send request to delete a vault entry.
export async function sendVaultDeleteRequest(payloadObject, sessionState = fourWaySessionState) {
    return sendClientSecureRequest(REQUEST_TYPES.VAULT_DELETE_ACCOUNT, payloadObject, sessionState);
}




// Helper — Send logout secure request
export async function sendLogoutSecureRequest(sessionState = fourWaySessionState) {
    return sendClientSecureRequest(REQUEST_TYPES.LOGOUT, {}, sessionState);
}
