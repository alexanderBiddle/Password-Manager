/**
 * File name: server_hello.js
 * Author: Alex Biddle
 *
 * Description:
 *    Builds the Step-3 Client Secure Request packet for the Four-Way Handshake.
 *    This packet uses AES-256-GCM, carries encrypted payload and metadata,
 *    and binds to the active session established during Client-Hello → Server-Hello. 
 */




// Imports
import {PROTOCOL_VERSION, CLIENT_SALT_LENGTH_BYTES, CHECKSUM_DIGEST_LENGTH_BYTES, AES_KEY_LENGTH_BYTES, VAULT_SALT_LENGTH_BYTES, RESPONSE_STATUSES} from "https://pascal/capstone/html/src/constants.js";
import {sanitizeText, sanitizeUsername, validateBase64Url, safeParseJSON, validateTimestamp} from "https://pascal/capstone/html/src/sanitization.js";
import {decodeBase64Url, toUtf8Bytes} from "https://pascal/capstone/html/src/encryption/encryption_utilities.js";
import {ChecksumEncryptionManager} from "https://pascal/capstone/html/src/encryption/checksum_encryption.js";
import {RsaEncryptionManager} from "https://pascal/capstone/html/src/encryption/rsa_encryption.js";
import {SessionState, fourWaySessionState} from "https://pascal/capstone/html/src/handshake/session_state.js";
import {packetTransit} from "https://pascal/capstone/html/src/handshake/packet_transit.js";


// Shared checksum manager (SHA-256)
const _checksumManager = new ChecksumEncryptionManager();



/**
 * Validate that object has exactly the required fields (no missing, no extras)
 */
function _assertExactServerHelloFields(packet) {

    // Confirm that the value is a non-null object
    if (typeof packet !== "object" || packet === null) {
        throw new Error("_assertExactServerHelloFields: value must be a non-null object");
    }

    // Define the exact set of required field names for the Server Hello packet
    const requiredFieldNames = new Set([
        "protocol_version",
        "response_status",
        "username",
        "timestamp",
        "server_checksum",
        "server_aes_session_key",
        "server_rsa_public_key",
        "server_key_identifier",
        "server_key_expiry",
        "server_digital_signature",
        "server_ciphertext"
    ]);

    const keys = Object.keys(packet);

    // missing fields
    for (const req of requiredFieldNames) {
        if (!keys.includes(req)) {
            throw new Error(`Server Hello: missing required field '${req}'`);
        }
    }

    // extra fields
    for (const key of keys) {
        if (!requiredFieldNames.has(key)) {
            throw new Error(`Server Hello: unknown extra field '${key}'`);
        }
    }
}




// Compute server checksum H(username + timestamp) and compare to expected digest
async function _verifyServerChecksum(usernameValue, timestampValue, checksumB64Url) {

    // Validate base 64 and convert to bytes
    const validatedChecksum = validateBase64Url(checksumB64Url);
    const checksumBytes = decodeBase64Url(validatedChecksum);

    if (checksumBytes.length !== CHECKSUM_DIGEST_LENGTH_BYTES) {
        throw new Error("Server Hello: checksum must be 32 bytes");
    }

    // Concatenate the sanitized username and sanitized timestamp into one string
    const bindingBytes = toUtf8Bytes(usernameValue + timestampValue);
    const expectedBytes  = await _checksumManager.computeChecksum(bindingBytes);
    
    // Check that both checksums are equal
    for (let i = 0; i < 32; i++) {
        if (checksumBytes[i] !== expectedBytes[i]) {
            throw new Error("Server Hello: checksum mismatch");
        }
    }
}



/**
 * Decrypt and process the RSA-encrypted server_ciphertext payload.
 *
 * @returns {Promise<{clientSaltBytes: Uint8Array|null, vaultSaltBytes: Uint8Array|null}>}
 */
async function _processServerCiphertext(serverCiphertextB64u, clientRsaManager) {

    // Decode ciphertext
    const ciphertextBytes = decodeBase64Url(validateBase64Url(serverCiphertextB64u));

    // Special-case: signup or vault requests send dummy value (0-byte payload)
    if (ciphertextBytes.length === 1 && ciphertextBytes[0] === 0) {
        return { clientSaltBytes: null, vaultSaltBytes: null };
    }
    
    // RSA-decrypt the ciphertext
    const decryptedBytes = await clientRsaManager.decryptWithPrivateKeyBytes(ciphertextBytes);
    const jsonText = new TextDecoder().decode(decryptedBytes);

    let parsed;

    // Parse the decrypted data
    try {
        parsed = JSON.parse(jsonText);
    
    // Error parsing
    } catch (err) {throw new Error("Server Hello: decrypted payload is not valid JSON");}

    // Validate expected fields
    if (typeof parsed !== "object" || parsed === null) {throw new Error("Server Hello: decrypted payload must be an object");}
    
    const { client_salt, vault_salt } = parsed;

    // If server did not send salts, return null for each
    if (!client_salt && !vault_salt) {
        return { clientSaltBytes: null, vaultSaltBytes: null };
    }

    // Validate salt values
    const clientSaltBytes = decodeBase64Url(validateBase64Url(client_salt));
    if (clientSaltBytes.length !== CLIENT_SALT_LENGTH_BYTES) {throw new Error("Server Hello: client_salt must be 16 bytes");}

    const vaultSaltBytes = decodeBase64Url(validateBase64Url(vault_salt));
    if (vaultSaltBytes.length !== VAULT_SALT_LENGTH_BYTES) {throw new Error("Server Hello: vault_salt must be 16 bytes");}

    return { clientSaltBytes, vaultSaltBytes };
}



/**
 * Process and validate a Step-2 Server Hello response.
 *
 * @param {object} transportResult - { ok:boolean, status:number, data:any } from packet_transit.sendClientHello()
 * @param {SessionState} sessionState - current handshake session state
 * @returns {Promise<{ ok:boolean, status:number, data:any }>}
 */
export async function processServerHello(transportResult, sessionState = fourWaySessionState) {

    // Validate parameters
    if (!(sessionState instanceof SessionState)) {
        throw new Error("processServerHello: sessionState must be a SessionState instance");
    }
   
    // Ensure the result of the data is valid
    if (!transportResult.ok) {return transportResult;}

    // Safe-parse JSON 
    const serverData = safeParseJSON(JSON.stringify(transportResult.data));

    // Ensure we actually got an object
    if (typeof serverData !== "object" || serverData === null || Array.isArray(serverData)) {
        throw new Error("processServerHello: serverData must be a non-null object");
    }

    _assertExactServerHelloFields(serverData);

    // Get all the fields from the packet
     const {
        protocol_version,
        response_status,
        username,
        timestamp,
        server_checksum,
        server_aes_session_key,
        server_rsa_public_key,
        server_key_identifier,
        server_key_expiry,
        server_digital_signature,
        server_ciphertext
    } = serverData;

    // Validate Protocol version and Response type
    if (protocol_version !== PROTOCOL_VERSION) {throw new Error("Server Hello: protocol_version mismatch");}
    if (!Object.values(RESPONSE_STATUSES).includes(response_status)) {throw new Error(`Server Hello: invalid response_status '${response_status}'`);}

    // Sanitize the packet username and Retrive the stored username
    const sanitizedUsername = sanitizeUsername(username);
    const session_username = sessionState.getUsername();
    if (sanitizedUsername !== session_username) {throw new Error("Server Hello: username mismatch");}

    // Set the server verified username to the user session object
    sessionState.setUsername(sanitizedUsername);

    // Validate the timestamp
    const sanitizedTimestamp = validateTimestamp(timestamp);

    // Verify the checksums match
    await _verifyServerChecksum(sanitizedUsername, sanitizedTimestamp, server_checksum);

    // Get the RSA manager for decrypting 
    const clientRsaManager = sessionState.getClientRsaManager();
    if (!(clientRsaManager instanceof RsaEncryptionManager)) {throw new Error("Server Hello: missing RsaEncryptionManager in session");}

    // Get the AES key bytes 
    const wrappedKeyBytes = decodeBase64Url(validateBase64Url(server_aes_session_key));

    // Decrypt the AES key bytes with the RSA manager
    const aesKeyBytes = await clientRsaManager.decryptWrappedAesKey(wrappedKeyBytes);
    if (aesKeyBytes.length !== AES_KEY_LENGTH_BYTES) {throw new Error("Server Hello: AES key must be 32 bytes");}

    // Import the RSA key in pem format
    const verifiedKey = await clientRsaManager.importPssPublicKey(sanitizeText(server_rsa_public_key));

    // Validate and convert the data for digital signature verification
    const keyIdBytes = toUtf8Bytes(sanitizeText(server_key_identifier));
    const timestampBytes = toUtf8Bytes(sanitizedTimestamp);

    // Concatonate the signature payload --> len(aes_key) + len(key_id) + len(timestamp)
    const payloadBytes = new Uint8Array(aesKeyBytes.length + keyIdBytes.length + timestampBytes.length);
    payloadBytes.set(aesKeyBytes, 0);
    payloadBytes.set(keyIdBytes, aesKeyBytes.length);
    payloadBytes.set(timestampBytes, aesKeyBytes.length + keyIdBytes.length);

    // Decode and validate the server digital signature
    const sigBytes = decodeBase64Url(validateBase64Url(server_digital_signature));

    // Get the salt length
    const modulusBytes = verifiedKey.algorithm.modulusLength / 8;
    const saltLength = modulusBytes - 32 - 2;

    // Verify the digital signature
    const signatureValid = await clientRsaManager.verifyPssSignature(verifiedKey, payloadBytes, sigBytes, saltLength);
    if (!signatureValid) {throw new Error("Server Hello: RSA-PSS signature invalid");}

    // Process and validate the salts
    const { clientSaltBytes, vaultSaltBytes } = await _processServerCiphertext(server_ciphertext, clientRsaManager);
    
    // Update the user session state 
    sessionState.setAfterServerHello({
        serverRsaPublicKeyPem: sanitizeText(server_rsa_public_key),
        serverKeyIdentifier: sanitizeText(server_key_identifier),
        serverAesSessionKeyBytes: aesKeyBytes,
        sessionCreatedAtIso8601: sanitizedTimestamp
    });
    
    
    // Set the client salt value
    if (clientSaltBytes) {
        sessionState.setClientSaltBytes(clientSaltBytes);
    }

    // Set the vault salt value
    if (vaultSaltBytes) {
        sessionState.setVaultSaltBytes(vaultSaltBytes);
    }

    return {
        ok: true,
        status: transportResult.status,
        data: serverData
    };
}



/**
 * Sends Client Hello (Step 1) + automatically processes Server Hello (Step 2)
 *
 * @param {object} clientHelloPacket
 * @param {SessionState} sessionState
 */
export async function runServerHello(clientHelloPacket, sessionState = fourWaySessionState) {
    const transport = await packetTransit.sendClientHello(clientHelloPacket);
    return await processServerHello(transport, sessionState);
}
