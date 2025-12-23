/**
 * File name: constants.js
 * Author: Alex Biddle
 *
 * Description:
 *      This file contains all the constant varibales used around the client.
 */




// CipherSafe Four-Way Handshake protocol version string.
export const PROTOCOL_VERSION = "CipherSafe Handshake v1";


// The length of a hashed password
export const HASHED_PASSWORD_LENGTH_BYTES = 32;


// AES-256 key data
export const AES_KEY_LENGTH_BYTES = 32;
export const AES_GCM_NONCE_LENGTH_BYTES = 12;


// Checksum Data
export const CHECKSUM_DIGEST_LENGTH_BYTES = 32;
export const CHECKSUM_ALGORITHM_NAME = "SHA-256";


//  Expected lengths for salt and hash 
export const CLIENT_SALT_LENGTH_BYTES = 16;
export const CLIENT_HASH_LENGTH_BYTES = 32;

// vault_salt 16 bytes
export const VAULT_SALT_LENGTH_BYTES = CLIENT_SALT_LENGTH_BYTES;


// Time data of sessions and packet 
export const TIMESTAMP_DRIFT_SECONDS = 5;
export const SESSION_TTL_SECONDS = 15 * 60;


// Strict ISO8601Z regex — matches SERVER CONSTANTS EXACTLY
export const ISO8601Z_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;


// Logical handshake states used by the server's
export const HANDSHAKE_STATES = Object.freeze({
    NONE: "none",
    HELLO: "hello",
    SECURE: "encrypted",
    COMPLETE: "complete"
});


// All valid "request_type" values for client packets.
export const REQUEST_TYPES = Object.freeze({
    LOGIN: "login",
    SIGNUP: "signup",
    LOGOUT: "logout",
    VAULT_FETCH_ACCOUNTS: "vault_fetch_accounts",
    VAULT_FETCH_ACCOUNT_PASSWORD: "vault_fetch_account_password",
    VAULT_ADD_ACCOUNT: "vault_add_account",
    VAULT_UPDATE_ACCOUNT: "vault_update_account",
    VAULT_DELETE_ACCOUNT: "vault_delete_account",
    VAULT_UPDATE_MASTER_PASSWORD: "vault_update_master_password"
});


// All valid "response_status" values for server packets.
export const RESPONSE_STATUSES = Object.freeze({
    SUCCESS: "success",
    INVALID_ACCOUNT: "invalid_account",
    AUTHENTICATION_FAILED: "authentication_failed",
    USER_ACCOUNT_EXISTS: "user_account_exists",
    INVALID_CHECKSUM: "invalid_checksum",
    FAILURE: "failure"
});


// Url paths for sending packets to the server
export const BASE_URL = "/capstone2";
export const HANDSHAKE_HELLO_PATH  = `${BASE_URL}/api/handshake/hello`;
export const HANDSHAKE_SECURE_PATH = `${BASE_URL}/api/handshake/secure`;
export const LOGOUT_PATH           = `${BASE_URL}/api/logout`;



// Standard JSON headers for all API calls.
export const JSON_HEADERS = Object.freeze({
    "Content-Type": "application/json",
    "Accept": "application/json"
});


// Argon2id parameters for client-side hashing.
export const ARGON2ID_PARAMS = Object.freeze({
    TIME_COST: 3,
    MEMORY_COST_KIB: 64 * 1024, // 64 MiB
    PARALLELISM: 2,
    HASH_LENGTH_BYTES: 32,
    SALT_LENGTH_BYTES: 16
});



// ApplicationCodes that the client must Take care of
export const ERROR_CODES = Object.freeze({
    MALFORMED_JSON: "malformed_json",
    MISSING_FIELDS: "missing_fields",
    UNKNOWN_FIELDS: "unknown_fields",
    INVALID_TYPE: "invalid_type",
    INVALID_LENGTH: "invalid_length",
    INVALID_CONTENT_TYPE: "invalid_content_type",
    INVALID_PROTOCOL: "invalid_protocol_version",
    INVALID_REQUEST: "invalid_request",
    INVALID_PACKET_STRUCTURE: "invalid_packet_structure",
    INVALID_REQUEST_TYPE: "invalid_request_type",
    INVALID_RESPONSE_STATUS: "invalid_response_status",
    INVALID_USERNAME: "invalid_username",
    INVALID_ACCOUNT: "invalid_account",
    USER_EXISTS: "user_exists",
    AUTH_FAILED: "auth_failed",
    INVALID_TIMESTAMP: "invalid_timestamp",
    REPLAY_DETECTED: "replay_detected",
    SESSION_EXPIRED: "session_expired",
    SESSION_NOT_FOUND: "session_not_found",
    SECURE_REQUEST_SESSION_ERROR: "secure_request_session_error",
    SECURE_REQUEST_USERNAME_MISMATCH: "secure_request_username_mismatch",
    SECURE_REQUEST_CHECKSUM_ERROR: "secure_request_checksum_error",
    SECURE_REQUEST_NONCE_ERROR: "secure_request_nonce_error",
    SECURE_REQUEST_DECRYPTION_ERROR: "secure_request_decryption_error",
    NOT_FOUND: "not_found",
    RATE_LIMITED: "rate_limited"
});