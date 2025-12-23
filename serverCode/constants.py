#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: constants.py
    Author: Alex Biddle

    Description:
        Centralized protocol constants for CipherSafe's Four-Way Handshake.
        Defines protocol version, allowed request/response types, maximum
        field sizes, and regex patterns shared across validation modules
        (packet handlers, sanitization, and handshake processing).
"""

import re
from typing import Set


# Protocol version string (used by handshake validation)
_PROTOCOL_VERSION = "CipherSafe Handshake v1"

 # 15 minutes TTL for each session
_SESSION_TTL_SECONDS: int = 15 * 60


# Allowed handshake states for internal session tracking
_HANDSHAKE_STATE_NONE = "none"
_HANDSHAKE_STATE_HELLO = "hello"
_HANDSHAKE_STATE_ENCRYPTED = "encrypted"
_HANDSHAKE_STATE_COMPLETE = "complete"
_ALLOWED_HANDSHAKE_STATES: Set[str] = {"none", "hello", "encrypted", "complete"}

# Maximum allowed username length
_MAX_USERNAME_LEN = 64

# Maximum decoded Base64URL size (bytes)
_MAX_B64URL_BYTES = 65536


# ISO8601 UTC timestamp regex
_ISO8601Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Base64URL regex with optional padding
_BASE64URL_RX = re.compile(r"^[A-Za-z0-9_\-]+={0,2}$")

# Nonce byte lenegth for a AES-GCM key
_AES_GCM_NONCE_LEN_BYTES = 12

# Number of bytes for the password salts
_LOGIN_SALT_LEN_BYTES = 16

# Number of bytes for a hashed password
_HASHED_PASSWORD_LENGTH = 32


################################################################################################
# Allowed request types
################################################################################################

# Allowed client request types
_ALLOWED_REQUEST_TYPES = {
    "login", 
    "signup", 
    "vault_fetch_accounts", 
    "vault_fetch_account_password",
    "vault_add_account", 
    "vault_update_account", 
    "vault_delete_account",
    "vault_update_master_password", 
    "logout"
}

# Allowed response status strings
_ALLOWED_RESPONSE_STATUSES = {
    "success",   
    "invalid_account",         
    "authentication_failed", 
    "user_account_exists", 
    "invalid_checksum",
    "failure", 
}

RESPONSE_STATUS_SUCCESS = "success"
RESPONSE_STATUS_INVALID_ACCOUNT = "invalid_account"
RESPONSE_STATUS_AUTH_FAILED = "authentication_failed"
RESPONSE_STATUS_USER_EXISTS = "user_account_exists"
RESPONSE_STATUS_INVALID_CHECKSUM = "invalid_checksum"
RESPONSE_STATUS_FAILURE = "failure"



################################################################################################
# Client packet fields
################################################################################################

# Fields required for the Client Hello (Step 1)
_CLIENT_HELLO_REQUIRED_FIELDS = {
    "protocol_version",
    "request_type",
    "username",
    "client_rsa_public_key",
    "timestamp",
    "client_checksum"
}

# Fields required for the Client Encrypted Request (Step 3)
_CLIENT_ENCRYPTED_REQUEST_REQUIRED_FIELDS = {
    "protocol_version",
    "request_type",
    "username",
    "timestamp",
    "client_checksum",
    "server_aes_session_key",
    "server_key_identifier",
    "client_ciphertext"
}


################################################################################################
# Server packet fields
################################################################################################

# Fields required for the Server Hello (Step 2)
_SERVER_HELLO_REQUIRED_FIELDS = {
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
}

# Fields required for the Server Secure Response (Step 4)
_SERVER_ENCRYPTED_RESPONSE_REQUIRED_FIELDS = {
    "protocol_version",
    "response_status",
    "username",
    "timestamp",
    "server_checksum",
    "server_ciphertext",
    "server_digital_signature"
}

# Fields required for the Server Logout Confirmation
_SERVER_LOGOUT_RESPONSE_REQUIRED_FIELDS = {
    "protocol_version",
    "response_status",
    "username",
    "timestamp",
    "message"
}

# Fields required for the Server Error Response
_SERVER_ERROR_RESPONSE_REQUIRED_FIELDS = {
    "protocol_version",
    "response_status",
    "username",
    "timestamp",
    "message",
    "error_code",
    "field"
}



################################################################################################
# Vault operation payload schemas (optional but recommended)
################################################################################################

# Required fields for vault_add_account payload
_VAULT_ADD_ACCOUNT_REQUIRED_FIELDS = {
    "website",              
    "account_username",     
    "account_email",       
    "account_password"      
}

# Required fields for vault_update_account payload
_VAULT_UPDATE_ACCOUNT_REQUIRED_FIELDS = {
    "old_website",
    "old_account_username",
    "new_website",
    "new_account_username",
    "new_account_email",
    "new_account_password"
}

# Required fields for vault_delete_account payload
_VAULT_DELETE_ACCOUNT_REQUIRED_FIELDS = {
    "website",
    "account_username"
}

# Required fields for vault_fetch_account_password payload
_VAULT_FETCH_ACCOUNT_PASSWORD_REQUIRED_FIELDS = {
    "website",
    "account_username"
}