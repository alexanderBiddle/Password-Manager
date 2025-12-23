#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: error_handler.py
    Author: Alex Biddle

    Description:
        Centralized error handling for all CipherSafe backend components.
        Converts exceptions into standardized error packets, logs diagnostic
        information to the audit log, and ensures consistent formatting of
        application error responses. Supports both CipherSafeError and
        unexpected exceptions, always producing a canonical failure packet.
"""


from dataclasses import dataclass
from typing import Tuple
import sys, os
from datetime import datetime, timezone, timedelta
from capstone.utilities.audit_log import AuditLog



# Protocol version string (used by handshake validation)
_PROTOCOL_VERSION = "CipherSafe Handshake v1"


"""
    Container Class for HTTP status constants.
"""
@dataclass
class HTTPCodes:
    # 200 OK
    OK = 200

    # 400 Bad Request
    BAD_REQUEST = 400

    # 401 Unauthorized
    UNAUTHORIZED = 401

    # 403 Forbidden
    FORBIDDEN = 403

    # 404 Not Found
    NOT_FOUND = 404

    # 408 Request Timeout
    REQUEST_TIMEOUT = 408

    # 409 Conflict
    CONFLICT = 409

    # 429 Too Many Requests
    TOO_MANY_REQUESTS = 429

    # 440 Custom – key validation failure per spec
    KEY_VALIDATION_FAILURE = 440

    # 498 Custom – ciphertext auth error
    CIPHERTEXT_AUTH_ERROR = 498

    # 500 Internal Server Error
    INTERNAL_SERVER_ERROR = 500


"""
    Container Class for server error code strings.
"""
@dataclass
class ApplicationCodes:
    
    MALFORMED_JSON           = "malformed_json"
    MISSING_FIELDS           = "missing_fields"
    UNKNOWN_FIELDS           = "unknown_fields"
    INVALID_TYPE             = "invalid_type"
    INVALID_LENGTH           = "invalid_length"
    INVALID_CONTENT_TYPE     = "invalid_content_type"
    INVALID_PROTOCOL         = "invalid_protocol_version"
    INVALID_REQUEST          = "invalid_request"
    INVALID_PACKET_STRUCTURE = "invalid_packet_structure"
    INVALID_REQUEST_TYPE     = "invalid_request_type"
    INVALID_RESPONSE_STATUS  = "invalid_response_status"
    INVALID_USERNAME         = "invalid_username"
    INVALID_ACCOUNT          = "invalid_account"
    USER_EXISTS              = "user_exists"
    AUTH_FAILED              = "auth_failed"
    INVALID_TIMESTAMP        = "invalid_timestamp"
    REPLAY_DETECTED          = "replay_detected"
    SESSION_EXPIRED          = "session_expired"
    SESSION_NOT_FOUND        = "session_not_found"
    HANDSHAKE_STATE_INVALID  = "handshake_state_invalid"
    KEY_MISMATCH             = "key_mismatch"
    INVALID_PUBLIC_KEY       = "invalid_public_key"
    INVALID_SIGNATURE        = "invalid_signature"
    INVALID_SIGNATURE_FORMAT = "invalid_signature_format"
    INVALID_AES_SESSION_KEY  = "invalid_aes_session_key"
    INVALID_KEY_IDENTIFIER   = "invalid_key_identifier"
    INVALID_KEY_EXPIRY       = "invalid_key_expiry"
    INVALID_BASE64URL        = "invalid_base64url"
    INVALID_CIPHERTEXT       = "invalid_ciphertext"
    INVALID_CHECKSUM         = "invalid_checksum"
    CIPHERTEXT_AUTH_ERROR    = "ciphertext_auth_error"
    PERMISSION_DENIED        = "permission_denied"
    RATE_LIMITED             = "rate_limited"
    KEY_EXPIRED              = "key_expired"
    NOT_FOUND                = "not_found"
    INTERNAL_SERVER_ERROR    = "internal_server_error"
    SESSION_UNKNOWN = "session_unknown"
    SESSION_UPDATE_ERROR = "session_update_error"
    SESSION_FIELD_MISSING = "session_field_missing"
    INVALID_NONCE = "invalid_nonce"
    INVALID_AES_KEY = "invalid_aes_key"
    INVALID_UPDATE_MAP = "invalid_update_map"
    SESSION_STORE_ERROR = "session_store_error"
    HANDSHAKE_INIT_ERROR = "handshake_init_error"
    HANDSHAKE_PACKET_ERROR = "handshake_packet_error"
    HANDSHAKE_TIMESTAMP_DRIFT = "handshake_timestamp_drift"
    HANDSHAKE_CHECKSUM_ERROR = "handshake_checksum_error"
    HANDSHAKE_SESSION_ERROR = "handshake_session_error"
    HANDSHAKE_RSA_ERROR = "handshake_rsa_error"
    HANDSHAKE_UNSUPPORTED_REQUEST = "handshake_unsupported_request"
    HANDSHAKE_INVALID_JSON = "handshake_invalid_json"
    ENCRYPTED_REQUEST_INVALID_JSON = "encrypted_request_invalid_json"
    ENCRYPTED_REQUEST_TIMESTAMP_DRIFT = "encrypted_request_timestamp_drift"
    ENCRYPTED_REQUEST_SESSION_ERROR = "encrypted_request_session_error"
    ENCRYPTED_REQUEST_USERNAME_MISMATCH = "encrypted_request_username_mismatch"
    ENCRYPTED_REQUEST_HANDSHAKE_STATE = "encrypted_request_handshake_state"
    ENCRYPTED_REQUEST_AES_KEY_MISMATCH = "encrypted_request_aes_key_mismatch"
    ENCRYPTED_REQUEST_KEY_IDENTIFIER_MISMATCH = "encrypted_request_key_identifier_mismatch"
    ENCRYPTED_REQUEST_CHECKSUM_ERROR = "encrypted_request_checksum_error"
    ENCRYPTED_REQUEST_NONCE_ERROR = "encrypted_request_nonce_error"
    ENCRYPTED_REQUEST_DECRYPTION_ERROR = "encrypted_request_decryption_error"
    ENCRYPTED_REQUEST_UNSUPPORTED_TYPE = "encrypted_request_unsupported_type"
    ENCRYPTED_REQUEST_BUILD_RESPONSE_ERROR = "encrypted_request_build_response_error"
    LOGOUT_SESSION_NOT_FOUND = "logout_session_not_found"
    HANDLER_MISSING_CAPABILITY = "handler_missing_capability"
    INVALID_SALT = "invalid_salt"
    PASSWORD_HASH_ERROR = "password_hash_error"
    PASSWORD_VERIFY_ERROR = "password_verify_error"
    INVALID_CHECKSUM_DATA = "invalid_checksum_data"
    KEYED_CHECKSUM_ERROR = "keyed_checksum_error"
    RSA_INIT_ERROR = "rsa_init_error"
    RSA_KEY_LOAD_ERROR = "rsa_key_load_error"
    RSA_KEY_GENERATION_ERROR = "rsa_key_generation_error"
    RSA_KEY_METADATA_ERROR = "rsa_key_metadata_error"
    RSA_KEY_ROTATION_ERROR = "rsa_key_rotation_error"
    RSA_ENCRYPT_ERROR = "rsa_encrypt_error"
    RSA_DECRYPT_ERROR = "rsa_decrypt_error"
    RSA_SIGN_ERROR = "rsa_sign_error"
    RSA_VERIFY_ERROR = "rsa_verify_error"
    INVALID_PATH = "invalid_path"






class CipherSafeError(Exception):

    """
        Initialize a CipherSafeError containing application code, HTTP code, detail message, and field context.

        @param application_code (str): Identifier from ApplicationCodes signaling the failure type.
        @param http_code (int): HTTP status code associated with the error.
        @param detail (str): Descriptive message intended for client-facing error packets.
        @param field (str): Logical field related to the error (optional).
        @require isinstance(application_code, str)
        @require isinstance(http_code, int)
        @require isinstance(detail, str)
        @ensures Error metadata is accessible to the centralized ErrorHandler.
    """
    def __init__(self, application_code: str, http_code: int, detail: str, field: str = "") -> None:
        self.application_code = application_code
        self.http_code = http_code
        self.detail = detail
        self.field = field
        super().__init__(f"{application_code}: {detail}")






class ErrorHandler:

    """
        Initialize the ErrorHandler and attach an AuditLog for diagnostic event recording.

        @require AuditLog must be importable and instantiable
        @ensures ErrorHandler is ready to format and log errors.
    """
    def __init__(self) -> None:
       
        self.audit_log = AuditLog()


    """
        Process an exception and return a standardized CipherSafe error packet.

        @param e (Exception): Exception raised during request handling.
        @param username (str): Username associated with the request, if known.
        @param context (str): Logical context string identifying the failing operation.
        @require isinstance(e, Exception)
        @require username is a string
        @require context is a string
        @return tuple[dict, int]: (clean_error_packet, http_status_code)
        @ensures Exception is logged to audit_log and a canonical failure packet is returned.
    """
    def handle_server_error(self, e: Exception, username: str = "", context: str = "") -> Tuple[dict, int]:

        # If the exception is already a CipherSafeError
        if isinstance(e, CipherSafeError):
            application_code = e.application_code
            http_code = e.http_code
            message = e.detail
            field = e.field
        else:
            # For non-raised errors, normalize to INTERNAL_SERVER_ERROR
            application_code = ApplicationCodes.INTERNAL_SERVER_ERROR
            http_code = HTTPCodes.INTERNAL_SERVER_ERROR
            message = "An internal server error occurred. Please try again later."
            field = ""

        # Always log the raw exception detail for operators
        self.audit_log.event(event="server_exception", username=username, context=context, detail=str(e),)

        # Build standardized error packet (response_status is always "failure" for errors)
        clean_packet = self.create_error_response_packet("failure", username, message, application_code, field)

        # Return packet and HTTP code
        return clean_packet, http_code




    """
        Build a standardized CipherSafe error response packet.

        @param response_status (str): Must be "failure" for all error packets.
        @param username (str): Username associated with the failure, if any.
        @param message (str): Human-readable error message for client.
        @param error_code (str): One of ApplicationCodes.* defining the error type.
        @param field (str): Logical field associated with the error (optional).
        @require isinstance(response_status, str)
        @require isinstance(username, str)
        @require isinstance(message, str)
        @require isinstance(error_code, str)
        @return dict: Serialized error packet including protocol_version and timestamp.
        @ensures Packet conforms to CipherSafe's Four-Way Handshake error schema.
    """
    def create_error_response_packet(self, response_status: str, username: str, message: str, error_code: str, field: str = "") -> dict:
        try:
            # Generate ISO8601Z timestamp
            timestamp_iso = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
            
			# Construct canonical error response
            packet = {
                "protocol_version": _PROTOCOL_VERSION,
                "response_status": response_status,
                "username": username,
                "timestamp": timestamp_iso,
                "message": message,
                "error_code": error_code,
                "field": field
            }

            return packet

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Internal error creating error response packet.", "")