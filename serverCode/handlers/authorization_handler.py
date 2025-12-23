#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: authorization_handler.py
    Author: Alex Biddle

    Description:
        Implements CipherSaf's full authentication lifecycle, including signup,
        login verification, client_salt retrieval for the handshake, and username
        validation. Coordinates interactions between session management, master
        password hashing, salt storage, and packet validation. Ensures no
        plaintext passwords are ever stored and all failures raise CipherSafeError
        for centralized error formatting.
"""


import typing
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes
from capstone.database.database_object import Database
from capstone.database.master_table import MasterTable
from capstone.database.salt_table import SaltTable
from capstone.database.vault_salt_table import VaultSaltTable
from capstone.handlers.session_handler import ServerSessionHandler
from capstone.handlers.packet_handler import PacketHandler
import capstone.handlers.sanitization_validation as VALIDATION
import capstone.constants as CONSTANTS


####################################################################################################
#                                   Authorization Handler
####################################################################################################

"""
    AuthorizationHandler

    Coordinates user signup and login flows, including:

        - Validating usernames (shared rules with PacketHandler/HandshakeHandler)
        - Handling client_salt retrieval for login handshakes
        - Implementing the two-stage Argon2id hashing pipeline:
              client_hash = Argon2id(password, client_salt)
              server_hash = Argon2id(client_hash, server_salt)
        - Persisting salts and server_hash in PostgreSQL via MasterTable and SaltTable
        - Verifying credentials during login using ServerSessionHandler's Argon2id manager

    All failures raise CipherSafeError so Flask/Gunicorn can format a consistent JSON error
    payload at the boundary layer.
"""
class AuthorizationHandler:

    """
        Initialize the AuthorizationHandler with shared session and database helpers.

        @param sessions (ServerSessionHandler): Shared session manager (provides Argon2id manager).
        @param database (Database): Shared Database helper object for PostgreSQL.
        @require isinstance(sessions, ServerSessionHandler)
        @require isinstance(database, Database)
        @ensures MasterTable and SaltTable helpers are bound to the shared Database.
    """
    def __init__(self, sessions: ServerSessionHandler, database: Database) -> None:

        try:
            # Validate dependencies
            if not isinstance(sessions, ServerSessionHandler):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE,HTTPCodes.INTERNAL_SERVER_ERROR,"sessions must be a ServerSessionHandler instance","sessions")
            if not isinstance(database, Database):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE,HTTPCodes.INTERNAL_SERVER_ERROR,"database must be a Database helper instance","database")

            # Store references
            self._sessions: ServerSessionHandler = sessions
            self._database: Database = database
            self._master_table: MasterTable = MasterTable(database)
            self._salt_table: SaltTable = SaltTable(database)
            self._vault_salt_table: VaultSaltTable = VaultSaltTable(database)
            self._packet_handler: PacketHandler = PacketHandler()

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize AuthorizationHandler", "authorization_handler_init")



    ################################################################################################
    #                     HANDSHAKE STEP 2: LOGIN CLIENT_SALT LOOKUP
    ################################################################################################

    """
        Retrieve the stored client_salt for a given username during the login handshake.

        This method is called from HandshakeHandler._perform_hello_packet_prechecks when
        the client indicates a LOGIN flow. The returned raw bytes are RSA-encrypted into
        the Server Hello packet and never exposed in plaintext to the network.

        @param username (str): Username supplied by the client attempting to log in.
        @require isinstance(username, str) and len(username.strip()) > 0
        @return bytes: Raw client_salt bytes (exactly 16 bytes).
        @ensures client_salt length is exactly 16 bytes; otherwise raises CipherSafeError.
    """
    def login_request_client_salt(self, username: str) -> bytes:

        try:
            # Validate username using shared PacketHandler rules
            validated_username = self._validate_username(username)

            # Query salt_storage for user_id + client_salt (base64url)
            client_salt_record = self._salt_table.get_client_salt(validated_username)

            # If no record, treat as authentication failure / unknown user
            if not client_salt_record or "client_salt" not in client_salt_record:
                raise CipherSafeError(ApplicationCodes.AUTH_FAILED, HTTPCodes.UNAUTHORIZED, "Invalid username or password", "client_hash")

            # Decode client_salt from base64url text → bytes
            client_salt_bytes = VALIDATION.decode_base64url_to_bytes("client_salt", client_salt_record["client_salt"])

            # Enforce strict 16-byte salt length (login salt invariant)
            if len(client_salt_bytes) != CONSTANTS._LOGIN_SALT_LEN_BYTES:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR,"client_salt must be exactly 16 bytes", "client_salt")

            # Return raw salt bytes so HandshakeHandler can RSA-encrypt them
            return client_salt_bytes

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR,"Unexpected error during client_salt lookup","client_salt_lookup")



    ################################################################################################
    #                     HANDSHAKE STEP 2: SIGNUP USERNAME AVAILABILITY CHECK
    ################################################################################################

    """
        Ensure a requested username is available for new account creation.

        Called by HandshakeHandler._perform_hello_packet_prechecks when the client indicates
        a SIGNUP flow. This performs the same username normalization rules as the login path
        and checks master_table to ensure no existing user row is present.
        @param username (str): Username client wants to register.
        @require isinstance(username, str) and len(username.strip()) > 0
        @ensures Confirms uniqueness of username prior to signup.
    """
    def ensure_username_available_for_signup(self, username: str) -> None:

        try:
            # Normalize and validate username
            validated_username = self._validate_username(username)

            # Check for existing user via master_table
            existing_user_id = self._master_table.get_user_id_by_username(validated_username)

            # If user already exists, signal a conflict
            if existing_user_id is not None:
                raise CipherSafeError(ApplicationCodes.USER_EXISTS, HTTPCodes.CONFLICT, "Username already exists", "username")

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR,"Unexpected error during signup availability check","authorization_signup_check")



    ################################################################################################
    #                           ENCRYPTED REQUEST: SIGNUP FLOW
    ################################################################################################

    """
        Create a new CipherSafe user using the two-stage Argon2id hashing pipeline.

        @param username (str): Logical username requested by the client.
        @param payload (dict): Decrypted signup payload containing: client_salt (base64url string, 16 bytes decoded) client_hash (base64url string, 32 bytes decoded)
        @require isinstance(username, str)
        @require isinstance(payload, dict)
        @return tuple[dict, int]: (plaintext response payload, HTTP status code)
        @ensures Creates new user in master_table and salt_storage with generated server_salt and server_hash.
    """
    def signup(self, username: str, payload: dict) -> typing.Tuple[dict, int]:

        try:
            # Normalize and validate username
            validated_username = self._validate_username(username)

            # Payload must be JSON object
            if not isinstance(payload, dict):
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "Signup payload must be a JSON object", "payload")

            # Decode client_salt from base64url → bytes
            client_salt_bytes = VALIDATION.decode_base64url_to_bytes("client_salt", payload.get("client_salt"))

            # Decode client_hash from base64url → bytes
            client_hash_bytes = VALIDATION.decode_base64url_to_bytes("client_hash", payload.get("client_hash"))

            # Enforce exact sizes (client_salt = 16 bytes, client_hash = 32 bytes)
            if len(client_salt_bytes) != CONSTANTS._LOGIN_SALT_LEN_BYTES:
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "client_salt must be exactly 16 bytes", "client_salt")

            if len(client_hash_bytes) != CONSTANTS._HASHED_PASSWORD_LENGTH:
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "client_hash must be exactly 32 bytes", "client_hash")

            # Check for existing user via master_table
            existing_user_id = self._master_table.get_user_id_by_username(validated_username)
            if existing_user_id is not None:
                raise CipherSafeError(ApplicationCodes.USER_EXISTS, HTTPCodes.CONFLICT, "Username already exists", "username")

            # Generate server_salt and compute server_hash
            server_salt_bytes, server_hash_bytes = self._server_hash_client_password(client_hash_bytes)

            # Canonical base64url encodings for storage
            client_salt_b64u = VALIDATION.encode_bytes_to_base64url(client_salt_bytes)
            server_salt_b64u = VALIDATION.encode_bytes_to_base64url(server_salt_bytes)
            server_hash_b64u = VALIDATION.encode_bytes_to_base64url(server_hash_bytes)

            # Persist hashed password in master_table and obtain user_id (UUID string)
            user_uuid = self._master_table.create_user(validated_username, server_master_pwd_hash_b64u=server_hash_b64u)

            # Store salts in salt_storage bound to same user_id
            created = self._salt_table.create_salt_record(user_id=user_uuid, username=validated_username, client_salt_b64u=client_salt_b64u, server_salt_b64u=server_salt_b64u)

            # Ensure salt row was actually inserted
            if not isinstance(created, bool) or not created:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "salt_storage insertion did not succeed", "salt_storage_create")

            # Generate a fresh 16-byte vault_salt using the Argon2id manager's salt generator
            vault_salt_bytes: bytes = self._sessions._argon2_manager.generate_salt()

            # Enforce that the vault_salt is also 16 bytes (same invariant as login salts)
            if len(vault_salt_bytes) != CONSTANTS._LOGIN_SALT_LEN_BYTES:
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.INTERNAL_SERVER_ERROR, "vault_salt must be exactly 16 bytes", "vault_salt")

            # Encode vault_salt as base64url for storage
            vault_salt_b64u: str = VALIDATION.encode_bytes_to_base64url(vault_salt_bytes)

            # Insert vault_salt row bound to the same user_id
            vault_created = self._vault_salt_table.create_vault_salt(user_id=user_uuid, vault_salt_b64u=vault_salt_b64u)

            # Ensure the vault_salt row was actually inserted
            if not isinstance(vault_created, bool) or not vault_created:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "vault_salt_storage insertion did not succeed", "vault_salt_storage_create")

            # Build timestamp in strict ISO8601Z (UTC)
            ts = VALIDATION.get_timestamp_iso8601z()

            # Prepare application-level payload (HandshakeHandler will encrypt this)
            response_payload: dict = {
                "username": validated_username,
                "timestamp": ts,
                "message": "Account created.",
            }

            return response_payload, HTTPCodes.OK

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error in signup flow", "authorization_signup")



    ################################################################################################
    #                           ENCRYPTED REQUEST: LOGIN FLOW
    ################################################################################################

    """
        Verify user credentials during the encrypted login flow.

        Called from HandshakeHandler._route_encrypted_request_packet() when the
        decrypted request_type is "login". The client sends only the Argon2id
        client_hash (base64url) derived from (password, client_salt). The server
        then recomputes server_hash and compares it against the stored hash using
        the Argon2id manager in constant time.

        @param username (str): Username supplied by client.
        @param payload (dict): Decrypted login payload containing: - client_hash (base64url string, 32 bytes decoded)
        @require isinstance(username, str)
        @require isinstance(payload, dict)
        @return tuple[dict, int]: Minimal response payload and HTTP 200 on success.
        @ensures Returns a small JSON structure with username, timestamp.
    """
    def login(self, username: str, payload: dict) -> typing.Tuple[dict, int]:

        try:
            # Normalize and validate username
            validated_username = self._validate_username(username)

            # Payload must be JSON object
            if not isinstance(payload, dict):
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "Login payload must be a JSON object", "payload")

            # Decode client_hash from base64url → bytes
            client_hash_bytes = VALIDATION.decode_base64url_to_bytes("client_hash", payload.get("client_hash"))

            # Enforce Argon2id digest length of 32 bytes
            if len(client_hash_bytes) != CONSTANTS._HASHED_PASSWORD_LENGTH:
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "client_hash must be exactly 32 bytes", "client_hash")

            # Fetch server_salt and user_id for this username from salt_storage
            salt_record = self._salt_table.get_server_salt_and_user_id(validated_username)

            # Username not found or salt row missing → uniform login error
            if (not salt_record or "server_salt" not in salt_record  or "user_id" not in salt_record):
                raise CipherSafeError( ApplicationCodes.AUTH_FAILED, HTTPCodes.UNAUTHORIZED, "Invalid username or password", "client_hash")

            server_salt_b64u = salt_record["server_salt"]
            user_uuid = salt_record["user_id"]

            # Retrieve server-side hashed password from master_table using user_id
            hash_record = self._master_table.get_hashed_password(user_uuid)

            # Hash missing for user entry → treat as invalid credentials (no info leak)
            if not hash_record or "password" not in hash_record:
                raise CipherSafeError(ApplicationCodes.AUTH_FAILED, HTTPCodes.UNAUTHORIZED, "Invalid username or password", "client_hash")

            server_hash_b64u = hash_record["password"]

            # Decode salts and server_hash from base64url to bytes
            server_salt_bytes = VALIDATION.decode_base64url_to_bytes("server_salt", server_salt_b64u)
            server_hash_bytes = VALIDATION.decode_base64url_to_bytes("server_hash", server_hash_b64u)

            # Verify password using Argon2id manager in constant time
            try:
                verified = self._sessions._argon2_manager.verify_password(password=client_hash_bytes, salt=server_salt_bytes, expected_hash=server_hash_bytes)

            except CipherSafeError:
                raise
            except Exception:
                raise CipherSafeError(ApplicationCodes.AUTH_FAILED, HTTPCodes.UNAUTHORIZED, "Invalid username or password", "client_hash")

            # Reject invalid credentials
            if not verified:
                raise CipherSafeError(ApplicationCodes.AUTH_FAILED, HTTPCodes.UNAUTHORIZED, "Invalid username or password", "client_hash")

            # Successful authentication; build timestamp
            ts = VALIDATION.get_timestamp_iso8601z()

            # Minimal success payload returned to client (encrypted by HandshakeHandler)
            response_payload: dict = {
                "username": validated_username,
                "timestamp": ts,
                "message": "Login successful.",
            }

            # Return minimal success payload + HTTP 200
            return response_payload, HTTPCodes.OK

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error in login flow", "authorization_login")



    ################################################################################################
    #                             INTERNAL ARGON2ID HASH HELPER
    ################################################################################################

    """
        This uses the ServerSessionHandler's Argon2id manager and CipherSafe's fixed
        parameters to derive a deterministic 32-byte digest.

        @param client_hash_bytes (bytes): 32-byte Argon2id digest from the client.
        @require isinstance(client_hash_bytes, (bytes, bytearray)) and len(client_hash_bytes) == 32
        @return tuple[bytes, bytes]: (server_salt, server_hash)
        @ensures Generates a fresh 16-byte server_salt and computes Argon2id(client_hash, server_salt).
    """
    def _server_hash_client_password(self, client_hash_bytes: bytes) -> typing.Tuple[bytes, bytes]:

        try:
            # Generate server salt via Argon2 manager (16 bytes)
            server_salt: bytes = self._sessions._argon2_manager.generate_salt()

            # Compute Argon2id over client_hash with server_salt (32-byte digest)
            server_hash: bytes = self._sessions._argon2_manager.hash_password(client_hash_bytes, server_salt)

            # Return (server_salt, server_hash)
            return server_salt, server_hash

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error computing server_hash", "authorization_server_hash")



    ################################################################################################
    #                           INTERNAL USERNAME NORMALIZATION HELPER
    ################################################################################################

    """
        Normalize and validate a username using shared PacketHandler validation rules.

        @param raw_username (Any): Username value provided by the client.
        @require isinstance(raw_username, str)
        @require 1 <= len(raw_username.strip()) <= 64
        @return str: Cleaned, validated username.
        @ensures Returned username is stripped of leading/trailing whitespace and passes PacketHandler's validation.
    """
    def _validate_username(self, raw_username: typing.Any) -> str:

        try:
            # Basic type check
            if not isinstance(raw_username, str):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "username must be a string", "username")

            # Strip whitespace and ensure non-empty
            cleaned = raw_username.strip()
            if not cleaned:
                raise CipherSafeError(ApplicationCodes.INVALID_USERNAME, HTTPCodes.BAD_REQUEST, "username must not be empty or whitespace", "username")

            # Enforce maximum length at this layer (defensive)
            if len(cleaned) > CONSTANTS._MAX_USERNAME_LEN:
                raise CipherSafeError(ApplicationCodes.INVALID_USERNAME, HTTPCodes.BAD_REQUEST, "Username exceeds maximum length (64 characters)", "username")

            # Delegate final semantic validation to PacketHandler (shared with handshake)
            self._packet_handler._validate_username(cleaned)

            # Return normalized username
            return cleaned

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INVALID_USERNAME, HTTPCodes.BAD_REQUEST, "Failed to validate username", "username")




    """
        Retrieve the stored vault_salt for a given username during the login handshake.

        This is used to let the client derive its long-term vault encryption key.
        The vault_salt itself is not secret in the same way as a password, but it
        must be bound to the correct user_id and kept consistent across logins.

        @param username (str): Username supplied by the client attempting to log in.
        @require isinstance(username, str) and len(username.strip()) > 0
        @return bytes: Raw vault_salt bytes (exactly 16 bytes).
        @ensures vault_salt length is exactly 16 bytes; otherwise raises CipherSafeError.
    """
    def login_request_vault_salt(self, username: str) -> bytes:

        try:
            # Normalize and validate username
            validated_username = self._validate_username(username)

            # Resolve user_id via master_table
            user_id = self._master_table.get_user_id_by_username(validated_username)

            # Unknown username → treat as authentication failure
            if user_id is None:
                raise CipherSafeError(ApplicationCodes.AUTH_FAILED, HTTPCodes.UNAUTHORIZED, "Invalid username or password", "vault_salt")

            # Lookup vault_salt in vault_salt_storage
            vault_salt_b64u = self._vault_salt_table.get_vault_salt(user_id)

            # Missing vault_salt should not happen for a valid user; treat as internal error
            if vault_salt_b64u is None:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "vault_salt not found for user", "vault_salt")

            # Decode base64url → bytes
            vault_salt_bytes = VALIDATION.decode_base64url_to_bytes("vault_salt", vault_salt_b64u)

            # Enforce strict 16-byte salt length
            if len(vault_salt_bytes) != CONSTANTS._LOGIN_SALT_LEN_BYTES:
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.INTERNAL_SERVER_ERROR, "vault_salt must be exactly 16 bytes", "vault_salt")

            return vault_salt_bytes

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error during vault_salt lookup", "vault_salt_lookup")