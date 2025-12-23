#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File name: handshake_handler.py
Author: Alex Biddle

Description:
    Implements CipherSafe's complete Four-Way Handshake protocol, coordinating
    packet validation, timestamp enforcement, checksum verification, RSA key
    operations, AES session-key establishment, replay defense, and encrypted
    request/response handling. Integrates with AuthorizationHandler,
    VaultHandler, and ServerSessionHandler to ensure secure initialization of
    all authenticated communication channels.
"""



import typing
from datetime import datetime, timezone
from capstone.handlers.session_handler import ServerSessionHandler
from capstone.handlers.packet_handler import PacketHandler
from capstone.handlers.authorization_handler import AuthorizationHandler
from capstone.handlers.vault_handler import VaultHandler
from capstone.handlers.error_handler import ApplicationCodes, CipherSafeError, HTTPCodes
from capstone.encryption.AES_manager import AESManager
from capstone.encryption.checksum_manager import ChecksumManager
from capstone.encryption.RSA_manager import RSAManager
import capstone.handlers.sanitization_validation as VALIDATION
import capstone.constants as CONSTANTS 



"""
    Coordinates the Four-Way Handshake protocol layers while delegating crypto,
    checksums, conversions, sanitization, and packet formatting to their
    dedicated managers and handler classes. All unexpected errors are routed to
    the Flask app's central error handler.
"""
class HandshakeHandler:
    """
        Initialize the HandshakeHandler with required session, authorization, and vault managers.

        @param: ServerSessionHandler - Manages session state, AES keys, and replay protection.
        @param: AuthorizationHandler - Provides login/signup verification logic.
        @param: VaultHandler - Handles encrypted vault operations.
    """
    def __init__(self, session_handler: ServerSessionHandler, authorization_handler: AuthorizationHandler, vault_handler: VaultHandler):
        try:
            # Validate parameter types
            if not isinstance(session_handler, ServerSessionHandler):
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "HandshakeHandler requires ServerSessionHandler instance", "session_handler")
            if not isinstance(authorization_handler, AuthorizationHandler):
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "HandshakeHandler requires AuthorizationHandler instance", "authorization_handler")
            if not isinstance(vault_handler, VaultHandler):
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "HandshakeHandler requires VaultHandler instance", "vault_handler")


            self._session_handler: ServerSessionHandler = session_handler
            self._authorization_handler: AuthorizationHandler = authorization_handler
            self._vault_handler: VaultHandler = vault_handler
            self._packet_handler: PacketHandler = PacketHandler()
            self._checksum_manager: ChecksumManager = self._session_handler._checksum_manager 
            self._rsa_manager: RSAManager = self._session_handler._rsa_manager  
            self._aes_manager: AESManager = self._session_handler._aes_manager  

            # Check encryption managers
            if not isinstance(self._checksum_manager, ChecksumManager):
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "ChecksumManager not wired", "checksum_manager")
            if not isinstance(self._rsa_manager, RSAManager):
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSAManager not wired", "rsa_manager")
            if not isinstance(self._aes_manager, AESManager):
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "AESManager not wired", "aes_manager")


        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed initializing HandshakeHandler", "handshake_handler_init")


    """
        Handle Step 1 → 2: Client Hello → Server Hello.

        @param: dict - Parsed JSON client hello object.
        @returns: Tuple[dict, int] - server hello packet and the HTTP code
    """
    def respond_to_client_hello_request(self, request_obj: dict) -> typing.Tuple[dict, int]:
        try:
            # Step 1: Validate the incoming client hello packet
            hello_packet = self._validate_client_hello_packet(request_obj)

            # Step 2: Check if this is a logout request
            self._packet_handler._validate_request_type(hello_packet["request_type"])
            if hello_packet["request_type"] == "logout":
                logout_packet, status = self.logout({"username": hello_packet["username"]})
                return logout_packet, status

            # Step 3: Resolve or create session, bind username / RSA key
            session_data, aes_key  = self._create_or_update_session_for_hello_packet(hello_packet)

            # Step 4: Run login/signup/vault pre-checks for hello (salt lookup, username availability)
            server_ciphertext_b64u = self._perform_hello_packet_prechecks(hello_packet, session_data)

            # Step 5: Build Server Hello packet using PacketHandler and sanitization helpers
            server_hello_packet = self._build_server_hello_packet(hello_packet=hello_packet, session_data=session_data, aes_key=aes_key, server_ciphertext_b64u=server_ciphertext_b64u)

            # Step 6: Final validation of server hello schema before returning
            self._packet_handler.validate_server_hello_response_packet_fields(server_hello_packet)

            return server_hello_packet, HTTPCodes.OK

        except CipherSafeError:
            raise



    """
        Handle Step 3 → 4: Client encrypted Request → Server encrypted Response.

        @param: dict - Parsed JSON client encrypted request object.
        @ensures: isinstance(response[0], dict) - response
        @returns: Tuple[dict, int] - server encrypted response packet and the HTTP code
    """
    def respond_to_client_encrypted_request(self, request_obj: dict) -> typing.Tuple[dict, int]:
        try:
            # Step 1: Validate the incoming client encrypted request packet 
            encrypted_packet = self._validate_encrypted_request_packet(request_obj)

            # Step 2: Resolve session and enforce state/TTL invariants
            session_data = self._get_active_session_for_encrypted_request(encrypted_packet)

            # Step 3: Verify checksums and nonce / replay protection
            self._verify_encrypted_request_integrity(encrypted_packet, session_data)

            # Step 4: Decrypt AES-GCM payload and parse plaintext JSON
            plaintext_obj = self._decrypt_encrypted_request_payload(encrypted_packet, session_data)

            # Step 5: Route services to Authorization/Vault handlers based off request_type
            response_payload, http_status = self._route_encrypted_request_packet(request_obj=encrypted_packet, plaintext_obj=plaintext_obj, session_data=session_data)

            # Step 6: If first encrypted packet, transition handshake state to "encrypted"
            self._ensure_encrypted_state_after_first_packet(session_data)

            # Step 7: Encrypt server response, compute checksum, sign
            server_response_packet = self._build_server_encrypted_response_packet(encrypted_packet=encrypted_packet, response_payload=response_payload, session_data=session_data)

            # Step 8: Validate server encrypted response payload.
            self._packet_handler.validate_server_encrypted_response_packet_fields(server_response_packet)

            return server_response_packet, http_status

        except CipherSafeError:
            raise



    """
        Handle logout logic and session cleanup.

        @param: dict - Packet containing at least the username.
        @ensures: isinstance(response[0], dict) - response
    """
    def logout(self, request_obj: typing.Mapping[str, typing.Any]) -> typing.Tuple[dict, int]:
        try:
            # Get username and sanitizaties/validation
            username = request_obj.get("username", "")
            self._packet_handler._validate_username(username)

            # Try to fetch current session via cookie; may be None if already cleared.
            client_session_data = self._session_handler.get_client_session_data_object()

            # If a session exists, invalidate it and let SessionHandler build the logout packet.
            if client_session_data is not None:
                logout_packet = self._session_handler.invalidate_client_session(client_session_data.session_uuid)

            # No active session; still return a well-formed logout packet for the client.
            else:
                timestamp_iso = VALIDATION.get_timestamp_iso8601z()
                logout_packet = self._packet_handler.create_logout_response_packet(username=username, timestamp_iso=timestamp_iso)

            # Validate the logout packet for correctness.
            self._packet_handler.validate_server_logout_response_packet_fields(logout_packet)

            return logout_packet, HTTPCodes.OK

        except CipherSafeError:
            raise



    ###########################################################################
    # Client Hello Helpers
    ###########################################################################

    """
        Normalize and validate Client Hello using PacketHandler and
        sanitization_validation helpers.

        @param: Any - Potentially malformed JSON object from Flask.
        @ensures: isinstance(clean_packet, dict) - clean_packet
    """
    def _validate_client_hello_packet(self, request_obj: typing.Any) -> dict:
        try: 
            # Enforce dict type early for easier error messages
            if not isinstance(request_obj, dict):
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INVALID_JSON, HTTPCodes.BAD_REQUEST, "Client Hello must be a JSON object", "client_hello")
            
            # Use PacketHandler to validate structure, required fields, and field-level rules
            self._packet_handler.validate_client_hello_packet_fields(request_obj)

            return request_obj
        
        except CipherSafeError:
            raise



    """
        Create or update the server-side session based on Client Hello.

        @param: dict - Validated client hello packet.
        @ensures: hasattr(session_data, \"session_uuid\") - session_data
    """
    def _create_or_update_session_for_hello_packet(self, hello_packet: dict) -> typing.Any:
        try:
            # Extract normalized username
            username = hello_packet["username"]
            self._packet_handler._validate_username(username)
            client_rsa_public_pem = hello_packet["client_rsa_public_key"]
            self._packet_handler._validate_rsa_public_key(client_rsa_public_pem)

            # Generate new AES-256 session key for this handshake.
            aes_key: bytes = AESManager.generate_key()

            # Create and bind a new server-side session; this also stores the AES key internally.
            session_data = self._session_handler.create_client_session(username=username, server_aes_key=aes_key, client_rsa_public_key=client_rsa_public_pem)

            if session_data is None or getattr(session_data, "session_uuid", None) is None:
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to create client session from hello", "create_client_session")

            return session_data, aes_key

        except CipherSafeError:
            raise



    """
        Perform login/signup/vault pre-checks for the hello step, including
        salt lookup and username availability.

        @param: dict - Validated client hello packet.
        @param: Any - Session data object.
        @ensures: isinstance(server_ciphertext_b64u, str) - server_ciphertext_b64u
    """
    def _perform_hello_packet_prechecks(self, hello_packet: dict, session_data: typing.Any) -> str:
        try:
            
            # Validate parameters
            username = hello_packet["username"]
            self._packet_handler._validate_username(username)
            request_type = hello_packet["request_type"]
            self._packet_handler._validate_request_type(request_type)
            client_rsa_public_pem = hello_packet["client_rsa_public_key"]
            self._packet_handler._validate_rsa_public_key(client_rsa_public_pem)
            
            # Empty server ciphertext variable
            server_ciphertext_b64u: str = ""


            try:
                # LOGIN: return RSA-encrypted client salt
                if request_type == "login":
                    
                    # Route the request to the authroization handler
                    client_salt_bytes = self._authorization_handler.login_request_client_salt(username)

                    # Validate that the salt is 16-byte salt 
                    if not isinstance(client_salt_bytes, (bytes, bytearray)) or len(client_salt_bytes) != CONSTANTS._LOGIN_SALT_LEN_BYTES:
                        raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "Salt must be 16 bytes", "salt")

                    # Fetch the 16-byte vault_salt used by the client to derive its vault encryption key
                    vault_salt_bytes = self._authorization_handler.login_request_vault_salt(username)

                    # Validate that the salt is 16-byte salt 
                    if not isinstance(vault_salt_bytes, (bytes, bytearray)) or len(vault_salt_bytes) != CONSTANTS._LOGIN_SALT_LEN_BYTES:
                        raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST,"vault_salt must be exactly 16 bytes","vault_salt")


                    # Encode both salts as base64url text for inclusion in a small JSON structure
                    client_salt_b64u = VALIDATION.encode_bytes_to_base64url(client_salt_bytes)
                    vault_salt_b64u = VALIDATION.encode_bytes_to_base64url(vault_salt_bytes)

                    salts_payload = {
                        "client_salt": client_salt_b64u,
                        "vault_salt":  vault_salt_b64u,
                    }

                    # Serialize the JSON payload to bytes
                    salts_payload_bytes = VALIDATION.encode_dict_to_json_bytes(salts_payload)

                    # Encrypt the salt with the client RSA public Key
                    try:
                        encrypted_salt_bytes = self._rsa_manager.encrypt(salts_payload_bytes, client_rsa_public_pem)
                    except Exception:
                        raise CipherSafeError(ApplicationCodes.HANDSHAKE_RSA_ERROR, HTTPCodes.BAD_REQUEST, "Failed to RSA-encrypt login salts payload", "salt")

                    # Encode the encrypted salt to base64
                    server_ciphertext_b64u = VALIDATION.encode_bytes_to_base64url(encrypted_salt_bytes)


                # SIGNUP: ensure username is available; no ciphertext payload needed
                elif request_type == "signup":
                    self._authorization_handler.ensure_username_available_for_signup(username)
                    server_ciphertext_b64u = VALIDATION.encode_bytes_to_base64url(b"\x00")


                # VAULT REQUESTS: no pre-hello ciphertext payload
                elif request_type.startswith("vault_"):
                    server_ciphertext_b64u = VALIDATION.encode_bytes_to_base64url(b"\x00")


                # Unsupported request_type
                else:
                    raise CipherSafeError(ApplicationCodes.HANDSHAKE_UNSUPPORTED_REQUEST, HTTPCodes.BAD_REQUEST, f"Unsupported request_type: {request_type}", "request_type")

            # For login/signup precheck failures, ensure handshake state is reset
            except CipherSafeError:
                try:
                    self._session_handler.set_client_handshake_state(session_data.session_uuid, "hello")
                except Exception:  
                    pass
                
                raise
            
            # Update the client sessions data
            self._session_handler.update_session_client_rsa_public_key(session_data.session_uuid, client_rsa_public_pem)
            self._session_handler.set_client_handshake_state(session_data.session_uuid, "hello")

            return server_ciphertext_b64u
        
        except CipherSafeError:
            raise



    """
        Build a Server Hello packet from normalized inputs using PacketHandler.

        @param: dict - Client hello packet.
        @param: Any - Session data object.
        @param: bytes - AES key for this session.
        @param: str - Optional server ciphertext (e.g., encrypted salt).
        @ensures: isinstance(server_hello_packet, dict) - server_hello_packet
    """
    def _build_server_hello_packet(self, hello_packet: dict, session_data: typing.Any, aes_key: bytes, server_ciphertext_b64u: str) -> dict:
        try:
            # Get the client username
            username = hello_packet["username"]
            self._packet_handler._validate_username(username)

            # Produce ISO8601Z timestamp via sanitization helpers
            server_timestamp_iso = VALIDATION.get_timestamp_iso8601z()

            # Compute server checksum = SHA-256(username || timestamp).
            username_bytes = VALIDATION.encode_utf8_text_to_bytes(username)
            timestamp_bytes = VALIDATION.encode_utf8_text_to_bytes(server_timestamp_iso)
            checksum_bytes = self._checksum_manager.compute_checksum(username_bytes + timestamp_bytes)
            server_checksum_b64u = VALIDATION.encode_bytes_to_base64url(checksum_bytes)

            # Get thelient's RSA public key.
            client_rsa_public_pem = hello_packet["client_rsa_public_key"]
            self._packet_handler._validate_rsa_public_key(client_rsa_public_pem)
            
            # Encrypt AES key with client's RSA public key.
            try:
                encrypted_aes_key_bytes = self._rsa_manager.encrypt(aes_key, client_rsa_public_pem)
            except Exception:
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_RSA_ERROR, HTTPCodes.BAD_REQUEST, "Failed to RSA-OAEP wrap AES key for hello response", "server_aes_session_key")

            # Encode the encrypted AES key to base 64
            encrypted_aes_key_b64u = VALIDATION.encode_bytes_to_base64url(encrypted_aes_key_bytes)

            # Load server RSA metadata (public key, key identifier, expiry).
            rsa_metadata = self._rsa_manager.get_public_key_data()
            server_rsa_public_key = rsa_metadata["rsa_public_key"]
            server_key_identifier = rsa_metadata["key_identifier"]
            server_key_expiry = rsa_metadata["key_expiry_time"]

            # Digital signature: RSA-PSS-SHA256(session_key_bytes || key_id || timestamp).
            signature_input = aes_key + VALIDATION.encode_utf8_text_to_bytes(f"{server_key_identifier}{server_timestamp_iso}")
            signature_bytes = self._rsa_manager.sign_data_with_private_key(signature_input)
            server_digital_signature_b64u = VALIDATION.encode_bytes_to_base64url(signature_bytes)

            response_status = CONSTANTS.RESPONSE_STATUS_SUCCESS
            
            # Construct the full server hello packet using PacketHandler.
            server_hello_packet = self._packet_handler.create_server_hello_response_packet(
                response_status=response_status,
                username=username,
                server_checksum=server_checksum_b64u,
                server_aes_session_key=encrypted_aes_key_b64u,
                server_rsa_public_key=server_rsa_public_key,
                server_key_identifier=server_key_identifier,
                server_key_expiry=server_key_expiry,
                server_digital_signature=server_digital_signature_b64u,
                server_ciphertext=server_ciphertext_b64u,
                timestamp_iso=server_timestamp_iso,
            )

            # Update the client session data object
            self._session_handler.update_full_session(session_data.session_uuid,{"server_rsa_public_key": server_rsa_public_key,"key_identifier": server_key_identifier,})

            return server_hello_packet

        except CipherSafeError:
            raise



    ###########################################################################
    # encrypted Request Helpers
    ###########################################################################

    """
        Normalize and validate the Client encrypted Request using PacketHandler
        and sanitization_validation.

        @param: Any - Potential JSON object from Flask.
        @ensures: isinstance(clean_packet, dict) - clean_packet
    """
    def _validate_encrypted_request_packet(self, request_obj: typing.Any) -> dict:
        try:
            if not isinstance(request_obj, dict):
                raise CipherSafeError(ApplicationCodes.ENCRYPTED_REQUEST_INVALID_JSON, HTTPCodes.BAD_REQUEST, "Client encrypted Request must be a JSON object", "client_encrypted_request")

            # Packet-level validation (required fields, types, pattern checks).
            self._packet_handler.validate_client_encrypted_request_packet_fields(request_obj)

            return request_obj
        
        except CipherSafeError:
            raise



    """
        Resolve an active session for a encrypted request and enforce TTL/state.

        @param: dict - Validated encrypted request packet.
        @ensures: hasattr(session_data, \"session_uuid\") - session_data
    """
    def _get_active_session_for_encrypted_request(self, encrypted_packet: dict) -> typing.Any:
        try:
            username = encrypted_packet["username"]
            self._packet_handler._validate_username(username)

            # Fetch current session via cookie.
            session_data = self._session_handler.get_client_session_data_object()

            if session_data is None:
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.UNAUTHORIZED, "No active session for encrypted request", "session_uuid")

            if session_data.username != username:
                raise CipherSafeError(ApplicationCodes.HANDSHAKE_INIT_ERROR, HTTPCodes.UNAUTHORIZED, "Encrypted request username does not match active session", "username")

            # Enforce per-session TTL / expiration.
            self._session_handler.check_single_session_expiration(session_data.session_uuid)

            return session_data

        except CipherSafeError:
            raise



    """
        Verify encrypted request integrity: checksum and nonce / replay.

        @param: dict - Validated encrypted request.
        @param: Any - Session data.
        @ensures: True - encrypted_request_integrity_verified
    """
    def _verify_encrypted_request_integrity(self, encrypted_packet: dict, session_data: typing.Any) -> None:
        try:
            # Validate and decode the client ciphertext
            client_ciphertext_b64u = encrypted_packet["client_ciphertext"]
            self._packet_handler._validate_ciphertext_client(client_ciphertext_b64u)
            ciphertext_bytes = VALIDATION.decode_base64url_to_bytes("client_ciphertext", client_ciphertext_b64u)

            # Verify the nonce
            if len(ciphertext_bytes) < CONSTANTS._AES_GCM_NONCE_LEN_BYTES:
                raise CipherSafeError(ApplicationCodes.INVALID_CIPHERTEXT, HTTPCodes.BAD_REQUEST, "Ciphertext too short to contain GCM nonce", "client_ciphertext")

            # Extract validate nonce (first 12 bytes)
            nonce_bytes = ciphertext_bytes[:CONSTANTS._AES_GCM_NONCE_LEN_BYTES]

            # Decode the nonce bytes to base 64
            nonce_b64u = VALIDATION.encode_bytes_to_base64url(nonce_bytes)

            # Add the nonce to the client session nonce count
            accepted, logout_packet = self._session_handler.accept_nonce_once(session_data.session_uuid, nonce_b64u)

            # If the nonce has been reused (replay attack) raise error
            if not accepted:
                self._session_handler.set_client_handshake_state(session_data.session_uuid, CONSTANTS._HANDSHAKE_STATE_NONE)
                if logout_packet:
                    raise CipherSafeError(ApplicationCodes.ENCRYPTED_REQUEST_NONCE_ERROR, HTTPCodes.OK, str({"ok": True, "data": logout_packet}), "nonce_logout")
                raise CipherSafeError(ApplicationCodes.ENCRYPTED_REQUEST_NONCE_ERROR, HTTPCodes.UNAUTHORIZED, "Replayed nonce detected", "nonce")

            # Verify and decode the clients checksum
            checksum_b64u = encrypted_packet["client_checksum"]
            self._packet_handler._validate_checksum_client(checksum_b64u)
            provided_checksum_bytes = VALIDATION.decode_base64url_to_bytes("client_checksum", checksum_b64u)

            # Re-calculate the client checksum
            expected_checksum_bytes = self._checksum_manager.compute_checksum(ciphertext_bytes + session_data.server_aes_key)

            # Verify the checksums match
            if not self._checksum_manager.verify_checksum(provided_checksum_bytes, expected_checksum_bytes):
                raise CipherSafeError(ApplicationCodes.ENCRYPTED_REQUEST_CHECKSUM_ERROR, HTTPCodes.UNAUTHORIZED, "Checksum mismatch for encrypted request", "checksum")
        
        except CipherSafeError:
            raise



    """
        Decrypt encrypted request AES-GCM payload and parse JSON.

        @param: dict - Validated encrypted packet.
        @param: Any - Session data.
        @ensures: isinstance(plaintext_obj, dict) - plaintext_obj
    """
    def _decrypt_encrypted_request_payload(self, encrypted_packet: dict, session_data: typing.Any) -> dict:
        try:
            # Validate parameters
            username = encrypted_packet["username"]
            self._packet_handler._validate_username(username)
            timestamp_str = encrypted_packet["timestamp"]
            self._packet_handler._validate_timestamp(timestamp_str)
            
            # Validate and decode the ciphertext
            client_ciphertext_b64u = encrypted_packet["client_ciphertext"]
            self._packet_handler._validate_ciphertext_client(client_ciphertext_b64u)
            ct_bytes_full = VALIDATION.decode_base64url_to_bytes("client_ciphertext", client_ciphertext_b64u)

            # Extract the nonce and the ciphertext
            nonce_bytes = ct_bytes_full[:CONSTANTS._AES_GCM_NONCE_LEN_BYTES]
            ct_with_tag = ct_bytes_full[CONSTANTS._AES_GCM_NONCE_LEN_BYTES:]
            
            # Encode the aad and intilaize the AES Manager
            aad_bytes = VALIDATION.encode_utf8_text_to_bytes(f"{username}{timestamp_str}")
            aes_manager = AESManager()
            aes_manager.set_key(session_data.server_aes_key)

            # Decrypt the the ciphertext
            try:
                plaintext_bytes = aes_manager.decrypt(aad=aad_bytes, nonce=nonce_bytes, ciphertext_with_tag=ct_with_tag)
            except Exception:
                raise CipherSafeError(ApplicationCodes.ENCRYPTED_REQUEST_DECRYPTION_ERROR, HTTPCodes.UNAUTHORIZED, "Failed to decrypt AES-GCM payload", "client_ciphertext")

            # Deserialize JSON bytes → dict
            plaintext_obj = VALIDATION.decode_json_bytes_to_dict(plaintext_bytes)

            # Validate that it is a dic
            if not isinstance(plaintext_obj, dict):
                raise CipherSafeError(ApplicationCodes.ENCRYPTED_REQUEST_INVALID_JSON, HTTPCodes.BAD_REQUEST, "Decrypted payload must be a JSON object", "encrypted_request_payload")

            return plaintext_obj
        
        except CipherSafeError:
            raise



    """
        Dispatch plaintext payload by request_type to Authorization/Vault.

        @param: dict - encrypted packet (outer metadata).
        @param: dict - Decrypted JSON payload.
        @param: Any - Session data.
        @ensures: isinstance(response_payload, dict) - response_payload
    """
    def _route_encrypted_request_packet(self, request_obj: dict, plaintext_obj: dict, session_data: typing.Any) -> typing.Tuple[dict, int]:
        try:
            # Validate parameters
            username = request_obj["username"]
            self._packet_handler._validate_username(username)
            request_type = request_obj["request_type"]
            self._packet_handler._validate_request_type(request_type)

            # SIGNUP
            if request_type == "signup":
                response_ciphertext, http_status = self._authorization_handler.signup(username, plaintext_obj)

            # LOGIN
            elif request_type == "login":
                response_ciphertext, http_status = self._authorization_handler.login(username, plaintext_obj)

            # LOGOUT (short-circuit)
            elif request_type == "logout":
                logout_packet, status = self.logout({"username": username})
                return logout_packet, status

            # VAULT OPERATIONS
            elif request_type.startswith("vault_"):
                response_ciphertext, http_status = self._vault_handler.handle(username, request_type, plaintext_obj)

            else:
                raise CipherSafeError(ApplicationCodes.ENCRYPTED_REQUEST_UNSUPPORTED_TYPE, HTTPCodes.BAD_REQUEST, f"Unsupported encrypted request_type: {request_type}", "request_type")

            # Normalize downstream payload to dict
            if not isinstance(response_ciphertext, dict):
                response_ciphertext = {"message": "OK"}

            # Update the handshake state
            self._session_handler.set_client_handshake_state(session_data.session_uuid, CONSTANTS._HANDSHAKE_STATE_COMPLETE)


            return response_ciphertext, http_status
        
        except CipherSafeError:
            raise



    """
        Ensure handshake state transitions to \"encrypted\" after first encrypted packet.

        @param: Any - Session data.
        @ensures: True - state_updated
    """
    def _ensure_encrypted_state_after_first_packet(self, session_data: typing.Any):
        try:
            state = getattr(session_data, "handshake_state", "")

            if state == "hello":
                self._session_handler.set_client_handshake_state(session_data.session_uuid, CONSTANTS._HANDSHAKE_STATE_ENCRYPTED)
                self._session_handler.clear_client_session_nonces(session_data.session_uuid)
                self._session_handler.update_session_field(session_data.session_uuid, "session_created_at", datetime.now(timezone.utc))
        
        except CipherSafeError:
            raise




    """
        Build the encrypted Server encrypted Response packet.

        @param: dict - Original encrypted request packet.
        @param: dict - Response payload to encrypt.
        @param: Any - Session data.
        @ensures: isinstance(server_response_packet, dict) - server_response_packet
    """
    def _build_server_encrypted_response_packet(self, encrypted_packet: dict, response_payload: dict, session_data: typing.Any) -> dict:
        try:
            # Validate and get packet fields
            username = encrypted_packet["username"]
            self._packet_handler._validate_username(username)
            response_bytes = VALIDATION.encode_dict_to_json_bytes(response_payload)
            server_timestamp_iso = VALIDATION.get_timestamp_iso8601z()
            aad_bytes = VALIDATION.encode_utf8_text_to_bytes(f"{username}{server_timestamp_iso}")
            aes_manager = AESManager()
            aes_manager.set_key(session_data.server_aes_key)

            # Encrypt the plaintext
            try:
                response_nonce, response_ciphertext_with_tag = aes_manager.encrypt(aad=aad_bytes, plaintext=response_bytes)
            except Exception:
                raise CipherSafeError(ApplicationCodes.ENCRYPTED_REQUEST_BUILD_RESPONSE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed encrypting server response", "server_ciphertext")

            # Concatonate the ciphertext with a nonce
            server_ciphertext_bytes = response_nonce + response_ciphertext_with_tag

            # Encode the ciphertext to base 64
            server_ciphertext_b64u = VALIDATION.encode_bytes_to_base64url(server_ciphertext_bytes)

            # Compute the checksum and encode to base 64
            server_checksum_bytes = self._checksum_manager.compute_checksum(server_ciphertext_bytes + session_data.server_aes_key)
            server_checksum_b64u = VALIDATION.encode_bytes_to_base64url(server_checksum_bytes)

            # Get the respoonse status
            response_status = CONSTANTS.RESPONSE_STATUS_SUCCESS

            # Digitally sign the data with the server signature
            signature_input = VALIDATION.encode_utf8_text_to_bytes(f"{server_checksum_b64u}{response_status}")
            signature_bytes = self._rsa_manager.sign_data_with_private_key(signature_input)
            server_digital_signature_b64u = VALIDATION.encode_bytes_to_base64url(signature_bytes)

            # Create the server encrypted response packet
            server_response_packet = self._packet_handler.create_server_encrypted_response_packet(
                response_status=response_status,
                username=username,
                server_checksum=server_checksum_b64u,
                server_ciphertext=server_ciphertext_b64u,
                server_digital_signature=server_digital_signature_b64u,
                timestamp_iso=server_timestamp_iso,
            )

            return server_response_packet

        except CipherSafeError:
            raise