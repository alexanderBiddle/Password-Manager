#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: session_handler.py
    Author: Alex Biddle

    Description:
        Manages all server-side session state for CipherSafe's Four-Way Handshake,
        including AES-256 session key generation, RSA key metadata binding,
        handshake-state transitions, per-session TTL enforcement, nonce replay
        protection, and atomic updates to ServerSessionDataObject instances.
        Provides thread-safe creation, retrieval, modification, and destruction
        of sessions using an internal RLock and in-memory session store.
"""


import threading
import uuid
from flask import session as public_cookie_session
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Set, List
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes
from capstone.encryption.RSA_manager import RSAManager
from capstone.encryption.AES_manager import AESManager
from capstone.encryption.argon2id_manager import Argon2idManager
from capstone.encryption.checksum_manager import ChecksumManager
from capstone.handlers.packet_handler import PacketHandler
import capstone.constants as CONSTANTS
import capstone.handlers.sanitization_validation as VALIDATION

####################################################################################################
# Server Session Data Object
####################################################################################################

"""
    Represents all server-side session state for a single client.

    This object is stored in-memory and never written to disk. It binds a generated
    session UUID to the logical username, the current AES-256 session key, RSA key
    metadata, handshake state, and replay-defense nonce set.

    session_uuid           : Unique per-session identifier (UUID4 string)
    username               : Logical username bound to the session
    handshake_state        : "none", "hello", "encrypted", or "complete"
    server_aes_key         : Raw AES-256 key bytes (32 bytes)
    server_rsa_public_key  : PEM-encoded RSA public key for the server
    key_identifier         : Identifier for the active server RSA keypair
    client_rsa_public_key  : PEM/DER-encoded client RSA public key (for reference)
    session_created_at     : UTC datetime when this session was created
    used_nonces            : Set of base64url-encoded nonces seen for this session
"""
@dataclass
class ServerSessionDataObject:
    
    session_uuid: str =             None
    username: str =                 None
    handshake_state: str =          "none"
    server_aes_key: bytes =         None
    server_rsa_public_key: str =    None
    key_identifier: str =           None
    client_rsa_public_key: str =    None
    session_created_at: datetime =  field(default_factory=lambda: datetime.now(timezone.utc))
    used_nonces: Set[str] =         field(default_factory=set)


####################################################################################################
# SESSION STORE
####################################################################################################

class ServerSessionHandler:

    """
        Initialize ServerSessionHandler with RSA, AES, Argon2id, and Checksum managers.

        @param rsa_manager (RSAManager): RSA key manager for key rotation and loading.
        @param aes_manager (AESManager): AES key utility for session-key generation.
        @param argon2_manager (Argon2idManager): Argon2id hashing manager.
        @param checksum_manager (ChecksumManager): BLAKE2b checksum manager.
        @require rsa_manager is RSAManager
        @require aes_manager is AESManager
        @require argon2_manager is Argon2idManager
        @require checksum_manager is ChecksumManager
        @return None: Initializes session dictionary, lock, and dependencies.
        @ensures All cryptographic managers are available for session creation.
    """
    def __init__(self, rsa_manager: RSAManager, aes_manager: AESManager, argon2_manager: Argon2idManager, checksum_manager: ChecksumManager) -> None:
        try:
            # Validate dependencies
            if not isinstance(rsa_manager, RSAManager):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "ServerSessionHandler requires RSAManager instance", "rsa_manager")
            if not isinstance(aes_manager, AESManager):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "ServerSessionHandler requires AESManager instance", "aes_manager")
            if not isinstance(argon2_manager, Argon2idManager):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "ServerSessionHandler requires Argon2idManager instance", "argon2_manager")
            if not isinstance(checksum_manager, ChecksumManager):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "ServerSessionHandler requires ChecksumManager instance", "checksum_manager")
            

            # Initialize a re-entrant lock for concurrent access protection
            self._lock = threading.RLock()

            # Initialize the in-memory dictionary for sessions
            self._sessions: Dict[str, ServerSessionDataObject] = {}

            # Inject all cryptographic manager dependencies
            self._rsa_manager: RSAManager = rsa_manager
            self._aes_manager: AESManager = aes_manager
            self._argon2_manager: Argon2idManager = argon2_manager
            self._checksum_manager: ChecksumManager = checksum_manager

            self._packet_handler: PacketHandler = PacketHandler()

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_STORE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize ServerSessionHandler", "session_store")


    """
        Create a new server-side session and return a ServerSessionDataObject.

        @param username (str): Logical username being authenticated.
        @param server_aes_key (bytes): Raw AES-256 key (32 bytes) for this session.
        @param client_rsa_public_key (str): Client RSA public key (PEM) to bind.
        @require username is a non-empty string
        @require server_aes_key is bytes and exactly 32 bytes long
        @require client_rsa_public_key is a non-empty string
        @return ServerSessionDataObject: Newly created session object.
        @ensures Session object is created under lock, stored internally, and mapped to a UUID.
    """
    def create_client_session(self, username: str, server_aes_key: bytes, client_rsa_public_key: str) -> ServerSessionDataObject:
        try:

            # Validate username as a non-empty string
            VALIDATION.validate_string(username, ApplicationCodes.INVALID_USERNAME, "username")

            # Validate AES session key: must be 32 bytes
            if not isinstance(server_aes_key, (bytes, bytearray)) or len(server_aes_key) != 32:
                raise CipherSafeError(ApplicationCodes.INVALID_AES_KEY, HTTPCodes.BAD_REQUEST,"server_aes_key must be 32 bytes", "server_aes_key")

            # Validate client RSA public key as non-empty string
            VALIDATION.validate_string(client_rsa_public_key, ApplicationCodes.INVALID_PUBLIC_KEY,"client_rsa_public_key")

            # Generate a random UUID 
            client_session_uuid = str(uuid.uuid4())

            # Store the created client UUID in Flask’s public cookie session
            public_cookie_session["client_session_uuid"] = client_session_uuid

            # Acquire lock before mutating shared state
            with self._lock:

                # Ensure current RSA key is loaded and valid
                self._rsa_manager._ensure_private_key_loaded()
                self._rsa_manager._check_key_rotation()

                # Retrieve current RSA public key data for caching
                rsa_public_key_data = self._rsa_manager.get_public_key_data()
                server_rsa_public_key = rsa_public_key_data["rsa_public_key"]
                key_identifier = rsa_public_key_data["key_identifier"]
                
                # Set the AES key 
                self._aes_manager.set_key(server_aes_key)
                
                # Construct a new ServerSessionDataObject instance
                session_object = ServerSessionDataObject(
                    session_uuid = client_session_uuid,
                    username = username,
                    handshake_state="hello",
                    server_aes_key = bytes(server_aes_key),
                    server_rsa_public_key = server_rsa_public_key,
                    key_identifier = key_identifier,
                    client_rsa_public_key = client_rsa_public_key,
                    session_created_at=datetime.now(timezone.utc),
                    used_nonces=set(),
                )

                # Add the session to the in-memory dictionary
                self._sessions[client_session_uuid] = session_object

                # Return the created session
                return session_object

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_STORE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to create client session", "session_creation")



    """
        Retrieve the current client's ServerSessionDataObject using Flask cookie UUID.

        @require Flask cookie “client_session_uuid” exists or None is returned
        @return ServerSessionDataObject | None: The session object, if present.
        @ensures Safe retrieval under lock without mutation.
    """
    def get_client_session_data_object(self) -> Optional[ServerSessionDataObject]:
        try:
            # Get the client session UUID from the Flask session
            client_session_uuid = public_cookie_session.get("client_session_uuid")
            if not client_session_uuid:
                return None
            
            # Validate the string
            VALIDATION.validate_string(client_session_uuid, ApplicationCodes.INVALID_TYPE, "client_session_uuid")

            # Acquire lock for safe concurrent access
            with self._lock:
                
                # Get the session from the dictionary
                return self._sessions.get(client_session_uuid, None)

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_STORE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to retrieve client session", "session_lookup")



    """
        Return the handshake_state of a client session.

        @param session_uuid (str): Session identifier.
        @require session_uuid is a non-empty string
        @return str: One of "none", "hello", "encrypted", "complete".
        @ensures Raises SESSION_UNKNOWN if session does not exist.
    """
    def get_client_handshake_state(self, session_uuid: str) -> str:
        try:

            # Validate session identifier
            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE, "session_uuid")

            # Acquire lock for safe read
            with self._lock:
                
                # Get the client session data object
                client_session_data_object = self._sessions.get(session_uuid)
                
                # If the client session uuid does not exist return error
                if not client_session_data_object:
                    raise CipherSafeError(ApplicationCodes.SESSION_UNKNOWN, HTTPCodes.UNAUTHORIZED, "Unknown session identifier in get_client_handshake_state", "session_uuid")
                
                
                return client_session_data_object.handshake_state

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_STORE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to get handshake state", "handshake_state")



    """
        Update the handshake_state of a session atomically.

        @param session_uuid (str): Identifier for the session.
        @param new_state (str): New handshake state ("none" | "hello" | "encrypted" | "complete").
        @require session_uuid is a non-empty string
        @require new_state is a valid handshake state string
        @ensures Session handshake state is updated under lock.
    """
    def set_client_handshake_state(self, session_uuid: str, new_state: str) -> None:
        try:
           
            # Validate parameters
            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE,"session_uuid")
            VALIDATION.validate_string(new_state, ApplicationCodes.INVALID_TYPE, "handshake_state")

            # Validate the handshake state
            if new_state not in CONSTANTS._ALLOWED_HANDSHAKE_STATES:
                raise CipherSafeError(ApplicationCodes.SESSION_UPDATE_ERROR, HTTPCodes.BAD_REQUEST, f"Invalid handshake state '{new_state}'", "handshake_state")
           
           # Acquire lock for safe write
            with self._lock:
                
                # Get the client session data object
                client_session_data_object = self._sessions.get(session_uuid)
                
                # If the client session uuid does not exist return error
                if not client_session_data_object:
                    raise CipherSafeError(ApplicationCodes.SESSION_UNKNOWN, HTTPCodes.UNAUTHORIZED, "Unknown session identifier in set_client_handshake_state", "session_uuid")

                # Update handshake state
                client_session_data_object.handshake_state = new_state

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_UPDATE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to set handshake state", "handshake_state")



    """
        Check whether a session has exceeded its 15-minute TTL.

        @param session_uuid (str): Identifier for the session.
        @require session_uuid is a string (exists or not)
        @return dict | None: Logout packet if expired, otherwise None.
        @ensures Expired session is removed, AES key cleared, nonces wiped, and logout packet generated using PacketHandler.
    """
    def check_single_session_expiration(self, session_uuid: str) -> Optional[dict]:
        try:

            # Validate identifier
            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE, "session_uuid")

            # Acquire lock for safe state inspection & mutation
            with self._lock:

                # Retrieve the session object from memory
                client_session_data_object = self._sessions.get(session_uuid)

                # If session does not exist, nothing to expire
                if not client_session_data_object:
                    return None

                # Compute elapsed wall clock time
                current_time = datetime.now(timezone.utc)
                elapsed = current_time - client_session_data_object.session_created_at

                # Check TTL (15 minutes)
                if elapsed <= timedelta(seconds=CONSTANTS._SESSION_TTL_SECONDS):

                    # Session is still valid
                    return None

                # Remove expired session from dictionary
                self._sessions.pop(session_uuid, None)

                # Remove cookie if it matches this session
                if public_cookie_session.get("client_session_uuid") == session_uuid:
                    public_cookie_session.pop("client_session_uuid", None)

                # Build the standardized logout packet with the PacketHandler
                logout_packet = self._packet_handler.create_logout_response_packet(username=client_session_data_object.username, timestamp_iso=VALIDATION.get_timestamp_iso8601z())

                # Return logout packet
                return logout_packet

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_STORE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed during session expiration check", "session_expiration")



    """
        Check all active sessions for TTL expiration and remove expired ones.

        @require Internal session store may contain zero or many sessions
        @return List[dict]: All generated logout packets for expired sessions.
        @ensures All expired sessions are removed and cleaned up under lock.
    """
    def cleanup_expired_sessions(self) -> List[dict]:
        try:
            # Initialize a list for logout packets
            logout_packets: List[dict] = []

            # Acquire lock for safe iteration
            with self._lock:

                # Iterate through copy of session UUIDs
                for session_uuid in list(self._sessions.keys()):

                    # Check if session expired and handle cleanup
                    logout_packet = self.check_single_session_expiration(session_uuid)

                    # If a logout packet was generated, append it to the list
                    if logout_packet:
                        logout_packets.append(logout_packet)

            # Return list of logout packets for Flask to handle
            return logout_packets

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_STORE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed during bulk expiration cleanup", "session_cleanup")
        


    """
        Accept a nonce only once per session to enforce replay protection.

        @param session_uuid (str): Identifier of the client session.
        @param nonce_b64url (str): Base64URL nonce string generated by the client.
        @require session_uuid is a non-empty string
        @require nonce_b64url is a non-empty string
        @return tuple[bool, Optional[dict]]:
        @ensures Nonce is recorded under lock if unique; expired sessions produce logout packets.
    """
    def accept_nonce_once(self, session_uuid: str, nonce_b64url: str) -> tuple[bool, Optional[dict]]:
        try:
            
            # Validate identifiers
            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE, "session_uuid")
            VALIDATION.validate_b64(nonce_b64url, ApplicationCodes.INVALID_NONCE, "nonce")
            
            # Acquire lock to atomically test-and-set the nonce
            with self._lock:

                # Retrieve the session object
                sess = self._sessions.get(session_uuid)

                # If no valid session found
                if not sess:
                    raise CipherSafeError(ApplicationCodes.SESSION_UNKNOWN, HTTPCodes.UNAUTHORIZED, "Unknown session identifier in accept_nonce_once", "session_uuid")

                # Check if session expired using single-session expiration function
                logout_packet = self.check_single_session_expiration(session_uuid)

                # If the session expired, return logout packet
                if logout_packet is not None:
                   
                    return False, logout_packet

                # Enforce uniqueness of nonce within this session
                if nonce_b64url in sess.used_nonces:
                    return False, None

                # Add the new nonce to the set
                sess.used_nonces.add(nonce_b64url)
                return True, None

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_UPDATE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to validate or record nonce", "nonce")
        


    """
        Clear all recorded nonces for a session.

        @param session_uuid (str): Identifier of the session.
        @require session_uuid is a non-empty string
        @ensures used_nonces is cleared under lock; raises if session unknown.
    """
    def clear_client_session_nonces(self, session_uuid: str) -> None:
        try:

            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE, "session_uuid")

            # Acquire lock for safe mutation of the session object
            with self._lock:

                # Retrieve the client session data object
                client_session_data_object = self._sessions.get(session_uuid)

                # If the client session uuid does not exist return error
                if not client_session_data_object:
                    raise CipherSafeError(ApplicationCodes.SESSION_UNKNOWN, HTTPCodes.UNAUTHORIZED, "Unknown session identifier in clear_client_session_nonces", "session_uuid")
                
                # Safely clear the nonce tracking structure
                try:
                    client_session_data_object.used_nonces.clear()
                except Exception:
                    client_session_data_object.used_nonces = set()

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_UPDATE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to clear session nonces", "used_nonces")



    """
        Destroy a client session and remove its Flask cookie link.

        @param session_uuid (str): UUID of the session to invalidate.
        @require session_uuid is a non-empty string
        @return dict: Logout response packet for the client.
        @ensures Session is removed and logout packet is generated.
    """
    def invalidate_client_session(self, session_uuid: str) -> dict:
        try:
            
            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE, "session_uuid")

            # Acquire lock for safe removal
            with self._lock:

                # Remove session if it exists
                client_session_data_object = self._sessions.pop(session_uuid, None)
                if not client_session_data_object:
                    raise CipherSafeError(ApplicationCodes.SESSION_UNKNOWN, HTTPCodes.UNAUTHORIZED, "Unknown session identifier in invalidate_client_session", "session_uuid")
            
            # If the Flask cookie references the same session, remove it
            current_cookie_uuid = public_cookie_session.get("client_session_uuid")
            if current_cookie_uuid == session_uuid:
                public_cookie_session.pop("client_session_uuid", None)

            # Build and return standard logout packet
            logout_packet = self._packet_handler.create_logout_response_packet(username=client_session_data_object.username, timestamp_iso=VALIDATION.get_timestamp_iso8601z())
            return logout_packet

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_UPDATE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to invalidate client session", "session_uuid")



    """
        Atomically update a session's AES-256 key and clear all stored nonces.

        @param session_uuid (str): Session identifier.
        @param new_server_aes_key (bytes): New 32-byte AES key.
        @require session_uuid is a non-empty string
        @require new_server_aes_key is bytes of length 32
        @ensures AES key replaced under lock, nonces cleared, session validated.
    """
    def update_session_aes_key(self, session_uuid: str, new_server_aes_key: bytes) -> None:
        try:

            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE, "session_uuid")

            # Ensure the provided key is 32 bytes
            if not isinstance(new_server_aes_key, (bytes, bytearray)) or len(new_server_aes_key) != 32:
                raise CipherSafeError(ApplicationCodes.INVALID_AES_KEY, HTTPCodes.BAD_REQUEST, "new_server_aes_key must be 32 bytes", "new_server_aes_key")
            
            # Acquire lock to safely modify the shared session dictionary
            with self._lock:

                # Retrieve the session object from the dictionary
                sess = self._sessions.get(session_uuid)

                # Ensure the session exists before attempting mutation
                if not sess:
                    raise CipherSafeError(ApplicationCodes.SESSION_UNKNOWN, HTTPCodes.UNAUTHORIZED, "Unknown session in update_session_aes_key", "session_uuid")

                # Replace the stored AES key with a new immutable bytes object
                sess.server_aes_key = bytes(new_server_aes_key)
                sess.used_nonces.clear()

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_UPDATE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to update AES session key", "server_aes_key")



    """
        Update the client's RSA public key reference stored inside the session.

        @param session_uuid (str): Session identifier.
        @param client_rsa_public_key (str): PEM-formatted client RSA key.
        @require session_uuid is a non-empty string
        @require client_rsa_public_key is a non-empty string
        @ensures client_rsa_public_key field updated safely under lock.
    """
    def update_session_client_rsa_public_key(self, session_uuid: str, client_rsa_public_key: str) -> None:
        try:
            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE, "session_uuid")
            VALIDATION.validate_string(client_rsa_public_key, ApplicationCodes.INVALID_PUBLIC_KEY, "client_rsa_public_key")

            # Acquire lock before modifying shared in-memory session store
            with self._lock:

                # Retrieve the session object from the dictionary
                sess = self._sessions.get(session_uuid)

                # Reject updates to non-existent sessions
                if not sess:
                    raise CipherSafeError(ApplicationCodes.SESSION_UNKNOWN, HTTPCodes.UNAUTHORIZED, "Unknown session in update_session_client_rsa_public_key", "session_uuid")

                # Update the client's RSA public key reference
                sess.client_rsa_public_key = client_rsa_public_key

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_UPDATE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to update client RSA key", "client_rsa_public_key")



    """
        Atomically update a single field on a ServerSessionDataObject.

        @param session_uuid (str): Identifier for the session.
        @param field_name (str): Name of the field to update.
        @param value (Any): New value to assign.
        @require session_uuid is a non-empty string
        @require field_name is a string and must exist on the session object
        @ensures Field is updated under lock; raises if field missing or session unknown.
    """
    def update_session_field(self, session_uuid: str, field_name: str, value) -> None:
        try:
            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE, "session_uuid")
            VALIDATION.validate_string(field_name, ApplicationCodes.SESSION_FIELD_MISSING, "field_name")

            # Acquire lock to ensure atomic field assignment
            with self._lock:

                # Retrieve the existing session object
                sess = self._sessions.get(session_uuid)

                # Reject updates if the session does not exist
                if not sess:
                    raise CipherSafeError(ApplicationCodes.SESSION_UNKNOWN, HTTPCodes.UNAUTHORIZED, "Unknown session in update_session_field", "session_uuid")

                # Ensure the field exists prior to assignment
                if not hasattr(sess, field_name):
                    raise CipherSafeError(ApplicationCodes.SESSION_FIELD_MISSING, HTTPCodes.BAD_REQUEST, f"Session object has no field '{field_name}'", field_name)

                # Assign the provided value to the indicated field
                setattr(sess, field_name, value)

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_UPDATE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to update session field", field_name)



    """
        Perform an atomic multi-field update on a session.
        @param session_uuid (str): Identifier of the session.
        @param updates (dict): Mapping of field_name → new value.
        @require updates is a dict
        @require session_uuid is a non-empty string
        @ensures All provided fields are updated under one lock, or error is raised
    """
    def update_full_session(self, session_uuid: str, updates: dict) -> None:
        try:
            VALIDATION.validate_string(session_uuid, ApplicationCodes.INVALID_TYPE, "session_uuid")

            # Ensure the provided value is a dictionary
            if not isinstance(updates, dict):
                raise CipherSafeError(ApplicationCodes.INVALID_UPDATE_MAP, HTTPCodes.BAD_REQUEST, "update_full_session requires dict input", "updates")

            # Acquire lock to guarantee atomic multi-field updates
            with self._lock:

                # Retrieve the targeted session object
                sess = self._sessions.get(session_uuid)

                # Reject if the session does not exist
                if not sess:
                    raise CipherSafeError(ApplicationCodes.SESSION_UNKNOWN, HTTPCodes.UNAUTHORIZED, "Unknown session in update_full_session", "session_uuid")

                # Loop over each key-value pair in the provided update map
                for key, value in updates.items():

                    if not isinstance(key, str) or not key.strip():
                        raise CipherSafeError(ApplicationCodes.INVALID_UPDATE_MAP, HTTPCodes.BAD_REQUEST, "All update keys must be non-empty strings", "updates")
                     
                    # Ensure that the session object contains this field
                    if not hasattr(sess, key):
                        raise CipherSafeError(ApplicationCodes.SESSION_FIELD_MISSING, HTTPCodes.BAD_REQUEST, f"Session object has no field '{key}'", key)

                    # Perform the field assignment
                    setattr(sess, key, value)

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.SESSION_UPDATE_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to perform multi-field session update", "updates")

