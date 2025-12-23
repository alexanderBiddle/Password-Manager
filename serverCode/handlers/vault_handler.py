#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: vault_handler.py
    Author: Alex Biddle

    Description:
        Handles all encrypted vault operations for CipherSafe, acting as the secure
        server-side interface between the Four-Way Handshake and the per-user vault
        tables in PostgreSQL. Ensures all ciphertext fields remain opaque, validates
        payloads, enforces session identity, and returns structured responses for
        account retrieval, insertion, updates, deletion, and master-password rotation.
"""


import typing
from capstone.database.database_object import Database
from capstone.database.master_table import MasterTable
from capstone.database.user_tables import UserTables
from capstone.database.salt_table import SaltTable
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes
from capstone.handlers.session_handler import ServerSessionHandler
from capstone.utilities.audit_log import AuditLog
import capstone.handlers.sanitization_validation as VALIDATION
import capstone.constants as CONSTANTS 



"""
    Manages all encrypted operations for user vault entries. This handler acts as a thin, 
    validated adapter between the Four-Way Handshake secure channel and the per-user
    PostgreSQL vault tables provided by UserTables. All fields describing websites,
    usernames, emails, and passwords are treated as opaque ciphertext strings 
    (typically AES-GCM + base64url) and are never decrypted on the server.
"""
class VaultHandler:

    """
        Initialize the VaultHandler with session, database, and audit log dependencies.

        @param session_manager (ServerSessionHandler): Manages server-side sessions.
        @param audit (AuditLog): Audit logger for non-sensitive event recording.
        @require isinstance(session_manager, ServerSessionHandler)
        @require isinstance(audit, AuditLog)
        @ensures Database, MasterTable, UserTables, and SaltTable helpers are initialized.
    """
    def __init__(self, session_manager: ServerSessionHandler, audit: AuditLog, database: Database) -> None:
        try:
            # Validate dependencies
            if not isinstance(session_manager, ServerSessionHandler):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "VaultHandler requires ServerSessionHandler instance", "session_manager")
            if not isinstance(audit, AuditLog):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "VaultHandler requires AuditLog instance", "audit")
            if not isinstance(database, Database):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "VaultHandler requires a Database instance", "database")
           
            # Store references
            self._sessions: ServerSessionHandler = session_manager
            self._audit: AuditLog = audit
            self._master_table: MasterTable = MasterTable(database)
            self._user_tables: UserTables = UserTables(database)
            self._salt_table: SaltTable = SaltTable(database)

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize VaultHandler", "vault_handler_init")



    """
        Validate that a vault field is a properly formatted AES-GCM ciphertext.
        The server assumes all vault fields are opaque ciphertext strings.

        @param value (str): Base64url ciphertext string.
        @param field_name (str): Field being validated.
    """
    def _validate_ciphertext_field(self, value: str, field_name: str) -> None:
        
        if not isinstance(value, str) or not value.strip():
            raise CipherSafeError(ApplicationCodes.INVALID_CIPHERTEXT, HTTPCodes.BAD_REQUEST, f"Missing or invalid ciphertext for '{field_name}'", field_name)

        VALIDATION.validate_b64(value, ApplicationCodes.INVALID_CIPHERTEXT, field_name)
        VALIDATION.validate_byte_size(value, CONSTANTS._MAX_B64URL_BYTES, ApplicationCodes.INVALID_LENGTH, field_name)



    """      
        Handle a decrypted secure vault request after AES-GCM removal.

        @param username (str): Username bound to the active secure session.
        @param request_type (str): One of the supported vault operation names.
        @param payload (dict): Decrypted JSON payload containing operation-specific fields.
        @require isinstance(username, str)
        @require isinstance(request_type, str)
        @require isinstance(payload, dict)
        @return tuple[dict, int]: (response_body, http_status)
    """
    def handle(self, username: str, request_type: str, payload: dict) -> typing.Tuple[dict, int]:
        try:
            # Ensure payload is a dictionary
            if not isinstance(payload, dict):
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "Vault payload must be a JSON object", "payload")

            # Load the current server session data object
            current_session = self._sessions.get_client_session_data_object()

            # Ensure there is an active session
            if current_session is None:
                raise CipherSafeError(ApplicationCodes.SESSION_NOT_FOUND, HTTPCodes.UNAUTHORIZED, "No active session for vault operation", "session")

            # Ensure the username is bound to the current session
            if current_session.username != username:
                raise CipherSafeError(ApplicationCodes.ENCRYPTED_REQUEST_USERNAME_MISMATCH, HTTPCodes.UNAUTHORIZED, "Username does not match active session", "username")

            # Look up user_id (UUID) via master_table
            user_id = self._master_table.get_user_id_by_username(username)

            # If no mapping exists, treat as invalid account
            if user_id is None:
                raise CipherSafeError(ApplicationCodes.INVALID_ACCOUNT, HTTPCodes.UNAUTHORIZED, "Unknown account for vault operation", "username")

            # Normalize request_type to string
            if not isinstance(request_type, str) or not request_type.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST_TYPE, HTTPCodes.BAD_REQUEST, "request_type must be a non-empty string", "request_type")

            request_type_clean = request_type.strip()

            # Dispatch by request_type
            if request_type_clean == "vault_fetch_accounts":
                return self._handle_fetch_accounts(user_id, username)

            elif request_type_clean == "vault_fetch_account_password":
                return self._handle_fetch_account_password(user_id, username, payload)

            elif request_type_clean == "vault_add_account":
                return self._handle_add_account(user_id, username, payload)

            elif request_type_clean == "vault_update_account":
                return self._handle_update_account(user_id, username, payload)

            elif request_type_clean == "vault_delete_account":
                return self._handle_delete_account(user_id, username, payload)

            elif request_type_clean == "vault_update_master_password":
                return self._handle_update_master_password(user_id, username, payload)

            # Unknown operation fallback
            raise CipherSafeError(ApplicationCodes.INVALID_REQUEST_TYPE, HTTPCodes.BAD_REQUEST, f"Unsupported vault request_type: {request_type_clean}", "request_type")

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error in VaultHandler.handle", "vault_handle")



    """
        Fetch all encrypted account metadata rows for the specified user.

        @param user_id (str): UUID identifying the user.
        @param username (str): Logical username (for audit and response construction).
        @require isinstance(user_id, str)
        @require isinstance(username, str)
        @return tuple[dict, int]: Response payload + HTTP code.
        @ensures Returns a success response containing an 'accounts' list with encrypted metadata fields exactly as stored in the database.
    """
    def _handle_fetch_accounts(self, user_id: str, username: str) -> typing.Tuple[dict, int]:
        try:
            # Retrieve all encrypted account rows
            rows = self._user_tables.fetch_accounts(user_id)

            # Build ISO8601Z timestamp
            timestamp_iso = VALIDATION.get_timestamp_iso8601z()

            # Construct response payload
            response_payload = {
                "protocol_version": CONSTANTS._PROTOCOL_VERSION,
                "response_status": CONSTANTS.RESPONSE_STATUS_SUCCESS,
                "username": username,
                "timestamp": timestamp_iso,
                "accounts": rows,
            }

            # Record audit event (do not log sensitive contents)
            self._audit.event(event="vault_fetch_accounts", username=username, context="vault_handler", detail=f"count={len(rows)}")

            # Always 200 OK on success
            return response_payload, HTTPCodes.OK

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error fetching vault accounts", "vault_fetch_accounts")



    """
        Retrieve a single encrypted account password for the given user.

        @param user_id (str): UUID identifying the user.
        @param username (str): Logical username for audit and response.
        @param payload (dict): JSON payload containing 'website' and 'account_username'.
        @require payload['website'] is a non-empty string
        @require payload['account_username'] is a non-empty string
        @return tuple[dict, int]: Response with encrypted password or NOT_FOUND error.
        @ensures Returns 'account_password' ciphertext exactly as stored.
    """
    def _handle_fetch_account_password(self, user_id: str, username: str, payload: dict) -> typing.Tuple[dict, int]:
        try:

            # Validate payload
            VALIDATION.validate_required_fields(payload, CONSTANTS._VAULT_FETCH_ACCOUNT_PASSWORD_REQUIRED_FIELDS, ApplicationCodes.MISSING_FIELDS, "vault_fetch_account_password")
            VALIDATION.validate_no_extra_fields(payload, CONSTANTS._VAULT_FETCH_ACCOUNT_PASSWORD_REQUIRED_FIELDS, ApplicationCodes.UNKNOWN_FIELDS,"vault_fetch_account_password")

            # Extract and validate required fields
            website_ct = payload.get("website")
            account_username_ct = payload.get("account_username")

            # website field must be provided
            self._validate_ciphertext_field(website_ct, "website")
            self._validate_ciphertext_field(account_username_ct, "account_username")

            # Query the encrypted password from the per-user table
            password_ct = self._user_tables.fetch_account_password(user_id, website_ct, account_username_ct)

            # If no row, surface a 404-style semantic error
            if password_ct is None:
                raise CipherSafeError(ApplicationCodes.NOT_FOUND, HTTPCodes.NOT_FOUND, "Requested vault entry not found", "vault_entry")

            # Build ISO8601Z timestamp
            timestamp_iso = VALIDATION.get_timestamp_iso8601z()

            # Construct response payload
            response_payload = {
                "protocol_version": CONSTANTS._PROTOCOL_VERSION,
                "response_status": CONSTANTS.RESPONSE_STATUS_SUCCESS,
                "username": username,
                "timestamp": timestamp_iso,
                "website": website_ct,
                "account_username": account_username_ct,
                "account_password": password_ct,
            }

            # Audit event (no password contents are logged)
            self._audit.event(event="vault_fetch_account_password", username=username, context="vault_handler", detail="single_password_fetch")

            return response_payload, HTTPCodes.OK

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error fetching vault account password", "vault_fetch_account_password")



    """
        Insert a new encrypted vault entry for the user.

        @param user_id (str): UUID identifying the user.
        @param username (str): Logical username for logging and response.
        @param payload (dict): JSON dictionary containing website, username, email, password.
        @require website, account_username, and account_password are non-empty strings
        @require account_email is a string (may be empty)
        @return tuple[dict, int]: Confirmation payload + HTTP code.
        @ensures A new encrypted row is inserted into the user's vault table.
    """
    def _handle_add_account(self, user_id: str, username: str, payload: dict) -> typing.Tuple[dict, int]:
        try:

            # Validate the payload
            VALIDATION.validate_required_fields(payload, CONSTANTS._VAULT_ADD_ACCOUNT_REQUIRED_FIELDS, ApplicationCodes.MISSING_FIELDS,"vault_add_account")
            VALIDATION.validate_no_extra_fields(payload, CONSTANTS._VAULT_ADD_ACCOUNT_REQUIRED_FIELDS,ApplicationCodes.UNKNOWN_FIELDS,"vault_add_account")

            # Extract required fields
            website_ct = payload.get("website")
            account_username_ct = payload.get("account_username")
            account_email_ct = payload.get("account_email")
            account_password_ct = payload.get("account_password")

            # Validate parameters
            self._validate_ciphertext_field(website_ct, "website")
            self._validate_ciphertext_field(account_username_ct, "account_username")
            self._validate_ciphertext_field(account_email_ct, "account_email")
            self._validate_ciphertext_field(account_password_ct, "account_password")

            # Insert new account row into the user's vault table
            created = self._user_tables.add_account(user_id, website_ct, account_username_ct, account_email_ct, account_password_ct)

            # If insertion did not succeed (False), signal internal error
            if not isinstance(created, bool) or not created:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to insert new vault account", "vault_add_account")

            # Build ISO8601Z timestamp
            timestamp_iso = VALIDATION.get_timestamp_iso8601z()

            # Build response payload
            response_payload = {
                "protocol_version": CONSTANTS._PROTOCOL_VERSION,
                "response_status": CONSTANTS.RESPONSE_STATUS_SUCCESS,
                "username": username,
                "timestamp": timestamp_iso,
                "message": "Vault account added.",
            }

            # Audit event for account creation
            self._audit.event(event="vault_add_account", username=username, context="vault_handler", detail="account_created")

            return response_payload, HTTPCodes.OK

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error adding vault account", "vault_add_account")



    """
        Update an existing encrypted account entry in the user's vault.

        @param user_id (str): UUID identifying the user.
        @param username (str): Logical username.
        @param payload (dict): Contains old_* and new_* encrypted fields.
        @require All old_* and new_* ciphertext inputs are non-empty strings.
        @require new_account_email is a string (may be empty)
        @return tuple[dict, int]: Confirmation payload + HTTP code.
        @ensures Exactly one row is updated; raises NOT_FOUND if the target entry does not exist.
    """
    def _handle_update_account(self, user_id: str, username: str, payload: dict) -> typing.Tuple[dict, int]:
        try:

            # Validate the payload
            VALIDATION.validate_required_fields(payload, CONSTANTS._VAULT_UPDATE_ACCOUNT_REQUIRED_FIELDS, ApplicationCodes.MISSING_FIELDS, "vault_update_account")
            VALIDATION.validate_no_extra_fields(payload, CONSTANTS._VAULT_UPDATE_ACCOUNT_REQUIRED_FIELDS, ApplicationCodes.UNKNOWN_FIELDS,"vault_update_account")

            # Extract old identification fields
            old_website_ct = payload.get("old_website")
            old_account_username_ct = payload.get("old_account_username")

            # Extract new fields
            new_website_ct = payload.get("new_website")
            new_account_username_ct = payload.get("new_account_username")
            new_account_email_ct = payload.get("new_account_email")
            new_account_password_ct = payload.get("new_account_password")

            # Validate parameters
            self._validate_ciphertext_field(old_website_ct, "old_website")
            self._validate_ciphertext_field(old_account_username_ct, "old_account_username")
            self._validate_ciphertext_field(new_website_ct, "new_website")
            self._validate_ciphertext_field(new_account_username_ct, "new_account_username")
            self._validate_ciphertext_field(new_account_email_ct, "new_account_email")
            self._validate_ciphertext_field(new_account_password_ct, "new_account_password")

            # Perform the update via UserTables
            updated = self._user_tables.update_account(
                user_id=user_id,
                old_website_ct=old_website_ct,
                old_account_username_ct=old_account_username_ct,
                new_website_ct=new_website_ct,
                new_account_username_ct=new_account_username_ct,
                new_account_email_ct=new_account_email_ct,
                new_account_password_ct=new_account_password_ct,
            )

            # If no row was updated, then the original entry did not exist
            if not isinstance(updated, bool) or not updated:
                raise CipherSafeError(ApplicationCodes.NOT_FOUND, HTTPCodes.NOT_FOUND, "Original vault entry not found for update", "vault_update_account")

            # Build ISO8601Z timestamp
            timestamp_iso = VALIDATION.get_timestamp_iso8601z()

            # Construct response payload
            response_payload = {
                "protocol_version": CONSTANTS._PROTOCOL_VERSION,
                "response_status": CONSTANTS.RESPONSE_STATUS_SUCCESS,
                "username": username,
                "timestamp": timestamp_iso,
                "message": "Vault account updated.",
            }

            # Audit update event
            self._audit.event(event="vault_update_account", username=username, context="vault_handler", detail="account_updated")

            return response_payload, HTTPCodes.OK

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error updating vault account", "vault_update_account")



    """
        Delete an encrypted vault entry for the user.

        @param user_id (str): UUID identifying the user.
        @param username (str): Logical username.
        @param payload (dict): JSON payload containing 'website' and 'account_username'.
        @require website and account_username are non-empty strings
        @return tuple[dict, int]: Confirmation payload + HTTP code.
        @ensures One encrypted row is removed; raises NOT_FOUND if entry does not exist.
    """
    def _handle_delete_account(self, user_id: str, username: str, payload: dict) -> typing.Tuple[dict, int]:
        try:

            # Validate the payload
            VALIDATION.validate_required_fields(payload, CONSTANTS._VAULT_DELETE_ACCOUNT_REQUIRED_FIELDS, ApplicationCodes.MISSING_FIELDS, "vault_delete_account")
            VALIDATION.validate_no_extra_fields(payload, CONSTANTS._VAULT_DELETE_ACCOUNT_REQUIRED_FIELDS, ApplicationCodes.UNKNOWN_FIELDS,"vault_delete_account")

            # Extract deletion keys
            website_ct = payload.get("website")
            account_username_ct = payload.get("account_username")

            # Validate parameters
            self._validate_ciphertext_field(website_ct, "website")
            self._validate_ciphertext_field(account_username_ct, "account_username")

            # Perform deletion
            deleted = self._user_tables.delete_account(user_id, website_ct, account_username_ct)

            # If nothing was deleted, signal a not-found condition
            if not isinstance(deleted, bool) or not deleted:
                raise CipherSafeError(ApplicationCodes.NOT_FOUND, HTTPCodes.NOT_FOUND, "Vault account not found for deletion", "vault_delete_account")

            # Build ISO8601Z timestamp
            timestamp_iso = VALIDATION.get_timestamp_iso8601z()

            # Build response payload
            response_payload = {
                "protocol_version": CONSTANTS._PROTOCOL_VERSION,
                "response_status": CONSTANTS.RESPONSE_STATUS_SUCCESS,
                "username": username,
                "timestamp": timestamp_iso,
                "message": "Vault account deleted.",
            }

            # Audit deletion event
            self._audit.event(event="vault_delete_account", username=username, context="vault_handler", detail="account_deleted")

            return response_payload, HTTPCodes.OK

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error deleting vault account", "vault_delete_account")



    """
        Rotate a user's master password and associated salts.

        @param user_id (str): UUID identifying the user.
        @param username (str): Logical username for audit and response.
        @param payload (dict): Must include old_client_hash, new_client_salt, new_client_hash.
        @require old_client_hash is base64url → 32 bytes
        @require new_client_salt is base64url → 16 bytes
        @require new_client_hash is base64url → 32 bytes
        @return tuple[dict, int]: Response packet confirming update + HTTP code.
        @ensures Old password is verified using Argon2id, new salts and hashes are computed, master_table and salt_table are updated, and a success response is generated.
    """
    def _handle_update_master_password(self, user_id: str, username: str, payload: dict) -> typing.Tuple[dict, int]:

        try:
            # Extract base64url fields
            old_client_hash_b64u = payload.get("old_client_hash")
            new_client_salt_b64u = payload.get("new_client_salt")
            new_client_hash_b64u = payload.get("new_client_hash")

            # Ensure required fields are present and non-empty strings
            if not isinstance(old_client_hash_b64u, str) or not old_client_hash_b64u.strip():
                raise CipherSafeError(ApplicationCodes.MISSING_FIELDS, HTTPCodes.BAD_REQUEST, "Missing or invalid 'old_client_hash' for vault_update_master_password", "old_client_hash")
            if not isinstance(new_client_salt_b64u, str) or not new_client_salt_b64u.strip():
                raise CipherSafeError(ApplicationCodes.MISSING_FIELDS, HTTPCodes.BAD_REQUEST, "Missing or invalid 'new_client_salt' for vault_update_master_password", "new_client_salt")
            if not isinstance(new_client_hash_b64u, str) or not new_client_hash_b64u.strip():
                raise CipherSafeError(ApplicationCodes.MISSING_FIELDS, HTTPCodes.BAD_REQUEST, "Missing or invalid 'new_client_hash' for vault_update_master_password", "new_client_hash")

            # Decode all fields from base64url → bytes
            old_client_hash_bytes = VALIDATION.decode_base64url_to_bytes("old_client_hash", old_client_hash_b64u)
            new_client_salt_bytes = VALIDATION.decode_base64url_to_bytes("new_client_salt", new_client_salt_b64u)
            new_client_hash_bytes = VALIDATION.decode_base64url_to_bytes("new_client_hash", new_client_hash_b64u)

            # Enforce lengths: hashes are 32 bytes, salts are 16 bytes
            if len(old_client_hash_bytes) != CONSTANTS._HASHED_PASSWORD_LENGTH:
                raise CipherSafeError(ApplicationCodes.INVALID_LENGTH, HTTPCodes.BAD_REQUEST, "old_client_hash must be exactly 32 bytes", "old_client_hash")

            if len(new_client_hash_bytes) != CONSTANTS._HASHED_PASSWORD_LENGTH:
                raise CipherSafeError(ApplicationCodes.INVALID_LENGTH, HTTPCodes.BAD_REQUEST, "new_client_hash must be exactly 32 bytes", "new_client_hash")

            if len(new_client_salt_bytes) != CONSTANTS._LOGIN_SALT_LEN_BYTES:
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "new_client_salt must be exactly 16 bytes", "new_client_salt")

            # Load existing salts for this user_id
            salts_record = self._salt_table.get_salts_by_user_id(user_id)

            # If no salts found, treat as invalid account configuration
            if not salts_record or "server_salt" not in salts_record:
                raise CipherSafeError(ApplicationCodes.INVALID_ACCOUNT, HTTPCodes.UNAUTHORIZED, "Salt record missing for account", "user_id")

            server_salt_b64u = salts_record["server_salt"]

            # Load existing server-side password hash from master_table
            hash_record = self._master_table.get_hashed_password(user_id)
            if not hash_record or "password" not in hash_record:
                raise CipherSafeError(ApplicationCodes.INVALID_ACCOUNT, HTTPCodes.UNAUTHORIZED, "Password record missing for account", "user_id")

            server_hash_b64u = hash_record["password"]

            # Decode salts and hash from base64url
            server_salt_bytes = VALIDATION.decode_base64url_to_bytes("server_salt", server_salt_b64u)
            server_hash_bytes = VALIDATION.decode_base64url_to_bytes("server_hash", server_hash_b64u)

            # Verify the old master password using Argon2id manager
            try:
                verified = self._sessions._argon2_manager.verify_password(password=old_client_hash_bytes, salt=server_salt_bytes, expected_hash=server_hash_bytes)
            
            except CipherSafeError:
                raise
            except Exception:
                raise CipherSafeError(ApplicationCodes.AUTH_FAILED, HTTPCodes.UNAUTHORIZED, "Invalid current master password", "old_client_hash")

            # Reject invalid current master password
            if not verified:
                raise CipherSafeError(ApplicationCodes.AUTH_FAILED, HTTPCodes.UNAUTHORIZED, "Invalid current master password", "old_client_hash")

            # Generate new server_salt and compute new server-side hash
            server_salt_new_bytes = self._sessions._argon2_manager.generate_salt()
            server_hash_new_bytes = self._sessions._argon2_manager.hash_password(password=new_client_hash_bytes, salt=server_salt_new_bytes)

            # Encode values for storage
            new_client_salt_b64u = VALIDATION.encode_bytes_to_base64url(new_client_salt_bytes)
            new_server_salt_b64u = VALIDATION.encode_bytes_to_base64url(server_salt_new_bytes)
            new_server_hash_b64u = VALIDATION.encode_bytes_to_base64url(server_hash_new_bytes)

            # Update master_table password hash
            updated_pwd = self._master_table.update_master_password(user_id, new_server_hash_b64u)
            if not isinstance(updated_pwd, bool) or not updated_pwd:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to update master password hash", "master_table_update")

            # Update salts in salt_storage
            updated_salts = self._salt_table.update_salts(user_id, new_client_salt_b64u, new_server_salt_b64u)
            if not isinstance(updated_salts, bool) or not updated_salts:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to update salt_storage record", "salt_storage_update")

            # Build ISO8601Z timestamp
            timestamp_iso = VALIDATION.get_timestamp_iso8601z()

            # Build response payload
            response_payload = {
                "protocol_version": CONSTANTS._PROTOCOL_VERSION,
                "response_status": CONSTANTS.RESPONSE_STATUS_SUCCESS,
                "username": username,
                "timestamp": timestamp_iso,
                "message": "Master password and salts updated.",
            }

            # Audit master password update (no secret data logged)
            self._audit.event(event="vault_update_master_password", username=username, context="vault_handler", detail="master_password_updated")

            return response_payload, HTTPCodes.OK

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error updating master password", "vault_update_master_password")