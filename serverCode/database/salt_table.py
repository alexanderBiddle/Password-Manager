#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: salt_table.py
    Author: Alex Biddle

    Description:
        Manages the salt_storage table, which stores per-user client and server
        salts used in the two-stage Argon2id password hashing pipeline. Ensures
        salts are base64url-encoded, safely inserted, retrieved, and updated
        through parameterized and validated SQL operations.
"""

import typing
import uuid
import sys, os
from capstone.database.database_object import Database
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes


class SaltTable:

    """
        Initialize a SaltTable helper bound to a Database instance.

        @param database (Database): Shared Database helper used to communicate with PostgreSQL.
        @require isinstance(database, Database)
        @ensures The salt_storage table is created if missing.
    """
    def __init__(self, database: Database) -> None:

        try:
            # Validate Database instance
            if not isinstance(database, Database):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "SaltTable requires a Database instance", "database")

            # Store ref
            self._database: Database = database

            # Ensure salt_storage exists
            self._ensure_table_exists()

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize SaltTable", "salt_table_init")


    """
        Create the salt_storage table if it does not already exist.

        @require Valid database connection available
        @ensures salt_storage contains user_id, username, client_salt, server_salt, created_at.
    """
    def _ensure_table_exists(self) -> None:

        try:
            # SQL for salt_storage (stores client and server salts used for Argon2id)
            create_salt_sql = """
                CREATE TABLE IF NOT EXISTS salt_storage (
                    user_id     UUID PRIMARY KEY REFERENCES master_table(user_id) ON DELETE CASCADE,
                    username    VARCHAR(64) UNIQUE NOT NULL,
                    client_salt TEXT        NOT NULL,
                    server_salt TEXT        NOT NULL
                );
            """

            # Execute creation statement
            self._database.execute_statment(create_salt_sql)

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to ensure salt_storage table exists", "salt_storage")


    """
        Create a new salt_storage row for a given user_id.

        @param user_id (str): UUID string referencing master_table.user_id.
        @param username (str): Associated username.
        @param client_salt_b64u (str): Base64url encoded client-side salt.
        @param server_salt_b64u (str): Base64url encoded server-side salt.

        @require user_id is a valid UUID string
        @require isinstance(username, str) and 0 < len(username) <= 64
        @require isinstance(client_salt_b64u, str) and len(client_salt_b64u.strip()) > 0
        @require isinstance(server_salt_b64u, str) and len(server_salt_b64u.strip()) > 0

        @return bool: True if one row was inserted successfully.

        @ensures No plaintext secrets are stored; salts written safely to salt_storage.
    """
    def create_salt_record(self, user_id: str, username: str, client_salt_b64u: str, server_salt_b64u: str) -> bool:

        try:
            # Validate user_id
            try:
                parsed_uuid = uuid.UUID(str(user_id))
            except Exception:
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "user_id must be a valid UUID string", "user_id")

            # Validate username
            if not isinstance(username, str) or not username.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_USERNAME, HTTPCodes.BAD_REQUEST, "Username must be a non-empty string", "username")

            if len(username) > 64:
                raise CipherSafeError(ApplicationCodes.INVALID_LENGTH, HTTPCodes.BAD_REQUEST, "Username exceeds maximum length (64)", "username")

            # Validate client salt
            if not isinstance(client_salt_b64u, str) or not client_salt_b64u.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "Client salt must be a non-empty base64url string", "client_salt")

            # Validate server salt
            if not isinstance(server_salt_b64u, str) or not server_salt_b64u.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "Server salt must be a non-empty base64url string", "server_salt")

            # Insert into salt_storage
            insert_salt_sql = """
                INSERT INTO salt_storage (user_id, username, client_salt, server_salt)
                VALUES (%s, %s, %s, %s);
            """

            rc = self._database.execute_statment(
                insert_salt_sql,
                (
                    str(parsed_uuid),
                    username.strip(),
                    client_salt_b64u.strip(),
                    server_salt_b64u.strip(),
                ),
            )

            return rc == 1

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to create salt_storage record", "create_salt_record")


    """
        Retrieve the client_salt and user_id for a given username.

        @param username (str): Username to look up.

        @require isinstance(username, str) and len(username.strip()) > 0

        @return dict|None: {'user_id': ..., 'client_salt': ...} if found; otherwise None.

        @ensures Only base64url salts are returned; no plaintext credentials.
    """
    def get_client_salt(self, username: str) -> typing.Optional[dict]:

        try:
            if not isinstance(username, str) or not username.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_USERNAME, HTTPCodes.BAD_REQUEST, "Username must be a non-empty string", "username")

            select_sql = """
                SELECT user_id, client_salt
                FROM salt_storage
                WHERE username = %s;
            """

            row = self._database.get_row(select_sql, (username.strip(),))

            if row is None:
                return None

            return {
                "user_id": str(row["user_id"]),
                "client_salt": row["client_salt"],
            }

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to fetch client_salt by username", "get_client_salt")


    """
        Retrieve the server_salt and user_id for a given username.

        @param username (str): Username to look up.

        @require isinstance(username, str) and len(username.strip()) > 0

        @return dict|None: {'user_id': ..., 'server_salt': ...} if found; otherwise None.

        @ensures Returns only salts and identifiers; no sensitive plaintext.
    """
    def get_server_salt_and_user_id(self, username: str) -> typing.Optional[dict]:

        try:
            if not isinstance(username, str) or not username.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_USERNAME, HTTPCodes.BAD_REQUEST, "Username must be a non-empty string", "username")

            select_sql = """
                SELECT user_id, server_salt
                FROM salt_storage
                WHERE username = %s;
            """

            row = self._database.get_row(select_sql, (username.strip(),))

            if row is None:
                return None

            return {
                "user_id": str(row["user_id"]),
                "server_salt": row["server_salt"],
            }

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to fetch server_salt and user_id by username", "get_server_salt_and_user_id")


    """
        Retrieve both client_salt and server_salt for a given user_id.

        @param user_id (str): UUID string identifying the user.

        @require user_id must be a valid UUID string

        @return dict|None: {'username': ..., 'client_salt': ..., 'server_salt': ...} if found; otherwise None.

        @ensures All salts returned are stored safely in base64url format.
    """
    def get_salts_by_user_id(self, user_id: str) -> typing.Optional[dict]:

        try:
            # Validate UUID
            try:
                parsed_uuid = uuid.UUID(str(user_id))
            except Exception:
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "user_id must be a valid UUID string", "user_id")

            select_sql = """
                SELECT username, client_salt, server_salt
                FROM salt_storage
                WHERE user_id = %s;
            """

            row = self._database.get_row(select_sql, (str(parsed_uuid),))

            if row is None:
                return None

            return {
                "username": row["username"],
                "client_salt": row["client_salt"],
                "server_salt": row["server_salt"],
            }

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to fetch salts by user_id", "get_salts_by_user_id")



    """
        Update both the client_salt and server_salt for a given user_id.

        @param user_id (str): UUID string identifying the user.
        @param client_salt_b64u (str): New base64url client_salt.
        @param server_salt_b64u (str): New base64url server_salt.

        @require user_id must be a valid UUID string
        @require isinstance(client_salt_b64u, str) and len(client_salt_b64u.strip()) > 0
        @require isinstance(server_salt_b64u, str) and len(server_salt_b64u.strip()) > 0

        @return bool: True if exactly one row was updated.

        @ensures salt_storage row is updated for the specified user_id.
    """
    def update_salts(self, user_id: str, client_salt_b64u: str, server_salt_b64u: str) -> bool:

        try:
            # Validate user_id
            try:
                parsed_uuid = uuid.UUID(str(user_id))
            except Exception:
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "user_id must be a valid UUID string", "user_id")

            # Validate client_salt_b64u
            if not isinstance(client_salt_b64u, str) or not client_salt_b64u.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "client_salt_b64u must be a non-empty string", "client_salt_b64u")

            # Validate server_salt_b64u
            if not isinstance(server_salt_b64u, str) or not server_salt_b64u.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "server_salt_b64u must be a non-empty string", "server_salt_b64u")

            # SQL update statement
            update_sql = """
                UPDATE salt_storage
                SET client_salt = %s, server_salt = %s
                WHERE user_id = %s;
            """

            # Execute update
            rc = self._database.execute_statment(
                update_sql,
                (client_salt_b64u.strip(), server_salt_b64u.strip(), str(parsed_uuid)),
            )

            # True if exactly one row was updated
            return rc == 1

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to update salts for user_id", "update_salts")
