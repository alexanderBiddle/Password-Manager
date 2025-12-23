#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: master_table.py
    Author: Alex Biddle

    Description:
        Implements secure creation and lookup operations for the CipherSafe
        master_table, which stores user_id, username, and server-side Argon2id
        hashed master passwords. Ensures safe inserts, updates, and queries using
        parameterized SQL and strict input validation.
"""

import typing
import uuid
import sys, os
from capstone.database.database_object import Database
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes



class MasterTable:

    """
        Initialize a MasterTable helper bound to a Database instance.

        @param db (Database): Shared Database helper used for PostgreSQL access.

        @require isinstance(db, Database)

        @ensures Internal references are stored and master_table existence is verified.
    """
    def __init__(self, db: Database) -> None:

        try:
            # Ensure a valid Database instance is provided
            if not isinstance(db, Database):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "MasterTable requires a Database instance", "db")

            # Store the database reference
            self._db: Database = db

            # Ensure required table exists
            self._ensure_table_exists()

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize MasterTable", "master_table_init")


    """
        Create the master_table if it does not already exist.

        @require Database connection must be valid

        @return None: Table is created if missing.

        @ensures master_table contains user_id, username, password, created_at, updated_at.
    """
    def _ensure_table_exists(self) -> None:

        try:
            # SQL for master_table (stores server-side hashed master password)
            create_master_sql = """
                CREATE TABLE IF NOT EXISTS master_table (
                    user_id    UUID PRIMARY KEY,
                    username   VARCHAR(64) UNIQUE NOT NULL,
                    password   TEXT        NOT NULL
                );
            """

            # Execute creation statement
            self._db.execute_statment(create_master_sql)

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to ensure master_table exists", "master_table")


    """
        Create a new user entry in master_table.

        @param username (str): Normalized username string.
        @param server_master_pwd_hash_b64u (str): Base64url-encoded Argon2id hash of master password.

        @require isinstance(username, str) and 0 < len(username) <= 64
        @require isinstance(server_master_pwd_hash_b64u, str) and len(server_master_pwd_hash_b64u.strip()) > 0

        @return str: The generated user_id UUID string.

        @ensures A new user row is inserted into master_table with no plaintext passwords stored.
    """
    def create_user(self, username: str, server_master_pwd_hash_b64u: str) -> str:

        try:
            # Validate username
            if not isinstance(username, str) or not username.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_USERNAME, HTTPCodes.BAD_REQUEST, "Username must be a non-empty string", "username")

            if len(username) > 64:
                raise CipherSafeError(ApplicationCodes.INVALID_LENGTH, HTTPCodes.BAD_REQUEST, "Username exceeds maximum length (64)", "username")

            # Validate password hash
            if not isinstance(server_master_pwd_hash_b64u, str) or not server_master_pwd_hash_b64u.strip():
                raise CipherSafeError(ApplicationCodes.PASSWORD_HASH_ERROR, HTTPCodes.BAD_REQUEST, "Password hash must be a non-empty base64url string", "password")

            # Generate a new UUID for the user
            user_id = uuid.uuid4()

            # Insert into master_table
            insert_master_sql = """
                INSERT INTO master_table (user_id, username, password)
                VALUES (%s, %s, %s);
            """

            # Execute insertion into master_table
            self._db.execute_statment(
                insert_master_sql,
                (str(user_id), username.strip(), server_master_pwd_hash_b64u.strip()),
            )

            # Return the UUID string for upstream use
            return str(user_id)

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to create new master_table user record", "create_user")


    """
        Look up the user_id for a given username.

        @param username (str): Username to look up.

        @require isinstance(username, str) and len(username.strip()) > 0

        @return str|None: The UUID string if found, otherwise None.

        @ensures Returns the stored user_id associated with the username.
    """
    def get_user_id_by_username(self, username: str) -> typing.Optional[str]:

        try:
            # Validate username type
            if not isinstance(username, str) or not username.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_USERNAME, HTTPCodes.BAD_REQUEST, "Username must be a non-empty string", "username")

            # SELECT user_id from master_table
            select_sql = """
                SELECT user_id
                FROM master_table
                WHERE username = %s;
            """

            # Perform lookup
            row = self._db.get_row(select_sql, (username.strip(),))

            # If not found, return None
            if row is None:
                return None

            # Return user_id as string
            return str(row["user_id"])

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to fetch user_id by username", "get_user_id_by_username")


    """
        Look up the username for a given user_id.

        @param user_id (str): UUID string representing the user.

        @require user_id must be a valid UUID string

        @return str|None: The username if found, otherwise None.

        @ensures Returns the corresponding username in master_table for the given user_id.
    """
    def get_username_by_user_id(self, user_id: str) -> typing.Optional[str]:

        try:
            # Validate user_id
            try:
                parsed_uuid = uuid.UUID(str(user_id))
            except Exception:
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "user_id must be a valid UUID string", "user_id")

            # SELECT username from master_table
            select_sql = """
                SELECT username
                FROM master_table
                WHERE user_id = %s;
            """

            row = self._db.get_row(select_sql, (str(parsed_uuid),))

            if row is None:
                return None

            return row["username"]

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to fetch username by user_id", "get_username_by_user_id")


    """
        Retrieve the stored server-side Argon2id hashed password for a given user_id.

        @param user_id (str): UUID string representing the user.

        @require user_id must be a valid UUID string

        @return dict|None: {"password": hashed_password} if found, otherwise None.

        @ensures Only the hashed password is returned; plaintext is never stored.
    """
    def get_hashed_password(self, user_id: str) -> typing.Optional[dict]:

        try:
            # Validate user_id
            try:
                parsed_uuid = uuid.UUID(str(user_id))
            except Exception:
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "user_id must be a valid UUID string", "user_id")

            # SELECT password from master_table
            select_sql = """
                SELECT password
                FROM master_table
                WHERE user_id = %s;
            """

            row = self._db.get_row(select_sql, (str(parsed_uuid),))

            if row is None:
                return None

            return {"password": row["password"]}

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to fetch hashed password by user_id", "get_hashed_password")


    """
        Update the stored server-side master password hash for a given user_id.

        @param user_id (str): UUID string identifying the user.
        @param new_server_pwd_hash_b64u (str): New base64url-encoded Argon2id hash.

        @require user_id must be a valid UUID string
        @require isinstance(new_server_pwd_hash_b64u, str) and len(new_server_pwd_hash_b64u.strip()) > 0

        @return bool: True if exactly one row was updated; False otherwise.

        @ensures master_table.password is updated for the given user_id.
    """
    def update_master_password(self, user_id: str, new_server_pwd_hash_b64u: str) -> bool:

        try:
            # Validate user_id
            try:
                parsed_uuid = uuid.UUID(str(user_id))
            except Exception:
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "user_id must be a valid UUID string", "user_id")

            # Validate password hash
            if not isinstance(new_server_pwd_hash_b64u, str) or not new_server_pwd_hash_b64u.strip():
                raise CipherSafeError(ApplicationCodes.PASSWORD_HASH_ERROR, HTTPCodes.BAD_REQUEST, "New password hash must be a non-empty base64url string", "password")

            # SQL for updating the hashed password
            update_master_sql = """
                UPDATE master_table
                SET password = %s
                WHERE user_id = %s
            """

            # Execute update
            rc = self._db.execute_statment(
                update_master_sql,
                (new_server_pwd_hash_b64u.strip(), str(parsed_uuid)),
            )

            # Return True if exactly one row was affected
            return rc == 1

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to update master password hash", "update_master_password")
