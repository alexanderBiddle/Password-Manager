#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: vault_salt_table.py
    Author: Alex Biddle

    Description:
        Manages the vault_salt_storage table, which stores a persistent per-user
        vault_salt (base64url-encoded). This salt is used by the client to derive
        the long-term vault encryption key.
"""


import typing
import uuid
from capstone.database.database_object import Database
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes



class VaultSaltTable:

    """
        Initialize a VaultSaltTable helper bound to a Database instance.

        @param database (Database): Shared Database helper for PostgreSQL operations.
        @require isinstance(database, Database)
        @ensures vault_salt_storage table exists.
    """
    def __init__(self, database: Database) -> None:
        try:
            if not isinstance(database, Database):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "VaultSaltTable requires a Database instance", "database")

            self._database: Database = database
            self._ensure_table_exists()

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize VaultSaltTable", "vault_salt_table_init")


    """
        Ensure that the vault_salt_storage table exists.

        @require Valid database connection
        @ensures vault_salt_storage contains (user_id, vault_salt), with user_id referencing master_table(user_id).
    """
    def _ensure_table_exists(self) -> None:
        try:
            create_sql = """
                CREATE TABLE IF NOT EXISTS vault_salt_storage (
                    user_id    UUID PRIMARY KEY REFERENCES master_table(user_id) ON DELETE CASCADE,
                    vault_salt TEXT NOT NULL
                );
            """

            self._database.execute_statment(create_sql)

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(
                ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to ensure vault_salt_storage table exists", "vault_salt_storage")


    """
        Insert a new vault_salt row for a user.

        @param user_id (str): UUID string for the user.
        @param vault_salt_b64u (str): Base64url-encoded vault_salt.
        @require user_id is UUID-formatted
        @require vault_salt_b64u is a non-empty base64url string
        @return bool: True if one row inserted.
        @ensures vault_salt is stored and linked to user_id.
    """
    def create_vault_salt(self, user_id: str, vault_salt_b64u: str) -> bool:
        try:
            # Validate UUID
            try:
                parsed_uuid = uuid.UUID(str(user_id))
            except Exception:
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "user_id must be a valid UUID string", "user_id")

            # Validate salt
            if not isinstance(vault_salt_b64u, str) or not vault_salt_b64u.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "vault_salt must be a non-empty base64url string", "vault_salt")

            insert_sql = """
                INSERT INTO vault_salt_storage (user_id, vault_salt)
                VALUES (%s, %s);
            """

            rc = self._database.execute_statment(insert_sql, (str(parsed_uuid), vault_salt_b64u.strip()))

            return rc == 1

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to insert vault_salt record", "create_vault_salt")


    """
        Retrieve the vault_salt for a given user_id.

        @param user_id (str): UUID string.
        @require user_id is valid UUID
        @return str|None: Base64url vault_salt or None if no row exists.
        @ensures Only encoded salt is returned; no secrets exposed.
    """
    def get_vault_salt(self, user_id: str) -> typing.Optional[str]:
        try:
            try:
                parsed_uuid = uuid.UUID(str(user_id))
            except Exception:
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "user_id must be a valid UUID string", "user_id")

            select_sql = """
                SELECT vault_salt
                FROM vault_salt_storage
                WHERE user_id = %s;
            """

            row = self._database.get_row(select_sql, (str(parsed_uuid),))

            if row is None:
                return None

            return row["vault_salt"]

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to retrieve vault_salt", "get_vault_salt")
