#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: user_tables.py
    Author: Alex Biddle

    Description:
        Handles per-user encrypted vault tables. Each user receives a dedicated
        PostgreSQL table named vault_<uuidhex>, storing AES-GCM ciphertext for
        website, account username, email, and password fields. Supports secure
        CRUD operations with strict validation and safe dynamic table name
        derivation.
"""


import re
import typing
import uuid
import sys, os
from capstone.database.database_object import Database
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes



class UserTables:

    """
        Initialize a UserTables helper bound to a Database instance.

        @param database (Database): Shared Database helper used for executing per-user vault table SQL.

        @require isinstance(database, Database)

        @ensures The helper is prepared to lazily create vault tables for users.
    """
    def __init__(self, database: Database) -> None:

        try:
            # Validate Database instance
            if not isinstance(database, Database):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "UserTables requires a Database instance", "database")

            # Store reference
            self._database: Database = database

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize UserTables", "user_tables_init")


    """
        Derive a safe PostgreSQL table name from a user_id UUID.

        @param user_id (str): UUID string associated with the user.

        @require user_id must be a valid UUID string

        @return str: A safe table name of the form 'vault_<uuidhex>'.

        @ensures The derived table name matches a strict regex and prevents SQL injection.
    """
    def _get_table_name_for_user(self, user_id: str) -> str:

        try:
            # Parse and normalize the UUID
            parsed_uuid = uuid.UUID(str(user_id))

            # Use the hex form (32 lowercase hex characters, no dashes)
            suffix = parsed_uuid.hex

            # Build the table name
            table_name = f"vault_{suffix}"

            # Ensure the table name only uses safe characters
            if not re.match(r"^[a-zA-Z0-9_]+$", table_name):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "Derived vault table name contains invalid characters", "table_name")

            # Return safe table name
            return table_name

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to derive vault table name", "table_name")


    """
        Ensure that a per-user vault table exists for the given user_id.

        @param user_id (str): UUID string for the user.

        @require user_id must be a valid UUID string

        @return None: Creates the vault table if missing.

        @ensures A table named 'vault_<uuidhex>' exists with encrypted fields only.
    """
    def ensure_vault_table_exists(self, user_id: str) -> None:

        try:
            # Derive safe table name
            table_name = self._get_table_name_for_user(user_id)

            # Build CREATE TABLE IF NOT EXISTS statement
            create_sql = f"""
                CREATE TABLE IF NOT EXISTS {table_name} (
                    item_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    website          TEXT NOT NULL,
                    account_username TEXT NOT NULL,
                    account_email    TEXT,
                    account_password TEXT NOT NULL
                );
            """

            # Execute the creation statement
            self._database.execute_statment(create_sql)

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to ensure user vault table exists", "vault_table_create")


    """
        Add a new encrypted account entry to the user's dedicated vault table.

        @param user_id (str): UUID string for the user.
        @param website_ct (str): AES-GCM ciphertext for the website.
        @param account_username_ct (str): AES-GCM ciphertext for the account username.
        @param account_email_ct (str): AES-GCM ciphertext for the email (may be empty string).
        @param account_password_ct (str): AES-GCM ciphertext for the password.

        @require user_id is a valid UUID string
        @require website_ct, account_username_ct, account_password_ct are non-empty strings
        @require account_email_ct is a string

        @return bool: True if one row was successfully inserted.

        @ensures One encrypted entry is added to the user's vault table.
    """
    def add_account(self, user_id: str, website_ct: str, account_username_ct: str, account_email_ct: str, account_password_ct: str) -> bool:

        try:
            # Ensure vault table exists
            self.ensure_vault_table_exists(user_id)

            # Derive table name
            table_name = self._get_table_name_for_user(user_id)

            # Validate ciphertext fields
            for field_name, value in [
                ("website", website_ct),
                ("account_username", account_username_ct),
                ("account_password", account_password_ct),
            ]:
                if not isinstance(value, str) or not value.strip():
                    raise CipherSafeError(ApplicationCodes.INVALID_CIPHERTEXT, HTTPCodes.BAD_REQUEST, f"{field_name} ciphertext must be a non-empty string", field_name)

            # Email may be empty, but must be a string
            if not isinstance(account_email_ct, str):
                raise CipherSafeError(ApplicationCodes.INVALID_CIPHERTEXT, HTTPCodes.BAD_REQUEST, "account_email ciphertext must be a string", "account_email")

            # Build INSERT statement
            insert_sql = f"""
                INSERT INTO {table_name} (
                    website,
                    account_username,
                    account_email,
                    account_password
                )
                VALUES (%s, %s, %s, %s);
            """

            # Execute insert
            rc = self._database.execute_statment(
                insert_sql,
                (
                    website_ct.strip(),
                    account_username_ct.strip(),
                    account_email_ct.strip(),
                    account_password_ct.strip(),
                ),
            )

            # Return True if exactly one row was inserted
            return rc == 1

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to add account to vault","vault_add_account")


    """
        Fetch all encrypted account entries for a user.

        @param user_id (str): UUID string referencing the user.

        @require user_id must be a valid UUID string

        @return list[dict]: A list of encrypted account rows; empty list if none exist.

        @ensures Returns all encrypted entries stored in the user's vault table.
    """
    def fetch_accounts(self, user_id: str) -> typing.List[dict]:

        try:
            # Derive table name
            table_name = self._get_table_name_for_user(user_id)

            # Ensure table exists
            self.ensure_vault_table_exists(user_id)

            # Build SELECT statement
            select_sql = f"""
                SELECT
                    item_id,
                    website,
                    account_username,
                    account_email,
                    account_password
                FROM {table_name};
            """

            # Fetch all encrypted rows
            rows = self._database.get_all_matching_rows(select_sql)

            return rows

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to fetch vault accounts", "vault_fetch_accounts")


    """
        Fetch a single encrypted account_password for the given website and username.

        @param user_id (str): UUID string referencing the user.
        @param website_ct (str): AES-GCM ciphertext for the website.
        @param account_username_ct (str): AES-GCM ciphertext for the account username.

        @require user_id must be a valid UUID string
        @require website_ct and account_username_ct are non-empty strings

        @return str|None: The encrypted account_password or None if not found.

        @ensures Returns only ciphertext; no plaintext secrets are exposed.
    """
    def fetch_account_password(self, user_id: str, website_ct: str, account_username_ct: str) -> typing.Optional[str]:

        try:
            # Derive table name
            table_name = self._get_table_name_for_user(user_id)

            # Ensure table exists
            self.ensure_vault_table_exists(user_id)

            # Build SELECT statement
            select_sql = f"""
                SELECT account_password
                FROM {table_name}
                WHERE website = %s
                  AND account_username = %s;
            """

            row = self._database.get_row(select_sql, (website_ct, account_username_ct))

            if row is None:
                return None

            return row["account_password"]

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to fetch account password from vault", "vault_fetch_account_password")


    """
        Update an existing encrypted account entry in the user's vault table.

        @param user_id (str): UUID string for the user.
        @param old_website_ct (str): Existing website ciphertext key.
        @param old_account_username_ct (str): Existing account username ciphertext key.
        @param new_website_ct (str): New website ciphertext.
        @param new_account_username_ct (str): New username ciphertext.
        @param new_account_email_ct (str): New email ciphertext.
        @param new_account_password_ct (str): New password ciphertext.

        @require user_id must be a valid UUID string
        @require all ciphertext parameters are non-empty strings

        @return bool: True if the update affected exactly one row.

        @ensures The matching encrypted entry is updated with new ciphertext values.
    """
    def update_account(self, user_id: str, old_website_ct: str, old_account_username_ct: str, new_website_ct: str, new_account_username_ct: str, new_account_email_ct: str, new_account_password_ct: str) -> bool:

        try:
            # Derive table name
            table_name = self._get_table_name_for_user(user_id)

            # Ensure table exists
            self.ensure_vault_table_exists(user_id)

            # Build UPDATE statement
            update_sql = f"""
                UPDATE {table_name}
                SET website = %s,
                    account_username = %s,
                    account_email = %s,
                    account_password = %s
                WHERE website = %s
                  AND account_username = %s;
            """

            rc = self._database.execute_statment(
                update_sql,
                (
                    new_website_ct,
                    new_account_username_ct,
                    new_account_email_ct,
                    new_account_password_ct,
                    old_website_ct,
                    old_account_username_ct,
                ),
            )

            return rc == 1

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to update account in vault", "vault_update_account")


    """
        Delete an encrypted account entry from the user's vault table.

        @param user_id (str): UUID string referencing the user.
        @param website_ct (str): AES-GCM ciphertext for the website.
        @param account_username_ct (str): AES-GCM ciphertext for the account username.

        @require user_id must be a valid UUID string
        @require website_ct and account_username_ct are non-empty strings

        @return bool: True if exactly one row was deleted.

        @ensures Removes the corresponding encrypted row from the vault table.
    """
    def delete_account(self, user_id: str, website_ct: str, account_username_ct: str) -> bool:

        try:
            # Derive table name
            table_name = self._get_table_name_for_user(user_id)

            # Ensure table exists
            self.ensure_vault_table_exists(user_id)

            # Build DELETE statement
            delete_sql = f"""
                DELETE FROM {table_name}
                WHERE website = %s
                  AND account_username = %s;
            """

            rc = self._database.execute_statment(delete_sql, (website_ct, account_username_ct))

            return rc == 1

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to delete account from vault", "vault_delete_account")
