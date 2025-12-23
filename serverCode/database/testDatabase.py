#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: testDatabaseTables.py
    Author: Alex Biddle

    Description:
        Integration and unit tests for the CipherSafe database layer. Verifies that
        Database, MasterTable, SaltTable, and UserTables work together to create
        users, store and update salts, and manage encrypted vault entries. Includes
        both happy-path lifecycle tests and extensive validation/error tests.
"""


import json
import uuid
import tempfile
import unittest
import sys, os
sys.path.insert(0, "/cslab/cgi-bin")
sys.path.insert(0, "/cslab/cgi-bin/capstone")
from capstone.database.database_object import Database
from capstone.database.master_table import MasterTable
from capstone.database.salt_table import SaltTable
from capstone.database.user_tables import UserTables
from capstone.database.vault_salt_table import VaultSaltTable
from capstone.handlers.error_handler import CipherSafeError


CREDENTIALS_PATH = os.path.join(os.path.dirname(__file__), "database_credentials.htaccess")


####################################################################################################
#                                         Database Tests
####################################################################################################


"""
    Exercises low-level Database helper behavior, including credential loading and
    SQL/parameter validation, without depending on the rest of the tables.
"""
class TestDatabaseCore(unittest.TestCase):


    """
        Verify that _load_database_credentials rejects a non-string credentials
        path and raises a CipherSafeError before attempting any file I/O.

        @ensures CipherSafeError is raised when _credentials_path is not a string.
    """
    def test_load_credentials_invalid_path_type(self):

        db = Database.__new__(Database)
        db._credentials_path = 123  # type: ignore[attr-defined]

        with self.assertRaises(CipherSafeError):
            db._load_database_credentials()


    """
        Verify that _load_database_credentials rejects an empty credentials path
        and raises a CipherSafeError before attempting any file I/O.

        @ensures CipherSafeError is raised when _credentials_path is empty/whitespace.
    """
    def test_load_credentials_empty_path(self):

        db = Database.__new__(Database)
        db._credentials_path = "   "

        with self.assertRaises(CipherSafeError):
            db._load_database_credentials()


    """
        Verify that _load_database_credentials rejects a path that does not exist
        and raises a CipherSafeError instead of continuing.

        @ensures CipherSafeError is raised when the credentials file is missing.
    """
    def test_load_credentials_missing_file(self):

        db = Database.__new__(Database)
        db._credentials_path = "/tmp/this_file_should_not_exist_12345.json"

        with self.assertRaises(CipherSafeError):
            db._load_database_credentials()


    """
        Verify that _load_database_credentials rejects malformed JSON and raises
        a CipherSafeError.

        @ensures CipherSafeError is raised when the credentials file contains invalid JSON.
    """
    def test_load_credentials_invalid_json(self):

        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("not-json")

            db = Database.__new__(Database)
            db._credentials_path = path

            with self.assertRaises(CipherSafeError):
                db._load_database_credentials()

        finally:
            try:
                os.remove(path)
            except OSError:
                pass


    """
        Verify that _load_database_credentials rejects JSON that is missing
        required fields and raises a CipherSafeError.

        @ensures CipherSafeError is raised when required credential keys are absent.
    """
    def test_load_credentials_missing_fields(self):

        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            bad_creds = {
                "database": "test_db",
                "user": "tester",
                # "password" missing
                "host": "localhost"
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(bad_creds, f)

            db = Database.__new__(Database)
            db._credentials_path = path

            with self.assertRaises(CipherSafeError):
                db._load_database_credentials()

        finally:
            try:
                os.remove(path)
            except OSError:
                pass


    """
        Verify that _load_database_credentials rejects JSON that is not an object
        and raises a CipherSafeError.

        @ensures CipherSafeError is raised when credentials JSON is not a dictionary.
    """
    def test_load_credentials_json_not_object(self):

        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(["not", "an", "object"], f)

            db = Database.__new__(Database)
            db._credentials_path = path

            with self.assertRaises(CipherSafeError):
                db._load_database_credentials()

        finally:
            try:
                os.remove(path)
            except OSError:
                pass


    """
        Verify that _load_database_credentials rejects credentials where required
        fields have invalid types and raises a CipherSafeError.

        @ensures CipherSafeError is raised when database, user, password, or host are not strings.
    """
    def test_load_credentials_invalid_field_types(self):

        invalid_cases = [
            {"database": 123, "user": "tester", "password": "pw", "host": "localhost"},
            {"database": "test_db", "user": 999, "password": "pw", "host": "localhost"},
            {"database": "test_db", "user": "tester", "password": ["not", "string"], "host": "localhost"},
            {"database": "test_db", "user": "tester", "password": "pw", "host": 456},
        ]

        for bad_creds in invalid_cases:

            fd, path = tempfile.mkstemp()
            os.close(fd)
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(bad_creds, f)

                db = Database.__new__(Database)
                db._credentials_path = path

                with self.assertRaises(CipherSafeError):
                    db._load_database_credentials()

            finally:
                try:
                    os.remove(path)
                except OSError:
                    pass


    """
        Verify that execute_statment enforces SQL and params validation and raises
        CipherSafeError for invalid inputs before opening any database connection.

        @ensures SQL must be a non-empty string, and params must be a tuple.
    """
    def test_execute_statment_validation_errors(self):

        db = Database.__new__(Database)

        with self.assertRaises(CipherSafeError):
            db.execute_statment("", ())

        with self.assertRaises(CipherSafeError):
            db.execute_statment(123, ())  # type: ignore[arg-type]

        with self.assertRaises(CipherSafeError):
            db.execute_statment("SELECT 1", ["not", "a", "tuple"])  # type: ignore[arg-type]


    """
        Verify that get_row enforces SQL and params validation for invalid inputs.

        @ensures SQL must be non-empty and params must be a tuple.
    """
    def test_get_row_validation_errors(self):

        db = Database.__new__(Database)

        with self.assertRaises(CipherSafeError):
            db.get_row("", ())

        with self.assertRaises(CipherSafeError):
            db.get_row(123, ())  # type: ignore[arg-type]

        with self.assertRaises(CipherSafeError):
            db.get_row("SELECT 1", ["not", "a", "tuple"])  # type: ignore[arg-type]


    """
        Verify that get_all_matching_rows enforces SQL and params validation for
        invalid inputs.

        @ensures SQL must be non-empty and params must be a tuple.
    """
    def test_get_all_matching_rows_validation_errors(self):

        db = Database.__new__(Database)

        with self.assertRaises(CipherSafeError):
            db.get_all_matching_rows("", ())

        with self.assertRaises(CipherSafeError):
            db.get_all_matching_rows(123, ())  # type: ignore[arg-type]

        with self.assertRaises(CipherSafeError):
            db.get_all_matching_rows("SELECT 1", ["not", "a", "tuple"])  # type: ignore[arg-type]


    """
        Basic smoke test that ensures a real Database instance can execute a
        trivial SELECT query and return a single row, assuming valid credentials.

        @ensures A row is returned with a constant value from SELECT 1.
    """
    def test_get_row_smoke_select_one(self):

        db = Database(credentials_path=CREDENTIALS_PATH)
        row = db.get_row("SELECT 1 AS value")
        self.assertIsNotNone(row)
        self.assertIn("value", row)
        self.assertEqual(row["value"], 1)


####################################################################################################
#                                   MasterTable + SaltTable Tests
####################################################################################################


"""
    Focused unit tests for MasterTable behavior, including validation errors and
    edge cases like unknown usernames and user_ids.
"""
class TestMasterTableBehavior(unittest.TestCase):


    """
        Create a shared Database and MasterTable instance for these tests.

        @ensures A working MasterTable bound to a live Database instance.
    """
    @classmethod
    def setUpClass(cls):

        cls._db = Database(credentials_path=CREDENTIALS_PATH)
        cls._master = MasterTable(cls._db)


    """
        Ensure that MasterTable rejects a non-Database instance in its constructor
        and raises a CipherSafeError.

        @ensures CipherSafeError is raised when db is not a Database instance.
    """
    def test_master_table_requires_database_instance(self):

        with self.assertRaises(CipherSafeError):
            MasterTable(db="not-a-db")  # type: ignore[arg-type]


    """
        Verify that create_user enforces username and password hash validation and
        raises a CipherSafeError for invalid inputs.

        @ensures Invalid usernames and password hashes are rejected.
    """
    def test_create_user_validation_errors(self):

        with self.assertRaises(CipherSafeError):
            self._master.create_user("", "some_hash")

        long_username = "x" * 65
        with self.assertRaises(CipherSafeError):
            self._master.create_user(long_username, "some_hash")

        with self.assertRaises(CipherSafeError):
            self._master.create_user("valid_username", "")


    """
        Verify that create_user enforces the UNIQUE constraint on username and
        raises a CipherSafeError when attempting to insert a duplicate username.

        @ensures Duplicate usernames cannot be created in master_table.
    """
    def test_create_user_duplicate_username_raises(self):

        username = f"dup_user_{uuid.uuid4().hex[:8]}"
        pwd_hash = f"hash_{uuid.uuid4().hex}"

        user_id = self._master.create_user(username, pwd_hash)
        self.assertIsInstance(user_id, str)

        with self.assertRaises(CipherSafeError):
            self._master.create_user(username, pwd_hash)


    """
        Verify that get_user_id_by_username returns None for a username that does
        not exist in master_table.

        @ensures Unknown usernames map to None.
    """
    def test_get_user_id_by_username_unknown_returns_none(self):

        unknown = f"unknown_{uuid.uuid4().hex[:8]}"
        result = self._master.get_user_id_by_username(unknown)
        self.assertIsNone(result)


    """
        Verify that get_user_id_by_username enforces non-empty string validation.

        @ensures Empty username raises CipherSafeError.
    """
    def test_get_user_id_by_username_invalid_empty(self):

        with self.assertRaises(CipherSafeError):
            self._master.get_user_id_by_username("")


    """
        Verify that get_username_by_user_id returns None for a UUID that is not
        present in the master_table.

        @ensures Unknown user_id returns None.
    """
    def test_get_username_by_user_id_unknown_returns_none(self):

        random_id = str(uuid.uuid4())
        result = self._master.get_username_by_user_id(random_id)
        self.assertIsNone(result)


    """
        Verify that get_username_by_user_id enforces UUID validation and raises
        a CipherSafeError for malformed user_id values.

        @ensures Invalid UUID strings are rejected.
    """
    def test_get_username_by_user_id_invalid_uuid_raises(self):

        with self.assertRaises(CipherSafeError):
            self._master.get_username_by_user_id("not-a-uuid")


    """
        Verify that get_hashed_password returns None when there is no matching
        user_id.

        @ensures Unknown user_id results in None instead of an error.
    """
    def test_get_hashed_password_unknown_returns_none(self):

        random_id = str(uuid.uuid4())
        result = self._master.get_hashed_password(random_id)
        self.assertIsNone(result)


    """
        Verify that get_hashed_password enforces UUID validation and raises a
        CipherSafeError for malformed user_id values.

        @ensures Invalid UUID strings are rejected.
    """
    def test_get_hashed_password_invalid_uuid_raises(self):

        with self.assertRaises(CipherSafeError):
            self._master.get_hashed_password("not-a-uuid")


    """
        Verify that update_master_password returns False when attempting to update
        a user_id that does not exist in master_table.

        @ensures Unknown user_id updates are treated as no-op (False).
    """
    def test_update_master_password_unknown_user_returns_false(self):

        random_id = str(uuid.uuid4())
        result = self._master.update_master_password(random_id, "new_hash_value")
        self.assertFalse(result)


    """
        Verify that update_master_password enforces UUID and password hash
        validation for invalid inputs.

        @ensures Invalid UUID or password hash raises CipherSafeError.
    """
    def test_update_master_password_validation_errors(self):

        with self.assertRaises(CipherSafeError):
            self._master.update_master_password("not-a-uuid", "hash_value")

        with self.assertRaises(CipherSafeError):
            self._master.update_master_password(str(uuid.uuid4()), "")


"""
    Focused unit tests for SaltTable behavior, covering creation, lookup, updates,
    validation, and edge cases for unknown users.
"""
class TestSaltTableBehavior(unittest.TestCase):


    """
        Create shared Database, MasterTable, and SaltTable instances and a single
        test user for salt operations.

        @ensures A known user exists in master_table for salt tests.
    """
    @classmethod
    def setUpClass(cls):

        cls._db = Database(credentials_path=CREDENTIALS_PATH)
        cls._master = MasterTable(cls._db)
        cls._salt = SaltTable(cls._db)

        cls.username = f"salt_user_{uuid.uuid4().hex[:8]}"
        cls.pwd_hash = f"hash_{uuid.uuid4().hex}"
        cls.user_id = cls._master.create_user(cls.username, cls.pwd_hash)


    """
        Ensure that SaltTable rejects a non-Database instance in its constructor
        and raises a CipherSafeError.

        @ensures CipherSafeError is raised when db is not a Database instance.
    """
    def test_salt_table_requires_database_instance(self):

        with self.assertRaises(CipherSafeError):
            SaltTable("not-a-db")  # type: ignore[arg-type]


    """
        Verify that create_salt_record enforces UUID, username, and salt string
        validation and raises CipherSafeError for invalid inputs.

        @ensures Invalid parameters are rejected before any SQL is executed.
    """
    def test_create_salt_record_validation_errors(self):

        with self.assertRaises(CipherSafeError):
            self._salt.create_salt_record("not-a-uuid", self.username, "c_salt", "s_salt")

        with self.assertRaises(CipherSafeError):
            self._salt.create_salt_record(self.user_id, "", "c_salt", "s_salt")

        with self.assertRaises(CipherSafeError):
            self._salt.create_salt_record(self.user_id, self.username, "", "s_salt")

        with self.assertRaises(CipherSafeError):
            self._salt.create_salt_record(self.user_id, self.username, "c_salt", "")


    """
        Verify that create_salt_record raises a CipherSafeError when attempting to
        insert a duplicate salt record for the same user/username.

        @ensures Duplicate salt records cannot be created.
    """
    def test_create_salt_record_duplicate_raises(self):

        ok = self._salt.create_salt_record(self.user_id, self.username, "c_salt_1", "s_salt_1")
        self.assertTrue(ok)

        with self.assertRaises(CipherSafeError):
            self._salt.create_salt_record(self.user_id, self.username, "c_salt_1", "s_salt_1")


    """
        Verify that get_client_salt returns None for an unknown username.

        @ensures Unknown usernames return None for client_salt lookup.
    """
    def test_get_client_salt_unknown_returns_none(self):

        result = self._salt.get_client_salt("unknown_" + self.username)
        self.assertIsNone(result)


    """
        Verify that get_client_salt enforces non-empty username validation.

        @ensures Empty username raises CipherSafeError.
    """
    def test_get_client_salt_invalid_username_raises(self):

        with self.assertRaises(CipherSafeError):
            self._salt.get_client_salt("")


    """
        Verify that get_server_salt_and_user_id returns None for an unknown
        username.

        @ensures Unknown usernames return None for server_salt lookup.
    """
    def test_get_server_salt_and_user_id_unknown_returns_none(self):

        result = self._salt.get_server_salt_and_user_id("unknown_" + self.username)
        self.assertIsNone(result)


    """
        Verify that get_server_salt_and_user_id enforces non-empty username
        validation.

        @ensures Empty username raises CipherSafeError.
    """
    def test_get_server_salt_and_user_id_invalid_username_raises(self):

        with self.assertRaises(CipherSafeError):
            self._salt.get_server_salt_and_user_id("")


    """
        Verify that get_salts_by_user_id returns None for an unknown user_id.

        @ensures Unknown user_id results in None instead of an error.
    """
    def test_get_salts_by_user_id_unknown_returns_none(self):

        random_id = str(uuid.uuid4())
        result = self._salt.get_salts_by_user_id(random_id)
        self.assertIsNone(result)


    """
        Verify that get_salts_by_user_id enforces UUID validation and raises a
        CipherSafeError for malformed user_id values.

        @ensures Invalid UUID strings are rejected.
    """
    def test_get_salts_by_user_id_invalid_uuid_raises(self):

        with self.assertRaises(CipherSafeError):
            self._salt.get_salts_by_user_id("not-a-uuid")


    """
        Verify that update_salts returns False when there is no existing salt row
        for the given user_id.

        @ensures Unknown user_id updates are treated as no-op (False).
    """
    def test_update_salts_unknown_user_returns_false(self):

        random_id = str(uuid.uuid4())
        result = self._salt.update_salts(random_id, "c_salt_new", "s_salt_new")
        self.assertFalse(result)


    """
        Verify that update_salts enforces UUID and salt validation for invalid
        inputs.

        @ensures Invalid UUID or salt strings raise CipherSafeError.
    """
    def test_update_salts_validation_errors(self):

        with self.assertRaises(CipherSafeError):
            self._salt.update_salts("not-a-uuid", "c_salt_new", "s_salt_new")

        with self.assertRaises(CipherSafeError):
            self._salt.update_salts(self.user_id, "", "s_salt_new")

        with self.assertRaises(CipherSafeError):
            self._salt.update_salts(self.user_id, "c_salt_new", "")


####################################################################################################
#                                       UserTables Tests
####################################################################################################


"""
    Focused unit tests for UserTables behavior, including table-name derivation,
    validation, and CRUD edge cases.
"""
class TestUserTablesBehavior(unittest.TestCase):


    """
        Create shared Database, MasterTable, SaltTable, and UserTables instances
        plus a dedicated test user for vault operations.

        @ensures A per-user vault table can be created and manipulated for tests.
    """
    @classmethod
    def setUpClass(cls):

        cls._db = Database(credentials_path=CREDENTIALS_PATH)
        cls._master = MasterTable(cls._db)
        cls._salt = SaltTable(cls._db)
        cls._users = UserTables(cls._db)

        cls.username = f"vault_user_{uuid.uuid4().hex[:8]}"
        cls.pwd_hash = f"hash_{uuid.uuid4().hex}"
        cls.user_id = cls._master.create_user(cls.username, cls.pwd_hash)

        cls._salt.create_salt_record(cls.user_id, cls.username, "vault_client_salt", "vault_server_salt")


    """
        Ensure that UserTables rejects a non-Database instance in its constructor
        and raises a CipherSafeError.

        @ensures CipherSafeError is raised when db is not a Database instance.
    """
    def test_user_tables_requires_database_instance(self):

        with self.assertRaises(CipherSafeError):
            UserTables("not-a-db")  # type: ignore[arg-type]


    """
        Verify that _get_table_name_for_user enforces UUID validation and raises
        a CipherSafeError when given a malformed user_id string.

        @ensures Invalid UUID strings are rejected.
    """
    def test_get_table_name_invalid_uuid_raises(self):

        users = self._users

        with self.assertRaises(CipherSafeError):
            users._get_table_name_for_user("not-a-uuid")  # type: ignore[arg-type]


    """
        Verify that ensure_vault_table_exists is idempotent and does not raise
        when called multiple times for the same user_id.

        @ensures Multiple calls to ensure_vault_table_exists succeed silently.
    """
    def test_ensure_vault_table_exists_idempotent(self):

        self._users.ensure_vault_table_exists(self.user_id)
        self._users.ensure_vault_table_exists(self.user_id)


    """
        Verify that fetch_accounts returns an empty list when the user has no
        stored vault entries.

        @ensures Users with no accounts get an empty list, not None.
    """
    def test_fetch_accounts_empty_for_new_user(self):

        accounts = self._users.fetch_accounts(self.user_id)
        self.assertIsInstance(accounts, list)
        self.assertEqual(len(accounts), 0)


    """
        Verify that add_account enforces required ciphertext validation and raises
        CipherSafeError for invalid values.

        @ensures website, account_username, and account_password must be non-empty strings;
                 account_email must be a string.
    """
    def test_add_account_validation_errors(self):

        with self.assertRaises(CipherSafeError):
            self._users.add_account(self.user_id, "", "user_ct", "email_ct", "pwd_ct")

        with self.assertRaises(CipherSafeError):
            self._users.add_account(self.user_id, "site_ct", "", "email_ct", "pwd_ct")

        with self.assertRaises(CipherSafeError):
            self._users.add_account(self.user_id, "site_ct", "user_ct", "email_ct", "")

        with self.assertRaises(CipherSafeError):
            self._users.add_account(self.user_id, "site_ct", "user_ct", 123, "pwd_ct")  # type: ignore[arg-type]


    """
        Verify that fetch_account_password returns None when no entry matches the
        supplied website/username ciphertext pair.

        @ensures Unknown account combinations yield None.
    """
    def test_fetch_account_password_unknown_returns_none(self):

        result = self._users.fetch_account_password(
            self.user_id,
            "nonexistent_site_ct",
            "nonexistent_user_ct",
        )
        self.assertIsNone(result)


    """
        Verify that update_account returns False when there is no matching entry
        for the provided old website/username ciphertext pair.

        @ensures Unknown entries are treated as no-op (False) on update.
    """
    def test_update_account_unknown_returns_false(self):

        result = self._users.update_account(
            self.user_id,
            old_website_ct="old_site_ct",
            old_account_username_ct="old_user_ct",
            new_website_ct="new_site_ct",
            new_account_username_ct="new_user_ct",
            new_account_email_ct="new_email_ct",
            new_account_password_ct="new_pwd_ct",
        )
        self.assertFalse(result)


    """
        Verify that delete_account returns False when there is no matching entry
        for the provided website/username ciphertext pair.

        @ensures Unknown entries are treated as no-op (False) on delete.
    """
    def test_delete_account_unknown_returns_false(self):

        result = self._users.delete_account(
            self.user_id,
            website_ct="no_site_ct",
            account_username_ct="no_user_ct",
        )
        self.assertFalse(result)


####################################################################################################
#                                       Integration Tests
####################################################################################################


"""
    Integration tests that exercise a complete user lifecycle across master_table,
    salt_storage, and per-user vault tables.
"""
class TestDatabaseIntegration(unittest.TestCase):


    """
        Set up shared Database, MasterTable, SaltTable, and UserTables instances
        for the integration tests. Creates a unique test username and related
        ciphertext values used throughout the test suite.

        @ensures A working Database connection and helper instances are available.
    """
    @classmethod
    def setUpClass(cls):

        cls._db = Database(credentials_path=CREDENTIALS_PATH)
        cls._master_table = MasterTable(cls._db)
        cls._salt_table = SaltTable(cls._db)
        cls._user_tables = UserTables(cls._db)

        cls.test_username = f"test_user_{uuid.uuid4().hex[:8]}"

        cls.initial_hash = f"test_hash_{uuid.uuid4().hex}"
        cls.updated_hash = f"updated_hash_{uuid.uuid4().hex}"
        cls.client_salt_1 = f"client_salt_{uuid.uuid4().hex}"
        cls.server_salt_1 = f"server_salt_{uuid.uuid4().hex}"
        cls.client_salt_2 = f"client_salt_{uuid.uuid4().hex}"
        cls.server_salt_2 = f"server_salt_{uuid.uuid4().hex}"

        cls.website_ct_1 = "cipher_website_example.com"
        cls.account_username_ct_1 = "cipher_alex@example.com"
        cls.account_email_ct_1 = "cipher_contact@example.com"
        cls.account_password_ct_1 = "cipher_password_1"

        cls.website_ct_2 = "cipher_newsite.com"
        cls.account_username_ct_2 = "cipher_newuser@example.com"
        cls.account_email_ct_2 = "cipher_new_contact@example.com"
        cls.account_password_ct_2 = "cipher_password_2"

        cls.test_user_id = None


    """
        Clean up test artifacts from the database. Removes the test user from
        master_table, cascades salts via foreign key, and drops the per-user
        vault table that was created for the test user.

        @ensures No permanent test data remains in the production database.
    """
    @classmethod
    def tearDownClass(cls):

        try:
            if cls.test_user_id is None:
                return

            suffix = uuid.UUID(str(cls.test_user_id)).hex
            vault_table_name = f"vault_{suffix}"

            drop_sql = f"DROP TABLE IF EXISTS {vault_table_name}"
            cls._db.execute_statment(drop_sql)

            delete_master_sql = """
                DELETE FROM master_table
                WHERE user_id = %s
            """
            cls._db.execute_statment(delete_master_sql, (str(cls.test_user_id),))

        except CipherSafeError:
            raise


    """
        Run a complete end-to-end lifecycle:

        1. Create a master_table user and verify user_id is returned.

        2. Look up user_id by username and username by user_id.

        3. Store initial salts in salt_storage and retrieve them by username and by user_id.

        4. Update the stored salts and verify that the new values are returned.

        5. Ensure the per-user vault table exists.

        6. Insert an encrypted vault account, fetch all accounts, and fetch a single account_password.

        7. Update the encrypted account values and verify that the updated ciphertext is visible.

        8. Delete the account and confirm it is no longer returned.

        @ensures All operations complete without unexpected errors and return values are consistent.
    """
    def test_full_user_and_vault_lifecycle(self):

        user_id = self._master_table.create_user(self.test_username, self.initial_hash)
        self.assertIsInstance(user_id, str)
        self.assertTrue(len(user_id.strip()) > 0)
        self.__class__.test_user_id = user_id

        looked_up_user_id = self._master_table.get_user_id_by_username(self.test_username)
        self.assertEqual(user_id, looked_up_user_id)

        looked_up_username = self._master_table.get_username_by_user_id(user_id)
        self.assertEqual(self.test_username, looked_up_username)

        pwd_record = self._master_table.get_hashed_password(user_id)
        self.assertEqual(pwd_record["password"], self.initial_hash)

        updated_ok = self._master_table.update_master_password(user_id, self.updated_hash)
        self.assertTrue(updated_ok)

        updated_pwd_record = self._master_table.get_hashed_password(user_id)
        self.assertEqual(updated_pwd_record["password"], self.updated_hash)

        created_salts = self._salt_table.create_salt_record(
            user_id=user_id,
            username=self.test_username,
            client_salt_b64u=self.client_salt_1,
            server_salt_b64u=self.server_salt_1,
        )
        self.assertTrue(created_salts)

        client_salt_row = self._salt_table.get_client_salt(self.test_username)
        self.assertIsNotNone(client_salt_row)
        self.assertEqual(client_salt_row["user_id"], user_id)
        self.assertEqual(client_salt_row["client_salt"], self.client_salt_1)

        server_salt_row = self._salt_table.get_server_salt_and_user_id(self.test_username)
        self.assertIsNotNone(server_salt_row)
        self.assertEqual(server_salt_row["user_id"], user_id)
        self.assertEqual(server_salt_row["server_salt"], self.server_salt_1)

        salts_by_id = self._salt_table.get_salts_by_user_id(user_id)
        self.assertIsNotNone(salts_by_id)
        self.assertEqual(salts_by_id["username"], self.test_username)
        self.assertEqual(salts_by_id["client_salt"], self.client_salt_1)
        self.assertEqual(salts_by_id["server_salt"], self.server_salt_1)

        update_ok = self._salt_table.update_salts(
            user_id=user_id,
            client_salt_b64u=self.client_salt_2,
            server_salt_b64u=self.server_salt_2,
        )
        self.assertTrue(update_ok)

        updated_salts_by_id = self._salt_table.get_salts_by_user_id(user_id)
        self.assertIsNotNone(updated_salts_by_id)
        self.assertEqual(updated_salts_by_id["client_salt"], self.client_salt_2)
        self.assertEqual(updated_salts_by_id["server_salt"], self.server_salt_2)

        self._user_tables.ensure_vault_table_exists(user_id)

        add_ok = self._user_tables.add_account(
            user_id=user_id,
            website_ct=self.website_ct_1,
            account_username_ct=self.account_username_ct_1,
            account_email_ct=self.account_email_ct_1,
            account_password_ct=self.account_password_ct_1,
        )
        self.assertTrue(add_ok)

        accounts = self._user_tables.fetch_accounts(user_id)
        self.assertIsInstance(accounts, list)
        self.assertGreaterEqual(len(accounts), 1)

        matching = [
            row for row in accounts
            if row["website"] == self.website_ct_1
            and row["account_username"] == self.account_username_ct_1
        ]
        self.assertEqual(len(matching), 1)
        row = matching[0]
        self.assertEqual(row["account_email"], self.account_email_ct_1)
        self.assertEqual(row["account_password"], self.account_password_ct_1)

        fetched_password = self._user_tables.fetch_account_password(
            user_id=user_id,
            website_ct=self.website_ct_1,
            account_username_ct=self.account_username_ct_1,
        )
        self.assertEqual(fetched_password, self.account_password_ct_1)

        update_account_ok = self._user_tables.update_account(
            user_id=user_id,
            old_website_ct=self.website_ct_1,
            old_account_username_ct=self.account_username_ct_1,
            new_website_ct=self.website_ct_2,
            new_account_username_ct=self.account_username_ct_2,
            new_account_email_ct=self.account_email_ct_2,
            new_account_password_ct=self.account_password_ct_2,
        )
        self.assertTrue(update_account_ok)

        old_password = self._user_tables.fetch_account_password(
            user_id=user_id,
            website_ct=self.website_ct_1,
            account_username_ct=self.account_username_ct_1,
        )
        self.assertIsNone(old_password)

        new_password = self._user_tables.fetch_account_password(
            user_id=user_id,
            website_ct=self.website_ct_2,
            account_username_ct=self.account_username_ct_2,
        )
        self.assertEqual(new_password, self.account_password_ct_2)

        delete_ok = self._user_tables.delete_account(
            user_id=user_id,
            website_ct=self.website_ct_2,
            account_username_ct=self.account_username_ct_2,
        )
        self.assertTrue(delete_ok)

        deleted_password = self._user_tables.fetch_account_password(
            user_id=user_id,
            website_ct=self.website_ct_2,
            account_username_ct=self.account_username_ct_2,
        )
        self.assertIsNone(deleted_password)



####################################################################################################
#                                       vault_salt_table Tests
####################################################################################################



class TestVaultSaltTableBehavior(unittest.TestCase):

    """
        Set up Database, MasterTable, and VaultSaltTable instances
        plus a test user for vault_salt operations.

        @ensures vault_salt tests run against a real user_id.
    """
    @classmethod
    def setUpClass(cls):

        cls._db = Database(credentials_path=CREDENTIALS_PATH)
        cls._master = MasterTable(cls._db)
        cls._vault_salt = VaultSaltTable(cls._db)

        cls.username = f"vaultsalt_user_{uuid.uuid4().hex[:8]}"
        cls.pwd_hash = f"hash_{uuid.uuid4().hex}"
        cls.user_id = cls._master.create_user(cls.username, cls.pwd_hash)

        cls.vault_salt_1 = f"vault_salt_{uuid.uuid4().hex}"
        cls.vault_salt_2 = f"vault_salt_{uuid.uuid4().hex}"


    """
        Ensure VaultSaltTable rejects a non-Database instance in the constructor.

        @ensures CipherSafeError is raised for invalid type.
    """
    def test_vault_salt_table_requires_database_instance(self):

        with self.assertRaises(CipherSafeError):
            VaultSaltTable("not-a-db")  # type: ignore[arg-type]


    """
        Verify that create_vault_salt enforces UUID and salt validation and
        raises CipherSafeError for invalid inputs.

        @ensures Invalid parameters are rejected before SQL execution.
    """
    def test_create_vault_salt_validation_errors(self):

        with self.assertRaises(CipherSafeError):
            self._vault_salt.create_vault_salt("not-a-uuid", self.vault_salt_1)

        with self.assertRaises(CipherSafeError):
            self._vault_salt.create_vault_salt(self.user_id, "")


    """
        Verify that create_vault_salt raises CipherSafeError when a duplicate row
        is inserted for the same user_id.

        @ensures vault_salt row is unique per user_id.
    """
    def test_create_vault_salt_duplicate_raises(self):

        ok = self._vault_salt.create_vault_salt(self.user_id, self.vault_salt_1)
        self.assertTrue(ok)

        # second insert should fail due to PRIMARY KEY(user_id)
        with self.assertRaises(CipherSafeError):
            self._vault_salt.create_vault_salt(self.user_id, self.vault_salt_1)


    """
        Verify that get_vault_salt returns the correct salt after insertion.

        @ensures vault_salt is retrievable and matches stored value.
    """
    def test_get_vault_salt_returns_correct_value(self):

        # Insert a new user to avoid collision with earlier duplicate test
        username2 = f"vaultsalt_user2_{uuid.uuid4().hex[:8]}"
        pwd_hash2 = f"hash_{uuid.uuid4().hex}"
        user_id2 = self._master.create_user(username2, pwd_hash2)

        vault_salt_new = f"vault_salt_{uuid.uuid4().hex}"
        ok = self._vault_salt.create_vault_salt(user_id2, vault_salt_new)
        self.assertTrue(ok)

        retrieved = self._vault_salt.get_vault_salt(user_id2)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved, vault_salt_new)


    """
        Verify that get_vault_salt returns None when no row exists.

        @ensures Unknown user_id returns None rather than raising.
    """
    def test_get_vault_salt_unknown_user_returns_none(self):

        random_id = str(uuid.uuid4())
        result = self._vault_salt.get_vault_salt(random_id)
        self.assertIsNone(result)


    """
        Verify that get_vault_salt enforces UUID validation.

        @ensures Invalid UUID strings raise CipherSafeError.
    """
    def test_get_vault_salt_invalid_uuid_raises(self):

        with self.assertRaises(CipherSafeError):
            self._vault_salt.get_vault_salt("not-a-uuid")




if __name__ == "__main__":
    unittest.main()
