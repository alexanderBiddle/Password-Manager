#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: database.py
    Author: Alex Biddle

    Description:
        Provides PostgreSQL connection handling and parameterized SQL execution
        for all CipherSafe backend components. Ensures secure credential loading,
        safe query execution, and structured error propagation to the central
        error handler.
"""


import sys, os
import typing
import json
import psycopg2
import psycopg2.extras
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes



"""
    Provides connection management and query execution methods for CipherSafe.

    @ensures Database credentials are validated, connections use parameterized queries, and all errors are raised upward as CipherSafeError instances.
"""
class Database:

    """
        Initialize a Database helper bound to a single PostgreSQL credential set.

        @param credentials_path (str|None): Path to the database credential file.

        @require credentials_path is None or isinstance(credentials_path, str)

        @ensures Loads and validates database, user, password, host values.
    """
    def __init__(self, credentials_path: typing.Optional[str] = None) -> None:

        try:
            # If a credentials path is not provided, default to file in the same directory
            if credentials_path is None:
                
                credentials_path = "/cslab/cgi-bin/capstone/database/database_credentials.htacess"

            # Store the credentials path
            self._credentials_path: str = credentials_path

            # Initialize placeholders
            self._database: str = ""
            self._user: str = ""
            self._password: str = ""
            self._host: str = ""

            # Load credentials from disk
            self._load_database_credentials()

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize Database helper", "database_init")


    """
       Load and validate database credentials from disk.

        @require self._credentials_path is a non-empty string
        @require database_credentials.htaccess exists and contains valid JSON
        @require JSON contains fields: database, user, password, host

        @ensures Populates self._database, self._user, self._password, self._host, and self._port.
    """
    def _load_database_credentials(self) -> None:

        try:
            # Ensure path is a non-empty string
            if not isinstance(self._credentials_path, str) or not self._credentials_path.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_PATH, HTTPCodes.INTERNAL_SERVER_ERROR, "Database credentials path must be a non-empty string", "database_credentials_path")

            # Ensure file actually exists
            if not os.path.isfile(self._credentials_path):
                raise CipherSafeError(ApplicationCodes.INVALID_PATH, HTTPCodes.INTERNAL_SERVER_ERROR, "Database credentials file not found", "database_credentials_path")

            # Read the file contents
            with open(self._credentials_path, "r", encoding="utf-8") as f:
                raw = f.read()

            # Attempt to parse as JSON
            try:
                creds = json.loads(raw)
            except Exception:
                raise CipherSafeError(ApplicationCodes.MALFORMED_JSON, HTTPCodes.INTERNAL_SERVER_ERROR, "Database credentials file must contain valid JSON", "database_credentials")

            # Ensure credentials is a dictionary
            if not isinstance(creds, dict):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "Database credentials JSON must be an object", "database_credentials")

            # Extract fields
            database = creds.get("database")
            user = creds.get("user")
            password = creds.get("password")
            host = creds.get("host", "localhost")

            # Validate 'database'
            if not isinstance(database, str) or not database.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "Missing or invalid 'database' in credentials file", "database")

            # Validate 'user'
            if not isinstance(user, str) or not user.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "Missing or invalid 'user' in credentials file", "user")

            # Validate 'password'
            if not isinstance(password, str) or not password.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "Missing or invalid 'password' in credentials file", "password")

            # Validate 'host'
            if not isinstance(host, str) or not host.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "Missing or invalid 'host' in credentials file", "host")

            # Assign validated fields
            self._database = database.strip()
            self._user = user.strip()
            self._password = password
            self._host = host.strip()

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error loading database credentials", "database_credentials")


    """
        Create a new psycopg2 database connection using validated credentials.

        @require self._database, self._user, self._password, self._host, self._port have been loaded

        @return connection (psycopg2.extensions.connection): A live PostgreSQL connection object.

        @ensures Returns a valid and active connection to PostgreSQL.
    """
    def _get_database_connection(self):

        try:
            # Build a new connection using the stored credentials
            conn = psycopg2.connect(
                dbname=self._database,
                user=self._user,
                password=self._password,
                host=self._host,
            )

            # Ensure connection object is valid
            if conn is None:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to create PostgreSQL connection", "database_connection")

            # Return the connection
            return conn

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Error connecting to PostgreSQL database", "database_connection")


    """
        Execute a non-SELECT SQL statement such as INSERT, UPDATE, or DELETE.

        @param sql (str): SQL statement with %s placeholders.
        @param params (tuple|None): Parameter tuple for the statement.

        @require isinstance(sql, str) and len(sql.strip()) > 0
        @require params is None or isinstance(params, tuple)

        @return int: Number of rows affected by the SQL operation.

        @ensures Statement is executed in its own transaction and committed on success.
    """
    def execute_statment(self, sql: str, params: typing.Optional[typing.Tuple[typing.Any, ...]] = None) -> int:

        try:
            # Validate SQL string
            if not isinstance(sql, str) or not sql.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "SQL must be a non-empty string", "sql")

            # Default params to empty tuple if None
            if params is None:
                params = ()

            # Validate params is a tuple
            if not isinstance(params, tuple):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "params must be a tuple", "params")

            # Open a new connection
            conn = self._get_database_connection()

            try:
                # Use a cursor with default behavior
                cur = conn.cursor()

                # Execute the parameterized statement
                cur.execute(sql, params)

                # Capture the affected row count
                rowcount = cur.rowcount

                # Commit the transaction
                conn.commit()

                # Return affected row count
                return rowcount

            # Rollback this transaction and re-raise
            except CipherSafeError:
                conn.rollback()
                raise
            
             # Rollback and normalize any DB error
            except Exception:
                conn.rollback()
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Database execution error", "sql_execute")

            finally:
                # Ensure cursor and connection are closed
                try:
                    cur.close()
                except Exception:
                    pass

                try:
                    conn.close()
                except Exception:
                    pass

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error during SQL execution", "sql_execute_outer")


    """
        Execute a SELECT query that returns a single row.

        @param sql (str): SQL SELECT query with %s placeholders.
        @param params (tuple|None): Parameter tuple.

        @require isinstance(sql, str) and len(sql.strip()) > 0
        @require params is None or isinstance(params, tuple)

        @return dict|None: Dictionary row if one exists, otherwise None.

        @ensures Returns exactly one row or None if no rows match.
    """
    def get_row(self, sql: str, params: typing.Optional[typing.Tuple[typing.Any, ...]] = None) -> typing.Optional[dict]:

        try:
            # Validate SQL string
            if not isinstance(sql, str) or not sql.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "SQL must be a non-empty string", "sql")

            # Default params to empty tuple
            if params is None:
                params = ()

            # Validate params type
            if not isinstance(params, tuple):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "params must be a tuple", "params")

            # Open connection
            conn = self._get_database_connection()

            try:
                # Use RealDictCursor to return dict rows
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                # Execute query
                cur.execute(sql, params)

                # Fetch one row
                row = cur.fetchone()

                # If no row is present, return None
                if row is None:
                    return None

                # Convert RealDictRow to plain dict
                return dict(row)

            except CipherSafeError:
                raise

            except Exception:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Database fetch_one error", "sql_fetch_one")

            finally:
                # Ensure resources are cleaned up
                try:
                    cur.close()
                except Exception:
                    pass

                try:
                    conn.close()
                except Exception:
                    pass

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError( ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error during fetch_one", "sql_fetch_one_outer")


    """
        Execute a SELECT query returning all matching rows.

        @param sql (str): SQL SELECT query.
        @param params (tuple|None): Parameter tuple.

        @require isinstance(sql, str) and len(sql.strip()) > 0
        @require params is None or isinstance(params, tuple)

        @return list[dict]: A list of dictionary rows (may be empty).

        @ensures Returns all rows in result set, converted to plain dictionaries.
    """
    def get_all_matching_rows(self, sql: str, params: typing.Optional[typing.Tuple[typing.Any, ...]] = None) -> typing.List[dict]:

        try:
            # Validate SQL string
            if not isinstance(sql, str) or not sql.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "SQL must be a non-empty string", "sql")

            # Default params to empty tuple
            if params is None:
                params = ()

            # Validate params type
            if not isinstance(params, tuple):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "params must be a tuple", "params")

            # Open connection
            conn = self._get_database_connection()

            try:
                # Use RealDictCursor to return dict rows
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                # Execute query
                cur.execute(sql, params)

                # Fetch all rows
                rows = cur.fetchall()

                # Convert all rows to plain dicts
                return [dict(r) for r in rows]

            except CipherSafeError:
                raise

            except Exception:
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Database fetch_all error", "sql_fetch_all")

            finally:
                # Cleanup cursor and connection
                try:
                    cur.close()
                except Exception:
                    pass

                try:
                    conn.close()
                except Exception:
                    pass

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error during fetch_all", "sql_fetch_all_outer")
