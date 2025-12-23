#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    File name: argon2id_manager.py
    Author: Alex Biddle

    Description:
        Provides CipherSafe's fixed-parameter Argon2id manager responsible for
        generating salts, hashing passwords, and verifying password digests.
        Ensures consistent, deterministic hashing using constant-time comparison
        and strict input validation to prevent side-channel leakage or misuse.   
"""


import hmac
import sys, os
from argon2.low_level import hash_secret_raw, Type as Argon2Type
from argon2 import PasswordHasher
from capstone.handlers.error_handler import HTTPCodes, ApplicationCodes, CipherSafeError



class Argon2idManager:

    """
        Initialize an Argon2idManager instance with CipherSafe's fixed parameters.

        @require Argon2id constants must be valid integer values

        @return None: Sets time cost, memory cost, parallelism, hash length, and salt length.

        @ensures The manager is fully initialized and ready for deterministic hashing.
    """
    def __init__(self) -> None:

        try:
            # Default Argon2id parameters (immutable)
            self._time_cost: int = 3
            self._memory_cost_kib: int = 64 * 1024
            self._parallelism: int = 2
            self._hash_len: int = 32
            self._salt_len: int = 16

        # Re-raise any initialization error so Flask server handles it via error_handler
        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize Argon2idManager", "argon2id_manager")


    """
        Generate a new random salt using a secure CSPRNG.

        @require os.urandom must return at least self._salt_len bytes
        @require self._salt_len is a positive integer

        @return bytes: A newly generated salt of length self._salt_len.

        @ensures Returned salt is cryptographically random and exactly the required length.
    """
    def generate_salt(self) -> bytes:

        try:
            # Generate 16 random bytes for salt
            salt = os.urandom(self._salt_len)

            # Validate salt properties
            if not isinstance(salt, bytes) or len(salt) != self._salt_len:
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.INTERNAL_SERVER_ERROR, "Generated salt must be 16 bytes", "salt")

            # Return generated salt
            return salt

        # Re-raise any error so Flask server handles it via error_handler
        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error during salt generation", "salt")




    """
        Hash a password using Argon2id and the provided salt.

        @param password (bytes): Raw password bytes to be hashed.
        @param salt (bytes): Salt that must be exactly self._salt_len bytes.

        @require isinstance(password, (bytes, bytearray))
        @require isinstance(salt, (bytes, bytearray)) and len(salt) == self._salt_len

        @return bytes: The Argon2id digest of length self._hash_len.

        @ensures Hashing uses CipherSafe's fixed parameters to produce deterministic digests.
    """
    def hash_password(self, password: bytes, salt: bytes) -> bytes:

        try:
            # Validate types
            if not isinstance(password, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "password must be bytes", "password")

            if not isinstance(salt, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "salt must be bytes", "salt")

            # Validate salt length
            if len(salt) != self._salt_len:
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "salt must be 16 bytes", "salt")

            # Perform Argon2id hashing with CipherSafe fixed parameters
            digest = hash_secret_raw(
                secret=bytes(password),
                salt=bytes(salt),
                time_cost=self._time_cost,
                memory_cost=self._memory_cost_kib,
                parallelism=self._parallelism,
                hash_len=self._hash_len,
                type=Argon2Type.ID,
            )

            # Validate output digest type and length
            if not isinstance(digest, bytes) or len(digest) != self._hash_len:
                raise CipherSafeError(ApplicationCodes.PASSWORD_HASH_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Invalid Argon2id digest length", "expected_hash")

            # Return raw digest bytes
            return digest

        # Re-raise any error so Flask server handles it via error_handler
        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.PASSWORD_HASH_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Argon2id hashing failed", "password")




    """
        Verify a password against a known Argon2id digest using constant-time comparison.

        @param password (bytes): Password input to hash and compare.
        @param salt (bytes): Salt used during original hashing.
        @param expected_hash (bytes): Stored Argon2id digest for comparison.

        @require isinstance(password, (bytes, bytearray))
        @require isinstance(salt, (bytes, bytearray)) and len(salt) == self._salt_len
        @require isinstance(expected_hash, (bytes, bytearray)) and len(expected_hash) == self._hash_len

        @return bool: True if recomputed digest matches expected_hash; False otherwise.

        @ensures Comparison is performed using constant-time comparison to prevent timing attacks.
    """
    def verify_password(self, password: bytes, salt: bytes, expected_hash: bytes) -> bool:

        try:
            # Validate all parameters
            if not isinstance(password, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "password must be bytes", "password")

            if not isinstance(salt, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "salt must be bytes", "salt")

            if len(salt) != self._salt_len:
                raise CipherSafeError(ApplicationCodes.INVALID_SALT, HTTPCodes.BAD_REQUEST, "salt must be 16 bytes", "salt")

            if not isinstance(expected_hash, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "expected_hash must be bytes", "expected_hash")

            if len(expected_hash) != self._hash_len:
                raise CipherSafeError(ApplicationCodes.INVALID_LENGTH, HTTPCodes.BAD_REQUEST, "expected_hash must be 32 bytes", "expected_hash")

            # Recompute digest using Argon2id
            recomputed = self.hash_password(password, salt)

            # Perform constant-time comparison
            result = hmac.compare_digest(recomputed, bytes(expected_hash))

            # Validate result type
            if not isinstance(result, bool):
                raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "verification result must be boolean", "verification_result")

            # Return True only if hashes match
            return result

        # Re-raise any error so Flask server handles it via error_handler
        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.PASSWORD_VERIFY_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Argon2id password verification failure", "expected_hash")
