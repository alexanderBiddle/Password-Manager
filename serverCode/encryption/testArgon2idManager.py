#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    File name:    testArgon2idManager.py
    Author:       
    Date:         

    Description:

        Test suite for Argon2idManager. Verifies salt generation, password hashing,
        password verification, and error handling with correct ApplicationCodes and
        HTTPCodes. This file is aligned with the production argon2id_manager.py
        implementation.
"""

import unittest
import sys, os
sys.path.insert(0, "/cslab/cgi-bin")
sys.path.insert(0, "/cslab/cgi-bin/capstone")
from capstone.encryption.argon2id_manager import Argon2idManager
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes
import encryption.argon2id_manager as argon2_module


class TestArgon2idManager(unittest.TestCase):

    PASSWORD = b"SuperSecretPassword!"
    WRONG_PASSWORD = b"NotTheSamePassword"
    SALT_LEN = 16
    HASH_LEN = 32

    """
        Create a fresh Argon2idManager and salt for each test.
    """
    def setUp(self) -> None:

        self.manager = Argon2idManager()
        self.salt = self.manager.generate_salt()

    """
        Generated salts must be bytes, correct length, and non-deterministic.
    """
    def test_generate_salt_properties(self):

        salt1 = self.manager.generate_salt()
        salt2 = self.manager.generate_salt()

        self.assertIsInstance(salt1, bytes)
        self.assertEqual(self.SALT_LEN, len(salt1))

        self.assertIsInstance(salt2, bytes)
        self.assertEqual(self.SALT_LEN, len(salt2))

        self.assertNotEqual(salt1, salt2)

    """
        hash_password must return a deterministic, fixed-length digest.
    """
    def test_hash_password_properties(self):

        digest1 = self.manager.hash_password(self.PASSWORD, self.salt)
        digest2 = self.manager.hash_password(self.PASSWORD, self.salt)

        self.assertIsInstance(digest1, bytes)
        self.assertEqual(self.HASH_LEN, len(digest1))
        self.assertEqual(digest1, digest2)

    """
        hash_password must reject non-bytes password with INVALID_TYPE / BAD_REQUEST.
    """
    def test_hash_password_rejects_invalid_password_type(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.hash_password("not-bytes", self.salt)  # type: ignore[arg-type]

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_TYPE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "password")

    """
        hash_password must reject non-bytes salt with INVALID_SALT / BAD_REQUEST.
    """
    def test_hash_password_rejects_invalid_salt_type(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.hash_password(self.PASSWORD, "not-bytes")  # type: ignore[arg-type]

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_SALT)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "salt")

    """
        hash_password must reject wrong salt length with INVALID_SALT / BAD_REQUEST.
    """
    def test_hash_password_rejects_wrong_salt_length(self):

        bad_salt_short = b"\x00" * (self.SALT_LEN - 1)
        bad_salt_long = b"\x00" * (self.SALT_LEN + 1)

        for bad_salt in (bad_salt_short, bad_salt_long):
            with self.subTest(len=len(bad_salt)):
                with self.assertRaises(CipherSafeError) as cm:
                    self.manager.hash_password(self.PASSWORD, bad_salt)

                exc = cm.exception
                self.assertEqual(exc.application_code, ApplicationCodes.INVALID_SALT)
                self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
                self.assertEqual(exc.field, "salt")

    """
        hash_password must wrap internal Argon2id failures as PASSWORD_HASH_ERROR / INTERNAL_SERVER_ERROR.
    """
    def test_hash_password_internal_error_wrapped(self):

        original_hash_secret_raw = argon2_module.hash_secret_raw

        def bad_hash_secret_raw(*args, **kwargs):
            raise RuntimeError("simulated internal Argon2 failure")

        try:
            argon2_module.hash_secret_raw = bad_hash_secret_raw  # type: ignore[assignment]

            with self.assertRaises(CipherSafeError) as cm:
                self.manager.hash_password(self.PASSWORD, self.salt)

            exc = cm.exception
            self.assertEqual(exc.application_code, ApplicationCodes.PASSWORD_HASH_ERROR)
            self.assertEqual(exc.http_code, HTTPCodes.INTERNAL_SERVER_ERROR)
            self.assertEqual(exc.field, "password")

        finally:
            argon2_module.hash_secret_raw = original_hash_secret_raw  # type: ignore[assignment]

    """
        verify_password must return True for matching password and hash.
    """
    def test_verify_password_true_for_correct_password(self):

        digest = self.manager.hash_password(self.PASSWORD, self.salt)
        result = self.manager.verify_password(self.PASSWORD, self.salt, digest)
        self.assertTrue(result)

    """
        verify_password must return False for wrong password with same salt/hash.
    """
    def test_verify_password_false_for_wrong_password(self):

        digest = self.manager.hash_password(self.PASSWORD, self.salt)
        result = self.manager.verify_password(self.WRONG_PASSWORD, self.salt, digest)
        self.assertFalse(result)

    """
        verify_password must reject non-bytes password with INVALID_TYPE / BAD_REQUEST.
    """
    def test_verify_password_rejects_invalid_password_type(self):

        digest = self.manager.hash_password(self.PASSWORD, self.salt)

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_password("not-bytes", self.salt, digest)  # type: ignore[arg-type]

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_TYPE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "password")

    """
        verify_password must reject non-bytes salt with INVALID_SALT / BAD_REQUEST.
    """
    def test_verify_password_rejects_invalid_salt_type(self):

        digest = self.manager.hash_password(self.PASSWORD, self.salt)

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_password(self.PASSWORD, "not-bytes", digest)  # type: ignore[arg-type]

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_SALT)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "salt")

    """
        verify_password must reject wrong salt length with INVALID_SALT / BAD_REQUEST.
    """
    def test_verify_password_rejects_wrong_salt_length(self):

        digest = self.manager.hash_password(self.PASSWORD, self.salt)
        bad_salt = b"\x00" * (self.SALT_LEN + 1)

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_password(self.PASSWORD, bad_salt, digest)

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_SALT)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "salt")

    """
        verify_password must reject non-bytes expected_hash with INVALID_TYPE / BAD_REQUEST.
    """
    def test_verify_password_rejects_invalid_expected_hash_type(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_password(self.PASSWORD, self.salt, "not-bytes")  # type: ignore[arg-type]

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_TYPE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "expected_hash")

    """
        verify_password must reject wrong expected_hash length with INVALID_LENGTH / BAD_REQUEST.
    """
    def test_verify_password_rejects_invalid_expected_hash_length(self):

        digest = self.manager.hash_password(self.PASSWORD, self.salt)
        bad_digest = digest[:-1]

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_password(self.PASSWORD, self.salt, bad_digest)

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_LENGTH)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "expected_hash")

    """
        verify_password must wrap internal failures as PASSWORD_VERIFY_ERROR / INTERNAL_SERVER_ERROR.
    """
    def test_verify_password_internal_error_wrapped(self):

        digest = self.manager.hash_password(self.PASSWORD, self.salt)

        original_hash_secret_raw = argon2_module.hash_secret_raw

        def bad_hash_secret_raw(*args, **kwargs):
            raise RuntimeError("simulated internal Argon2 failure in verify")

        try:
            argon2_module.hash_secret_raw = bad_hash_secret_raw  # type: ignore[assignment]

            with self.assertRaises(CipherSafeError) as cm:
                self.manager.verify_password(self.PASSWORD, self.salt, digest)

            exc = cm.exception
            self.assertEqual(exc.application_code, ApplicationCodes.PASSWORD_HASH_ERROR)
            self.assertEqual(exc.http_code, HTTPCodes.INTERNAL_SERVER_ERROR)
            self.assertEqual(exc.field, "password")

        finally:
            argon2_module.hash_secret_raw = original_hash_secret_raw  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
