#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    File name: TestAESManager.py
    Author: Alex Biddle      

    Description:
        Updated test suite for AESManager (AES-256-GCM) class based on the
        revised AES_manager.py implementation which now requires calling
        set_key() after initialization. This suite verifies key/nonce generation,
        encryption/decryption correctness, and all error-handling branches.
"""

import unittest
import sys, os
sys.path.insert(0, "/cslab/cgi-bin")
sys.path.insert(0, "/cslab/cgi-bin/capstone")
from capstone.encryption.AES_manager import AESManager
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes


class TestAESManager(unittest.TestCase):

    PLAINTEXT = b"cipher-safe-test-plaintext"
    AAD = b"cipher-safe-aad"

    """
        Prepare a fresh AESManager instance with a valid 32-byte AES key.
    """
    def setUp(self) -> None:

        # Generate a fresh valid AES-256 key
        self.key = AESManager.generate_key()

        # Create AESManager (constructor no longer accepts a key)
        self.manager = AESManager()

        # Assign key using new API
        self.manager.set_key(self.key)

        self.aad = self.AAD
        self.plaintext = self.PLAINTEXT

    """
        generate_key() must return 32-byte random values.
    """
    def test_generate_key_properties(self):

        key1 = AESManager.generate_key()
        key2 = AESManager.generate_key()

        self.assertIsInstance(key1, bytes)
        self.assertEqual(32, len(key1))

        self.assertIsInstance(key2, bytes)
        self.assertEqual(32, len(key2))

        self.assertNotEqual(key1, key2)

    """
        generate_nonce() must return 12-byte random values.
    """
    def test_generate_nonce_properties(self):

        nonce1 = AESManager.generate_nonce()
        nonce2 = AESManager.generate_nonce()

        self.assertIsInstance(nonce1, bytes)
        self.assertEqual(12, len(nonce1))

        self.assertIsInstance(nonce2, bytes)
        self.assertEqual(12, len(nonce2))

        self.assertNotEqual(nonce1, nonce2)

    """
        AESManager() must initialize with no key; encrypt/decrypt should fail.
    """
    def test_encrypt_without_setting_key_fails(self):

        mgr = AESManager()

        with self.assertRaises(Exception):
            mgr.encrypt(self.aad, self.plaintext)

    """
        set_key() must reject invalid types.
    """
    def test_set_key_rejects_invalid_type(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.set_key("not-bytes")  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_AES_KEY)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "aes_key")

    """
        set_key() must reject keys of invalid lengths.
    """
    def test_set_key_rejects_invalid_length(self):

        for bad_len in (0, 16, 24, 31, 33):
            with self.subTest(bad_len=bad_len):
                with self.assertRaises(CipherSafeError) as cm:
                    self.manager.set_key(os.urandom(bad_len))

                exc = cm.exception
                self.assertEqual(exc.application_code, ApplicationCodes.INVALID_AES_KEY)
                self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
                self.assertEqual(exc.field, "aes_key")

    """
        Encrypting and then decrypting returns the original plaintext.
    """
    def test_encrypt_decrypt_round_trip(self):

        nonce, ciphertext = self.manager.encrypt(self.aad, self.plaintext)
        recovered = self.manager.decrypt(self.aad, nonce, ciphertext)

        self.assertEqual(self.plaintext, recovered)

    """
        encrypt(): invalid AAD type.
    """
    def test_encrypt_rejects_invalid_aad_type(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.encrypt("not-bytes", self.plaintext)  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_TYPE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "aad")

    """
        encrypt(): invalid plaintext type.
    """
    def test_encrypt_rejects_invalid_plaintext_type(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.encrypt(self.aad, "not-bytes")  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_TYPE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "plaintext")

    """
        encrypt(): empty plaintext.
    """
    def test_encrypt_rejects_empty_plaintext(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.encrypt(self.aad, b"")

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_LENGTH)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "plaintext")

    """
        decrypt(): invalid AAD type.
    """
    def test_decrypt_rejects_invalid_aad_type(self):

        nonce, ciphertext = self.manager.encrypt(self.aad, self.plaintext)

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.decrypt("not-bytes", nonce, ciphertext)  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_TYPE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "aad")

    """
        decrypt(): invalid nonce type.
    """
    def test_decrypt_rejects_invalid_nonce_type(self):

        _, ciphertext = self.manager.encrypt(self.aad, self.plaintext)

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.decrypt(self.aad, "not-bytes", ciphertext)  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_NONCE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "nonce")

    """
        decrypt(): invalid nonce length.
    """
    def test_decrypt_rejects_invalid_nonce_length(self):

        _, ciphertext = self.manager.encrypt(self.aad, self.plaintext)
        bad_nonce = os.urandom(8)

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.decrypt(self.aad, bad_nonce, ciphertext)

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_NONCE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "nonce")

    """
        decrypt(): invalid ciphertext type.
    """
    def test_decrypt_rejects_invalid_ciphertext_type(self):

        nonce, _ = self.manager.encrypt(self.aad, self.plaintext)

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.decrypt(self.aad, nonce, "not-bytes")  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_CIPHERTEXT)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "ciphertext")

    """
        decrypt(): ciphertext shorter than tag (less than 16 bytes).
    """
    def test_decrypt_rejects_short_ciphertext(self):

        nonce = AESManager.generate_nonce()
        short_ct = b"\x00" * 8

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.decrypt(self.aad, nonce, short_ct)

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_CIPHERTEXT)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "ciphertext")

    """
        decrypt(): tampered ciphertext must raise authentication error.
    """
    def test_decrypt_authentication_failure_raises_cipher_safe_error(self):

        nonce, ciphertext = self.manager.encrypt(self.aad, self.plaintext)

        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.decrypt(self.aad, nonce, bytes(tampered))

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.CIPHERTEXT_AUTH_ERROR)
        self.assertEqual(exc.http_code, HTTPCodes.UNAUTHORIZED)
        self.assertEqual(exc.field, "ciphertext")


if __name__ == "__main__":
    unittest.main()
