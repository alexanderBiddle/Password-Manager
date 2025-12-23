#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    File name: testRSAManager.py
    Author:       
    Date:         

    Description:

        Test suite for RSAManager. Ensures valid initialization, signing,
        verification, RSA-OAEP encryption/decryption, rotation behavior,
        and proper CipherSafeError ApplicationCodes & HTTPCodes. This test
        file is fully aligned with the production RSAManager implementation,
        which does NOT accept an external public PEM for verification.
"""

import unittest
import tempfile
import json
import sys, os
sys.path.insert(0, "/cslab/cgi-bin")
sys.path.insert(0, "/cslab/cgi-bin/capstone")
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from capstone.encryption.RSA_manager import RSAManager
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes


class TestRSAManager(unittest.TestCase):

    DATA = b"cipher-safe-test-message"
    AES_KEY_32 = b"\x01" * 32

    """
        Creates a temporary directory for RSA key and metadata files,
        then initializes RSAManager for each test.
    """
    def setUp(self) -> None:

        self.temp_dir = tempfile.mkdtemp(prefix="rsa_manager_test_")

        self.private_key_path = os.path.join(self.temp_dir, "server_private_key.pem")
        self.private_key_data_path = os.path.join(self.temp_dir, "server_private_key_data.json")

        self.manager = RSAManager(self.private_key_path, self.private_key_data_path)

    """
        Removes temp directory used for RSAManager testing.
    """
    def tearDown(self) -> None:

        try:
            for root, dirs, files in os.walk(self.temp_dir, topdown=False):
                for name in files:
                    try:
                        os.remove(os.path.join(root, name))
                    except OSError:
                        pass
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except OSError:
                        pass
            os.rmdir(self.temp_dir)
        except Exception:
            pass

    """
        RSAManager must generate RSA key + metadata on initialization.
    """
    def test_init_generates_key_and_metadata(self):

        self.assertTrue(os.path.isfile(self.private_key_path))
        self.assertTrue(os.path.isfile(self.private_key_data_path))

        with open(self.private_key_data_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertIn("key_identifier", meta)
        self.assertIn("key_creation_time", meta)
        self.assertIn("key_expiry_time", meta)

    """
        Invalid constructor paths must raise INVALID_PATH / INTERNAL_SERVER_ERROR.
    """
    def test_init_invalid_paths(self):

        with self.assertRaises(CipherSafeError) as cm:
            RSAManager("", self.private_key_data_path)

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_PATH)
        self.assertEqual(exc.http_code, HTTPCodes.INTERNAL_SERVER_ERROR)
        self.assertEqual(exc.field, "private_key_path")

        with self.assertRaises(CipherSafeError) as cm:
            RSAManager(self.private_key_path, "")

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_PATH)
        self.assertEqual(exc.http_code, HTTPCodes.INTERNAL_SERVER_ERROR)
        self.assertEqual(exc.field, "private_key_data_path")

    """
        get_public_key_data must return PEM + metadata fields.
    """
    def test_get_public_key_data_structure(self):

        data = self.manager.get_public_key_data()

        self.assertIn("rsa_public_key", data)
        self.assertIn("key_identifier", data)
        self.assertIn("key_creation_time", data)
        self.assertIn("key_expiry_time", data)

        self.assertTrue(data["rsa_public_key"].startswith("-----BEGIN PUBLIC KEY-----"))

    """
        Signing and verifying must work with server's own RSA keypair.
    """
    def test_sign_and_verify_valid_signature(self):

        signature = self.manager.sign_data_with_private_key(self.DATA)
        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 0)

        result = self.manager.verify_signature_with_public_key(self.DATA, signature)
        self.assertTrue(result)

    """
        Verifying modified data must return False.
    """
    def test_verify_returns_false_for_modified_data(self):

        signature = self.manager.sign_data_with_private_key(self.DATA)

        result = self.manager.verify_signature_with_public_key(self.DATA + b"!", signature)
        self.assertFalse(result)

    """
        Verifying modified signature must return False.
    """
    def test_verify_returns_false_for_modified_signature(self):

        signature = self.manager.sign_data_with_private_key(self.DATA)

        bad_signature = signature[:-1] + bytes([signature[-1] ^ 0x01])

        result = self.manager.verify_signature_with_public_key(self.DATA, bad_signature)
        self.assertFalse(result)

    """
        sign_data_with_private_key must reject non-bytes with INVALID_TYPE / BAD_REQUEST.
    """
    def test_sign_rejects_invalid_data_type(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.sign_data_with_private_key("not-bytes")  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_TYPE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "data")

    """
        verify_signature_with_public_key must reject invalid data types with INVALID_TYPE / BAD_REQUEST.
    """
    def test_verify_rejects_invalid_types(self):

        signature = self.manager.sign_data_with_private_key(self.DATA)

        # Invalid data
        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_signature_with_public_key("not-bytes", signature)  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_TYPE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "data")

        # Invalid signature
        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_signature_with_public_key(self.DATA, "not-bytes")  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_TYPE)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "signature")

    """
        encrypt_aes_key must properly encrypt AES-256 material using client RSA public key.
    """
    def test_encrypt_aes_key_valid(self):

        client_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = client_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        wrapped = self.manager.encrypt_aes_key(self.AES_KEY_32, public_pem)
        self.assertIsInstance(wrapped, bytes)

        recovered = client_private.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        self.assertEqual(recovered, self.AES_KEY_32)

    """
        encrypt_aes_key must reject invalid AES key length/type.
    """
    def test_encrypt_aes_key_invalid_key(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.encrypt_aes_key("not-bytes", "pem")  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_AES_KEY)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "aes_key")

        for bad_len in (0, 1, 15, 17, 20):
            with self.subTest(bad_len=bad_len):
                with self.assertRaises(CipherSafeError) as cm:
                    self.manager.encrypt_aes_key(b"\x00" * bad_len, "pem")

                exc = cm.exception
                self.assertEqual(exc.application_code, ApplicationCodes.INVALID_AES_KEY)
                self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
                self.assertEqual(exc.field, "aes_key")

    """
        encrypt_aes_key must reject invalid client public key PEM with INVALID_PUBLIC_KEY.
    """
    def test_encrypt_aes_key_invalid_public_key(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.encrypt_aes_key(self.AES_KEY_32, "")  # empty PEM

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_PUBLIC_KEY)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "client_rsa_public_key")

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.encrypt_aes_key(self.AES_KEY_32, "not-a-pem")

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_PUBLIC_KEY)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "client_rsa_public_key")

    """
        decrypt_aes_key must unwrap a key encrypted with the server public key.
    """
    def test_decrypt_aes_key_valid(self):

        pub_data = self.manager.get_public_key_data()
        server_public_pem = pub_data["rsa_public_key"]

        public_key = serialization.load_pem_public_key(server_public_pem.encode("utf-8"))

        wrapped = public_key.encrypt(
            self.AES_KEY_32,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        recovered = self.manager.decrypt_aes_key(wrapped)
        self.assertEqual(recovered, self.AES_KEY_32)

    """
        decrypt_aes_key must reject invalid ciphertext.
    """
    def test_decrypt_aes_key_invalid_ciphertext(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.decrypt_aes_key("not-bytes")  # type: ignore

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_CIPHERTEXT)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "wrapped_key")

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.decrypt_aes_key(b"")

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_CIPHERTEXT)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "wrapped_key")

    """
        decrypt_aes_key must wrap internal failures as RSA_DECRYPT_ERROR.
    """
    def test_decrypt_aes_key_internal_failure(self):

        bad_wrapped = b"\x00" * 256

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.decrypt_aes_key(bad_wrapped)

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.RSA_DECRYPT_ERROR)
        self.assertEqual(exc.http_code, HTTPCodes.INTERNAL_SERVER_ERROR)
        self.assertEqual(exc.field, "wrapped_key")


if __name__ == "__main__":
    unittest.main()
