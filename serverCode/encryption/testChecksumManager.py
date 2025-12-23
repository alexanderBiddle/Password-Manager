#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    File name:    testChecksumManager.py
    Author:       
    Date:         

    Description:

        Test suite for ChecksumManager — aligned with production checksum_manager.py.
        Covers checksum computation, keyed checksum, verification behavior,
        and correct CipherSafeError ApplicationCodes and HTTPCodes.

        NOTE:
            Updated to SHA-256 (32-byte digest) instead of BLAKE2b-256.
"""

import unittest
import sys, os
sys.path.insert(0, "/cslab/cgi-bin")
sys.path.insert(0, "/cslab/cgi-bin/capstone")

from capstone.encryption.checksum_manager import ChecksumManager
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes



class TestChecksumManager(unittest.TestCase):

    DATA = b"cipher-safe-test-payload"
    DATA_MODIFIED = b"cipher-safe-test-payload-modified"

    # Keyed checksum tests still exist but are expected to return SHA-256(key || data)
    KEY = b"key-material"


    """
        Create fresh ChecksumManager for each test.
    """
    def setUp(self):
        self.manager = ChecksumManager()



    """
        compute_checksum returns deterministic 32-byte SHA-256 digest.
    """
    def test_compute_checksum_properties(self):

        digest1 = self.manager.compute_checksum(self.DATA)
        digest2 = self.manager.compute_checksum(self.DATA)

        self.assertIsInstance(digest1, bytes)
        self.assertEqual(32, len(digest1))  # SHA-256 = 32 bytes
        self.assertEqual(digest1, digest2)



    """
        compute_checksum rejects non-bytes data with INVALID_CHECKSUM_DATA / BAD_REQUEST.
    """
    def test_compute_checksum_rejects_invalid_type(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.compute_checksum("not-bytes")  # type: ignore[arg-type]

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_CHECKSUM_DATA)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "data")



    """
        verify_checksum returns True for correct data.
    """
    def test_verify_checksum_true(self):

        digest = self.manager.compute_checksum(self.DATA)
        self.assertTrue(self.manager.verify_checksum(self.DATA, digest))



    """
        verify_checksum returns False for modified data.
    """
    def test_verify_checksum_false_for_modified(self):

        digest = self.manager.compute_checksum(self.DATA)
        self.assertFalse(self.manager.verify_checksum(self.DATA_MODIFIED, digest))



    """
        verify_checksum rejects non-bytes data with INVALID_CHECKSUM_DATA / BAD_REQUEST.
    """
    def test_verify_checksum_rejects_invalid_data(self):

        digest = self.manager.compute_checksum(self.DATA)

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_checksum("not-bytes", digest)  # type: ignore[arg-type]

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_CHECKSUM_DATA)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "data")



    """
        verify_checksum rejects non-bytes expected_checksum with INVALID_CHECKSUM / BAD_REQUEST.
    """
    def test_verify_checksum_rejects_invalid_checksum_type(self):

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_checksum(self.DATA, "not-bytes")  # type: ignore[arg-type]

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_CHECKSUM)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "expected_checksum")



    """
        verify_checksum rejects expected_checksum of wrong length with INVALID_LENGTH / BAD_REQUEST.
    """
    def test_verify_checksum_rejects_invalid_checksum_length(self):

        digest = self.manager.compute_checksum(self.DATA)
        bad = digest[:-1]  # too short

        with self.assertRaises(CipherSafeError) as cm:
            self.manager.verify_checksum(self.DATA, bad)

        exc = cm.exception
        self.assertEqual(exc.application_code, ApplicationCodes.INVALID_LENGTH)
        self.assertEqual(exc.http_code, HTTPCodes.BAD_REQUEST)
        self.assertEqual(exc.field, "expected_checksum")


if __name__ == "__main__":
    unittest.main()
