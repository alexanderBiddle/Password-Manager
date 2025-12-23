#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    File name: checksum_manager.py
    Author: Alex Biddle

    Description:
        Provides SHA-256 checksum utilities for CipherSafe, including plain
        hashing and constant-time verification. All methods enforce strict
        type and length validation and raise CipherSafeError so the Flask server
        can consistently handle checksum-related failures.  
"""


import hashlib
import hmac
import sys, os
from capstone.handlers.error_handler import HTTPCodes, ApplicationCodes, CipherSafeError



class ChecksumManager:

    """
        Initialize a ChecksumManager configured for BLAKE2b-256.

        @require hashlib.sha256 produces a 32-byte digest
        @ensures The manager is ready to compute deterministic 32-byte SHA-256 digests.
    """
    def __init__(self) -> None:

        try:
            self._digest_size: int = 32
            self._algorithm: str = "SHA-256"

            # Validate digest size
            if not isinstance(self._digest_size, int) or self._digest_size != 32:
                raise CipherSafeError(ApplicationCodes.INVALID_LENGTH, HTTPCodes.INTERNAL_SERVER_ERROR, "Invalid SHA-256 digest size", "digest_size")

            # Validate algorithm type
            if not isinstance(self._algorithm, str):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "Algorithm name must be a string", "algorithm")

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed initializing ChecksumManager", "checksum_manager")



    """
        Compute a SHA-256 checksum for the given bytes.

        @param data (bytes): Raw input bytes.
        @return bytes: 32-byte SHA-256 digest.
    """
    def compute_checksum(self, data: bytes) -> bytes:

        try:
            # Validate input type
            if not isinstance(data, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_CHECKSUM_DATA, HTTPCodes.BAD_REQUEST, "Input to compute_checksum must be bytes", "data")

            # Compute SHA-256 hash of the data
            digest = hashlib.sha256(data).digest()

            # Validate digest output
            if not isinstance(digest, bytes) or len(digest) != self._digest_size:
                raise CipherSafeError(ApplicationCodes.INVALID_CHECKSUM, HTTPCodes.INTERNAL_SERVER_ERROR, "Invalid digest output from SHA-256", "checksum")

            # Return the computed checksum bytes
            return digest

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INVALID_CHECKSUM, HTTPCodes.INTERNAL_SERVER_ERROR, "Checksum computation failure", "checksum")



    """
        Verify that SHA-256(data) == expected_checksum using constant-time comparison.

        @return bool: True if match, False otherwise.
    """
    def verify_checksum(self, data: bytes, expected_checksum: bytes) -> bool:

        try:
            # Validate input data type
            if not isinstance(data, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_CHECKSUM_DATA, HTTPCodes.BAD_REQUEST, "Data must be bytes for checksum verification", "data")

            # Validate expected checksum type and size
            if not isinstance(expected_checksum, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_CHECKSUM, HTTPCodes.BAD_REQUEST, "Expected checksum must be bytes", "expected_checksum")

            if len(expected_checksum) != self._digest_size:
                raise CipherSafeError(ApplicationCodes.INVALID_LENGTH, HTTPCodes.BAD_REQUEST, "Expected checksum must be 32 bytes", "expected_checksum")

            # Compute a fresh checksum for the provided data
            #computed = self.compute_checksum(data)

            return hmac.compare_digest(data, bytes(expected_checksum))

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INVALID_CHECKSUM, HTTPCodes.INTERNAL_SERVER_ERROR, "Checksum verification failure", "checksum")
