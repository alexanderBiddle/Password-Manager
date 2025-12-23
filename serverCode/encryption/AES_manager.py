#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: AES_manager.py
    Author: Alex Biddle

    Description:
        Implements AES-256-GCM authenticated encryption for CipherSafe. Provides
        key and nonce generation utilities along with high-level encrypt and
        decrypt methods that validate inputs and raise CipherSafeError on any
        misuse or authentication failure        
"""


import typing
import sys, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes
import capstone.constants as CONSTANTS



class AESManager:

    """
        Initialize an AESManager instance bound to a single AES-256 key.

        @param key (bytes): 32-byte symmetric AES-256 key used for encryption and decryption.

        @require isinstance(key, (bytes, bytearray)) and len(key) == 32

        @ensures An internal AESGCM context is created and bound to the validated key.
    """
    def __init__(self) -> None:

        try:
            # AES key and AESGCM context start unset
            self._key: typing.Optional[bytes] = None
            self._aes: typing.Optional[AESGCM] = None

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected AESManager initialization failure", "aes_manager_init")



    """
        Assign the AES-256 key for this instance.

        @param key (bytes): Must be exactly 32 bytes.

        @require isinstance(key, (bytes, bytearray)) and len(key) == 32

        @ensures The AESGCM context is reinitialized with this new key.
    """
    def set_key(self, key: bytes) -> None:

        try:
            # Validate type
            if not isinstance(key, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_AES_KEY, HTTPCodes.BAD_REQUEST, "AES key must be raw bytes", "aes_key")

            # Key must be 32 bytes
            if len(key) != 32:
                raise CipherSafeError(ApplicationCodes.INVALID_AES_KEY, HTTPCodes.BAD_REQUEST, "AES-256 key must be exactly 32 bytes", "aes_key")

            # Freeze copy
            self._key = bytes(key)

            # Reinitialize AES-GCM context
            self._aes = AESGCM(self._key)

        except CipherSafeError:
            raise

        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to set AES key", "aes_key_init")



    """
        Generate a fresh 32-byte AES-256 key using a CSPRNG.

        @require os.urandom is available and returns at least 32 bytes of randomness
        @return bytes: A newly generated 32-byte AES-256 key.
        @ensures The returned key is cryptographically random and exactly 32 bytes long.
    """
    @staticmethod
    def generate_key() -> bytes:

        try:
            # Generate 32 random bytes for AES-256
            key = os.urandom(32)

            # Validate key properties
            if not isinstance(key, bytes) or len(key) != 32:
                raise CipherSafeError(ApplicationCodes.INVALID_AES_KEY, HTTPCodes.INTERNAL_SERVER_ERROR, "Generated AES key must be 32 bytes", "generated_key")

            # Return the generated key
            return key

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected AES key generation failure", "generate_key")


    """
        Generate a fresh 12-byte nonce suitable for AES-GCM.

        @require os.urandom is available and returns at least 12 bytes of randomness

        @return bytes: A newly generated 12-byte GCM nonce.

        @ensures The returned nonce is cryptographically random and exactly 12 bytes long.
    """
    @staticmethod
    def generate_nonce() -> bytes:

        try:
            # Generate 12 random bytes as the GCM nonce
            nonce = os.urandom(CONSTANTS._AES_GCM_NONCE_LEN_BYTES)

            # Validate nonce type and length
            if not isinstance(nonce, bytes) or len(nonce) != CONSTANTS._AES_GCM_NONCE_LEN_BYTES:
                raise CipherSafeError(ApplicationCodes.INVALID_NONCE, HTTPCodes.INTERNAL_SERVER_ERROR, "Generated GCM nonce must be 12 bytes", "nonce")

            return nonce

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected GCM nonce generation failure", "generate_nonce")




    """
        Encrypt and authenticate plaintext using AES-256-GCM.

        @param aad (bytes): Associated data to be bound to the authentication tag.
        @param plaintext (bytes): Non-empty plaintext bytes to encrypt.

        @require isinstance(aad, (bytes, bytearray))
        @require isinstance(plaintext, (bytes, bytearray)) and len(plaintext) > 0

        @return tuple[bytes, bytes]: (nonce, ciphertext_with_tag) where nonce is 12 bytes and ciphertext_with_tag includes the 16-byte GCM tag.

        @ensures Returns a fresh 12-byte nonce and ciphertext that verifies successfully with the same key, aad, and nonce.
    """
    def encrypt(self, aad: bytes, plaintext: bytes) -> typing.Tuple[bytes, bytes]:

        try:
            # Validate AAD
            if not isinstance(aad, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "AAD must be bytes", "aad")

            # Validate plaintext
            if not isinstance(plaintext, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Plaintext must be bytes", "plaintext")

            if len(plaintext) == 0:
                raise CipherSafeError(ApplicationCodes.INVALID_LENGTH, HTTPCodes.BAD_REQUEST, "Plaintext cannot be empty", "plaintext")

            # Generate 12-byte GCM nonce
            nonce = AESManager.generate_nonce()

            # Perform GCM encryption
            ciphertext_with_tag = self._aes.encrypt(nonce, bytes(plaintext), bytes(aad))

            # Validate ciphertext
            if not isinstance(ciphertext_with_tag, bytes) or len(ciphertext_with_tag) < 16:
                raise CipherSafeError(ApplicationCodes.INVALID_CIPHERTEXT, HTTPCodes.INTERNAL_SERVER_ERROR, "Ciphertext output invalid (missing GCM tag)", "ciphertext")

            return nonce, ciphertext_with_tag

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.CIPHERTEXT_AUTH_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "AES-GCM encryption failed", "ciphertext")


    """
        Decrypt and authenticate AES-256-GCM ciphertext.

        @param aad (bytes): Associated data that must match the value used for encryption.
        @param nonce (bytes): 12-byte nonce used during encryption.
        @param ciphertext_with_tag (bytes): Ciphertext concatenated with a 16-byte GCM tag.

        @require isinstance(aad, (bytes, bytearray))
        @require isinstance(nonce, (bytes, bytearray)) and len(nonce) == 12
        @require isinstance(ciphertext_with_tag, (bytes, bytearray)) and len(ciphertext_with_tag) >= 16

        @return bytes: The decrypted plaintext bytes if authentication succeeds.

        @ensures Returns the original plaintext when aad, nonce, key, and ciphertext_with_tag are valid; raises an error on authentication failure.
    """
    def decrypt(self, aad: bytes, nonce: bytes, ciphertext_with_tag: bytes) -> bytes:

        try:
            # Validate AAD
            if not isinstance(aad, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "AAD must be bytes", "aad")

            # Validate nonce
            if not isinstance(nonce, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_NONCE, HTTPCodes.BAD_REQUEST, "Nonce must be bytes", "nonce")

            if len(nonce) != CONSTANTS._AES_GCM_NONCE_LEN_BYTES:
                raise CipherSafeError(ApplicationCodes.INVALID_NONCE, HTTPCodes.BAD_REQUEST, "Nonce must be 12 bytes", "nonce")

            # Validate ciphertext
            if not isinstance(ciphertext_with_tag, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_CIPHERTEXT, HTTPCodes.BAD_REQUEST, "Ciphertext must be bytes", "ciphertext")

            if len(ciphertext_with_tag) < 16:
                raise CipherSafeError(ApplicationCodes.INVALID_CIPHERTEXT, HTTPCodes.BAD_REQUEST, "Ciphertext must include 16-byte GCM tag", "ciphertext")

            # Perform authenticated decryption
            plaintext = self._aes.decrypt(bytes(nonce), bytes(ciphertext_with_tag), bytes(aad))

            # Validate output type
            if not isinstance(plaintext, bytes):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.INTERNAL_SERVER_ERROR, "Plaintext output must be bytes", "plaintext")

            return plaintext

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.CIPHERTEXT_AUTH_ERROR, HTTPCodes.UNAUTHORIZED, "AES-GCM authentication failed", "ciphertext")


