#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: RSA_manager.py
    Author: Alex Biddle

    Description:
        Manages CipherSafe's RSA-2048 keypair generation, storage, loading, and
        automatic rotation. Provides secure signing, verification, and RSA-OAEP
        encryption/decryption for AES session keys. Ensures all key operations
        use proper locking, strict validation, and structured error propagation.
"""

import json
import uuid
import threading
from datetime import datetime, timezone, timedelta
import sys, os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from capstone.handlers.error_handler import HTTPCodes, ApplicationCodes, CipherSafeError
import capstone.handlers.sanitization_validation as VALIDATION
import capstone.constants as CONSTANTS


class RSAManager:

    """
        Initialize an RSAManager instance and load or generate the active RSA-2048 keypair.

        @param private_key_path (str): Filesystem path where the private key (PEM) is stored.
        @param private_key_data_path (str): Path where non-sensitive key metadata JSON is stored.
        @require isinstance(private_key_path, str) and private_key_path.strip() != ""
        @require isinstance(private_key_data_path, str) and private_key_data_path.strip() != ""
        @ensures A valid RSA-2048 private key and metadata are available in memory.
    """
    def __init__(self, private_key_path: str, private_key_data_path: str):

        try:
            # Record where the encrypted private key will live
            if not isinstance(private_key_path, str) or not private_key_path.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_PATH, HTTPCodes.INTERNAL_SERVER_ERROR, "private_key_path must be a non-empty string", "private_key_path")

            # Store metadata path next to the private key (no secrets inside)
            if not isinstance(private_key_data_path, str) or not private_key_data_path.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_PATH, HTTPCodes.INTERNAL_SERVER_ERROR, "private_key_data_path must be a non-empty string", "private_key_data_path")

            self._private_key_path: str = private_key_path
            self._private_key_data_path: str = private_key_data_path

            # Lock to use for threading 
            self._lock = threading.RLock()

            # Key validity window (24 hours by default for rotation metadata)
            self._key_validity_hours: int = 24

            # Internal RSA private key object and metadata
            self._private_key = None
            self._key_identifier: str = None
            self._key_creation_time: str = None
            self._key_expiry_time: str = None

            # Ensure the private key is loaded or generated and rotation metadata is set
            self._ensure_private_key_loaded()
            self._check_key_rotation()

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_INIT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to initialize RSAManager", "rsa_manager")



    """
        Ensure the RSA private key and metadata are loaded into memory.
        @require private_key_path and private_key_data_path must reference readable files if they exist
        @ensures self._private_key, self._key_identifier, self._key_creation_time, and self._key_expiry_time are valid.
    """
    def _ensure_private_key_loaded(self) -> None:
        try:
            # If the already loaded, nothing to do
            if self._private_key is not None and all([self._key_identifier, self._key_creation_time, self._key_expiry_time]):
                return

            # Guard file operations with the lock
            with self._lock:

                # If key file or metadata missing, generate a new keypair
                key_exists = os.path.isfile(self._private_key_path)
                key_data_exists = os.path.isfile(self._private_key_data_path)

                if not key_exists or not key_data_exists:
                    self._generate_and_store_private_key()
                    return

                # Otherwise, load existing private key and metadata
                self._load_private_key_from_disk()
                self._read_rsa_key_data_file()

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to load or initialize RSA private key", "rsa_key")

        


    """
        Generate a new RSA-2048 private key and write PEM + metadata to disk.

        @require private_key_path and its directory must be writable
        @require key size = 2048 and exponent = 65537
        @ensures Key is written in PKCS#8 format with restrictive permissions and valid metadata is created.
    """
    def _generate_and_store_private_key(self) -> None:
        try:
            with self._lock:

                # Generate RSA private key (2048-bit modulus, exponent 65537)
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

                # Serialize to PKCS#8 PEM without encryption (filesystem permissions must protect it)
                private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

                # Ensure directory exists
                key_dir = os.path.dirname(self._private_key_path)
                if key_dir and not os.path.isdir(key_dir):
                    os.makedirs(key_dir, exist_ok=True)

                # Write key 
                with open(self._private_key_path, "wb") as f:
                    f.write(private_key_bytes)
                
                
                # Compute metadata fields
                key_identifier = uuid.uuid4().hex
                creation_iso = VALIDATION.get_timestamp_iso8601z()
                expiry_dt = VALIDATION.parse_timestamp(creation_iso) + timedelta(hours=self._key_validity_hours)
                expiry_iso = expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                VALIDATION.validate_iso8601(expiry_iso, ApplicationCodes.INVALID_TIMESTAMP, "key_expiry_time")

                metadata = {
                    "key_identifier": key_identifier,
                    "key_creation_time": creation_iso,
                    "key_expiry_time": expiry_iso,
                }

                # Write metadata JSON (non-secret)
                with open(self._private_key_data_path, "w", encoding="utf-8") as f:
                    json.dump(metadata, f, indent=4)

                # Update in-memory attributes
                self._private_key = private_key
                self._key_identifier = key_identifier
                self._key_creation_time = metadata["key_creation_time"]
                self._key_expiry_time = metadata["key_expiry_time"]

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_KEY_GENERATION_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed to generate or store RSA private key", "rsa_key")




    """
        Load the RSA private key from disk into memory.

        @require private_key_path must exist and contain a valid PEM-encoded RSA key
        @ensures self._private_key is a valid RSAPrivateKey instance.
    """
    def _load_private_key_from_disk(self) -> None:
        try:

            # Check that the file exists
            if not os.path.isfile(self._private_key_path):
                raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA private key file not found", "private_key_path")

            # Read private key from the file
            with open(self._private_key_path, "rb") as f:
                key_data = f.read()

            # Ensure the file isn't empty
            if not key_data:
                raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA private key file is empty", "private_key_path")

             # Load the private key
            private_key = serialization.load_pem_private_key(key_data, password=None)

            # Ensure the key is of the correct object
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Loaded key is not a valid RSA private key", "rsa_key")

            # Set in-memory reference
            self._private_key = private_key

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed parsing RSA private key from disk", "rsa_key")



    """
        Load RSA key metadata (identifier, creation time, expiry time) from JSON.

        @require private_key_data_path must reference a valid JSON file
        @require JSON must contain key_identifier, key_creation_time, key_expiry_time
        @ensures Metadata fields are fully populated and validated.
    """
    def _read_rsa_key_data_file(self) -> None:    
        try:

            # Ensure the path exists 
            if not os.path.isfile(self._private_key_data_path):
                raise CipherSafeError(ApplicationCodes.RSA_KEY_METADATA_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA key data file not found", "private_key_data_path")

            # Read key data from file
            with open(self._private_key_data_path, "r", encoding="utf-8") as f:
                key_data = json.load(f)

            # Ensure the data was read in properly
            if not isinstance(key_data, dict):
                raise CipherSafeError(ApplicationCodes.RSA_KEY_METADATA_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA key_data must be a JSON object", "rsa_metadata")

            # Populate fields if present
            key_identifier = key_data.get("key_identifier")
            key_creation_time = key_data.get("key_creation_time")
            key_expiry_time = key_data.get("key_expiry_time")

            if not isinstance(key_identifier, str) or not key_identifier.strip():
                raise CipherSafeError(ApplicationCodes.RSA_KEY_METADATA_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Missing key_identifier in RSA key data", "key_identifier")

            if not isinstance(key_creation_time, str) or not key_creation_time.strip():
                raise CipherSafeError(ApplicationCodes.RSA_KEY_METADATA_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Missing key_creation_time in RSA key data", "key_creation_time")

            if not isinstance(key_expiry_time, str) or not key_expiry_time.strip():
                raise CipherSafeError(ApplicationCodes.RSA_KEY_METADATA_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Missing key_expiry_time in RSA key data", "key_expiry_time")

            # Validate timestamp data
            VALIDATION.validate_iso8601(key_creation_time, ApplicationCodes.INVALID_TIMESTAMP, "key_creation_time")
            VALIDATION.validate_iso8601(key_expiry_time, ApplicationCodes.INVALID_TIMESTAMP, "key_expiry_time")

            # Assign the data
            self._key_identifier = key_identifier
            self._key_creation_time = key_creation_time
            self._key_expiry_time = key_expiry_time

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_KEY_METADATA_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed loading RSA metadata from disk", "rsa_metadata")




    """
        Check whether the active RSA keypair has expired and rotate if necessary.
        @require key metadata fields must be present and valid ISO8601Z strings
        @ensures A fresh RSA keypair and updated metadata exist when rotation is required.
    """
    def _check_key_rotation(self) -> None:
        try:
            # Ensure we have metadata
            if not self._key_expiry_time:
                return

            # Parse expiry timestamp as naive UTC ISO8601Z
            expiry_dt = VALIDATION.parse_timestamp(self._key_expiry_time)
            now_dt = VALIDATION.parse_timestamp(VALIDATION.get_timestamp_iso8601z())


            # If key is expired, generate and store a new keypair
            if now_dt >= expiry_dt:
                self._generate_and_store_private_key()

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_KEY_ROTATION_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed during RSA key rotation check", "rsa_key_rotation")





    """
        Retrieve the active RSA public key and associated metadata.

        @require self._private_key must be loaded and valid

        @return dict: {
            'rsa_public_key': PEM-formatted public key,
            'key_identifier': identifier string,
            'key_creation_time': ISO8601Z timestamp,
            'key_expiry_time': ISO8601Z timestamp
        }

        @ensures Key rotation is checked prior to returning metadata.
    """
    def get_public_key_data(self) -> dict:
        try:
            # Ensure key material and metadata are loaded and valid
            self._ensure_private_key_loaded()
            self._check_key_rotation()

            # Check that the private key exists
            if self._private_key is None:
                raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA private key not loaded", "rsa_key")

            # Get the public key 
            public_key = self._private_key.public_key()

            # Serialize public key to PEM on one line
            public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")

            return {
                "rsa_public_key": public_pem,
                "key_identifier": self._key_identifier,
                "key_creation_time": self._key_creation_time,
                "key_expiry_time": self._key_expiry_time,
            }

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Failed building RSA public key data", "rsa_public_key")


    """
        Sign arbitrary data using RSA-PSS with SHA-256.

        @param data (bytes): The message to sign.
        @require isinstance(data, (bytes, bytearray))
        @require self._private_key must be a valid RSAPrivateKey
        @return bytes: The RSA-PSS signature.
        @ensures Signature is produced using RSA-PSS(SHA-256) under correct key state.
    """
    def sign_data_with_private_key(self, data: bytes) -> bytes:
        try:
            
            # Validate input
            if not isinstance(data, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Data to sign must be bytes", "data")

            # Ensure key present and not expired
            self._ensure_private_key_loaded()
            self._check_key_rotation()

            # Ensure the private key exists
            if self._private_key is None:
                raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA private key not loaded", "rsa_key")

            # Perform signing under lock (private key access)
            with self._lock:
                signature = self._private_key.sign(bytes(data), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                
            # Check that the encrypted data is valid
            if not isinstance(signature, bytes) or len(signature) == 0:
                raise CipherSafeError(ApplicationCodes.RSA_SIGN_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA-PSS signing produced empty signature", "signature")

            return signature

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_SIGN_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA-PSS signing failure", "signature")




    """
        Verify an RSA-PSS signature using the active public key.

        @param data (bytes): Original signed message.
        @param signature (bytes): RSA-PSS signature to verify.
        @require isinstance(data, (bytes, bytearray))
        @require isinstance(signature, (bytes, bytearray))
        @require self._private_key must be valid to derive the public key
        @return bool: True if signature is valid, False otherwise.
        @ensures Verification uses RSA-PSS(SHA-256) and constant-time public key operations.
    """
    def verify_signature_with_public_key(self, data: bytes, signature: bytes) -> bool:      
        try:

            #  Validate inputs
            if not isinstance(data, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Data must be bytes", "data")
            if not isinstance(signature, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Signature must be bytes", "signature")


            # Ensure key present and not expired
            self._ensure_private_key_loaded()
            self._check_key_rotation()

            # Ensure the private key exists
            if self._private_key is None:
                raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA private key not loaded", "rsa_key")

             # Perform signing under lock (private key access)
            with self._lock:
                
                # Get public key for verification
                public_key = self._private_key.public_key()

            # Check that thepublic key is the right object
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise CipherSafeError(ApplicationCodes.INVALID_PUBLIC_KEY, HTTPCodes.BAD_REQUEST, "Parsed key is not an RSA public key", "public_key_pem")

            # Attempt verification
            try:
                public_key.verify(bytes(signature), bytes(data), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                return True
            
            except Exception:
                # Verification failure is not an internal error; it is a normal false result
                return False

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_VERIFY_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error during RSA-PSS verification", "signature")



    """
        Encrypt data using RSA-OAEP (SHA-256) with the client's public key.

        @param data (bytes): 
        @param client_rsa_public_pem (str): Client-provided PEM-encoded RSA public key.
        @require isinstance(client_rsa_public_pem, str) and client_rsa_public_pem.strip() != ""
        @return bytes: RSA-OAEP encrypted data
        @ensures Returned ciphertext is produced using RSA-OAEP with SHA-256.
    """
    def encrypt(self, data: bytes, client_rsa_public_pem: str ) -> bytes:
        try:
            # Validate AES key material
            if not isinstance(data, bytes):
                raise CipherSafeError(ApplicationCodes.INVALID_AES_KEY, HTTPCodes.BAD_REQUEST, "Encrypted Data must be bytes", "data")
            
            # Validate client RSA public key PEM
            if not isinstance(client_rsa_public_pem, str) or not client_rsa_public_pem.strip():
                raise CipherSafeError(ApplicationCodes.INVALID_PUBLIC_KEY, HTTPCodes.BAD_REQUEST, "Client RSA public key PEM must be a non-empty string", "client_rsa_public_key")

            try:
                client_public_key = serialization.load_pem_public_key(client_rsa_public_pem.encode("utf-8"))
            except Exception:
                raise CipherSafeError(ApplicationCodes.INVALID_PUBLIC_KEY, HTTPCodes.BAD_REQUEST, "Failed to parse client RSA public key PEM", "client_rsa_public_key")

            # Ensure we have a valid RSAPublicKey instance
            if not isinstance(client_public_key, rsa.RSAPublicKey):
                raise CipherSafeError(ApplicationCodes.INVALID_PUBLIC_KEY, HTTPCodes.BAD_REQUEST, "Parsed client key is not an RSA public key", "client_rsa_public_key")

            # Encrypt using RSA-OAEP with SHA-256
            encrypted_data = client_public_key.encrypt(bytes(data), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            
            if not isinstance(encrypted_data, bytes) or len(encrypted_data) == 0:
                raise CipherSafeError(ApplicationCodes.RSA_ENCRYPT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA-OAEP encryption returned empty ciphertext", "encrypted_data")

            return encrypted_data

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_ENCRYPT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA-OAEP encryption failure", "encrypted_data")



    """
        Decrypt an RSA-OAEP encrypted data using the RSA private key.

        @param encrypted_data (bytes): RSA-OAEP ciphertext to decrypt.
        @require isinstance(encrypted_data, (bytes, bytearray)) and len(encrypted_data) > 0
        @require self._private_key must be valid and loaded
        @return bytes: The decrypted data 
        @ensures Decryption uses RSA-OAEP(SHA-256) and output length is validated.
    """
    def decrypt(self, encrypted_data: bytes) -> bytes:
        try:
            # Validate ciphertext input
            if not isinstance(encrypted_data, (bytes, bytearray)):
                raise CipherSafeError(ApplicationCodes.INVALID_CIPHERTEXT, HTTPCodes.BAD_REQUEST, "Encrypted data must be bytes", "encrypted_data")

            if len(encrypted_data) == 0:
                raise CipherSafeError(ApplicationCodes.INVALID_CIPHERTEXT, HTTPCodes.BAD_REQUEST, "Encrypted Data cannot be empty", "encrypted_data")

            # Ensure key present and not expired
            self._ensure_private_key_loaded()
            self._check_key_rotation()

            # Check that the private key exists
            if self._private_key is None:
                raise CipherSafeError(ApplicationCodes.RSA_KEY_LOAD_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA private key not loaded", "rsa_key")

             # Decrypt with private key under lock
            with self._lock:
                aes_key = self._private_key.decrypt(bytes(encrypted_data), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

            return aes_key

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.RSA_DECRYPT_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "RSA-OAEP decryption failure", "wrapped_key")
