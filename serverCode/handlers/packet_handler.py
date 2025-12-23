#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: packet_handler.py
    Author: Alex Biddle

    Description:
        Provides all packet-format validation, field checking, and server-response
        construction for CipherSafe's Four-Way Handshake. Ensures strict schema
        enforcement for every packet type, including Client Hello, Client Encrypted
        Request, Server Hello, Server Encrypted Response, Logout Confirmation, and
        Error Response packets. Implements Base64URL validation, protocol version
        checks, timestamp checks, signature format validation, AES-session-key rules,
        user-input constraints, and all size and type enforcement requirements.
"""


from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes
import capstone.constants as CONSTANTS
import capstone.handlers.sanitization_validation as VALIDATION


####################################################################################################
#                                         Packet Format Handlers
####################################################################################################

"""
    Provides helper methods to construct packets for server responses and packet formats for client 
    packet authentication. Each packet is returned as a dictionary ready for a digital signature 
    and or serialization.
"""
class PacketHandler:

    ################################################################################################
    #                                     GENERIC VALIDATION WRAPPERS
    ################################################################################################

    def _validate_protocol_version(self, value: str):
        VALIDATION.validate_string(value, ApplicationCodes.INVALID_PROTOCOL, "protocol_version")
        if value != CONSTANTS._PROTOCOL_VERSION:
            raise CipherSafeError(ApplicationCodes.INVALID_PROTOCOL, HTTPCodes.BAD_REQUEST, "Invalid protocol version.", "protocol_version")

    def _validate_request_type(self, value: str):
        VALIDATION.validate_string(value, ApplicationCodes.INVALID_REQUEST_TYPE, "request_type")
        VALIDATION.validate_in_set(value, CONSTANTS._ALLOWED_REQUEST_TYPES, ApplicationCodes.INVALID_REQUEST_TYPE, "request_type")

    def _validate_response_status(self, value: str):
        VALIDATION.validate_string(value, ApplicationCodes.INVALID_RESPONSE_STATUS, "response_status")
        VALIDATION.validate_in_set(value, CONSTANTS._ALLOWED_RESPONSE_STATUSES, ApplicationCodes.INVALID_RESPONSE_STATUS, "response_status")

    def _validate_username(self, value: str):
        VALIDATION.validate_string(value, ApplicationCodes.INVALID_USERNAME, "username")
        VALIDATION.validate_max_length(value, CONSTANTS._MAX_USERNAME_LEN, ApplicationCodes.INVALID_USERNAME, "username")

    def _validate_timestamp(self, value: str):
        VALIDATION.validate_iso8601(value, ApplicationCodes.INVALID_TIMESTAMP, "timestamp")

    def _validate_checksum_client(self, value: str):
        VALIDATION.validate_b64(value, ApplicationCodes.INVALID_BASE64URL, "client_checksum")

    def _validate_checksum_server(self, value: str):
        VALIDATION.validate_b64(value, ApplicationCodes.INVALID_BASE64URL, "server_checksum")

    def _validate_aes_session_key(self, value: str):
        VALIDATION.validate_b64(value, ApplicationCodes.INVALID_AES_SESSION_KEY, "server_aes_session_key")

    def _validate_key_identifier(self, value: str):
        VALIDATION.validate_string(value, ApplicationCodes.INVALID_KEY_IDENTIFIER, "server_key_identifier")

    def _validate_key_expiry(self, value: str):
        VALIDATION.validate_iso8601(value, ApplicationCodes.INVALID_KEY_EXPIRY, "server_key_expiry")

    def _validate_rsa_public_key(self, value: str):
        VALIDATION.validate_string(value, ApplicationCodes.INVALID_PUBLIC_KEY, "rsa_public_key")
        VALIDATION.validate_startswith(value, "-----BEGIN PUBLIC KEY-----", ApplicationCodes.INVALID_PUBLIC_KEY, "rsa_public_key")

    def _validate_ciphertext_client(self, value: str):
        VALIDATION.validate_b64(value, ApplicationCodes.INVALID_CIPHERTEXT, "client_ciphertext")
        VALIDATION.validate_byte_size(value, CONSTANTS._MAX_B64URL_BYTES, ApplicationCodes.INVALID_LENGTH, "client_ciphertext")

    def _validate_ciphertext_server(self, value: str):
        VALIDATION.validate_b64(value, ApplicationCodes.INVALID_CIPHERTEXT, "server_ciphertext")
        VALIDATION.validate_byte_size(value, CONSTANTS._MAX_B64URL_BYTES, ApplicationCodes.INVALID_LENGTH, "server_ciphertext")

    def _validate_digital_signature(self, value: str):
        VALIDATION.validate_b64(value, ApplicationCodes.INVALID_SIGNATURE_FORMAT, "server_digital_signature")

    def _validate_message(self, value: str):
        VALIDATION.validate_string(value, ApplicationCodes.INVALID_TYPE, "message")
        VALIDATION.validate_max_length(value, 512, ApplicationCodes.INVALID_LENGTH, "message")


    ################################################################################################
    #                              CLIENT REQUEST PACKET VALIDATION
    ################################################################################################

    """
        Validate the top-level structure of client-sent packets and route them to the
        appropriate detailed validator (Client Hello or Client Encrypted Request).

        @param packet (dict): Client-sent JSON object.
        @require isinstance(packet, dict)
        @ensures Proper packet type is detected and forwarded to the correct validator.
    """
    def check_client_request_packet_fields(self, packet: dict) -> None:
        try:

            # Ensure object type is dictionary
            if not isinstance(packet, dict):
                raise CipherSafeError(ApplicationCodes.INVALID_PACKET_STRUCTURE, HTTPCodes.BAD_REQUEST, "Invalid packet (expected dictionary).", "packet")

            # Identify packet type by field presence
            provided_fields = set(packet.keys())

            # Client Hello (Step 1)
            if CONSTANTS._CLIENT_HELLO_REQUIRED_FIELDS.issubset(provided_fields):
                self.validate_client_hello_packet_fields(packet)

            # Client Encrypted Request (Step 3)
            elif CONSTANTS._CLIENT_ENCRYPTED_REQUEST_REQUIRED_FIELDS.issubset(provided_fields):
                self.validate_client_encrypted_request_packet_fields(packet)
            else:
                raise CipherSafeError(ApplicationCodes.INVALID_PACKET_STRUCTURE, HTTPCodes.BAD_REQUEST, "Unrecognized client packet structure (missing required fields).", "packet")

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Internal error validating client request packet.", "packet")


    """
        Validate all required fields, types, protocols, and formats for Client Hello(Handshake Step 1).

        @param packet (dict): Client Hello JSON request.
        @require isinstance(packet, dict)
        @ensures Required fields exist, no unknown fields remain, and all field formats pass protocol-version, checksum, timestamp, username, and RSA-key checks.
    """
    def validate_client_hello_packet_fields(self, packet: dict) -> None:
        try:
            
            # Ensure all required fields exist
            for field in CONSTANTS._CLIENT_HELLO_REQUIRED_FIELDS:
                if field not in packet:
                    raise CipherSafeError(ApplicationCodes.MISSING_FIELDS, HTTPCodes.BAD_REQUEST, f"Missing required field '{field}' in ClientHello packet.", field)

            # Raise error for any unknown fields
            unknown_fields = set(packet.keys()) - CONSTANTS._CLIENT_HELLO_REQUIRED_FIELDS
            if unknown_fields:
                raise CipherSafeError(ApplicationCodes.UNKNOWN_FIELDS, HTTPCodes.BAD_REQUEST, f"Unknown fields detected in ClientHello packet: {', '.join(unknown_fields)}.", "packet")
            

            # Validate each field
            self._validate_protocol_version(packet["protocol_version"])
            self._validate_request_type(packet["request_type"])
            self._validate_username(packet["username"])
            self._validate_rsa_public_key(packet["client_rsa_public_key"])
            self._validate_timestamp(packet["timestamp"])
            self._validate_checksum_client(packet["client_checksum"])

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "Invalid ClientHello packet fields.", "packet")


    """
        Validate all required fields, types, and formats for Client Encrypted Request(Handshake Step 3).

        @param packet (dict): Client Encrypted Request JSON object.
        @require isinstance(packet, dict)
        @ensures AES-session-key, key-identifier, ciphertext, timestamp, and checksum fields are all validated for correct Base64URL formatting and size.
    """
    def validate_client_encrypted_request_packet_fields(self, packet: dict) -> None:
        try:
            
            # Ensure all required fields exist
            for field in CONSTANTS._CLIENT_ENCRYPTED_REQUEST_REQUIRED_FIELDS:
                if field not in packet:
                    raise CipherSafeError(ApplicationCodes.MISSING_FIELDS, HTTPCodes.BAD_REQUEST, f"Missing required field '{field}' in ClientEncryptedRequest packet.", field)

            # Raise error for any unknown fields
            unknown_fields = set(packet.keys()) - CONSTANTS._CLIENT_ENCRYPTED_REQUEST_REQUIRED_FIELDS
            if unknown_fields:
                raise CipherSafeError(ApplicationCodes.UNKNOWN_FIELDS, HTTPCodes.BAD_REQUEST, f"Unknown fields detected in ClientEncryptedRequest packet: {', '.join(unknown_fields)}.", "packet")

            # Validate each field using helper methods
            self._validate_protocol_version(packet["protocol_version"])
            self._validate_request_type(packet["request_type"])
            self._validate_username(packet["username"])
            self._validate_timestamp(packet["timestamp"])
            self._validate_checksum_client(packet["client_checksum"])
            self._validate_aes_session_key(packet["server_aes_session_key"])
            self._validate_key_identifier(packet["server_key_identifier"])
            self._validate_ciphertext_client(packet["client_ciphertext"])

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "Invalid ClientEncryptedRequest packet fields.", "packet")



    """
        Validate structure and field content for Server Hello (Handshake Step 2).

        @param packet (dict): Server Hello response dictionary.
        @require isinstance(packet, dict)
        @ensures Required fields exist, no unknown fields remain, and RSA key, AES key, checksum, signature, username, timestamp, and expiry formats are valid.
    """
    def validate_server_hello_response_packet_fields(self, packet: dict) -> None:
        try:

            # Ensure all required fields exist
            for field in CONSTANTS._SERVER_HELLO_REQUIRED_FIELDS:
                if field not in packet:
                    raise CipherSafeError(ApplicationCodes.MISSING_FIELDS, HTTPCodes.BAD_REQUEST, f"Missing required field '{field}' in ServerHello packet.", field)

            # Raise error for any unknown fields
            unknown_fields = set(packet.keys()) - CONSTANTS._SERVER_HELLO_REQUIRED_FIELDS
            if unknown_fields:
                raise CipherSafeError(ApplicationCodes.UNKNOWN_FIELDS, HTTPCodes.BAD_REQUEST, f"Unknown fields detected in ServerHello packet: {', '.join(unknown_fields)}.", "packet")

            # Validate each field using helper methods
            self._validate_protocol_version(packet["protocol_version"])
            self._validate_response_status(packet["response_status"])
            self._validate_username(packet["username"])
            self._validate_timestamp(packet["timestamp"])
            self._validate_checksum_server(packet["server_checksum"])
            self._validate_aes_session_key(packet["server_aes_session_key"])
            self._validate_rsa_public_key(packet["server_rsa_public_key"])
            self._validate_key_identifier(packet["server_key_identifier"])
            self._validate_key_expiry(packet["server_key_expiry"])
            self._validate_digital_signature(packet["server_digital_signature"])
            self._validate_ciphertext_server(packet["server_ciphertext"])

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "Invalid ServerHello packet fields.", "packet")



    """
        Validate field presence and formatting for Server Encrypted Response(Handshake Step 4).

        @param packet (dict): Server encrypted response packet.
        @require isinstance(packet, dict)
        @ensures Ciphertext, checksum, timestamp, signature, and protocol-version fields follow strict validation rules.
    """
    def validate_server_encrypted_response_packet_fields(self, packet: dict) -> None:
        try:

            # Ensure all required fields exist
            for field in CONSTANTS._SERVER_ENCRYPTED_RESPONSE_REQUIRED_FIELDS:
                if field not in packet:
                    raise CipherSafeError(ApplicationCodes.MISSING_FIELDS, HTTPCodes.BAD_REQUEST, f"Missing required field '{field}' in ServerEncryptedResponse packet.", field)

            # Raise error for any unknown fields
            unknown_fields = set(packet.keys()) - CONSTANTS._SERVER_ENCRYPTED_RESPONSE_REQUIRED_FIELDS
            if unknown_fields:
                raise CipherSafeError(ApplicationCodes.UNKNOWN_FIELDS, HTTPCodes.BAD_REQUEST, f"Unknown fields detected in ServerEncryptedResponse packet: {', '.join(unknown_fields)}.", "packet")

            # Validate each field using helper methods
            self._validate_protocol_version(packet["protocol_version"])
            self._validate_response_status(packet["response_status"])
            self._validate_username(packet["username"])
            self._validate_timestamp(packet["timestamp"])
            self._validate_checksum_server(packet["server_checksum"])
            self._validate_ciphertext_server(packet["server_ciphertext"])
            self._validate_digital_signature(packet["server_digital_signature"])

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "Invalid ServerEncryptedResponse packet fields.", "packet")


    """
        Validate a server logout confirmation packet.

        @param packet (dict): Logout response packet.
        @require isinstance(packet, dict)
        @ensures All required fields exist and no extraneous fields remain
    """
    def validate_server_logout_response_packet_fields(self, packet: dict) -> None:
        try:
            # Ensure all required fields exist
            for field in CONSTANTS._SERVER_LOGOUT_RESPONSE_REQUIRED_FIELDS:
                if field not in packet:
                    raise CipherSafeError(ApplicationCodes.MISSING_FIELDS, HTTPCodes.BAD_REQUEST, f"Missing required field '{field}' in ServerLogoutResponse packet.", field)

            # Raise error for any unknown fields
            unknown_fields = set(packet.keys()) - CONSTANTS._SERVER_LOGOUT_RESPONSE_REQUIRED_FIELDS
            if unknown_fields:
                raise CipherSafeError(ApplicationCodes.UNKNOWN_FIELDS, HTTPCodes.BAD_REQUEST, f"Unknown fields detected in ServerLogoutResponse packet: {', '.join(unknown_fields)}.", "packet")

            # Validate each field using helper methods
            self._validate_protocol_version(packet["protocol_version"])
            self._validate_response_status(packet["response_status"])
            self._validate_username(packet["username"])
            self._validate_timestamp(packet["timestamp"])
            self._validate_message(packet["message"])

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "Invalid ServerLogoutResponse packet fields.", "packet")



    """
        Validate a Server Error Response packet.

        @param packet (dict): Error packet to validate.
        @require isinstance(packet, dict)
        @ensures All required error fields exist, are valid types, and match formatting rules.
    """
    def validate_server_error_response_packet_fields(self, packet: dict) -> None:
        try:
            # Ensure all required fields exist
            for field in CONSTANTS._SERVER_ERROR_RESPONSE_REQUIRED_FIELDS:
                if field not in packet:
                    raise CipherSafeError(ApplicationCodes.MISSING_FIELDS, HTTPCodes.BAD_REQUEST, f"Missing required field '{field}' in ServerErrorResponse packet.", field)

            # Raise error for any unknown fields
            unknown_fields = set(packet.keys()) - CONSTANTS._SERVER_ERROR_RESPONSE_REQUIRED_FIELDS
            if unknown_fields:
                raise CipherSafeError(ApplicationCodes.UNKNOWN_FIELDS, HTTPCodes.BAD_REQUEST, f"Unknown fields detected in ServerErrorResponse packet: {', '.join(unknown_fields)}.", "packet")

            # Validate each field using helper methods
            self._validate_protocol_version(packet["protocol_version"])
            self._validate_response_status(packet["response_status"])
            self._validate_username(packet["username"])
            self._validate_timestamp(packet["timestamp"])
            self._validate_message(packet["message"])

            # error_code: non-empty string
            if not isinstance(packet["error_code"], str) or not packet["error_code"].strip():
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Invalid error_code in ServerErrorResponse packet.", "error_code")

            # field: must be string (may be empty)
            if not isinstance(packet["field"], str):
                raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Invalid field in ServerErrorResponse packet (must be string).", "field")

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, "Invalid ServerErrorResponse packet fields.", "packet")
        



    """
        Construct the complete Server Hello packet for Handshake Step 2.

        @param response_status (str): Status string ("success", etc.)
        @param username (str): Verified username.
        @param server_checksum (str): Base64URL checksum over Step 2 components.
        @param server_aes_session_key (str): RSA-OAEP wrapped AES session key.
        @param server_rsa_public_key (str): PEM-encoded server RSA public key.
        @param server_key_identifier (str): UUID of active RSA keypair.
        @param server_key_expiry (str): ISO8601Z timestamp marking key expiration.
        @param server_digital_signature (str): Base64URL RSA-PSS signature.
        @param server_ciphertext (str): Encrypted hello metadata.
        @param timestamp_iso (str): ISO8601Z timestamp for the packet.
        @require All parameters are non-empty strings.
        @return dict: Fully assembled Server Hello packet.
        @ensures Packet strictly matches the Step 2 schema before being returned.
    """
    def create_server_hello_response_packet(self, response_status: str, username: str, server_checksum: str, server_aes_session_key: str, server_rsa_public_key: str, server_key_identifier: str, server_key_expiry: str, server_digital_signature: str, server_ciphertext: str, timestamp_iso: str) -> dict:
        try:
            # Build Server Hello response dictionary
            packet = {
                "protocol_version": CONSTANTS._PROTOCOL_VERSION,
                "response_status": response_status,
                "username": username,
                "timestamp": timestamp_iso,
                "server_checksum": server_checksum,
                "server_aes_session_key": server_aes_session_key,
                "server_rsa_public_key": server_rsa_public_key,
                "server_key_identifier": server_key_identifier,
                "server_key_expiry": server_key_expiry,
                "server_digital_signature": server_digital_signature,
                "server_ciphertext": server_ciphertext 
            }

            self.validate_server_hello_response_packet_fields(packet)
            return packet

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Internal error creating ServerHello response packet.", "")



    """
        Construct the complete Server Encrypted Response packet for Handshake Step 4.

        @param username (str): Verified username.
        @param response_status (str): Status string.
        @param server_checksum (str): Base64URL checksum over encrypted content.
        @param server_ciphertext (str): AES-GCM encrypted payload.
        @param server_digital_signature (str): Base64URL RSA-PSS signature.
        @param timestamp_iso (str): ISO8601Z UTC timestamp.
        @require All parameters must be strings and properly formatted.
        @return dict: Fully assembled Step 4 response packet.
        @ensures Packet strictly matches Step 4 schema using all validation helpers.
    """
    def create_server_encrypted_response_packet(self, username: str, response_status: str, server_checksum: str, server_ciphertext: str, server_digital_signature: str, timestamp_iso: str) -> dict:
        try:

            # Structure Step 4 response dictionary
            packet = {
                "protocol_version": CONSTANTS._PROTOCOL_VERSION,
                "response_status": response_status,
                "username": username,
                "timestamp": timestamp_iso,
                "server_checksum": server_checksum,
                "server_ciphertext": server_ciphertext,
                "server_digital_signature": server_digital_signature
            }

            self.validate_server_encrypted_response_packet_fields(packet)
            return packet

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Internal error creating ServerEncryptedResponse packet.", "")



    """
        Construct a standardized logout confirmation packet.

        @param username (str): Username initiating logout.
        @require isinstance(username, str)
        @return dict: Canonical logout response packet.
        @ensures Packet contains protocol version, timestamp, success status, and message.
    """
    def create_logout_response_packet(self, username: str, timestamp_iso: str) -> dict:
        try:

            # Compose logout response dictionary
            packet = {
                "protocol_version": CONSTANTS._PROTOCOL_VERSION,
                "response_status": "success",
                "username": username,
                "timestamp": timestamp_iso,
                "message": "Client successfully logged out."
            }

            self.validate_server_logout_response_packet_fields(packet)
            return packet

        except CipherSafeError:
            raise
        except Exception:
            raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Internal error creating logout response packet.", "")