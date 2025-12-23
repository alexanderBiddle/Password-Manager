#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: sanitization_validation.py
    Author: Alex Biddle

    Description:
        Provides all encoding, decoding, parsing, and general type-conversion
        utilities for CipherSafe's cryptographic and network layers, as well as
        reusable field-level validation helpers for the Four-Way Handshake.
        Includes Base64URL conversions, UTF-8 helpers, JSON serialization methods,
        AES/RSA type conversions, UUID parsing, timestamp parsing, integer coercion,
        and strict field validation for protocol_version, request_type,
        response_status, usernames, timestamps, checksums, ciphertexts, AES session
        keys, key identifiers, and digital signatures.

        Ensures strict input validation and raises CipherSafeError for all malformed
        or non-conforming data types processed during request handling.
"""

import base64
import typing
import json
import uuid
from datetime import datetime, timezone

from capstone.handlers.error_handler import CipherSafeError, ApplicationCodes, HTTPCodes
import capstone.constants as CONSTANTS


####################################################################################################
#                                   Base64URL Encoding / Decoding
####################################################################################################

"""
    Convert a Base64URL string into raw bytes.

    @param field_name (str): Logical field name for context in error messages.
    @param b64u_text (Any): Base64URL-encoded string to decode.
    @require b64u_text is a non-empty string
    @return bytes: Decoded byte sequence.
    @ensures Padding is normalized and invalid base64url input raises CipherSafeError.
"""
def decode_base64url_to_bytes(field_name: str, b64u_text: typing.Any) -> bytes:
    try:
        # Validate input with generic validators
        validate_string(b64u_text, ApplicationCodes.INVALID_TYPE, field_name)
        validate_b64(b64u_text, ApplicationCodes.INVALID_BASE64URL, field_name)

        # Add padding if necessary (base64url allows stripped "=")
        padded = b64u_text + "=" * ((4 - len(b64u_text) % 4) % 4)

        # Decode base64url text into bytes
        decoded_bytes = base64.urlsafe_b64decode(padded)

        # Validate output type
        if not isinstance(decoded_bytes, (bytes, bytearray)):
            raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, f"{field_name} decode failed", field_name)

        return bytes(decoded_bytes)

    except CipherSafeError:
        raise
    except Exception:
        raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, f"Invalid base64url for {field_name}", field_name)



"""
    Convert raw bytes into a Base64URL string without padding.

    @param raw (bytes): Bytes to encode.
    @require raw is bytes or bytearray
    @return str: Base64URL-encoded ASCII string without '=' padding.
    @ensures Output string is safe for URL transport and JSON serialization.
"""
def encode_bytes_to_base64url(raw: bytes) -> str:
    try:
        # Validate input type
        if not isinstance(raw, (bytes, bytearray)):
            raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "b64url encode expects bytes", "raw")

        # Perform base64url encoding and strip padding
        return base64.urlsafe_b64encode(bytes(raw)).decode("ascii").rstrip("=")

    except CipherSafeError:
        raise
    except Exception:
        raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected error during base64url encoding", "raw")



####################################################################################################
#                                   UTF-8 / JSON Conversions
####################################################################################################

"""
    Convert raw bytes into a UTF-8 decoded string.

    @param raw_bytes (bytes): UTF-8 encoded bytes.
    @require raw_bytes is bytes or bytearray
    @return str: UTF-8 decoded text.
    @ensures Raises CipherSafeError on invalid UTF-8 sequences.
"""
def decode_bytes_to_utf8_text(raw_bytes: bytes) -> str:
    try:
        # Validate input type
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Input must be bytes for UTF-8 decode", "raw_bytes")

        # Decode to text
        return raw_bytes.decode("utf-8")

    except CipherSafeError:
        raise
    except Exception:
        raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Invalid UTF-8 byte sequence", "raw_bytes")



"""
    Convert UTF-8 text into raw bytes.

    @param text (str): Input string.
    @require text is a string
    @return bytes: UTF-8 encoded byte sequence.
    @ensures Raises CipherSafeError on encoding failure.
"""
def encode_utf8_text_to_bytes(text: str) -> bytes:
    try:
        # Validate input type
        if not isinstance(text, str):
            raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Input must be string", "text")

        # Encode to bytes
        return text.encode("utf-8")

    except CipherSafeError:
        raise
    except Exception:
        raise CipherSafeError(ApplicationCodes.INTERNAL_SERVER_ERROR, HTTPCodes.INTERNAL_SERVER_ERROR, "Unexpected UTF-8 encoding error", "text")



"""
    Encode a dictionary into compact UTF-8 JSON bytes.

    @param data (dict): JSON-serializable dictionary.
    @require data is a dict
    @return bytes: UTF-8 encoded JSON payload.
    @ensures Raises error on non-serializable or malformed input.
"""
def encode_dict_to_json_bytes(data: typing.Dict[str, typing.Any]) -> bytes:
    try:
        # Validate input type
        if not isinstance(data, dict):
            raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Input must be dict", "data")

        # Serialize to JSON and encode to bytes
        return json.dumps(data, separators=(",", ":")).encode("utf-8")

    except CipherSafeError:
        raise
    except Exception:
        raise CipherSafeError(ApplicationCodes.MALFORMED_JSON, HTTPCodes.BAD_REQUEST, "Failed to serialize JSON payload", "data")



"""
    Convert UTF-8 JSON bytes into a Python dictionary.

    @param json_bytes (bytes): Raw JSON bytes.
    @require json_bytes is bytes or bytearray
    @return dict: Parsed JSON object.
    @ensures Raises CipherSafeError on malformed or non-object JSON values.
"""
def decode_json_bytes_to_dict(json_bytes: bytes) -> dict:
    try:
        # Validate input type
        if not isinstance(json_bytes, (bytes, bytearray)):
            raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Input must be bytes", "json_bytes")

        # Decode UTF-8 then parse JSON
        obj = json.loads(json_bytes.decode("utf-8"))

        # Validate output type
        if not isinstance(obj, dict):
            raise CipherSafeError(ApplicationCodes.MALFORMED_JSON, HTTPCodes.BAD_REQUEST, "Expected JSON object", "json_bytes")

        return obj

    except CipherSafeError:
        raise
    except Exception:
        raise CipherSafeError(ApplicationCodes.MALFORMED_JSON, HTTPCodes.BAD_REQUEST, "Malformed JSON payload", "json_bytes")



####################################################################################################
#                                   Generalized Type Parsers
####################################################################################################

"""
    Parse a UUID string into a uuid.UUID object.

    @param value (str): String representation of a UUID.
    @require value is a string
    @return uuid.UUID: Parsed UUID.
    @ensures Invalid UUID input raises CipherSafeError.
"""
def parse_uuid(value: str) -> uuid.UUID:
    try:
        # Validate type
        validate_string(value, ApplicationCodes.INVALID_TYPE, "uuid")

        return uuid.UUID(value)

    except CipherSafeError:
        raise
    except Exception:
        raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Invalid UUID format", "uuid")



"""
    Parse a strict ISO8601Z timestamp into a UTC-aware datetime object.

    @param value (str): Timestamp ending with 'Z'.
    @require value is a string ending with 'Z'
    @return datetime: Parsed UTC datetime.
    @ensures Raises CipherSafeError on invalid timestamp formatting.
"""
def parse_timestamp(value: str) -> datetime:
    try:
        # Strip whitespace
        cleaned = value.strip()
        
        # Validate type first
        validate_iso8601(cleaned, ApplicationCodes.INVALID_TIMESTAMP, "timestamp")

        # Parse strict ISO8601Z: YYYY-MM-DDTHH:MM:SSZ
        parsed = datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%SZ")

        # Force UTC timezone
        return parsed.replace(tzinfo=timezone.utc)

    except CipherSafeError:
        raise
    except Exception:
        raise CipherSafeError(ApplicationCodes.INVALID_TIMESTAMP, HTTPCodes.BAD_REQUEST, "Invalid ISO8601Z timestamp", "timestamp")



"""
    Convert a numeric value or numeric string into an integer.

    @param value (Any): Value to convert.
    @require value must be convertible via int()
    @return int: Integer representation.
    @ensures Raises CipherSafeError if conversion fails.
"""
def coerce_to_int(value: typing.Any) -> int:
    try:
        return int(value)

    except CipherSafeError:
        raise
    except Exception:
        raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Value cannot be coerced to int", "value")



####################################################################################################
#                               GENERIC VALIDATORS (REUSABLE)
####################################################################################################

"""
    Function: Validate that a value is a non-empty string.

    @param: typing.Any - value to be validated
    @param: ApplicationCodes - application-level error type to raise if validation fails
    @param: str - field_name identifying the failing field
    @require: value must be a string with at least one non-whitespace character
    @ensures: raises CipherSafeError if value is not a valid non-empty string
"""
def validate_string(value: typing.Any, application_code, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise CipherSafeError(application_code, HTTPCodes.BAD_REQUEST, f"{field_name} must be a non-empty string.", field_name)



"""
    Function: Validate that a string does not exceed a maximum length.

    @param: str - value to be validated
    @param: int - max_len specifying the maximum allowed characters
    @param: ApplicationCodes - application-level error type to raise if validation fails
    @param: str - field_name identifying the failing field
    @require: value must be a string
    @ensures: raises CipherSafeError if value length exceeds max_len
"""
def validate_max_length(value: str, max_len: int, application_code, field_name: str) -> None:
    if len(value) > max_len:
        raise CipherSafeError(application_code, HTTPCodes.BAD_REQUEST, f"{field_name} exceeds maximum length ({max_len}).", field_name)



"""
    Function: Validate that a string matches a regular expression exactly.

    @param: str - value to be validated
    @param: regex - compiled regex pattern to enforce fullmatch
    @param: ApplicationCodes - application-level error type to raise if validation fails
    @param: str - field_name identifying the failing field
    @require: value must be a string
    @ensures: raises CipherSafeError if value does not match regex
"""
def validate_regex(value: str, regex, application_code, field_name: str) -> None:
    if not regex.fullmatch(value):
        raise CipherSafeError(application_code, HTTPCodes.BAD_REQUEST, f"{field_name} has invalid format.", field_name)



"""
    Function: Validate that a value belongs to an allowed set.

    @param: str - value to be validated
    @param: set - allowed_set containing permitted values
    @param: ApplicationCodes - application-level error type to raise if validation fails
    @param: str - field_name identifying the failing field
    @require: value must be a string
    @ensures: raises CipherSafeError if value is not in allowed_set
"""
def validate_in_set(value: str, allowed_set: set, application_code, field_name: str) -> None:
    if value not in allowed_set:
        raise CipherSafeError(application_code, HTTPCodes.BAD_REQUEST, f"Invalid {field_name}: '{value}'.", field_name)



"""
    Function: Validate that a string starts with a required prefix.

    @param: str - value to be validated
    @param: str - prefix the value must begin with
    @param: ApplicationCodes - application-level error type to raise on failure
    @param: str - field_name identifying the failing field
    @require: value must be a string
    @ensures: raises CipherSafeError if value does not start with prefix
"""
def validate_startswith(value: str, prefix: str, application_code, field_name: str) -> None:
    if not value.startswith(prefix):
        raise CipherSafeError(application_code, HTTPCodes.BAD_REQUEST, f"{field_name} missing required prefix.", field_name)



"""
    Function: Validate that a string is Base64URL formatted.

    @param: str - value to be validated
    @param: ApplicationCodes - application-level error type to raise on failure
    @param: str - field_name identifying the failing field
    @require: value must be a string
    @ensures: raises CipherSafeError if value is not valid Base64URL
"""
def validate_b64(value: str, application_code, field_name: str) -> None:
    if not isinstance(value, str) or not CONSTANTS._BASE64URL_RX.match(value):
        raise CipherSafeError(application_code, HTTPCodes.BAD_REQUEST, f"{field_name} must be Base64URL.", field_name)



"""
    Function: Validate ciphertext length does not exceed allowed bytes (Base64URL encoded length).

    @param: str - value to be validated
    @param: int - max_bytes specifying the encoded-length limit
    @param: ApplicationCodes - application-level error type for failures
    @param: str - field_name identifying the failing field
    @require: value must already be validated as Base64URL
    @ensures: raises CipherSafeError if encoded ciphertext exceeds max_bytes
"""
def validate_byte_size(value: str, max_bytes: int, application_code, field_name: str) -> None:
    if len(value) > max_bytes:
        raise CipherSafeError(application_code, HTTPCodes.BAD_REQUEST, f"{field_name} exceeds maximum allowed size.", field_name)



"""
    Function: Validate that a value is a strict ISO8601Z timestamp.

    @param: str - value containing timestamp
    @param: ApplicationCodes - application-level error type to raise on failure
    @param: str - field_name identifying the failing field
    @require: value must be a string ending with 'Z'
    @ensures: raises CipherSafeError if timestamp does not match ISO8601Z pattern
"""
def validate_iso8601(value: str, application_code, field_name: str) -> None:
    if not isinstance(value, str) or not CONSTANTS._ISO8601Z.fullmatch(value):
        raise CipherSafeError(application_code, HTTPCodes.BAD_REQUEST, f"{value} must be ISO8601Z timestamp.", field_name)
    



"""
    Function: Generate a strict ISO8601Z UTC timestamp for the CipherSafe protocol.

    @ensures: Returns timestamp in exact format YYYY-MM-DDTHH:MM:SSZ
    @returns: str - ISO8601Z formatted UTC timestamp with no fractional seconds.
"""
def get_timestamp_iso8601z() -> str:

    # Get current UTC time without fractional seconds
    now = datetime.now(timezone.utc).replace(microsecond=0)
    
    # Produce ISO8601 without offset, force 'Z'
    ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Validate timestamp using the project-wide validator
    validate_iso8601(ts, ApplicationCodes.INVALID_TIMESTAMP, "timestamp")

    return ts


"""
    Ensure all required fields are present in the payload.

    @param payload (dict): Incoming JSON payload.
    @param required_fields (set[str]): Required field names.
    @param error_code (ApplicationCodes): Error code to raise.
    @param field_context (str): Name of the payload being validated.

    @ensures All required fields exist or raises CipherSafeError.
"""
def validate_required_fields(payload: dict, required_fields: set, error_code: str, field_context: str) -> None:
    
    # Validate parameters
    if not isinstance(payload, dict):
        raise CipherSafeError(ApplicationCodes.INVALID_TYPE, HTTPCodes.BAD_REQUEST, "Payload must be a JSON object.", field_context)

    missing = required_fields - set(payload.keys())
    if missing:
        raise CipherSafeError(error_code,HTTPCodes.BAD_REQUEST,f"Missing required fields: {', '.join(missing)}", field_context)



"""
    Ensure no unknown or unapproved fields exist in payload.

    @param payload (dict): Incoming data.
    @param allowed_fields (set[str]): Allowed field names.
    @param error_code (ApplicationCodes): Error code to raise.
    @param field_context (str): Name of the payload.

    @ensures No unknown fields or raises CipherSafeError.
"""
def validate_no_extra_fields(payload: dict, allowed_fields: set, error_code: str, field_context: str) -> None:
    extra = set(payload.keys()) - allowed_fields
    if extra:
        raise CipherSafeError(error_code, HTTPCodes.BAD_REQUEST, f"Unknown fields in payload: {', '.join(extra)}", field_context)