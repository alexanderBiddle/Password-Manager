#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    File name: server.py
    Author: Alex Biddle

    Description:
        Entry point for the CipherSafe backend. Configures the Flask application,
        cryptographic managers, session handler, audit logging, error handling,
        handshake processing, authorization logic, vault operations, and periodic
        session-expiration cleanup. Exposes all API routes including Client Hello,
        Client Encrypted Request, and Logout. Normalizes all exceptions through the
        centralized ErrorHandler to maintain consistent packet structures.
"""


import sys, os
import time
import threading
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, current_app

# Import logging module
from capstone.utilities.audit_log import AuditLog

# Import encryption managers
from capstone.encryption.RSA_manager import RSAManager
from capstone.encryption.AES_manager import AESManager
from capstone.encryption.argon2id_manager import Argon2idManager
from capstone.encryption.checksum_manager import ChecksumManager

# Import handlers
from capstone.handlers.session_handler import ServerSessionHandler
from capstone.handlers.handshake_handler import HandshakeHandler
from capstone.handlers.authorization_handler import AuthorizationHandler
from capstone.handlers.vault_handler import VaultHandler
from capstone.handlers.error_handler import ErrorHandler
from capstone.handlers.packet_handler import PacketHandler
from capstone.handlers.error_handler import ApplicationCodes, HTTPCodes, CipherSafeError
from capstone.database.database_object import Database


#####################################################################################################################################################################

"""
    Create and configure the full CipherSafe Flask application.

    @require Flask must be importable and environment supports cryptographic modules
    @return Flask: Fully configured Flask application instance.
    @ensures All cryptographic managers, session handlers, route handlers, audit log, packet handler, and background cleanup worker are initialized.
"""
def create_app() -> Flask:

    app = Flask(__name__)

    # Ensures all Flask routes work 
    app.config["APPLICATION_ROOT"] = "/capstone2"

    # Configure Flask security secret key
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

    # Enforce a 256 KB payload limit to align with packet validation caps
    app.config["MAX_CONTENT_LENGTH"] = 262_144

    # Set a 15-minute session lifetime window (session TTL policies live in the session handler)
    app.permanent_session_lifetime = timedelta(minutes=15)

    ###############################################################
    # Absolute paths for deployment on /cslab/cgi-bin/capstone/
    ###############################################################

    # Absolute root directory for the project
    CAPSTONE_ROOT = "/cslab/cgi-bin/capstone"

    # Absolute path to database credentials
    DATABASE_CREDENTIALS_PATH = os.path.join(CAPSTONE_ROOT, "database", "database_credentials.htaccess")

    # Absolute path to RSA key directory
    KEYS_DIR = os.path.join(CAPSTONE_ROOT, "keys")

    # Ensure keys directory exists (safe even if already created)
    os.makedirs(KEYS_DIR, exist_ok=True)

    # Absolute RSA key paths
    RSA_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "server_private_key.pem")
    RSA_KEY_DATA_PATH = os.path.join(KEYS_DIR, "server_key_data.json")

    
    ################################################################################################
    # Initialize Handlers
    ################################################################################################

    # Initialize Encryption Managers
    rsa_manager = RSAManager(private_key_path=RSA_PRIVATE_KEY_PATH, private_key_data_path=RSA_KEY_DATA_PATH)
    aes_manager = AESManager()
    argon2_manager = Argon2idManager()
    checksum_manager = ChecksumManager()

    # Database with explicit path
    app.database = Database(credentials_path=DATABASE_CREDENTIALS_PATH)

    # Instantiate audit log for non-sensitive operational logging
    app.audit_log = AuditLog()

    # Centralized error handler
    app.error_handler = ErrorHandler()

    # Packet formatter/builder (used by handlers to form server packets)
    app.packet_handler = PacketHandler()

    # Unified session manager with crypto managers injected
    app.session_handler = ServerSessionHandler(rsa_manager=rsa_manager, aes_manager=aes_manager, argon2_manager=argon2_manager, checksum_manager=checksum_manager)

    # Handler for loggging in and signing up
    authorization_handler = AuthorizationHandler(app.session_handler, app.database)
    
    # Handler for vault retrival/storage
    vault_handler = VaultHandler(app.session_handler, app.audit_log, app.database)

    # Provide the session manager to the handshake handler
    app.handshake_handler = HandshakeHandler(session_handler=app.session_handler, authorization_handler=authorization_handler, vault_handler=vault_handler)
  


    ################################################################################################
    # Background Session Cleanup (TTL enforcement/logouts)
    ################################################################################################

    """
        Background daemon that periodically purges expired sessions.

        @require Session manager must be initialized
        @ensures Expired sessions are removed, logout packets generated, and events logged every 60 seconds without blocking the main server thread.
    """
    def _session_cleanup_worker():

        # Loop forever as a daemon worker
        while True:
            try:
                # Ask session manager to cleanup expired sessions; expect a list of informational dicts or events
                logout_packets_or_events = app.session_handler.cleanup_expired_sessions()

                # Log each produced event for traceability (avoid misusing the error handler here)
                for event in logout_packets_or_events:
                    
                    # Record audit entry with structured info
                    app.audit_log.event(event="session_cleanup",username=str(event.get("username", "")), context="cleanup_expired_sessions", detail=str(event),)

                # Sleep for 60 seconds between scans
                time.sleep(60)

            except Exception as e:
                
                # Route unexpected exceptions through centralized error handler
                clean_packet, status = app.error_handler.handle_server_error(e, context="session_cleanup_worker")
                
                # Best-effort log of the clean packet for operators
                app.audit_log.event(event="cleanup_exception", username="", context="cleanup_worker", detail=str(clean_packet))

                # Back off briefly before retrying
                time.sleep(60)

    # Start the cleanup thread in daemon mode so it won't block process exit
    cleanup_thread = threading.Thread(target=_session_cleanup_worker, daemon=True)
    cleanup_thread.start()




    ################################################################################################
    # ROUTES
    ################################################################################################

    """
        Handle Step 1: Client Hello → Return Server Hello (Step 2).

        @require Request method is POST and Content-Type is application/json
        @require JSON body must parse into a dict
        @return flask.Response: JSON packet + status code
        @ensures Delegates to handshake handler, normalizes errors through ErrorHandler.
    """
    @app.post("/api/handshake/hello")
    def handshake_hello():
        try:
           
            # Enforce POST method explicitly 
            if request.method != "POST":
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, f"Invalid HTTP method: {request.method}","http_method")

            # Require JSON content type
            content_type = request.headers.get("Content-Type", "").lower()
            if "application/json" not in content_type:
                raise CipherSafeError(ApplicationCodes.INVALID_CONTENT_TYPE, HTTPCodes.BAD_REQUEST, f"Invalid Content-Type header: {content_type}", "Content-Type")

           # Parse JSON body strictly
            try:
                client_hello_request = request.get_json(force=True)
            except Exception:
                raise CipherSafeError(ApplicationCodes.MALFORMED_JSON, HTTPCodes.BAD_REQUEST, "Failed to parse JSON body for Client Hello", "body")

            # Validate object type is dict
            if not isinstance(client_hello_request, dict):
                raise CipherSafeError(ApplicationCodes.INVALID_PACKET_STRUCTURE, HTTPCodes.BAD_REQUEST, "Invalid JSON structure (expected object)", "request_obj")

            # Delegate to handshake handler for Step 2 response
            resp_obj, http_status = app.handshake_handler.respond_to_client_hello_request(client_hello_request)

            # Return successful response packet
            return jsonify(resp_obj), http_status

        except Exception as e:
            # Ensure any unhandled errors are normalized by the centralized handler
            clean_packet, status = app.error_handler.handle_server_error(e, context="handshake_hello_error")
            return jsonify(clean_packet), status



    """
        Handle Step 3: Client Encrypted Request → Return Server Encrypted Response (Step 4).

        @require POST method, JSON body, dict structure
        @return flask.Response: JSON encrypted response packet
        @ensures Delegates to handshake handler, validates all fields, and returns Step 4 packet.
    """
    @app.post("/api/handshake/secure")
    def handshake_secure():
        try:
            
            # Enforce POST method
            if request.method != "POST":
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, f"Invalid HTTP method: {request.method}", "http_method")

            # Require JSON content type
            content_type = request.headers.get("Content-Type", "").lower()
            if "application/json" not in content_type:
                raise CipherSafeError(ApplicationCodes.INVALID_CONTENT_TYPE, HTTPCodes.BAD_REQUEST, f"Invalid Content-Type header: {content_type}", "Content-Type")

            # Parse JSON body strictly
            try:
                client_encrypted_request = request.get_json(force=True)
            except Exception:
                raise CipherSafeError(ApplicationCodes.MALFORMED_JSON, HTTPCodes.BAD_REQUEST, "Failed to parse JSON body for Client Encrypted Request", "body")

            # Validate object type is dict
            if not isinstance(client_encrypted_request, dict):
                raise CipherSafeError(ApplicationCodes.INVALID_PACKET_STRUCTURE, HTTPCodes.BAD_REQUEST, "Invalid JSON structure (expected object)", "request_obj")

            # Delegate to handshake handler for Step 4 response
            resp_obj, http_status = app.handshake_handler.respond_to_client_encrypted_request(client_encrypted_request)

            # Return successful encrypted response packet
            return jsonify(resp_obj), http_status

        # Normalize unhandled errors
        except Exception as e:
            clean_packet, status = app.error_handler.handle_server_error(e, context="handshake_secure_error")
            return jsonify(clean_packet), status


    """
        Handle explicit client logout requests.

        @require POST method and valid JSON body
        @return flask.Response: Logout confirmation JSON packet
        @ensures Session is invalidated and a canonical logout response is returned.
    """
    @app.post("/capstone2/api/logout")
    def logout():

        try:
            # Enforce POST method
            if request.method != "POST":
                raise CipherSafeError(ApplicationCodes.INVALID_REQUEST, HTTPCodes.BAD_REQUEST, f"Invalid HTTP method: {request.method}", "http_method")

            # Require JSON content type
            content_type = request.headers.get("Content-Type", "").lower()
            if "application/json" not in content_type:
                raise CipherSafeError(ApplicationCodes.INVALID_CONTENT_TYPE, HTTPCodes.BAD_REQUEST, f"Invalid Content-Type header: {content_type}", "Content-Type")

            # Parse JSON body strictly
            try:
                client_logout_request = request.get_json(force=True)
            except Exception:
                raise CipherSafeError(ApplicationCodes.MALFORMED_JSON, HTTPCodes.BAD_REQUEST, "Failed to parse JSON body for Logout", "body")

            # Validate object type is dict
            if not isinstance(client_logout_request, dict):
                raise CipherSafeError(ApplicationCodes.INVALID_PACKET_STRUCTURE, HTTPCodes.BAD_REQUEST, "Invalid JSON structure (expected object)", "request_obj")

            # Delegate to handshake handler logout flow
            resp_obj, http_status = app.handshake_handler.logout(client_logout_request)

            # Return logout confirmation
            return jsonify(resp_obj), http_status

        # Normalize unhandled errors
        except Exception as e:
            clean_packet, status = app.error_handler.handle_server_error(e, context="logout_error")
            return jsonify(clean_packet), status
        

    ################################################################################################
    # GLOBAL ERROR HANDLERS
    ################################################################################################


    """
        413 Payload Too Large exception into a CipherSafe error packet.

        @param _e (Exception): Raw 413 exception.
        @require _e is an Exception type
        @return flask.Response: Standardized CipherSafe error packet + HTTP code
        @ensures Oversized payload errors are always returned in a consistent format.
    """
    @app.errorhandler(413)
    def handle_payload_too_large(_e):
        
        # Build a normalized error response
        e = CipherSafeError(ApplicationCodes.INVALID_LENGTH, HTTPCodes.BAD_REQUEST, "Payload exceeds maximum size limit", "body")

        # Delegate to centralized error handler
        clean_packet, status = app.error_handler.handle_server_error(e, context="payload_too_large")

        # Return standardized response
        return jsonify(clean_packet), status


    """
        Catch-all handler for any unexpected exception raised during request processing.

        @param e (Exception): Unhandled exception.
        @require e is Exception
        @return flask.Response: Standardized CipherSafe error packet + HTTP code
        @ensures All unexpected exceptions are logged and normalized through ErrorHandler.
    """
    @app.errorhandler(Exception)
    def handle_internal_error(e: Exception):

        # Delegate to centralized error handler
        clean_packet, status = app.error_handler.handle_server_error(e, context="global_error_handler")

        # Return standardized response
        return jsonify(clean_packet), status

    # Return the configured Flask app
    return app



    
   