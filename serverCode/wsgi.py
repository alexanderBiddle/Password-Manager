#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
	WSGI entry point for the CipherSafe Flask application.
	Apache loads this file using mod_wsgi and calls `application`,
	which must reference the Flask app returned by create_app().
"""

import os
import sys


sys.path.insert(0, "/cslab/cgi-bin")


# Import the Flask app factory
from capstone.server import create_app

# mod_wsgi requires this symbol
application = create_app()

