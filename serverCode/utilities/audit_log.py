#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from datetime import datetime, timezone, timedelta
import json
import os
import sys
import typing
import threading

_AUDIT_FILE = os.path.join(os.path.dirname(__file__), "audit.log")


#####################################################################################################################################################################

"""
    Provides persistent structured audit logging for CipherSafe.
"""
class AuditLog:

	def __init__(self):
		self._lock = threading.RLock()
		

	def event(self, **kv: typing.Any):

		# Construct ISO8601Z timestamp
		ts = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

		# Append timestamp to event
		record = {"timestamp": ts}
		record.update(kv)
        
		with self._lock:
			try:
				with open(_AUDIT_FILE, "a") as f:
					json.dump(record, f, ensure_ascii=False)
					f.write("\n")
			
			except Exception as e:
				print(f"Audit log write error: {e}", file=sys.stderr)
