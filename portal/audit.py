"""Append-only audit trail in JSON lines. Only listed fields are ever written."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime
from pathlib import Path

ALLOWED_FIELDS = {
    "event",
    "request_id",
    "actor",
    "requester",
    "role",
    "duration_seconds",
    "justification",
    "reason",
    "session_name",
    "session_expires_at",
}


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def write(self, at: datetime, **fields) -> None:
        unknown = set(fields) - ALLOWED_FIELDS
        if unknown:
            # Guards against someone passing credentials in by accident.
            raise ValueError(f"field(s) not allowed in audit log: {sorted(unknown)}")
        line = json.dumps({"at": at.isoformat(), **fields}, sort_keys=True)
        with self._lock:
            # "a" mode only appends; nothing in the app rewrites or truncates this file.
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
