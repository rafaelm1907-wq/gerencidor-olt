#!/usr/bin/env python3
"""Cria, de forma idempotente, índices usados nas leituras do painel."""
import os
import sqlite3
import time
from pathlib import Path


data_root = Path(os.environ.get("DATA_ROOT", "/var/lib/olt-vision"))
for path in sorted(data_root.glob("*.db")):
    if path.name == "auth.db":
        continue
    started = time.monotonic()
    with sqlite3.connect(path, timeout=120) as db:
        db.execute("PRAGMA busy_timeout=120000")
        db.execute("CREATE INDEX IF NOT EXISTS idx_ont_reason_time "
                   "ON ont_samples(ont_id,poll_id) WHERE disconnect_reason IS NOT NULL")
    print(path.name, f"{time.monotonic() - started:.2f}s", flush=True)
