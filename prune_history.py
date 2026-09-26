#!/usr/bin/env python3
"""Aplica imediatamente a retenção histórica sem remover inventário ou estado atual."""
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


data_root = Path(os.environ.get("DATA_ROOT", "/var/lib/olt-vision"))
days = int(os.environ.get("HISTORY_DAYS", "2"))
cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
tables = ("ont_samples", "interface_samples", "pon_samples", "slot_samples",
          "snmp_raw_samples", "dashboard_snapshots", "telegram_alerts")

for path in sorted(data_root.glob("*.db")):
    if path.name == "auth.db":
        continue
    started = time.monotonic()
    before = path.stat().st_size
    with sqlite3.connect(path, timeout=120) as db:
        db.execute("PRAGMA busy_timeout=120000")
        old_polls = db.execute("SELECT count(*) FROM poll_runs WHERE collected_at < ?", (cutoff,)).fetchone()[0]
        if old_polls:
            db.execute("CREATE TEMP TABLE old_polls(id INTEGER PRIMARY KEY)")
            db.execute("INSERT INTO old_polls SELECT id FROM poll_runs WHERE collected_at < ?", (cutoff,))
            for table in tables:
                db.execute(f"DELETE FROM {table} WHERE poll_id IN (SELECT id FROM old_polls)")
            db.execute("DELETE FROM poll_runs WHERE id IN (SELECT id FROM old_polls)")
        # Eventos não são usados para reconstruir o estado atual.
        db.execute("DELETE FROM events WHERE occurred_at < ?", (cutoff,))
        db.commit()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.execute("VACUUM")
    after = path.stat().st_size
    print(path.name, "polls removidos", old_polls,
          f"{before / 1048576:.1f} MiB -> {after / 1048576:.1f} MiB",
          f"em {time.monotonic() - started:.1f}s", flush=True)
