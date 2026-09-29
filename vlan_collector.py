#!/usr/bin/env python3
"""Coletor independente e conservador do vínculo S/F/P + ONT + VLAN."""
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from app import DB_PATH, telnet_vlan_data

INTERVAL = int(os.environ.get("VLAN_POLL_INTERVAL", "1800"))
START_DELAY = int(os.environ.get("START_DELAY", "0")) + int(os.environ.get("VLAN_DELAY_OFFSET", "180"))
LOCK_WAIT = int(os.environ.get("VLAN_LOCK_WAIT", "90"))
RETRY_DELAY = int(os.environ.get("VLAN_RETRY_DELAY", "120"))
CLI_LOCK_PATH = Path(os.environ.get("CLI_LOCK_PATH", str(Path(DB_PATH).with_suffix(".cli.lock"))))
ONT_PRIORITY_PATH = Path(os.environ.get("ONT_PRIORITY_PATH", str(Path(DB_PATH).with_suffix(".ont-priority"))))


def latest_pons(db):
    row = db.execute("SELECT payload_json FROM dashboard_snapshots WHERE json_array_length(json_extract(payload_json,'$.pons')) > 0 ORDER BY poll_id DESC LIMIT 1").fetchone()
    return json.loads(row[0]).get("pons", []) if row else []


def persist_valid(db, vlan_map, collected_at):
    db.execute("CREATE TABLE IF NOT EXISTS latest_vlan_status (id INTEGER PRIMARY KEY CHECK(id=1), collected_at TEXT NOT NULL, payload_json TEXT NOT NULL, link_count INTEGER NOT NULL)")
    payload = {f"{sfp}:{ont}": sorted(vlans) for (sfp, ont), vlans in vlan_map.items()}
    db.execute("INSERT INTO latest_vlan_status(id,collected_at,payload_json,link_count) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET collected_at=excluded.collected_at,payload_json=excluded.payload_json,link_count=excluded.link_count", (collected_at, json.dumps(payload), len(payload)))
    db.commit()


def ont_has_priority():
    try:
        if time.time() - ONT_PRIORITY_PATH.stat().st_mtime > 900:
            ONT_PRIORITY_PATH.unlink()
            return False
        return True
    except FileNotFoundError:
        return False

def acquire_vlan_slot():
    """A VLAN espera no máximo LOCK_WAIT e nunca passa à frente de ONTs."""
    import fcntl
    CLI_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + LOCK_WAIT
    lock_file = open(CLI_LOCK_PATH, "a+b")
    while time.monotonic() < deadline:
        if ont_has_priority():
            time.sleep(5)
            continue
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            time.sleep(5)
            continue
        if not ont_has_priority():
            return lock_file
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        time.sleep(5)
    lock_file.close()
    return None

def collect_once():
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        db.execute("PRAGMA busy_timeout=15000")
        pons = latest_pons(db)
    if not pons:
        raise RuntimeError("Aguardando descoberta das PONs")
    lock_file = acquire_vlan_slot()
    if lock_file is None:
        print(f"VLAN adiada: ONTs/CLI ocupada por mais de {LOCK_WAIT}s", flush=True)
        return False
    try:
        vlan_map = telnet_vlan_data(pons)
    finally:
        import fcntl
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()
    if not vlan_map:
        raise RuntimeError("A CLI não retornou vínculos de VLAN; último inventário válido foi preservado")
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        db.execute("PRAGMA busy_timeout=15000")
        persist_valid(db, vlan_map, now)
    print(f"VLANs: {len(vlan_map)} vínculos persistidos em {now}", flush=True)
    return True


if __name__ == "__main__":
    if START_DELAY:
        time.sleep(START_DELAY)
    retry_delay = RETRY_DELAY
    while True:
        started = time.monotonic()
        try:
            completed = collect_once()
            if completed:
                retry_delay = RETRY_DELAY
                next_wait = INTERVAL
            else:
                next_wait = retry_delay
                retry_delay = min(600, retry_delay * 2)
        except Exception as exc:
            print(f"Coleta de VLAN falhou: {exc}", flush=True)
            next_wait = min(600, retry_delay)
            retry_delay = min(600, retry_delay * 2)
        time.sleep(max(5, next_wait - (time.monotonic() - started)))
