#!/usr/bin/env python3
"""Inventário horário e de baixa prioridade dos módulos ópticos das PONs."""
import fcntl
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from app import DB_PATH, OLT_HOST, cli_session

INTERVAL = int(os.environ.get("MODULE_POLL_INTERVAL", "3600"))
LOCK_WAIT = int(os.environ.get("MODULE_LOCK_WAIT", "300"))
RETRY_DELAY = int(os.environ.get("MODULE_RETRY_DELAY", "300"))
CLI_LOCK_PATH = Path(os.environ.get("CLI_LOCK_PATH", str(Path(DB_PATH).with_suffix(".cli.lock"))))
ONT_PRIORITY_PATH = Path(os.environ.get("ONT_PRIORITY_PATH", str(Path(DB_PATH).with_suffix(".ont-priority"))))

FIELDS = {
    "last_down_cause": "Last down cause", "last_up_time": "Last up time", "last_down_time": "Last down time",
    "vendor_name": "Vendor name", "vendor_rev": "Vendor rev", "vendor_oui": "Vendor OUI",
    "vendor_pn": "Vendor PN", "vendor_sn": "Vendor SN", "date_code": "Date Code",
    "module_type": "Module type", "module_subtype": "Module sub-type",
    "max_distance_km": "Max Distance(Km)", "max_rate_kbps": "Max rate(Kbps)",
    "wavelength_nm": "Wave length(nm)", "connector": "Connector",
}


def parse_module_state(text):
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text or "").replace("\r", "")
    result = {}
    for key, label in FIELDS.items():
        match = re.search(rf"^\s*{re.escape(label)}\s+(.+?)\s*$", clean, re.M | re.I)
        if match:
            value = match.group(1).strip()
            if value and value not in ("-", "Unspecified"):
                result[key] = value
    return result


def latest_pons():
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        row = db.execute("SELECT payload_json FROM dashboard_snapshots WHERE json_array_length(json_extract(payload_json,'$.pons')) > 0 ORDER BY poll_id DESC LIMIT 1").fetchone()
    return json.loads(row[0]).get("pons", []) if row else []


def ont_has_priority():
    try:
        if time.time() - ONT_PRIORITY_PATH.stat().st_mtime > 900:
            ONT_PRIORITY_PATH.unlink()
            return False
        return True
    except FileNotFoundError:
        return False


def acquire_slot():
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


def collect_modules(pons):
    sfps = sorted({pon.get("sfp") for pon in pons if pon.get("sfp")},
                  key=lambda value: tuple(int(part) for part in value.split("/")))
    inventory = {}
    with cli_session(60) as session:
        session.enter_config()
        active_board = None
        for sfp in sfps:
            frame, slot, port = sfp.split("/")
            board = f"{frame}/{slot}"
            if board != active_board:
                if active_board is not None:
                    session.command("quit")
                session.command(f"interface gpon {board}")
                active_board = board
            parsed = parse_module_state(session.command(f"display port state {port}"))
            if parsed:
                inventory[sfp] = parsed
        if active_board is not None:
            session.command("quit")
    return inventory


def persist(inventory):
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        db.execute("PRAGMA busy_timeout=15000")
        db.execute("CREATE TABLE IF NOT EXISTS latest_module_inventory (id INTEGER PRIMARY KEY CHECK(id=1), collected_at TEXT NOT NULL, payload_json TEXT NOT NULL, module_count INTEGER NOT NULL)")
        previous = db.execute("SELECT payload_json FROM latest_module_inventory WHERE id=1").fetchone()
        merged = json.loads(previous[0]) if previous else {}
        merged.update(inventory)
        db.execute("INSERT INTO latest_module_inventory(id,collected_at,payload_json,module_count) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET collected_at=excluded.collected_at,payload_json=excluded.payload_json,module_count=excluded.module_count",
                   (now, json.dumps(merged, ensure_ascii=False), len(merged)))
    return now, len(merged)


def collect_once():
    pons = latest_pons()
    if not pons:
        raise RuntimeError("Aguardando descoberta das PONs")
    lock_file = acquire_slot()
    if lock_file is None:
        print(f"{OLT_HOST} módulos adiados: fila CLI ocupada", flush=True)
        return False
    try:
        inventory = collect_modules(pons)
    finally:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()
    if not inventory:
        raise RuntimeError("A CLI não retornou inventário de módulos")
    collected_at, count = persist(inventory)
    print(f"{OLT_HOST} módulos: {count} PONs inventariadas em {collected_at}", flush=True)
    return True


if __name__ == "__main__":
    while True:
        started = time.monotonic()
        try:
            completed = collect_once()
            wait = INTERVAL if completed else RETRY_DELAY
        except Exception as exc:
            print(f"{OLT_HOST} falha no inventário de módulos: {exc}", flush=True)
            wait = RETRY_DELAY
        time.sleep(max(1, wait - (time.monotonic() - started)))
