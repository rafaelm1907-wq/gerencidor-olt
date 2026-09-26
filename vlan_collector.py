#!/usr/bin/env python3
"""Coletor independente e conservador do vínculo S/F/P + ONT + VLAN."""
import json
import os
import sqlite3
import time
from datetime import datetime, timezone

from app import DB_PATH, telnet_vlan_data

INTERVAL = int(os.environ.get("VLAN_POLL_INTERVAL", "1800"))
START_DELAY = int(os.environ.get("START_DELAY", "0")) + int(os.environ.get("VLAN_DELAY_OFFSET", "180"))


def latest_pons(db):
    row = db.execute("SELECT payload_json FROM dashboard_snapshots WHERE json_array_length(json_extract(payload_json,'$.pons')) > 0 ORDER BY poll_id DESC LIMIT 1").fetchone()
    return json.loads(row[0]).get("pons", []) if row else []


def persist_valid(db, vlan_map, collected_at):
    db.execute("CREATE TABLE IF NOT EXISTS latest_vlan_status (id INTEGER PRIMARY KEY CHECK(id=1), collected_at TEXT NOT NULL, payload_json TEXT NOT NULL, link_count INTEGER NOT NULL)")
    payload = {f"{sfp}:{ont}": sorted(vlans) for (sfp, ont), vlans in vlan_map.items()}
    db.execute("INSERT INTO latest_vlan_status(id,collected_at,payload_json,link_count) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET collected_at=excluded.collected_at,payload_json=excluded.payload_json,link_count=excluded.link_count", (collected_at, json.dumps(payload), len(payload)))
    db.commit()


def collect_once():
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        db.execute("PRAGMA busy_timeout=15000")
        pons = latest_pons(db)
    if not pons:
        raise RuntimeError("Aguardando descoberta das PONs")
    vlan_map = telnet_vlan_data(pons)
    if not vlan_map:
        raise RuntimeError("A CLI não retornou vínculos de VLAN; último inventário válido foi preservado")
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        db.execute("PRAGMA busy_timeout=15000")
        persist_valid(db, vlan_map, now)
    print(f"VLANs: {len(vlan_map)} vínculos persistidos em {now}", flush=True)


if __name__ == "__main__":
    if START_DELAY:
        time.sleep(START_DELAY)
    while True:
        started = time.monotonic()
        try:
            collect_once()
        except Exception as exc:
            print(f"Coleta de VLAN falhou: {exc}", flush=True)
        time.sleep(max(5, INTERVAL - (time.monotonic() - started)))
