#!/usr/bin/env python3
"""Coleta leve do estado das PONs; mantém só a leitura mais recente."""
import json
import os
import re
import shlex
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/var/lib/olt-vision"))
COMMUNITY = os.environ.get("SNMP_COMMUNITY", "")
INTERVAL = int(os.environ.get("FAST_POLL_INTERVAL", "120"))
TRAFFIC_INTERVAL = int(os.environ.get("TRAFFIC_POLL_INTERVAL", "60"))
OID = "1.3.6.1.4.1.2011.6.128.1.1.2.21.1.10"
IN32 = "1.3.6.1.2.1.2.2.1.10"
OUT32 = "1.3.6.1.2.1.2.2.1.16"
ENV_ROOT = Path(os.environ.get("OLT_ENV_ROOT", "/etc/olt-vision/olts"))

def configured_olts():
    return json.loads((ROOT / "olts.json").read_text(encoding="utf-8"))

def community_for(olt_id):
    path = ENV_ROOT / f"{olt_id}.env"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("SNMP_COMMUNITY="):
                values = shlex.split(line.partition("=")[2], comments=False)
                if len(values) == 1: return values[0]
    return COMMUNITY

def read_pons(host, community):
    cmd = ["snmpwalk", "-v2c", "-c", community, "-On", "-t", "2", "-r", "0", host, OID]
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=15)
    rows = {}
    for line in result.stdout.splitlines():
        match = re.match(rf"\.{re.escape(OID)}\.(\d+)\s+=\s+INTEGER:\s+(-?\d+)", line)
        if match: rows[match.group(1)] = "online" if match.group(2) == "1" else "offline"
    if not rows: raise RuntimeError(result.stderr.strip() or "Sem resposta SNMP")
    return rows

def read_counters(host, community, oid):
    command = ["snmpbulkwalk", "-v2c", "-c", community, "-On", "-Cr20", "-t", "2", "-r", "0", host, oid]
    result = subprocess.run(command, text=True, capture_output=True, timeout=20)
    rows = {}
    for line in result.stdout.splitlines():
        match = re.match(rf"\.{re.escape(oid)}\.(\d+)\s+=\s+Counter32:\s+(\d+)", line)
        if match: rows[match.group(1)] = int(match.group(2))
    if not rows: raise RuntimeError(result.stderr.strip() or "Sem contadores SNMP")
    return rows

def traffic_samples(host, community, previous):
    incoming = read_counters(host, community, IN32)
    outgoing = read_counters(host, community, OUT32)
    now = time.monotonic()
    samples = {}
    for index in incoming.keys() & outgoing.keys():
        old = previous.get(index)
        in_bps = out_bps = None
        if old and now > old[2]:
            elapsed = now - old[2]
            in_bps = ((incoming[index] - old[0]) % 2**32) * 8 / elapsed
            out_bps = ((outgoing[index] - old[1]) % 2**32) * 8 / elapsed
        samples[index] = {"in_octets":incoming[index], "out_octets":outgoing[index], "in_bps":in_bps, "out_bps":out_bps}
        previous[index] = (incoming[index], outgoing[index], now)
    return samples

def save(olt_id, statuses=None, error=None):
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    path = DATA_ROOT / f"{olt_id}.db"
    for attempt in range(8):
        try:
            with sqlite3.connect(path, timeout=10) as db:
                db.execute("PRAGMA busy_timeout=10000")
                db.execute("CREATE TABLE IF NOT EXISTS latest_fast_status (id INTEGER PRIMARY KEY CHECK(id=1), last_ok_at TEXT, last_attempt_at TEXT, pons_json TEXT, error TEXT)")
                now = datetime.now(timezone.utc).isoformat()
                if statuses is not None:
                    db.execute("INSERT INTO latest_fast_status(id,last_ok_at,last_attempt_at,pons_json,error) VALUES(1,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET last_ok_at=excluded.last_ok_at,last_attempt_at=excluded.last_attempt_at,pons_json=excluded.pons_json,error=NULL", (now,now,json.dumps(statuses)))
                else:
                    db.execute("INSERT INTO latest_fast_status(id,last_attempt_at,error) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,error=excluded.error", (now,error))
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 7: raise
            time.sleep(1 + attempt)

def save_traffic(olt_id, samples):
    path = DATA_ROOT / f"{olt_id}.db"
    for attempt in range(8):
        try:
            with sqlite3.connect(path, timeout=10) as db:
                db.execute("PRAGMA busy_timeout=10000")
                db.execute("CREATE TABLE IF NOT EXISTS latest_fast_traffic (id INTEGER PRIMARY KEY CHECK(id=1), last_ok_at TEXT, interfaces_json TEXT)")
                now = datetime.now(timezone.utc).isoformat()
                db.execute("INSERT INTO latest_fast_traffic(id,last_ok_at,interfaces_json) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET last_ok_at=excluded.last_ok_at,interfaces_json=excluded.interfaces_json", (now,json.dumps(samples)))
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 7: raise
            time.sleep(1 + attempt)

def main():
    previous = {}
    status_at = 0
    while True:
        started = time.monotonic()
        for olt in configured_olts():
            community = community_for(olt["id"])
            if started - status_at >= INTERVAL:
                try: save(olt["id"], statuses=read_pons(olt["host"], community))
                except Exception as exc:
                    try: save(olt["id"], error=str(exc))
                    except sqlite3.OperationalError: pass
            try: save_traffic(olt["id"], traffic_samples(olt["host"], community, previous.setdefault(olt["id"], {})))
            except Exception: pass
        if started - status_at >= INTERVAL: status_at = started
        time.sleep(max(0, TRAFFIC_INTERVAL - (time.monotonic() - started)))

if __name__ == "__main__": main()
