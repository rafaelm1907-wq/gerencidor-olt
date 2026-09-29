#!/usr/bin/env python3
"""Painel de monitoramento Huawei OLT: dependências apenas da biblioteca padrão."""
import json, os, re, sqlite3, subprocess, threading, time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from huawei_telnet import HuaweiTelnet
from huawei_ssh import HuaweiSSH

OLT_HOST = os.environ.get("OLT_HOST", "")
COMMUNITY = os.environ.get("SNMP_COMMUNITY", "")
INTERVAL = int(os.environ.get("POLL_INTERVAL", "120"))
DB_PATH = os.environ.get("DATABASE_PATH", "/var/lib/olt-vision/olt-vision.db")
SERVE_HTTP = os.environ.get("SERVE_HTTP", "1") == "1"
START_DELAY = int(os.environ.get("START_DELAY", "0"))
COLLECTOR_LOCK_PATH = os.environ.get("COLLECTOR_LOCK_PATH", "")
HISTORY_DAYS = int(os.environ.get("HISTORY_DAYS", "2"))
OLT_CONFIG_PATH = Path(__file__).with_name("olts.json")
OLT_CONFIG = next((item for item in json.loads(OLT_CONFIG_PATH.read_text(encoding="utf-8")) if item["host"] == OLT_HOST), {}) if OLT_CONFIG_PATH.exists() else {}
TELNET_ONT_SOURCE = OLT_CONFIG.get("ont_source") in ("telnet", "ssh", "cli")
TELNET_VLAN_SOURCE = OLT_CONFIG.get("vlan_source") in ("telnet", "ssh", "cli")
TELNET_USERNAME = os.environ.get("TELNET_USERNAME", "")
TELNET_PASSWORD = os.environ.get("TELNET_PASSWORD", "")
ACCESS_PROTOCOL = os.environ.get("ACCESS_PROTOCOL", OLT_CONFIG.get("access_protocol", "telnet")).lower()
ACCESS_USERNAME = os.environ.get("ACCESS_USERNAME", TELNET_USERNAME)
ACCESS_PASSWORD = os.environ.get("ACCESS_PASSWORD", TELNET_PASSWORD)
ACCESS_PORT = int(os.environ.get("ACCESS_PORT", "22" if ACCESS_PROTOCOL == "ssh" else "23"))
TELNET_ONT_OIDS = ("ont_rx", "ont_disconnect", "ont_status", "ont_temp")

def cli_session(timeout=45):
    cls = HuaweiSSH if ACCESS_PROTOCOL == "ssh" else HuaweiTelnet
    return cls(OLT_HOST, ACCESS_USERNAME, ACCESS_PASSWORD, port=ACCESS_PORT, timeout=timeout)

OIDS = {
    "pon_status": "1.3.6.1.4.1.2011.6.128.1.1.2.21.1.10",
    "pon_bias": "1.3.6.1.4.1.2011.6.128.1.1.2.23.1.3",
    "pon_laser": "1.3.6.1.4.1.2011.6.128.1.1.2.21.1.9",
    "pon_temp": "1.3.6.1.4.1.2011.6.128.1.1.2.23.1.1",
    "pon_type": "1.3.6.1.4.1.2011.6.128.1.1.2.22.1.28",
    "pon_tx": "1.3.6.1.4.1.2011.6.128.1.1.2.23.1.4",
    "pon_voltage": "1.3.6.1.4.1.2011.6.128.1.1.2.23.1.2",
    "if_status": "1.3.6.1.2.1.2.2.1.8",
    "if_name": "1.3.6.1.2.1.31.1.1.1.1",
    "if_alias": "1.3.6.1.2.1.31.1.1.1.18",
    "if_description": "1.3.6.1.2.1.2.2.1.2",
    "if_in": "1.3.6.1.2.1.31.1.1.1.6",
    "if_out": "1.3.6.1.2.1.31.1.1.1.10",
    "if_in32": "1.3.6.1.2.1.2.2.1.10",
    "if_out32": "1.3.6.1.2.1.2.2.1.16",
    "uptime": "1.3.6.1.2.1.1.3.0",
    "slot_temp": "1.3.6.1.4.1.2011.6.3.3.2.1.13",
    "board_temp": "1.3.6.1.4.1.2011.2.6.7.1.1.2.1.10",
    "board_cpu": "1.3.6.1.4.1.2011.2.6.7.1.1.2.1.5.0",
    "board_fan": "1.3.6.1.4.1.2011.6.1.1.5.1.9",
    "ont_description": "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.9",
    "ont_serial": "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3",
    "ont_rx": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4",
    "ont_disconnect": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.24",
    "ont_macs": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.21",
    "ont_status": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15",
    "ont_temp": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.1",
}
CACHE = {"at": 0, "data": {"status": "Aguardando primeira coleta"}}
PREVIOUS_COUNTERS = {}
POLL_LOCK = threading.Lock()
DISCONNECT_REASONS = {
    1: "LOS — perda de sinal", 2: "LOSi/LOBi — perda de sinal ou de burst da ONT",
    3: "LOFI — perda de quadro", 4: "SFI — falha de sinal",
    5: "LOAI — perda de confirmação", 6: "LOAMI — perda de PLOAM",
    7: "Falha ao desativar a ONT", 8: "ONT desativada com sucesso",
    9: "ONT reiniciada", 10: "ONT registrada novamente",
    11: "Falha de pop-up", 13: "Dying gasp — perda de energia na ONT",
    15: "LOKI — perda de sincronismo da chave",
    18: "ONT desativada devido ao anel", 30: "Módulo óptico da ONT desligado",
    31: "ONT reiniciada por comando", 32: "ONT reiniciada pelo botão de reset",
    33: "ONT reiniciada pelo software", 34: "ONT desativada por ataque de broadcast",
    35: "Falha na verificação do operador", 37: "ONT rogue detectada por ela própria",
}

def disconnect_reason_text(code):
    if code is None or code == -1: return "Sem informação"
    return f"{DISCONNECT_REASONS.get(code, 'Motivo não mapeado')} (código {code})"

def pon_identity(index, if_name=None):
    """Prefere o ifName informado pela OLT; decodifica o ifIndex como reserva."""
    match = re.search(r"(?:GPON|XGPON|XGSPON)\s+(\d+)/(\d+)/(\d+)", if_name or "", re.I)
    if match:
        frame, slot, port = map(int, match.groups())
    else:
        try:
            offset = int(index) - 4194304000
            if offset < 0 or offset % 256 or (offset % 8192) // 256 > 15:
                return None
            frame, slot, port = 0, offset // 8192, (offset % 8192) // 256
        except (TypeError, ValueError):
            return None
    return {"frame": frame, "slot": slot, "port": port, "sfp": f"{frame}/{slot}/{port}"}

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS olts (id INTEGER PRIMARY KEY, host TEXT UNIQUE NOT NULL, name TEXT, vendor TEXT DEFAULT 'Huawei', model TEXT, software_version TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS poll_runs (id INTEGER PRIMARY KEY, olt_id INTEGER NOT NULL, collected_at TEXT NOT NULL, status TEXT NOT NULL, uptime TEXT, errors_json TEXT, FOREIGN KEY(olt_id) REFERENCES olts(id));
CREATE TABLE IF NOT EXISTS interfaces (id INTEGER PRIMARY KEY, olt_id INTEGER NOT NULL, snmp_index TEXT NOT NULL, name TEXT, kind TEXT, last_status TEXT, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, UNIQUE(olt_id,snmp_index));
CREATE TABLE IF NOT EXISTS interface_samples (id INTEGER PRIMARY KEY, poll_id INTEGER NOT NULL, interface_id INTEGER NOT NULL, status TEXT, in_octets INTEGER, out_octets INTEGER, in_bps REAL, out_bps REAL, FOREIGN KEY(poll_id) REFERENCES poll_runs(id), FOREIGN KEY(interface_id) REFERENCES interfaces(id));
CREATE TABLE IF NOT EXISTS pons (id INTEGER PRIMARY KEY, olt_id INTEGER NOT NULL, snmp_index TEXT NOT NULL, pon_number INTEGER, slot TEXT, port TEXT, last_status TEXT, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, UNIQUE(olt_id,snmp_index));
CREATE TABLE IF NOT EXISTS pon_samples (id INTEGER PRIMARY KEY, poll_id INTEGER NOT NULL, pon_id INTEGER NOT NULL, status TEXT, tx_power_cdbm INTEGER, temperature_c INTEGER, voltage_cv INTEGER, bias_ma INTEGER, laser_state INTEGER, transceiver_type INTEGER, FOREIGN KEY(poll_id) REFERENCES poll_runs(id), FOREIGN KEY(pon_id) REFERENCES pons(id));
CREATE TABLE IF NOT EXISTS slot_samples (id INTEGER PRIMARY KEY, poll_id INTEGER NOT NULL, slot TEXT NOT NULL, temperature_c INTEGER, FOREIGN KEY(poll_id) REFERENCES poll_runs(id));
CREATE TABLE IF NOT EXISTS onts (id INTEGER PRIMARY KEY, olt_id INTEGER NOT NULL, snmp_index TEXT NOT NULL, pon_id INTEGER, description TEXT, serial_hex TEXT, serial_text TEXT, vlan_list TEXT, last_status TEXT, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, UNIQUE(olt_id,snmp_index));
CREATE TABLE IF NOT EXISTS ont_samples (id INTEGER PRIMARY KEY, poll_id INTEGER NOT NULL, ont_id INTEGER NOT NULL, status TEXT, rx_power_cdbm INTEGER, connected_macs INTEGER, disconnect_reason INTEGER, extra_json TEXT, FOREIGN KEY(poll_id) REFERENCES poll_runs(id), FOREIGN KEY(ont_id) REFERENCES onts(id));
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, olt_id INTEGER NOT NULL, occurred_at TEXT NOT NULL, severity TEXT, entity_type TEXT, entity_id INTEGER, event_type TEXT, message TEXT, payload_json TEXT);
CREATE TABLE IF NOT EXISTS snmp_raw_samples (id INTEGER PRIMARY KEY, poll_id INTEGER NOT NULL, oid TEXT NOT NULL, snmp_index TEXT, raw_value TEXT, collected_at TEXT NOT NULL, FOREIGN KEY(poll_id) REFERENCES poll_runs(id));
CREATE TABLE IF NOT EXISTS dashboard_snapshots (poll_id INTEGER PRIMARY KEY, payload_json TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(poll_id) REFERENCES poll_runs(id));
CREATE TABLE IF NOT EXISTS telegram_alerts (id INTEGER PRIMARY KEY, poll_id INTEGER NOT NULL, pon_index TEXT NOT NULL, part INTEGER NOT NULL, chat_id TEXT NOT NULL, message TEXT NOT NULL, report_filename TEXT, report_text TEXT, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, sent_at TEXT, last_error TEXT, UNIQUE(poll_id,pon_index,part), FOREIGN KEY(poll_id) REFERENCES poll_runs(id));
CREATE TABLE IF NOT EXISTS alert_states (alert_key TEXT PRIMARY KEY, active INTEGER NOT NULL DEFAULT 0, affected_count INTEGER NOT NULL DEFAULT 0, last_message TEXT, started_at TEXT, last_changed_at TEXT, resolved_at TEXT);
CREATE INDEX IF NOT EXISTS idx_poll_olt_time ON poll_runs(olt_id,collected_at); CREATE INDEX IF NOT EXISTS idx_interface_sample_time ON interface_samples(interface_id,poll_id); CREATE INDEX IF NOT EXISTS idx_pon_sample_time ON pon_samples(pon_id,poll_id);
CREATE INDEX IF NOT EXISTS idx_ont_sample_time ON ont_samples(ont_id,poll_id); CREATE INDEX IF NOT EXISTS idx_ont_pon ON onts(pon_id);
CREATE INDEX IF NOT EXISTS idx_ont_reason_time ON ont_samples(ont_id,poll_id) WHERE disconnect_reason IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_telegram_pending ON telegram_alerts(status,created_at);
"""

def alert_date(value):
    try: moment = datetime.fromisoformat(value).astimezone(ZoneInfo("America/Sao_Paulo"))
    except (TypeError, ValueError): return "Sem horário"
    return moment.strftime("%d-%m-%Y %H:%M")

def alert_host():
    return f"{OLT_CONFIG.get('name',OLT_HOST)} ({OLT_HOST})"

def reason_short(reason):
    labels = {1:"LOS",2:"LOSi/LOBi",3:"LOFI",5:"LOAI",6:"LOAMI",13:"Dying-gasp",15:"LOKI"}
    return f"{labels.get(reason,'Código')} ({reason})"

ALERT_PERCENT = 20

def pon_totals(data):
    totals = {}
    for ont in data.get("onts", []):
        index = ont.get("pon_index")
        if index is not None: totals[index] = totals.get(index, 0) + 1
    return totals

def meets_alert_threshold(affected, total):
    return total > 0 and affected * 100 >= total * ALERT_PERCENT

def affected_label(affected, total):
    percent = affected * 100 / total if total else 0
    return f"{affected} de {total} ({percent:.0f}%)"

def low_signal_alerts(data):
    """Uma mensagem curta e um único TXT por GPON com possível atenuação."""
    chat_id = OLT_CONFIG.get("telegram_chat_id")
    if not chat_id: return []
    grouped = {}
    for ont in data.get("onts", []):
        rx = ont.get("rx_power")
        if ont.get("status") == "online" and rx is not None and rx <= -2700:
            grouped.setdefault(ont["pon_index"], []).append(ont)
    pons = {pon["index"]: pon for pon in data.get("pons", [])}
    totals = pon_totals(data)
    alerts = []
    for pon_index, onts in grouped.items():
        total = totals.get(pon_index, 0)
        if not meets_alert_threshold(len(onts), total): continue
        pon = pons.get(pon_index)
        if not pon or not pon.get("sfp"): continue
        board = "/".join(pon["sfp"].split("/")[:2])
        message = ("⚠️ Possível atenuação na PON\n"
                   f"Host: {alert_host()}\nPlaca: {board} | PON: {pon['sfp']}\n"
                   f"Descrição: {pon.get('description') or 'Sem descrição'}\n"
                   f"Clientes afetados: {affected_label(len(onts), total)}\nStatus: RX ≤ -27,00 dBm")
        alerts.append((f"pon:{pon_index}:atenuacao", 1, str(chat_id), message, None, None))
    return alerts

def outage_alerts(data):
    """Alertas por placa para indícios de energia ou rompimento óptico."""
    chat_id = OLT_CONFIG.get("telegram_chat_id")
    if not chat_id: return []
    pons = {pon["index"]: pon for pon in data.get("pons", [])}
    totals = pon_totals(data)
    sfp_indexes = {pon.get("sfp"): index for index,pon in pons.items() if pon.get("sfp")}
    definitions = (("energia", "Possível queda de energia", {13}),
                   ("rompimento", "Possível rompimento", {1, 2, 3, 5, 6, 15}))
    alerts = []
    for category, title, reasons in definitions:
        grouped = {}
        for ont in data.get("onts", []):
            pon = pons.get(ont.get("pon_index"))
            sfp = pon.get("sfp") if pon else None
            if ont.get("status") != "offline" or ont.get("disconnect_reason") not in reasons or not sfp: continue
            grouped.setdefault(sfp, []).append(ont)
        for sfp, entries in grouped.items():
            index = sfp_indexes.get(sfp)
            total = totals.get(index, 0)
            if not meets_alert_threshold(len(entries), total): continue
            reason_counts = {}
            for ont in entries: reason_counts[ont["disconnect_reason"]] = reason_counts.get(ont["disconnect_reason"],0) + 1
            breakdown = " | ".join(f"{reason_short(reason)}: {count}" for reason,count in sorted(reason_counts.items()))
            message = (f"⚠️ {title}\nHost: {alert_host()}\n"
                       f"PON: {sfp}\nDescrição: {pons[next(index for index,pon in pons.items() if pon.get('sfp') == sfp)].get('description') or 'Sem descrição'}\n"
                       f"Clientes afetados: {affected_label(len(entries), total)}\nStatus de desconexão: {breakdown}")
            alerts.append((f"pon:{sfp}:{category}", 1, str(chat_id), message, None, None))
    return alerts

def affected_count(message):
    match = re.search(r"Clientes afetados:\s*(\d+)", message)
    return int(match.group(1)) if match else 0

def resolution_message(message, started_at, resolved_at):
    context = [line for line in message.splitlines() if line.startswith(("Host:", "PON:", "Descrição:"))]
    return ("✅ Problema resolvido\n" + "\n".join(context) +
            f"\nProblema iniciado em: {alert_date(started_at)}" +
            f"\nProblema resolvido em: {alert_date(resolved_at)}" +
            "\nClientes afetados: 0")

def queue_alert_events(db, poll_id, now, alerts, allow_resolution=True):
    """Enfileira abertura, aumento e resolução sem repetir o mesmo evento."""
    current = {alert[0]: alert for alert in alerts}
    for key, (_, part, chat_id, message, filename, report) in current.items():
        count = affected_count(message)
        state = db.execute("SELECT active,affected_count,last_message,started_at,last_changed_at FROM alert_states WHERE alert_key=?", (key,)).fetchone()
        if not state or not state[0]:
            db.execute("INSERT INTO telegram_alerts(poll_id,pon_index,part,chat_id,message,report_filename,report_text,created_at) VALUES(?,?,?,?,?,?,?,?)", (poll_id,key,part,chat_id,message,filename,report,now))
        elif count > state[1]:
            update = message + f"\n\n(Atualização do problema: eram {state[1]}, agora {count} clientes afetados.)"
            db.execute("INSERT INTO telegram_alerts(poll_id,pon_index,part,chat_id,message,report_filename,report_text,created_at) VALUES(?,?,?,?,?,?,?,?)", (poll_id,key,part,chat_id,update,filename,report,now))
        started_at = now if not state or not state[0] else (state[3] or state[4] or now)
        db.execute("INSERT INTO alert_states(alert_key,active,affected_count,last_message,started_at,last_changed_at,resolved_at) VALUES(?,?,?,?,?,?,NULL) ON CONFLICT(alert_key) DO UPDATE SET active=1,affected_count=excluded.affected_count,last_message=excluded.last_message,started_at=COALESCE(alert_states.started_at,excluded.started_at),last_changed_at=excluded.last_changed_at,resolved_at=NULL", (key,1,count,message,started_at,now))
    if allow_resolution:
        active = db.execute("SELECT alert_key,last_message,started_at,last_changed_at FROM alert_states WHERE active=1").fetchall()
        for key, message, started_at, last_changed_at in active:
            if key in current: continue
            previous = message or ""
            chat = next((alert[2] for alert in alerts if alert[0] == key), None)
            # O chat não está disponível quando o evento desaparece; recupera do último alerta.
            if chat is None:
                row = db.execute("SELECT chat_id FROM telegram_alerts WHERE pon_index=? ORDER BY id DESC LIMIT 1", (key,)).fetchone()
                chat = row[0] if row else OLT_CONFIG.get("telegram_chat_id")
            if chat:
                db.execute("INSERT INTO telegram_alerts(poll_id,pon_index,part,chat_id,message,created_at) VALUES(?,?,?,?,?,?)", (poll_id,key,1,chat,resolution_message(previous, started_at or last_changed_at or now, now),now))
            db.execute("UPDATE alert_states SET active=0,affected_count=0,resolved_at=?,last_changed_at=? WHERE alert_key=?", (now,now,key))

def database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    new_database = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA busy_timeout=5000")
    if new_database:
        db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        db.execute("VACUUM")
    db.executescript(SCHEMA)
    columns = {row[1] for row in db.execute("PRAGMA table_info(ont_samples)")}
    if "temperature_c" not in columns:
        db.execute("ALTER TABLE ont_samples ADD COLUMN temperature_c INTEGER")
    ont_columns = {row[1] for row in db.execute("PRAGMA table_info(onts)")}
    if "vlan_list" not in ont_columns:
        db.execute("ALTER TABLE onts ADD COLUMN vlan_list TEXT")
    alert_columns = {row[1] for row in db.execute("PRAGMA table_info(telegram_alerts)")}
    if "report_filename" not in alert_columns: db.execute("ALTER TABLE telegram_alerts ADD COLUMN report_filename TEXT")
    if "report_text" not in alert_columns: db.execute("ALTER TABLE telegram_alerts ADD COLUMN report_text TEXT")
    state_columns = {row[1] for row in db.execute("PRAGMA table_info(alert_states)")}
    if "started_at" not in state_columns:
        db.execute("ALTER TABLE alert_states ADD COLUMN started_at TEXT")
        # Eventos ativos anteriores não têm o instante original disponível; usa-se a última mudança como referência.
        db.execute("UPDATE alert_states SET started_at=last_changed_at WHERE active=1 AND started_at IS NULL")
    # Esta função também é chamada na inicialização, fora de um bloco ``with``.
    # Confirma as migrações antes de o coletor iniciar a primeira leitura SNMP.
    db.commit()
    return db

def persist(data):
    if data.get("status") == "error": return
    now = data["collected_at"]
    with database() as db:
        db.execute("INSERT INTO olts(host,created_at,updated_at) VALUES(?,?,?) ON CONFLICT(host) DO UPDATE SET updated_at=excluded.updated_at", (OLT_HOST,now,now))
        olt_id = db.execute("SELECT id FROM olts WHERE host=?",(OLT_HOST,)).fetchone()[0]
        cur = db.execute("INSERT INTO poll_runs(olt_id,collected_at,status,uptime,errors_json) VALUES(?,?,?,?,?)",(olt_id,now,data["status"],data.get("uptime"),json.dumps(data.get("collection_errors",{}))))
        poll_id = cur.lastrowid
        for pos,p in enumerate(data["pons"]):
            db.execute("INSERT INTO pons(olt_id,snmp_index,pon_number,slot,port,last_status,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(olt_id,snmp_index) DO UPDATE SET pon_number=excluded.pon_number,slot=excluded.slot,port=excluded.port,last_status=excluded.last_status,last_seen_at=excluded.last_seen_at",(olt_id,p["index"],p.get("port",pos),f'{p["frame"]}/{p["slot"]}' if p.get("frame") is not None else None,str(p["port"]) if p.get("port") is not None else None,p["status"],now,now))
            pon_id=db.execute("SELECT id FROM pons WHERE olt_id=? AND snmp_index=?",(olt_id,p["index"])).fetchone()[0]
            db.execute("INSERT INTO pon_samples(poll_id,pon_id,status,tx_power_cdbm,temperature_c,voltage_cv,bias_ma,laser_state,transceiver_type) VALUES(?,?,?,?,?,?,?,?,?)",(poll_id,pon_id,p["status"],p["tx_power"],p["temperature"],p["voltage"],p["bias"],p["laser"],p["type"]))
        for i in data["interfaces"]:
            db.execute("INSERT INTO interfaces(olt_id,snmp_index,name,kind,last_status,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(olt_id,snmp_index) DO UPDATE SET name=excluded.name,kind=excluded.kind,last_status=excluded.last_status,last_seen_at=excluded.last_seen_at",(olt_id,i["index"],i["name"],i["kind"],i["status"],now,now))
            interface_id=db.execute("SELECT id FROM interfaces WHERE olt_id=? AND snmp_index=?",(olt_id,i["index"])).fetchone()[0]
            # Counter64 pode exceder o inteiro assinado do SQLite; TEXT preserva o valor exato.
            in_octets = str(i["in_octets"]) if i["in_octets"] is not None and i["in_octets"] > 9223372036854775807 else i["in_octets"]
            out_octets = str(i["out_octets"]) if i["out_octets"] is not None and i["out_octets"] > 9223372036854775807 else i["out_octets"]
            db.execute("INSERT INTO interface_samples(poll_id,interface_id,status,in_octets,out_octets,in_bps,out_bps) VALUES(?,?,?,?,?,?,?)",(poll_id,interface_id,i["status"],in_octets,out_octets,i["in_bps"],i["out_bps"]))
        for t in data["temperatures"]: db.execute("INSERT INTO slot_samples(poll_id,slot,temperature_c) VALUES(?,?,?)",(poll_id,t["slot"],t["temperature"]))
        for ont in data.get("onts", []):
            pon_row = db.execute("SELECT id FROM pons WHERE olt_id=? AND snmp_index=?", (olt_id, ont["pon_index"])).fetchone()
            pon_id = pon_row[0] if pon_row else None
            vlans = ",".join(str(vlan) for vlan in ont.get("vlans", [])) or None
            db.execute("INSERT INTO onts(olt_id,snmp_index,pon_id,description,serial_hex,serial_text,vlan_list,last_status,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(olt_id,snmp_index) DO UPDATE SET pon_id=excluded.pon_id,description=excluded.description,serial_hex=excluded.serial_hex,serial_text=excluded.serial_text,vlan_list=excluded.vlan_list,last_status=excluded.last_status,last_seen_at=excluded.last_seen_at", (olt_id,ont["index"],pon_id,ont["description"],ont["serial_hex"],ont["serial_text"],vlans,ont["status"],now,now))
            ont_id = db.execute("SELECT id FROM onts WHERE olt_id=? AND snmp_index=?", (olt_id,ont["index"])).fetchone()[0]
            db.execute("INSERT INTO ont_samples(poll_id,ont_id,status,rx_power_cdbm,connected_macs,disconnect_reason,extra_json,temperature_c) VALUES(?,?,?,?,?,?,?,?)", (poll_id,ont_id,ont["status"],ont["rx_power"],ont["connected_macs"],ont["disconnect_reason"],None,ont["temperature"]))
        db.execute("INSERT INTO dashboard_snapshots(poll_id,payload_json,created_at) VALUES(?,?,?)", (poll_id,json.dumps(data),now))
        alerts = [*low_signal_alerts(data), *outage_alerts(data)]
        queue_alert_events(db, poll_id, now, alerts, allow_resolution=not data.get("collection_errors"))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=HISTORY_DAYS)).isoformat()
        old_ids = [row[0] for row in db.execute("SELECT id FROM poll_runs WHERE collected_at < ? ORDER BY id LIMIT 500", (cutoff,))]
        if old_ids:
            for table in ("ont_samples", "interface_samples", "pon_samples", "slot_samples", "snmp_raw_samples", "dashboard_snapshots", "telegram_alerts"):
                db.executemany(f"DELETE FROM {table} WHERE poll_id=?", ((old_id,) for old_id in old_ids))
            db.executemany("DELETE FROM poll_runs WHERE id=?", ((old_id,) for old_id in old_ids))
        snapshot_cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        db.execute("DELETE FROM dashboard_snapshots WHERE created_at < ?", (snapshot_cutoff,))

def latest_database_snapshot():
    """Usa a última coleta com PONs válidas; falhas parciais não apagam o painel."""
    try:
        with database() as db:
            row = db.execute("SELECT payload_json FROM dashboard_snapshots ORDER BY poll_id DESC LIMIT 1").fetchone()
            latest = json.loads(row[0]) if row else None
            if latest and latest.get("pons"):
                data = latest
            else:
                row = db.execute("SELECT payload_json FROM dashboard_snapshots WHERE json_array_length(json_extract(payload_json,'$.pons')) > 0 ORDER BY poll_id DESC LIMIT 1").fetchone()
                data = json.loads(row[0]) if row else latest
                if data and data.get("pons"):
                    data["collection_warning"] = "Exibindo a última leitura válida das PONs"
            if data and data.get("pons"):
                ont_data = latest_ont_snapshot()
                if ont_data: data["onts"] = ont_data["onts"]
                return data
            pons = db.execute("SELECT p.snmp_index,p.pon_number,s.status,s.tx_power_cdbm,s.temperature_c,s.voltage_cv,s.bias_ma,s.laser_state,s.transceiver_type FROM pons p JOIN pon_samples s ON s.id=(SELECT MAX(x.id) FROM pon_samples x WHERE x.pon_id=p.id) ORDER BY p.pon_number").fetchall()
            if pons:
                data = latest or {"host": OLT_HOST, "interfaces": [], "temperatures": [], "status": "degraded"}
                data["pons"] = [{"index": p[0], "name": f"PON {p[1]}", "status": p[2], "tx_power": p[3], "temperature": p[4], "voltage": p[5], "bias": p[6], "laser": p[7], "type": p[8]} for p in pons]
                data["collection_warning"] = "Exibindo a última leitura válida das PONs"
                return data
            return latest
    except sqlite3.Error:
        return None

def latest_ont_snapshot():
    with database() as db:
        row = db.execute("SELECT payload_json FROM dashboard_snapshots WHERE json_array_length(json_extract(payload_json,'$.onts')) > 0 ORDER BY poll_id DESC LIMIT 1").fetchone()
        if not row: return None
        data = json.loads(row[0])
        history = {index: (reason,status) for index,reason,status in db.execute("SELECT o.snmp_index,(SELECT s.disconnect_reason FROM ont_samples s WHERE s.ont_id=o.id AND s.disconnect_reason IS NOT NULL ORDER BY s.poll_id DESC LIMIT 1),(SELECT s.status FROM ont_samples s WHERE s.ont_id=o.id AND s.status IN ('online','offline') ORDER BY s.poll_id DESC LIMIT 1) FROM onts o WHERE o.olt_id=(SELECT id FROM olts WHERE host=?)", (OLT_HOST,)).fetchall()}
        inherited = 0
        for ont in data["onts"]:
            if ont.get("disconnect_reason") is None:
                ont["disconnect_reason"] = history.get(ont["index"],(None,None))[0]
            if ont.get("status") not in ("online", "offline"):
                old_status = history.get(ont["index"],(None,None))[1]
                if old_status:
                    ont["status"] = old_status
                    ont["_status_inherited"] = True
                    inherited += 1
            ont["disconnect_reason_text"] = disconnect_reason_text(ont.get("disconnect_reason"))
        if inherited:
            data["status_warning"] = f"Estado de {inherited} ONT(s) obtido da última leitura válida no banco"
        return data

def onts_text(data):
    onts = data["onts"]
    groups = [("ONLINE", [o for o in onts if o["status"] == "online"]),
              ("OFFLINE", [o for o in onts if o["status"] == "offline"]),
              ("ESTADO DESCONHECIDO", [o for o in onts if o["status"] not in ("online", "offline")])]
    lines = ["RELATÓRIO DE ONTs — LVL - gerenciador de OLTs", f"OLT: {data.get('host', OLT_HOST)}", f"PON S/F/P: {data.get('pon_label',data['pon_number'])}", f"Última coleta de ONTs: {data['collected_at']}",
             f"Total: {len(onts)} | Online: {len(groups[0][1])} | Offline: {len(groups[1][1])} | Estado desconhecido: {len(groups[2][1])}",
             f"Sinal RX disponível: {sum(o.get('rx_power') is not None for o in groups[0][1])}/{len(groups[0][1])} online | Temperatura disponível: {sum(o.get('temperature') is not None for o in groups[0][1])}/{len(groups[0][1])} online",
             "", "Potência RX em dBm. Temperatura em °C. 'Sem leitura' indica dado indisponível."]
    if data.get("status_warning"): lines.append(data["status_warning"])
    for heading, entries in groups:
        lines.extend(["", f"{heading} ({len(entries)})", "=" * 72])
        for o in sorted(entries, key=lambda item: item["ont_number"]):
            lines.append(f"ONT {o['ont_number']} | {o.get('description') or 'Sem descrição'} | Serial: {o.get('serial_text') or o.get('serial_hex') or 'Sem leitura'}")
            vlans = o.get("vlans") or []
            lines.append(f"    VLAN: {', '.join(str(vlan) for vlan in vlans)}" if vlans else "    VLAN: Sem VLAN nativa configurada")
            if heading == "ONLINE":
                rx = o.get("rx_power"); temperature = o.get("temperature")
                lines.append(f"    Sinal RX: {rx/100:.2f} dBm" if rx is not None else "    Sinal RX: Sem leitura")
                lines.append(f"    Temperatura: {temperature} °C" if temperature is not None else "    Temperatura: Sem leitura")
            elif heading == "OFFLINE":
                reason = o.get("disconnect_reason")
                lines.append(f"    Última causa de desconexão: {disconnect_reason_text(reason)}")
            lines.append("")
    return "\r\n".join(lines) + "\r\n"

def polling_loop():
    if START_DELAY: time.sleep(START_DELAY)
    while True:
        started = time.monotonic()
        if POLL_LOCK.acquire(blocking=False):
            try:
                if COLLECTOR_LOCK_PATH:
                    import fcntl
                    with open(COLLECTOR_LOCK_PATH, "a+b") as lock_file:
                        fcntl.flock(lock_file, fcntl.LOCK_EX)
                        collect()
                        fcntl.flock(lock_file, fcntl.LOCK_UN)
                else:
                    collect()
            finally:
                POLL_LOCK.release()
        while True:
            interval = configured_interval()
            remaining = interval - (time.monotonic() - started)
            if remaining <= 0: break
            time.sleep(min(5, remaining))

def configured_interval():
    identifier = "olt-" + OLT_HOST.replace(".", "-")
    path = Path(os.environ.get("OLT_ENV_ROOT", "/etc/olt-vision/olts")) / f"{identifier}.env"
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("POLL_INTERVAL="):
                return max(60, min(600, int(line.split("=", 1)[1])))
    except (OSError, ValueError): pass
    return max(60, min(600, INTERVAL))

def walk(oid):
    # Alguns firmwares Huawei falham em GETBULK em tabelas GPON; GETNEXT é
    # mais lento, porém confiável e ainda coleta a tabela inteira em lote.
    cmd = (["snmpget", "-v2c", "-c", COMMUNITY, "-On", "-t", "2", "-r", "0", OLT_HOST, oid]
           if oid.endswith(".1.3.0") else
           ["snmpbulkwalk", "-v2c", "-c", COMMUNITY, "-On", "-Cr20", "-t", "2", "-r", "0", OLT_HOST, oid])
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=45)
        output, error, returncode = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        error, returncode = "Tempo limite da varredura SNMP", 1
    rows = {}
    for line in output.splitlines():
        m = re.match(r"\.(.+?)\s+=\s+\w+(?:-\w+)?:\s*(.*)", line)
        if m:
            full, value = m.groups()
            rows["" if full == oid else full.removeprefix(oid + ".")] = value.strip('"')
    if returncode and not rows: raise RuntimeError(error.strip() or "Falha SNMP")
    return rows

def value_num(v):
    m = re.search(r"-?\d+", str(v)); return int(m.group()) if m else None

def unavailable(value):
    """Huawei usa INT32_MAX como sentinela de leitura indisponível/offline."""
    return None if value_num(value) == 2147483647 else value_num(value)

def uptime_pt(value):
    """Converte Timeticks SNMP em uma duração legível no painel."""
    ticks = value_num(value)
    if ticks is None or ticks < 0: return "Sem leitura"
    seconds = ticks // 100
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    pieces = []
    if days: pieces.append(f"{days} {'dia' if days == 1 else 'dias'}")
    if hours or days: pieces.append(f"{hours}h")
    pieces.append(f"{minutes:02d}min")
    return " ".join(pieces)

def ping_host(host):
    """Uma única tentativa curta, sem afetar o tempo de coleta das ONTs."""
    try:
        result = subprocess.run(["ping", "-n" if os.name == "nt" else "-c", "1", "-W" if os.name != "nt" else "-w", "1" if os.name != "nt" else "1000", host],
                                text=True, capture_output=True, timeout=3)
        match = re.search(r"(?:time|tempo)[=<]([0-9.]+)\s*ms", result.stdout, re.I)
        return float(match.group(1)) if result.returncode == 0 and match else (0.0 if result.returncode == 0 else None)
    except (OSError, subprocess.TimeoutExpired):
        return None

def ont_serial(value):
    if not value: return None, None
    octets = re.findall(r"[0-9A-Fa-f]{2}", value)
    if len(octets) != 8: return value, None
    raw = bytes.fromhex("".join(octets))
    vendor = raw[:4].decode("ascii", "replace")
    return raw.hex().upper(), vendor + raw[4:].hex().upper()

def telnet_reason(text):
    value = (text or "").lower()
    mapping = (("dying-gasp",13),("losi",2),("lobi",2),("lofi",3),("loai",5),
               ("loami",6),("loki",15),("loss of signal",1),("los",1))
    return next((code for needle,code in mapping if needle in value), None)

def parse_autofind(text):
    """Extrai somente S/F/P e serial do resultado de `display ont autofind all`."""
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text or "").replace("\r", "")
    total_match = re.search(r"The number of GPON autofind ONT is\s+(\d+)", clean, re.I)
    onts = []
    for block in re.split(r"(?=^\s*Number\s*:\s*\d+\s*$)", clean, flags=re.M):
        sfp_match = re.search(r"^\s*F/S/P\s*:\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s*$", block, re.M | re.I)
        serial_match = re.search(r"^\s*Ont SN\s*:\s*([0-9A-Fa-f]{16})\b", block, re.M | re.I)
        if sfp_match and serial_match:
            onts.append({"sfp": "/".join(str(int(value)) for value in sfp_match.groups()),
                         "serial": serial_match.group(1).upper()})
    reported = int(total_match.group(1)) if total_match else len(onts)
    if reported != len(onts):
        raise ValueError(f"Autofind informou {reported} ONT(s), mas {len(onts)} foram interpretadas")
    return {"count": reported, "onts": onts}

def telnet_ont_data(pons):
    """Coleta ONTs pela CLI sem modificar configuração persistente da OLT."""
    by_sfp = {pon.get("sfp"): pon["index"] for pon in pons if pon.get("sfp")}
    boards = sorted({"/".join(sfp.split("/")[:2]) for sfp in by_sfp})
    result, summary = {}, {}
    port_re = re.compile(r"In port\s+(\d+/\d+/\d+),.*?total of ONTs are:\s*(\d+),\s*online:\s*(\d+)", re.I)
    row_re = re.compile(r"^\s*(\d+)\s+(online|offline)\s+(.+?)\s*$", re.M | re.I)
    optical_re = re.compile(r"^\s*(\d+)\s+(-?[\d.]+)\s+[-\d.]+\s+[-\d.]+\s+(-?\d+)", re.M)
    with cli_session(45) as session:
        session.enter_config()
        for board in boards:
            text = session.command(f"display ont info summary {board}")
            current = None
            for line in text.splitlines():
                header = port_re.search(line)
                if header:
                    current = header.group(1)
                    summary[current] = {"total": int(header.group(2)), "online": int(header.group(3)), "onts": {}}
                    continue
                row = row_re.match(line)
                if current and row:
                    ont, state, tail = row.groups()
                    summary[current]["onts"][int(ont)] = {"status": state.lower(), "reason": telnet_reason(tail)}
        for sfp, info in summary.items():
            if sfp not in by_sfp or info["online"] <= 0:
                continue
            frame, slot, port = sfp.split("/")
            session.command(f"interface gpon {frame}/{slot}")
            text = session.command(f"display ont optical-info {port} all")
            session.command("quit")
            for ont, rx, temperature in optical_re.findall(text):
                entry = info["onts"].setdefault(int(ont), {"status": "online", "reason": None})
                entry.update({"rx_power": int(round(float(rx) * 100)), "temperature": int(temperature)})
        for sfp, info in summary.items():
            pon_index = by_sfp.get(sfp)
            if pon_index is None:
                continue
            for number, item in info["onts"].items():
                result[f"{pon_index}.{number}"] = item
    return result

def telnet_vlan_data(pons):
    """Lê somente o vínculo porta/ONT/VLAN, sem consultar estado ou óptica."""
    by_sfp = {pon.get("sfp") for pon in pons if pon.get("sfp")}
    boards = sorted({"/".join(sfp.split("/")[:2]) for sfp in by_sfp})
    result = {}
    vlan_re = re.compile(r"^\s*ont\s+port\s+(?:native-)?vlan\s+(\d+)\s+(\d+)\s+eth\s+\d+\s+vlan\s+(\d+)\b", re.M | re.I)
    with cli_session(55) as session:
        session.enter_config()
        for board in boards:
            frame, slot = board.split("/")
            interface_output = session.command(f"interface gpon {frame}/{slot}")
            vlan_command = OLT_CONFIG.get("vlan_command", "display this | include vlan")
            text = session.command(vlan_command)
            fallback = vlan_command != "display current-configuration" and ("Unknown command" in text or "% Unknown" in text or "error locates" in text)
            if fallback:
                text = session.command("display current-configuration")
            session.command("quit")
            text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
            matches = vlan_re.findall(text)
            full_config = vlan_command == "display current-configuration" or fallback
            print(f"{OLT_HOST} VLAN placa {board}: {len(matches)} linhas ({'configuração completa' if full_config else 'filtro CLI'})", flush=True)
            if not matches:
                interface_tail = interface_output.replace("\r", "").replace("\n", " | ")[-240:]
                response_head = text.replace("\r", "").replace("\n", " | ")[:400]
                print(f"{OLT_HOST} VLAN diagnóstico {board}: interface={interface_tail!r}; resposta={response_head!r}", flush=True)
            for port, ont, vlan in matches:
                sfp = f"{board}/{int(port)}"
                if sfp in by_sfp:
                    result.setdefault((sfp, int(ont)), set()).add(int(vlan))
    return result

def collect():
    global CACHE, PREVIOUS_COUNTERS
    started_at = time.monotonic()
    try:
        raw, errors = {}, {}
        skipped_ont_oids = TELNET_ONT_OIDS if TELNET_ONT_SOURCE and ACCESS_USERNAME and ACCESS_PASSWORD else ()
        for key, oid in OIDS.items():
            if key in skipped_ont_oids:
                raw[key] = {}
                continue
            oid_started = time.monotonic()
            try: raw[key] = walk(oid)
            except Exception as exc:
                raw[key] = {}; errors[key] = str(exc)
            print(f"{OLT_HOST} {key}: {len(raw[key])} registros em {time.monotonic()-oid_started:.1f}s", flush=True)
        pons = []
        for index, state in raw["pon_status"].items():
            identity = pon_identity(index, raw["if_name"].get(index)) or {}
            alias = raw["if_alias"].get(index)
            pons.append({"index": index, "name": f"GPON {identity['sfp']}" if identity else "PON sem identificação", **identity, "status": "online" if value_num(state) == 1 else "offline",
                         "bias": unavailable(raw["pon_bias"].get(index)), "laser": unavailable(raw["pon_laser"].get(index)),
                         "temperature": unavailable(raw["pon_temp"].get(index)), "type": unavailable(raw["pon_type"].get(index)),
                         "tx_power": unavailable(raw["pon_tx"].get(index)), "voltage": unavailable(raw["pon_voltage"].get(index)),
                         "description": alias if alias else None})
        telnet_onts, vlan_map = {}, {}
        if skipped_ont_oids:
            try:
                telnet_onts = telnet_ont_data(pons)
                if raw["ont_description"] and not telnet_onts:
                    raise RuntimeError("Telnet não retornou ONTs; preservando coleta SNMP")
                print(f"{OLT_HOST} Telnet ONTs: {len(telnet_onts)} registros", flush=True)
            except Exception as exc:
                errors["telnet_onts"] = str(exc)
                print(f"{OLT_HOST} Telnet ONTs falhou; usando SNMP: {exc}", flush=True)
                for key in skipped_ont_oids:
                    oid_started = time.monotonic()
                    try: raw[key] = walk(OIDS[key])
                    except Exception as walk_exc:
                        raw[key] = {}; errors[key] = str(walk_exc)
                    print(f"{OLT_HOST} {key}: {len(raw[key])} registros em {time.monotonic()-oid_started:.1f}s", flush=True)
        ont_keys = set().union(*(raw[k] for k in ("ont_description", "ont_serial", "ont_rx", "ont_disconnect", "ont_macs", "ont_status", "ont_temp")))
        ont_keys.update(telnet_onts)
        onts = []
        for key in sorted(ont_keys, key=lambda x: tuple(int(v) for v in x.split(".") if v.isdigit())):
            parts = key.split(".")
            if len(parts) != 2 or not all(part.isdigit() for part in parts): continue
            serial_hex, serial_text = ont_serial(raw["ont_serial"].get(key))
            telnet = telnet_onts.get(key, {})
            pon_sfp = next((pon.get("sfp") for pon in pons if pon["index"] == parts[0]), None)
            mapped_vlans = vlan_map.get((pon_sfp, int(parts[1])), set())
            rx = telnet.get("rx_power", unavailable(raw["ont_rx"].get(key)))
            temperature = telnet.get("temperature", unavailable(raw["ont_temp"].get(key)))
            status_code = value_num(raw["ont_status"].get(key))
            macs = value_num(raw["ont_macs"].get(key))
            reason = telnet.get("reason", value_num(raw["ont_disconnect"].get(key)))
            telnet_status = telnet.get("status")
            onts.append({"index":key, "pon_index":parts[0], "ont_number":int(parts[1]),
                         "description":raw["ont_description"].get(key), "serial_hex":serial_hex,
                         "serial_text":serial_text, "rx_power":rx,
                         "temperature": temperature,
                         "status":telnet_status or ("online" if status_code == 1 else "offline" if status_code == 2 else "desconhecido"),
                         "connected_macs":macs if macs is not None and macs >= 0 else None,
                         "disconnect_reason":reason if reason is not None and reason >= 0 else None,
                         "vlans":telnet.get("vlans", sorted(mapped_vlans)),
                         "disconnect_reason_text":disconnect_reason_text(reason)})
        pon_vlans = {}
        for ont in onts:
            for vlan in ont.get("vlans", []):
                pon_vlans.setdefault(ont["pon_index"], set()).add(vlan)
        for pon in pons:
            pon["vlans"] = sorted(pon_vlans.get(pon["index"], set()))
        now = time.time(); interfaces = []
        for i, v in raw["if_status"].items():
            incoming, outgoing = value_num(raw["if_in"].get(i)), value_num(raw["if_out"].get(i))
            bits = 64
            if incoming in (None, 18446744073709551615) or outgoing in (None, 18446744073709551615):
                incoming, outgoing = value_num(raw["if_in32"].get(i)), value_num(raw["if_out32"].get(i))
                bits = 32
            old = PREVIOUS_COUNTERS.get(i); in_bps = out_bps = None
            if old and incoming is not None and outgoing is not None and old[3] == bits:
                elapsed = now - old[2]
                if elapsed > 0:
                    delta_in, delta_out = incoming-old[0], outgoing-old[1]
                    if bits == 32:
                        delta_in %= 2**32; delta_out %= 2**32
                    if delta_in >= 0 and delta_out >= 0:
                        in_bps, out_bps = delta_in*8/elapsed, delta_out*8/elapsed
            if incoming is not None and outgoing is not None: PREVIOUS_COUNTERS[i] = (incoming, outgoing, now, bits)
            interfaces.append({"index":i, "name":raw["if_name"].get(i) or raw["if_description"].get(i) or f"Interface {i}", "alias":raw["if_alias"].get(i), "status":"up" if value_num(v)==1 else "down", "in_octets":incoming, "out_octets":outgoing, "in_bps":in_bps, "out_bps":out_bps, "counter_bits":bits, "kind":"pon" if i in raw["pon_status"] else "interface"})
        temps = [{"slot": k, "temperature": unavailable(v)} for k,v in raw["slot_temp"].items()]
        ping_ms = ping_host(OLT_HOST)
        CACHE = {"at": time.time(), "data": {"status":"online" if not errors else "degraded", "host": OLT_HOST, "collected_at": datetime.now(timezone.utc).isoformat(),
                 "uptime": uptime_pt(raw["uptime"].get("")), "ping_ms": ping_ms, "snmp_ok": bool(raw["pon_status"]) and "pon_status" not in errors, "pons": pons, "onts": onts, "interfaces": interfaces, "temperatures": temps,
                 "board_temperatures": raw["board_temp"], "board_cpu": {k: n if (n := unavailable(v)) is not None and 0 <= n <= 100 else None for k,v in raw["board_cpu"].items()}, "board_fans": {k: n if (n := unavailable(v)) is not None and 0 <= n <= 100 else None for k,v in raw["board_fan"].items()}, "collection_errors": errors}}
        persist(CACHE["data"])
        print(f"{OLT_HOST} ciclo concluído em {time.monotonic()-started_at:.1f}s; {len(onts)} ONTs; {len(errors)} falhas", flush=True)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"{OLT_HOST} falha no ciclo após {time.monotonic()-started_at:.1f}s: {e!r}", flush=True)
        CACHE = {"at": time.time(), "data": {"status":"error", "host":OLT_HOST, "error":str(e), "collected_at":datetime.now(timezone.utc).isoformat(), "pons":[], "interfaces":[], "temperatures":[]}}
    return CACHE["data"]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        request = urlsplit(self.path)
        if request.path == "/onts.txt":
            query = parse_qs(request.query)
            value = query.get("pon", [])
            if len(value) != 1 or not value[0].isdigit():
                self.send_error(400, "Informe uma PON válida")
                return
            pon_number = int(value[0])
            topology = latest_database_snapshot()
            data = latest_ont_snapshot()
            if not topology or not data:
                self.send_error(503, "Ainda não há coleta de ONTs no banco")
                return
            pons = topology.get("pons", [])
            if pon_number >= len(pons):
                self.send_error(404, "PON não encontrada")
                return
            pon_index = pons[pon_number]["index"]
            selected_onts = [ont for ont in data["onts"] if ont["pon_index"] == pon_index]
            data = {**data, "pons": pons, "onts": selected_onts, "pon_number": pon_number}
            inherited = sum(bool(ont.get("_status_inherited")) for ont in selected_onts)
            data["status_warning"] = f"Estado de {inherited} ONT(s) obtido da última leitura válida no banco" if inherited else None
            body = ("\ufeff" + onts_text(data)).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="onts-pon-{pon_number}.txt"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if self.path == "/status.json":
            data = latest_database_snapshot() or CACHE["data"]
            body = json.dumps(data).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(body); return
        if self.path != "/": self.send_error(404); return
        page = open(os.path.join(os.path.dirname(__file__), "index.html"), encoding="utf-8").read()
        snapshot = latest_database_snapshot()
        if snapshot is None:
            snapshot = collect() if time.time()-CACHE["at"] > INTERVAL else CACHE["data"]
        body = page.replace("__OLT_DATA__", json.dumps(snapshot).replace("</", "<\\/")).encode()
        self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers(); self.wfile.write(body)

if __name__ == "__main__":
    if not COMMUNITY: raise SystemExit("Defina SNMP_COMMUNITY no arquivo de ambiente")
    database().close()
    if SERVE_HTTP:
        threading.Thread(target=polling_loop, daemon=True).start()
        ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "6000"))), Handler).serve_forever()
    else:
        polling_loop()
