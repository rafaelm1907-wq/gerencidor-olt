#!/usr/bin/env python3
"""Entrega avisos persistidos, respeitando um intervalo por grupo Telegram."""
import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/var/lib/olt-vision"))
ENV_ROOT = Path(os.environ.get("OLT_ENV_ROOT", "/etc/olt-vision/olts"))
OLTS = json.loads((ROOT / "olts.json").read_text(encoding="utf-8"))
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
LAST_SENT = {}

def token_for(olt):
    try:
        for line in (ENV_ROOT / f"{olt['id']}.env").read_text(encoding="utf-8").splitlines():
            if line.startswith("TELEGRAM_BOT_TOKEN="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return TOKEN

def next_alert():
    candidates = []
    for olt in OLTS:
        token = token_for(olt)
        if not olt.get("telegram_chat_id") or not token: continue
        path = DATA_ROOT / f"{olt['id']}.db"
        if not path.exists(): continue
        try:
            with sqlite3.connect(path, timeout=5) as db:
                row = db.execute("SELECT id,chat_id,message,report_filename,report_text,created_at FROM telegram_alerts WHERE status='pending' ORDER BY CASE WHEN message LIKE '✅%' THEN 0 ELSE 1 END,created_at,id LIMIT 1").fetchone()
                if row: candidates.append((row[5], str(path), token, *row[:5]))
        except sqlite3.OperationalError:
            continue
    return min(candidates) if candidates else None

def update_alert(path, alert_id, status, error=None):
    with sqlite3.connect(path, timeout=5) as db:
        db.execute("UPDATE telegram_alerts SET status=?,attempts=attempts+1,last_error=?,sent_at=? WHERE id=?",
                   (status,error,datetime.now(timezone.utc).isoformat() if status == "sent" else None,alert_id))

def send(token, chat_id, message):
    payload = urlencode({"chat_id":chat_id,"text":message}).encode("utf-8")
    request = Request(f"https://api.telegram.org/bot{token}/sendMessage", data=payload, method="POST")
    try:
        with urlopen(request, timeout=20) as response:
            result = json.load(response)
            if not result.get("ok"): raise RuntimeError("Telegram não confirmou envio")
    except HTTPError as exc:
        retry_after = 30
        try:
            body = json.loads(exc.read())
            retry_after = int(body.get("parameters",{}).get("retry_after",30))
        except (ValueError,TypeError): pass
        return False, f"HTTP {exc.code}", retry_after, exc.code in (400,403)
    except (URLError,TimeoutError,OSError,RuntimeError) as exc:
        return False, type(exc).__name__, 30, False
    return True, None, 0, False

def send_document(token, chat_id, filename, content):
    boundary = "----LVL" + uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{chat_id}\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{filename}\"\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n").encode("utf-8") + content.encode("utf-8") + f"\r\n--{boundary}--\r\n".encode("utf-8")
    request = Request(f"https://api.telegram.org/bot{token}/sendDocument", data=body, method="POST", headers={"Content-Type":f"multipart/form-data; boundary={boundary}"})
    try:
        with urlopen(request, timeout=30) as response:
            if not json.load(response).get("ok"): raise RuntimeError("Telegram não confirmou o arquivo")
    except HTTPError as exc:
        return False, f"HTTP {exc.code}", 30, exc.code in (400,403)
    except (URLError,TimeoutError,OSError,RuntimeError) as exc:
        return False, type(exc).__name__, 30, False
    return True, None, 0, False

def main():
    while True:
        alert = next_alert()
        if alert is None:
            time.sleep(1)
            continue
        _,path,token,alert_id,chat_id,message,filename,report = alert
        is_resolution = message.startswith("✅")
        if not is_resolution:
            time.sleep(max(0, LAST_SENT.get(chat_id,0) + 3.1 - time.monotonic()))
        ok,error,retry_after,permanent = send(token,chat_id,message)
        if ok:
            update_alert(path,alert_id,"sent")
            LAST_SENT[chat_id] = time.monotonic()
            print(f"Telegram: alerta {alert_id} enviado ({Path(path).name})", flush=True)
        elif permanent:
            update_alert(path,alert_id,"failed",error)
            print(f"Telegram: alerta {alert_id} falhou permanentemente: {error}", flush=True)
        else:
            print(f"Telegram: envio pendente após {error}; nova tentativa em {retry_after}s", flush=True)
            time.sleep(max(3,retry_after))

if __name__ == "__main__": main()
