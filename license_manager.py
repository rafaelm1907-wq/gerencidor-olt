"""Licença do LVL: validação remota, reserva de host e tolerância offline."""
import hashlib
import json
import os
import socket
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/var/lib/olt-vision"))
LICENSE_FILE = Path(os.environ.get("LICENSE_FILE", "/etc/olt-vision/license.env"))
STATE_FILE = DATA_ROOT / "license-state.json"
API_URL = os.environ.get("LICENSE_API_URL", "https://lvllicencas.lvltech.com.br/api/v1")
PRODUCT = os.environ.get("LICENSE_PRODUCT", "LVL - gerenciador de OLTs")
LOCK = threading.Lock()
MEMORY = {"checked": None, "status": None}

def utcnow(): return datetime.now(timezone.utc)
def parse_time(value):
    try:
        result = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError): return None

def load_json(path):
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError): return {}

def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)

def license_key():
    try:
        for line in LICENSE_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith("LICENSE_KEY="): return line.split("=", 1)[1].strip()
    except OSError: pass
    return ""

def set_license_key(value):
    value = (value or "").strip()
    if not value or len(value) > 256: raise ValueError("Informe uma chave de licença válida.")
    LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = LICENSE_FILE.with_suffix(".tmp")
    temporary.write_text("# Arquivo local. Não versione esta chave.\nLICENSE_KEY=" + value + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(LICENSE_FILE)
    with LOCK: MEMORY.update({"checked": None, "status": None})

def post(path, payload):
    request = Request(API_URL.rstrip("/") + path, data=json.dumps(payload).encode("utf-8"), method="POST",
                      headers={"Content-Type": "application/json", "Accept": "application/json",
                               "User-Agent": "LVL-OLT-License/1.0"})
    try:
        with urlopen(request, timeout=10) as response: return json.loads(response.read().decode("utf-8")), response.status
    except HTTPError as exc:
        try: detail = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError): detail = {"reason": f"HTTP {exc.code}"}
        return detail, exc.code
    except (URLError, OSError, ValueError) as exc: raise OSError(str(exc)) from exc

def host_id(state):
    installation = state.get("installation_id")
    if not installation:
        installation = str(uuid.uuid4())
        state["installation_id"] = installation
    digest = hashlib.sha256(("lvl-olt-host:" + installation).encode("utf-8")).hexdigest()
    return digest

def claim(key, state):
    identifier = host_id(state)
    data, http_status = post("/hosts/claim", {"license_key": key, "product": PRODUCT, "host_id": identifier,
                                                "host_name": socket.gethostname()[:256]})
    if http_status != 200 or data.get("valid") is not True:
        reason = data.get("reason", "não foi possível reservar este host")
        if reason == "host_limit_reached": reason = "limite de hosts desta licença atingido"
        return None, reason
    return data, None

def offline_status(state, error):
    last = parse_time(state.get("last_validated_at")); grace = int(state.get("offline_grace_days", 0) or 0); expires = parse_time(state.get("expires_at"))
    if last and grace and utcnow() <= last + timedelta(days=grace) and (not expires or utcnow() <= expires):
        return {"active": True, "mode": "grace", "message": "Servidor de licenças indisponível; operando dentro da tolerância offline.",
                "expires_at": state.get("expires_at"), "last_validated_at": state.get("last_validated_at"),
                "host_limit": state.get("host_limit"), "hosts_in_use": state.get("hosts_in_use"), "error": error}
    return {"active": False, "mode": "unavailable", "message": "Não foi possível validar a licença e não há tolerância offline disponível.", "error": error}

def status(force=False):
    with LOCK:
        current = utcnow()
        if not force and MEMORY["status"] and MEMORY["checked"] and (current - MEMORY["checked"]).total_seconds() < 60:
            return MEMORY["status"]
        state = load_json(STATE_FILE); key = license_key()
        if not key:
            result = {"active": False, "mode": "missing", "message": "Informe a chave de licença para ativar esta instalação."}
        else:
            fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()
            if state.get("key_fingerprint") != fingerprint:
                for field in ("last_validated_at", "expires_at", "check_again_after_hours", "offline_grace_days", "host_limit", "hosts_in_use", "host_claimed"):
                    state.pop(field, None)
                state["key_fingerprint"] = fingerprint
            identifier = host_id(state)
            # O mesmo identificador deve sobreviver mesmo se a primeira validação falhar;
            # caso contrário uma nova tentativa poderia consumir outra vaga de host.
            save_json(STATE_FILE, state)
            last = parse_time(state.get("last_validated_at")); interval = max(1, int(state.get("check_again_after_hours", 24) or 24))
            needs_check = force or not last or current >= last + timedelta(hours=interval)
            if not needs_check:
                expires = parse_time(state.get("expires_at"))
                result = {"active": not expires or current <= expires, "mode": "valid" if not expires or current <= expires else "expired",
                          "message": "Licença válida." if not expires or current <= expires else "A licença está expirada.",
                          "expires_at": state.get("expires_at"), "last_validated_at": state.get("last_validated_at"),
                          "host_limit": state.get("host_limit"), "hosts_in_use": state.get("hosts_in_use")}
            else:
                try:
                    # A vaga é reservada uma única vez por chave/instalação. Repetir
                    # esse POST em cada validação pode ser bloqueado pelo validador.
                    already_claimed = bool(state.get("host_claimed")) or (state.get("installation_id") and state.get("host_limit") is not None)
                    host, error = ({"host_limit": state.get("host_limit"), "hosts_in_use": state.get("hosts_in_use")}, None) if already_claimed else claim(key, state)
                    if error:
                        result = {"active": False, "mode": "host_limit", "message": error}
                    else:
                        answer, code = post("/validate", {"license_key": key, "product": PRODUCT, "device_id": identifier})
                        expires = parse_time(answer.get("expires_at"))
                        valid = code == 200 and answer.get("valid") is True and answer.get("product") == PRODUCT and (not expires or current <= expires)
                        if not valid:
                            result = {"active": False, "mode": "invalid", "message": "A licença não é válida para este produto ou está expirada."}
                        else:
                            state.update({"key_fingerprint": fingerprint, "last_validated_at": current.isoformat(), "expires_at": answer.get("expires_at"),
                                          "check_again_after_hours": answer.get("check_again_after_hours", 24), "offline_grace_days": answer.get("offline_grace_days", 0),
                                          "host_limit": answer.get("host_limit", host.get("host_limit")), "hosts_in_use": host.get("hosts_in_use"), "host_claimed": True})
                            save_json(STATE_FILE, state)
                            result = {"active": True, "mode": "valid", "message": "Licença válida.", "expires_at": answer.get("expires_at"),
                                      "last_validated_at": state["last_validated_at"], "host_limit": state.get("host_limit"), "hosts_in_use": host.get("hosts_in_use")}
                except OSError as exc: result = offline_status(state, str(exc))
        MEMORY.update({"checked": current, "status": result})
        return result
