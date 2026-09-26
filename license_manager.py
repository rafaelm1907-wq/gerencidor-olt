"""Validação de licença no servidor, com tolerância controlada a indisponibilidade."""
import json
import os
import threading
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/var/lib/olt-vision"))
LICENSE_FILE = Path(os.environ.get("LICENSE_FILE", "/etc/olt-vision/license.env"))
STATE_FILE = DATA_ROOT / "license-state.json"
API_URL = os.environ.get("LICENSE_API_URL", "http://163.245.211.182:10100/api/v1/validate")
PRODUCT = os.environ.get("LICENSE_PRODUCT", "LVL - gerenciador de OLTs")
LOCK = threading.Lock()
MEMORY = {"checked": None, "status": None}

def _utcnow():
    return datetime.now(timezone.utc)

def _parse_time(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None

def _load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

def _save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    os.chmod(temp, 0o600)
    temp.replace(path)

def _load_env_key():
    try:
        for line in LICENSE_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith("LICENSE_KEY="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""

def set_license_key(key):
    key = (key or "").strip()
    if not key or len(key) > 256:
        raise ValueError("Informe uma chave de licença válida.")
    LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp = LICENSE_FILE.with_suffix(".tmp")
    temp.write_text("# Arquivo local; não versione esta chave.\nLICENSE_KEY=" + key + "\n", encoding="utf-8")
    os.chmod(temp, 0o600)
    temp.replace(LICENSE_FILE)
    with LOCK:
        MEMORY.update({"checked": None, "status": None})

def _device_id(state):
    device_id = state.get("device_id")
    if not isinstance(device_id, str) or not device_id:
        device_id = str(uuid.uuid4())
        state["device_id"] = device_id
        _save_json(STATE_FILE, state)
    return device_id

def _remote_validate(key, device_id):
    body = json.dumps({"license_key": key, "product": PRODUCT, "device_id": device_id}).encode("utf-8")
    request = Request(API_URL, data=body, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    with urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise OSError(f"Servidor de licenças retornou HTTP {response.status}")
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise OSError("Resposta inválida do servidor de licenças")
    return payload

def _offline_status(state, error):
    last_ok = _parse_time(state.get("last_validated_at"))
    grace_days = int(state.get("offline_grace_days", 0) or 0)
    expires_at = _parse_time(state.get("expires_at"))
    if last_ok and grace_days > 0 and _utcnow() <= last_ok + timedelta(days=grace_days) and (not expires_at or _utcnow() <= expires_at):
        return {"active": True, "mode": "grace", "expires_at": state.get("expires_at"), "last_validated_at": state.get("last_validated_at"),
                "message": "Servidor de licenças indisponível; operando dentro da tolerância offline.", "error": error}
    return {"active": False, "mode": "unavailable", "message": "Não foi possível validar a licença e não há tolerância offline disponível.", "error": error}

def status(force=False):
    with LOCK:
        now = _utcnow()
        if not force and MEMORY["status"] and MEMORY["checked"] and (now - MEMORY["checked"]).total_seconds() < 60:
            return MEMORY["status"]
        state = _load_json(STATE_FILE)
        key = _load_env_key()
        if not key:
            result = {"active": False, "mode": "missing", "message": "Informe a chave de licença para ativar esta instalação."}
        else:
            key_fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()
            if state.get("key_fingerprint") != key_fingerprint:
                for field in ("last_validated_at", "expires_at", "check_again_after_hours", "offline_grace_days"):
                    state.pop(field, None)
                state["key_fingerprint"] = key_fingerprint
                _save_json(STATE_FILE, state)
            device_id = _device_id(state)
            check_after = int(state.get("check_again_after_hours", 24) or 24)
            last_ok = _parse_time(state.get("last_validated_at"))
            needs_check = force or not last_ok or now >= last_ok + timedelta(hours=max(1, check_after))
            if not needs_check:
                expires_at = _parse_time(state.get("expires_at"))
                if expires_at and now > expires_at:
                    result = {"active": False, "mode": "expired", "expires_at": state.get("expires_at"), "message": "A licença está expirada."}
                else:
                    result = {"active": True, "mode": "valid", "expires_at": state.get("expires_at"), "last_validated_at": state.get("last_validated_at"), "message": "Licença válida."}
            else:
                try:
                    answer = _remote_validate(key, device_id)
                    expires_at = _parse_time(answer.get("expires_at"))
                    valid = answer.get("valid") is True and answer.get("product") == PRODUCT and (not expires_at or now <= expires_at)
                    if valid:
                        state.update({"device_id": device_id, "key_fingerprint": key_fingerprint, "last_validated_at": now.isoformat(), "expires_at": answer.get("expires_at"),
                                      "check_again_after_hours": answer.get("check_again_after_hours", 24), "offline_grace_days": answer.get("offline_grace_days", 0)})
                        _save_json(STATE_FILE, state)
                        result = {"active": True, "mode": "valid", "expires_at": answer.get("expires_at"), "last_validated_at": state["last_validated_at"], "message": "Licença válida."}
                    else:
                        result = {"active": False, "mode": "invalid", "expires_at": answer.get("expires_at"), "message": "A licença não é válida para este produto ou está expirada."}
                except (OSError, ValueError, HTTPError, URLError) as exc:
                    result = _offline_status(state, str(exc))
        MEMORY.update({"checked": now, "status": result})
        return result
