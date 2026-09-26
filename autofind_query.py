"""Consulta Huawei autofind sob demanda, sem persistência ou alteração na OLT."""
import json
import os
from pathlib import Path

from app import parse_autofind
from huawei_ssh import HuaweiSSH
from huawei_telnet import HuaweiTelnet


GLOBAL_ENV = Path(os.environ.get("OLT_GLOBAL_ENV", "/etc/olt-vision.env"))
OLT_ENV_ROOT = Path(os.environ.get("OLT_ENV_ROOT", "/etc/olt-vision/olts"))


def read_env(path):
    values = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            pass
        values[key.strip()] = str(value)
    return values


def query(config):
    env = read_env(GLOBAL_ENV)
    env.update(read_env(OLT_ENV_ROOT / f"{config['id']}.env"))
    protocol = env.get("ACCESS_PROTOCOL", config.get("access_protocol", "telnet")).lower()
    username = env.get("ACCESS_USERNAME") or env.get("TELNET_USERNAME")
    password = env.get("ACCESS_PASSWORD") or env.get("TELNET_PASSWORD")
    if protocol not in ("ssh", "telnet"):
        raise ValueError("Protocolo de acesso não suportado")
    if not username or not password:
        raise ValueError("A OLT não possui credenciais CLI configuradas")
    port = int(env.get("ACCESS_PORT", 22 if protocol == "ssh" else 23))
    session_class = HuaweiSSH if protocol == "ssh" else HuaweiTelnet
    with session_class(config["host"], username, password, port=port, timeout=45) as session:
        session.enter_config()
        return parse_autofind(session.command("display ont autofind all"))
