"""Descoberta SNMP e cadastro administrativo de OLTs."""
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
import math
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app import pon_identity
from huawei_telnet import HuaweiTelnet
from huawei_ssh import HuaweiSSH

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "olts.json"
ENV_ROOT = Path(os.environ.get("OLT_ENV_ROOT", "/etc/olt-vision/olts"))
DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/var/lib/olt-vision"))
PON_STATUS = "1.3.6.1.4.1.2011.6.128.1.1.2.21.1.10"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"

def validate(ip, community, name=""):
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError as exc:
        raise ValueError("Informe um endereço IPv4 válido.") from exc
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError("Informe o IPv4 privado de gerenciamento da OLT.")
    if not 1 <= len(community) <= 128 or any(ord(char) < 33 or ord(char) > 126 for char in community):
        raise ValueError("A community deve ter de 1 a 128 caracteres ASCII sem espaços.")
    if len(name) > 60 or any(ord(char) < 32 for char in name):
        raise ValueError("O nome deve ter até 60 caracteres.")
    return str(address), community, name.strip() or str(address)

def snmp_rows(host, community, oid):
    result = subprocess.run(["snmpbulkwalk", "-v2c", "-c", community, "-On", "-Cr10", "-t", "2", "-r", "0", host, oid],
                            text=True, capture_output=True, timeout=20)
    rows = {}
    for line in result.stdout.splitlines():
        match = re.match(rf"\.{re.escape(oid)}\.(\d+)\s+=\s+[^:]+:\s*(.*)", line)
        if match: rows[match.group(1)] = match.group(2).strip().strip('"')
    if not rows and result.returncode:
        raise ValueError("OLT não respondeu à consulta SNMP. Verifique IP, community e rota.")
    return rows

def validate_access(protocol, username, password, port=""):
    protocol = protocol.strip().lower()
    if protocol not in ("ssh", "telnet"): raise ValueError("Escolha SSH ou Telnet.")
    if not username or len(username) > 64 or any(ord(char) < 33 for char in username):
        raise ValueError("Informe um usuário de acesso válido.")
    if not password or len(password) > 128 or any(ord(char) < 32 for char in password):
        raise ValueError("Informe uma senha de acesso válida.")
    default_port = 22 if protocol == "ssh" else 23
    try: access_port = int(port) if str(port).strip() else default_port
    except ValueError as exc: raise ValueError("A porta de acesso é inválida.") from exc
    if not 1 <= access_port <= 65535: raise ValueError("A porta de acesso é inválida.")
    return protocol, username, password, access_port

def cli_probe(ip, protocol, username, password, port, boards, ports):
    session_class = HuaweiSSH if protocol == "ssh" else HuaweiTelnet
    started = time.monotonic()
    first_board, first_sfp = boards[0], ports[0]
    frame, slot = first_board.split("/")
    pon_port = first_sfp.split("/")[2]
    with session_class(ip, username, password, port=port, timeout=55) as session:
        session.enter_config()
        summary = session.command(f"display ont info summary {first_board}")
        total_onts = sum(int(value) for value in re.findall(r"total of ONTs are:\s*(\d+)", summary, re.I))
        session.command(f"interface gpon {frame}/{slot}")
        vlan_output = session.command("display this | include vlan")
        vlan_command = "display this | include vlan"
        if "Unknown command" in vlan_output or "% Unknown" in vlan_output or "error locates" in vlan_output:
            session.command("quit")
            session.command(f"interface gpon {frame}/{slot}")
            vlan_output = session.command("display current-configuration")
            vlan_command = "display current-configuration"
        clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", vlan_output)
        vlan_count = len(re.findall(r"^\s*ont\s+port\s+(?:native-)?vlan\s+\d+\s+\d+\s+eth\s+\d+\s+vlan\s+\d+\b", clean, re.M | re.I))
        optical = session.command(f"display ont optical-info {pon_port} all")
        optical_count = len(re.findall(r"^\s*\d+\s+-?[\d.]+\s+[-\d.]+\s+[-\d.]+\s+-?\d+", optical, re.M))
    elapsed = time.monotonic() - started
    if elapsed > 120 or total_onts > 2000 or len(ports) > 64: recommended = 600
    elif elapsed > 50 or total_onts > 1000 or len(ports) > 32: recommended = 600
    else: recommended = 300
    return {"ok": True, "elapsed": round(elapsed, 1), "ont_count": total_onts,
            "vlan_count": vlan_count, "optical_count": optical_count,
            "vlan_command": vlan_command, "recommended_interval": recommended}

def interval_bounds(recommended):
    recommended = min(600, max(60, int(recommended)))
    minimum = max(1, math.ceil((recommended / 2) / 60))
    return minimum, 10

def chosen_interval(recommended, minutes):
    minimum, maximum = interval_bounds(recommended)
    try: value = int(minutes)
    except (TypeError, ValueError): value = recommended // 60
    if not minimum <= value <= maximum:
        raise ValueError(f"O intervalo deve ficar entre {minimum} e {maximum} minutos para esta OLT.")
    return value * 60

def _env_interval(identifier, fallback):
    try:
        for line in (ENV_ROOT / f"{identifier}.env").read_text(encoding="utf-8").splitlines():
            if line.startswith("POLL_INTERVAL="): return int(line.split("=", 1)[1])
    except (OSError, ValueError): pass
    return fallback

def interval_info(config):
    recommended = min(600, int(config.get("recommended_interval", 600)))
    current = _env_interval(config["id"], recommended)
    minimum, maximum = interval_bounds(recommended)
    return {"recommended_minutes": recommended // 60, "current_minutes": max(1, current // 60), "minimum_minutes": minimum, "maximum_minutes": maximum}

def update_interval(identifier, minutes):
    configs = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    config = next((item for item in configs if item.get("id") == identifier), None)
    if not config: raise ValueError("OLT não encontrada.")
    recommended = min(600, int(config.get("recommended_interval", _env_interval(identifier, 600))))
    seconds = chosen_interval(recommended, minutes)
    env_path = ENV_ROOT / f"{identifier}.env"
    if not env_path.exists(): raise ValueError("Arquivo de configuração da OLT não encontrado.")
    lines = env_path.read_text(encoding="utf-8").splitlines()
    lines = [f"POLL_INTERVAL={seconds}" if line.startswith("POLL_INTERVAL=") else line for line in lines]
    if not any(line.startswith("POLL_INTERVAL=") for line in lines): lines.append(f"POLL_INTERVAL={seconds}")
    fd, temp_name = tempfile.mkstemp(prefix=".interval-", dir=ENV_ROOT)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream: stream.write("\n".join(lines) + "\n")
        os.chmod(temp_name, 0o600); os.replace(temp_name, env_path)
    finally:
        if os.path.exists(temp_name): os.unlink(temp_name)
    return seconds

def _read_env(identifier):
    path = ENV_ROOT / f"{identifier}.env"
    if not path.exists():
        raise ValueError("Arquivo de configuração da OLT não encontrado.")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return path, values

def _write_env(path, values):
    fd, temp_name = tempfile.mkstemp(prefix=".olt-config-", dir=ENV_ROOT)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("\n".join(f"{key}={value}" for key, value in values.items()) + "\n")
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name): os.unlink(temp_name)

def validate_telegram(token, chat_id):
    token, chat_id = token.strip(), chat_id.strip()
    if not token or len(token) > 256 or any(char.isspace() for char in token) or ":" not in token:
        raise ValueError("Informe um token de bot Telegram válido.")
    if not re.fullmatch(r"-?\d{5,20}", chat_id):
        raise ValueError("O ID do grupo Telegram é inválido.")
    return token, chat_id

def test_telegram(token, chat_id, name):
    token, chat_id = validate_telegram(token, chat_id)
    message = f"✅ Teste de integração Telegram — LVL Gerenciador de OLTs\nOLT: {name}"
    request = Request(f"https://api.telegram.org/bot{token}/sendMessage",
                      data=urlencode({"chat_id": chat_id, "text": message}).encode("utf-8"), method="POST")
    try:
        with urlopen(request, timeout=15) as response:
            if not json.load(response).get("ok"):
                raise ValueError("Telegram não confirmou o envio do teste.")
    except HTTPError as exc:
        raise ValueError("Telegram recusou o teste. Confira o token e o ID do grupo.") from exc
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        if isinstance(exc, ValueError): raise
        raise ValueError("Não foi possível comunicar com o Telegram para realizar o teste.") from exc
    return True

def telegram_info(config):
    try:
        _, values = _read_env(config["id"])
        token = values.get("TELEGRAM_BOT_TOKEN", "").strip()
    except ValueError:
        token = ""
    return {"chat_id": config.get("telegram_chat_id", ""), "configured": bool(token and config.get("telegram_chat_id"))}

def update_telegram(identifier, token, chat_id):
    configs = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    config = next((item for item in configs if item.get("id") == identifier), None)
    if not config: raise ValueError("OLT não encontrada.")
    path, values = _read_env(identifier)
    token = token.strip() or values.get("TELEGRAM_BOT_TOKEN", "").strip()
    token, chat_id = validate_telegram(token, chat_id)
    test_telegram(token, chat_id, config.get("name", identifier))
    values["TELEGRAM_BOT_TOKEN"] = token
    _write_env(path, values)
    config["telegram_chat_id"] = chat_id
    fd, temp_name = tempfile.mkstemp(prefix=".olts-", dir=CONFIG_PATH.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream: json.dump(configs, stream, ensure_ascii=False, indent=2)
        os.chmod(temp_name, 0o644); os.replace(temp_name, CONFIG_PATH)
    finally:
        if os.path.exists(temp_name): os.unlink(temp_name)
    return True

def probe(ip, community, name="", protocol="telnet", username="", password="", port="", telegram_chat_id="", telegram_bot_token=""):
    ip, community, name = validate(ip, community, name)
    protocol, username, password, access_port = validate_access(protocol, username, password, port)
    snmp_started = time.monotonic()
    states = snmp_rows(ip, community, PON_STATUS)
    if not states: raise ValueError("A OLT respondeu, mas não retornou portas GPON nesse OID.")
    names = snmp_rows(ip, community, IF_NAME)
    ports = []
    for index in states:
        identity = pon_identity(index, names.get(index))
        if identity and identity.get("sfp"):
            ports.append(identity["sfp"])
    ports = sorted(set(ports), key=lambda p: tuple(int(n) for n in p.split("/")))
    if not ports: raise ValueError("Não foi possível identificar as portas por S/F/P.")
    boards = sorted(set("/".join(port.split("/")[:2]) for port in ports), key=lambda p: tuple(int(n) for n in p.split("/")))
    snmp_elapsed = round(time.monotonic() - snmp_started, 1)
    telegram_chat_id, telegram_bot_token = telegram_chat_id.strip(), telegram_bot_token.strip()
    if bool(telegram_chat_id) != bool(telegram_bot_token):
        raise ValueError("Informe o token do bot e o ID do grupo Telegram juntos.")
    if telegram_chat_id: validate_telegram(telegram_bot_token, telegram_chat_id)
    discovery = {"ip":ip, "name":name, "community":community, "boards":boards, "ports":ports,
                 "protocol":protocol, "username":username, "password":password, "access_port":access_port,
                 "telegram_chat_id":telegram_chat_id, "telegram_bot_token":telegram_bot_token,
                 "snmp_ok":True, "snmp_elapsed":snmp_elapsed}
    try:
        discovery["cli"] = cli_probe(ip, protocol, username, password, access_port, boards, ports)
        # Uma OLT nova ou uma placa ainda sem clientes pode retornar zero ONTs/VLANs.
        # O cadastro depende de SNMP + login CLI válidos; as contagens são apenas
        # diagnóstico e não devem impedir a inclusão do equipamento.
        discovery["ready"] = discovery["cli"].get("ok") is True
    except Exception as exc:
        discovery["cli"] = {"ok":False, "error":str(exc)}
        discovery["ready"] = False
    if telegram_chat_id:
        try:
            test_telegram(telegram_bot_token, telegram_chat_id, name)
            discovery["telegram"] = {"ok": True}
        except ValueError as exc:
            discovery["telegram"] = {"ok": False, "error": str(exc)}
            discovery["ready"] = False
    return discovery

def register(discovery, poll_minutes=None):
    ip, community, name = validate(discovery["ip"], discovery["community"], discovery["name"])
    olts = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if any(item["host"] == ip for item in olts): raise ValueError("Esta OLT já está cadastrada.")
    identifier = "olt-" + ip.replace(".", "-")
    if any(item["id"] == identifier for item in olts): raise ValueError("Identificador já cadastrado.")
    ENV_ROOT.mkdir(parents=True, exist_ok=True)
    env_path = ENV_ROOT / f"{identifier}.env"
    if env_path.exists(): raise ValueError("Já existe configuração para este endereço.")
    delay = (len(olts) * 30) % 300
    if not discovery.get("ready"): raise ValueError("O diagnóstico de acesso ainda não foi aprovado.")
    recommended = min(600, int(discovery["cli"]["recommended_interval"]))
    interval = chosen_interval(recommended, poll_minutes)
    protocol, username, password, access_port = validate_access(discovery["protocol"], discovery["username"], discovery["password"], discovery["access_port"])
    env_data = (f"OLT_HOST={ip}\nSNMP_COMMUNITY={json.dumps(community)}\nDATABASE_PATH={DATA_ROOT / (identifier + '.db')}\n"
                f"ACCESS_PROTOCOL={protocol}\nACCESS_USERNAME={json.dumps(username)}\nACCESS_PASSWORD={json.dumps(password)}\nACCESS_PORT={access_port}\n"
                f"POLL_INTERVAL={interval}\nSTART_DELAY={delay}\nSERVE_HTTP=0\n")
    if discovery.get("telegram_bot_token"):
        env_data += f"TELEGRAM_BOT_TOKEN={discovery['telegram_bot_token']}\n"
    fd, temp_name = tempfile.mkstemp(prefix=".olt-", dir=ENV_ROOT)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream: stream.write(env_data)
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, env_path)
        config = {"id":identifier, "name":name, "host":ip, "access_protocol":protocol,
                  "ont_source":protocol, "vlan_source":protocol,
                  "vlan_command":discovery["cli"]["vlan_command"],
                  "recommended_interval":recommended}
        if discovery.get("telegram_chat_id"):
            config["telegram_chat_id"] = discovery["telegram_chat_id"]
        config["collection_note"] = f"Coleta configurada a cada {interval // 60} minutos; recomendação: {recommended // 60} minutos."
        olts.append(config)
        fd, config_temp = tempfile.mkstemp(prefix=".olts-", dir=CONFIG_PATH.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream: json.dump(olts, stream, ensure_ascii=False, indent=2)
            os.chmod(config_temp, 0o644)
            os.replace(config_temp, CONFIG_PATH)
        finally:
            if os.path.exists(config_temp): os.unlink(config_temp)
    finally:
        if os.path.exists(temp_name): os.unlink(temp_name)
    services = ["systemctl", "enable", "--now", f"olt-collector@{identifier}.service", f"olt-vlan@{identifier}.service"]
    if discovery.get("telegram_bot_token"):
        services.append("olt-telegram.service")
    started = subprocess.run(services, capture_output=True, text=True, timeout=20)
    if started.returncode:
        raise RuntimeError("OLT cadastrada, mas a coleta não iniciou. Verifique o serviço do coletor.")
    if discovery.get("telegram_bot_token"):
        subprocess.run(["systemctl", "restart", "olt-telegram.service"], capture_output=True, text=True, timeout=20)
    return identifier
