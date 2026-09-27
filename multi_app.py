#!/usr/bin/env python3
"""Painel único das seis OLTs, lendo apenas bancos locais persistidos."""
import json
import html
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
from http.cookies import SimpleCookie
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from app import disconnect_reason_text, onts_text, pon_identity
import auth_store
import olt_registry
import autofind_query
import license_manager

ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/var/lib/olt-vision"))
def configured_olts():
    return json.loads((ROOT / "olts.json").read_text(encoding="utf-8"))
HTML = (ROOT / "multi_index.html").read_text(encoding="utf-8")
LOGIN_HTML = (ROOT / "login.html").read_text(encoding="utf-8")
ADMIN_HTML = (ROOT / "admin.html").read_text(encoding="utf-8")
LICENSE_HTML = (ROOT / "license.html").read_text(encoding="utf-8")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
VIEWER_USERNAME = os.environ.get("VIEWER_USERNAME", "viewer")
CACHE = {"at": 0.0, "olts": [], "refreshing": False}
LOCK = threading.Lock()
PROBES = {}
AUTOFIND_LOCK = threading.Lock()
AUTOFIND_LAST = {}
AUTOFIND_RUNNING = set()
AUTOFIND_COOLDOWN = 30

def latest_nonempty(db, field):
    try:
        row = db.execute(f"SELECT payload_json FROM dashboard_snapshots WHERE json_array_length(json_extract(payload_json,'$.{field}')) > 0 ORDER BY poll_id DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None
    except sqlite3.OperationalError:
        return None

def read_olt(config):
    result = {"id": config["id"], "name": config["name"], "host": config["host"],
              "pons": [], "onts": [], "interfaces": [], "temperatures": [],
              "status": "aguardando", "collected_at": None, "ont_collected_at": None,
              "fast_collected_at": None, "collection_warning": None,
              "collection_note": config.get("collection_note")}
    path = DATA_ROOT / f"{config['id']}.db"
    if not path.exists(): return result
    try:
        with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=5) as db:
            db.execute("PRAGMA busy_timeout=5000")
            full = latest_nonempty(db, "pons")
            ont_snapshot = latest_nonempty(db, "onts")
            if full:
                for key in ("pons", "interfaces", "temperatures", "uptime", "ping_ms", "snmp_ok", "collected_at", "status", "board_cpu", "board_temperatures", "board_fans"):
                    result[key] = full.get(key, result.get(key))
                interface_names = {row["index"]: row.get("name") for row in result["interfaces"]}
                for pon in result["pons"]:
                    identity = pon_identity(pon["index"], interface_names.get(pon["index"]))
                    if identity: pon.update(identity)
            if ont_snapshot:
                result["onts"] = ont_snapshot["onts"]
                result["ont_collected_at"] = ont_snapshot.get("collected_at")
                try:
                    history = {index: (reason,status) for index,reason,status in db.execute("SELECT o.snmp_index,(SELECT s.disconnect_reason FROM ont_samples s WHERE s.ont_id=o.id AND s.disconnect_reason IS NOT NULL ORDER BY s.poll_id DESC LIMIT 1),(SELECT s.status FROM ont_samples s WHERE s.ont_id=o.id AND s.status IN ('online','offline') ORDER BY s.poll_id DESC LIMIT 1) FROM onts o",).fetchall()}
                    for ont in result["onts"]:
                        reason, status = history.get(ont["index"], (None,None))
                        if ont.get("disconnect_reason") is None: ont["disconnect_reason"] = reason
                        if ont.get("status") not in ("online", "offline") and status:
                            ont["status"] = status
                            ont["_status_inherited"] = True
                        ont["disconnect_reason_text"] = disconnect_reason_text(ont.get("disconnect_reason"))
                except sqlite3.OperationalError:
                    pass
            try:
                vlan_row = db.execute("SELECT collected_at,payload_json,link_count FROM latest_vlan_status WHERE id=1").fetchone()
            except sqlite3.OperationalError:
                vlan_row = None
            if vlan_row:
                vlan_payload = json.loads(vlan_row[1])
                pon_by_index = {pon.get("index"): pon for pon in result["pons"]}
                pon_vlans = {}
                for ont in result["onts"]:
                    pon = pon_by_index.get(ont.get("pon_index"))
                    sfp = pon.get("sfp") if pon else None
                    vlans = vlan_payload.get(f"{sfp}:{ont.get('ont_number')}", []) if sfp else []
                    ont["vlans"] = vlans
                    if vlans:
                        pon_vlans.setdefault(ont.get("pon_index"), set()).update(vlans)
                for pon in result["pons"]:
                    pon["vlans"] = sorted(pon_vlans.get(pon.get("index"), set()))
                result["vlan_collected_at"] = vlan_row[0]
            try:
                row = db.execute("SELECT last_ok_at,pons_json,error FROM latest_fast_status WHERE id=1").fetchone()
            except sqlite3.OperationalError:
                row = None
            if row and row[0] and row[1]:
                result["fast_collected_at"] = row[0]
                fast = json.loads(row[1])
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(row[0])).total_seconds()
                if age <= 300:
                    if not result["pons"]:
                        result["pons"] = [{"index":index,"name":f"GPON {(pon_identity(index) or {}).get('sfp','?')}","status":status,
                                           "temperature":None,"tx_power":None,**(pon_identity(index) or {})}
                                          for index,status in sorted(fast.items(), key=lambda item:int(item[0]))]
                    else:
                        for pon in result["pons"]:
                            if pon["index"] in fast: pon["status"] = fast[pon["index"]]
            try:
                traffic_row = db.execute("SELECT last_ok_at,interfaces_json FROM latest_fast_traffic WHERE id=1").fetchone()
            except sqlite3.OperationalError:
                traffic_row = None
            if traffic_row and traffic_row[0] and traffic_row[1]:
                traffic_age = (datetime.now(timezone.utc) - datetime.fromisoformat(traffic_row[0])).total_seconds()
                if traffic_age <= 90:
                    traffic = json.loads(traffic_row[1])
                    for interface in result["interfaces"]:
                        # A tabela leve guarda a última taxa calculada a cada 30s.
                        # Ela prevalece sobre a taxa da coleta completa, que pode estar
                        # vazia logo após reinício ou após uma virada de contador.
                        if interface["index"] in traffic:
                            sample = traffic[interface["index"]]
                            if sample.get("in_bps") is not None and sample.get("out_bps") is not None:
                                interface.update(sample)
            if not full and result["pons"]: result["status"] = "parcial"
            if not result["pons"]: result["collection_warning"] = "Aguardando primeira leitura das PONs"
            return result
    except (sqlite3.Error, ValueError) as exc:
        result["collection_warning"] = f"Falha ao ler banco local: {exc}"
        return result

def refresh_cache(configs):
    try:
        fresh = [read_olt(config) for config in configs]
        with LOCK:
            CACHE["olts"] = fresh
            CACHE["at"] = time.monotonic()
    finally:
        with LOCK:
            CACHE["refreshing"] = False

def all_olts():
    configs = configured_olts()
    config_ids = {item["id"] for item in configs}
    with LOCK:
        cached_ids = {item["id"] for item in CACHE["olts"]}
        expired = time.monotonic() - CACHE["at"] > 20
        if CACHE["olts"] and cached_ids == config_ids:
            if expired and not CACHE["refreshing"]:
                CACHE["refreshing"] = True
                threading.Thread(target=refresh_cache, args=(configs,), daemon=True).start()
            return CACHE["olts"]
        CACHE["refreshing"] = True
    # Na primeira carga, ainda precisamos de um resultado antes de responder.
    refresh_cache(configs)
    with LOCK:
        return CACHE["olts"]

def dashboard_olts():
    response = []
    for olt in all_olts():
        counts = {}
        for ont in olt["onts"]:
            item = counts.setdefault(ont["pon_index"], {"total": 0, "online": 0, "offline": 0})
            item["total"] += 1
            if ont["status"] in ("online", "offline"): item[ont["status"]] += 1
        response.append({**{key:value for key,value in olt.items() if key != "onts"},
                         "ont_count":len(olt["onts"]), "ont_counts":counts})
    return response

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def admin_page(self, session, notice="", discovery=None, status=200):
        users = auth_store.managed_users(session)
        license_status = license_manager.status()
        license_line = license_status.get("message", "Estado desconhecido")
        if license_status.get("expires_at"): license_line += f' Vencimento: {license_status["expires_at"][:10]}.'
        if license_status.get("host_limit") is not None: license_line += f' Hosts: {license_status.get("hosts_in_use", 0)}/{license_status["host_limit"]}.'
        discovery_html = ""
        if discovery:
            boards = ", ".join(discovery["boards"])
            ports = ", ".join(discovery["ports"])
            cli = discovery.get("cli", {})
            protocol = discovery.get("protocol", "telnet").upper()
            snmp_card = f'<div class="check"><span class="ok">✓ SNMP respondendo</span><br><small>{discovery.get("snmp_elapsed", 0):.1f}s</small></div>'
            if cli.get("ok"):
                interval = int(cli["recommended_interval"])
                cli_card = (f'<div class="check"><span class="ok">✓ {html.escape(protocol)} respondendo</span><br>'
                            f'<small>Diagnóstico em {float(cli["elapsed"]):.1f}s</small></div>'
                            f'<div class="check"><strong>{int(cli["ont_count"])} ONTs</strong><br><small>Resumo da placa testada</small></div>'
                            f'<div class="check"><strong>{int(cli["vlan_count"])} VLANs</strong><br><small>Linhas associadas a ONTs</small></div>'
                            f'<div class="check"><strong>{int(cli["optical_count"])} ópticas</strong><br><small>Leituras na PON testada</small></div>'
                            f'<div class="check"><strong>{interval // 60} min</strong><br><small>Intervalo recomendado</small></div>')
            else:
                cli_card = (f'<div class="check"><span class="bad">✕ Falha no {html.escape(protocol)}</span><br>'
                            f'<small>{html.escape(cli.get("error", "Sem resposta"))}</small></div>')
            confirm = ""
            if discovery.get("ready"):
                confirm = (f'<form method="post" action="/admin/olts/add"><input type="hidden" name="csrf" value="{html.escape(session["csrf"])}">'
                           '<button type="submit">Confirmar cadastro e iniciar coleta</button></form>')
            else:
                confirm = '<p class="bad">Cadastro bloqueado: o teste precisa retornar ONTs e VLANs pela CLI.</p>'
            discovery_html = (f'<div class="probe{("" if discovery.get("ready") else " error")}"><h3>Diagnóstico da OLT</h3>'
                              f'<p><strong>{html.escape(discovery["name"])} · {html.escape(discovery["ip"])}</strong></p>'
                              f'<div class="checks">{snmp_card}{cli_card}</div><p>Placas: {html.escape(boards)}</p>'
                              f'<p>{len(discovery["ports"])} portas detectadas: {html.escape(ports)}</p>{confirm}</div>')
        existing = "".join(f'<li>{html.escape(item["name"])} · {html.escape(item["host"])}</li>' for item in configured_olts())
        user_rows = "".join(f'<li><strong>{html.escape(item["username"])}</strong> · {html.escape(item["role"].replace("superadmin", "Superadmin").replace("viewer", "Visualização").replace("admin", "Admin"))} · {"Ativo" if item["enabled"] else "Desativado"}</li>' for item in users) or "<li>Nenhum usuário cadastrado.</li>"
        password_targets = "".join(f'<option value="{html.escape(item["username"])}">{html.escape(item["username"])}</option>' for item in users)
        can_manage_olts = session["role"] == "superadmin"
        roles = '<option value="admin">Admin</option><option value="viewer">Visualização</option><option value="superadmin">Superadmin</option>' if can_manage_olts else '<option value="viewer">Visualização</option>'
        body = (ADMIN_HTML.replace("__CSRF__", html.escape(session["csrf"]))
                .replace("__VIEWER_STATUS__", "Ativo" if viewer and viewer["enabled"] else "Desativado")
                .replace("__VIEWER_USERNAME__", html.escape(VIEWER_USERNAME))
                .replace("__NEXT_ENABLED__", "0" if viewer and viewer["enabled"] else "1")
                .replace("__ACTION__", "Desativar" if viewer and viewer["enabled"] else "Ativar")
                .replace("__NOTICE__", html.escape(notice))
                .replace("__LICENSE_STATUS__", html.escape(license_line))
                .replace("__OLT_SECTION_CLASS__", "" if can_manage_olts else "hidden")
                .replace("__USER_ROLES__", roles)
                .replace("__USER_LIST__", user_rows)
                .replace("__PASSWORD_TARGETS__", password_targets)
                .replace("__USER_LIMIT_NOTE__", "Você pode criar usuários Admin, Visualização e Superadmin." if can_manage_olts else "Você pode cadastrar até 3 usuários de visualização; cada um pode manter até 2 sessões abertas.")
                .replace("__DISCOVERY__", discovery_html)
                .replace("__OLT_LIST__", existing))
        self.send_body(status, body)

    def send_body(self, status, body, content_type="text/html; charset=utf-8", headers=None):
        if isinstance(body, str): body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        for key,value in (headers or {}).items(): self.send_header(key,value)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, destination, cookie=None):
        headers = {"Location":destination}
        if cookie: headers["Set-Cookie"] = cookie
        self.send_body(303, b"", headers=headers)

    def session(self):
        try:
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookies["olt_session"].value if "olt_session" in cookies else None
        except Exception:
            token = None
        return auth_store.current_session(token)

    def login_page(self, error="", status=200):
        body = LOGIN_HTML.replace("__ERROR__", html.escape(error))
        self.send_body(status, body)

    def license_page(self, state, status=200):
        detail = state.get("error", "")
        if state.get("expires_at"): detail = f'Vencimento: {state["expires_at"][:10]}'
        body = (LICENSE_HTML.replace("__MESSAGE__", html.escape(state.get("message", "Licença indisponível.")))
                .replace("__DETAIL__", html.escape(detail))
                .replace("__STATUS_CLASS__", "ok" if state.get("active") else "error"))
        self.send_body(status, body)

    def form(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > 4096 or self.headers.get("Content-Type", "").split(";")[0] != "application/x-www-form-urlencoded":
            return None
        try:
            return {key:values[0] for key,values in parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True).items()}
        except (UnicodeDecodeError, ValueError):
            return None

    def do_POST(self):
        path = urlsplit(self.path).path
        form = self.form()
        if form is None:
            self.send_error(400)
            return
        if path == "/license/activate":
            try:
                license_manager.set_license_key(form.get("license_key", ""))
                state = license_manager.status(force=True)
            except ValueError as exc:
                self.license_page({"active": False, "message": str(exc)}, 400)
                return
            if not state.get("active"):
                self.license_page(state, 403)
                return
            self.redirect("/login")
            return
        if not license_manager.status().get("active"):
            self.redirect("/license")
            return
        if path == "/login":
            user = auth_store.authenticate(form.get("username", "")[:64], form.get("password", ""), self.client_address[0])
            if not user:
                self.login_page("Usuário ou senha inválidos, ou tentativas em excesso.", 401)
                return
            token = auth_store.create_session(user["id"])
            if not token:
                self.login_page("Limite de sessões simultâneas atingido para este usuário.", 403)
                return
            flags = "; Secure" if COOKIE_SECURE else ""
            self.redirect("/", f"olt_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={auth_store.SESSION_SECONDS}{flags}")
            return
        session = self.session()
        if not session:
            self.send_error(401)
            return
        if not form.get("csrf") or not secrets.compare_digest(form["csrf"], session["csrf"]):
            self.send_error(403)
            return
        if path == "/logout":
            auth_store.revoke_session(session["token"])
            with LOCK: PROBES.pop(session["token"], None)
            flags = "; Secure" if COOKIE_SECURE else ""
            self.redirect("/login", f"olt_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{flags}")
            return
        if session["role"] not in ("superadmin", "admin"):
            self.send_error(403)
            return
        if path == "/admin/license/validate":
            state = license_manager.status(force=True)
            self.admin_page(session, state.get("message", "Validação concluída."))
            return
        if path == "/options/users/add":
            try:
                auth_store.create_user(session, form.get("username", ""), form.get("password", ""), form.get("role", ""))
            except ValueError as exc:
                self.admin_page(session, str(exc), status=400)
                return
            self.redirect("/options?updated=user")
            return
        if path == "/options/users/password":
            try:
                auth_store.set_password_scoped(session, form.get("username", ""), form.get("password", ""))
            except ValueError as exc:
                self.admin_page(session, str(exc), status=400)
                return
            self.redirect("/options?updated=password")
            return
        if session["role"] != "superadmin":
            self.send_error(403)
            return
        if path == "/admin/olts/probe":
            try:
                discovery = olt_registry.probe(form.get("ip", ""), form.get("community", ""), form.get("name", ""),
                                               form.get("protocol", ""), form.get("access_username", ""),
                                               form.get("access_password", ""), form.get("access_port", ""),
                                               form.get("telegram_chat_id", ""))
                if any(item["host"] == discovery["ip"] for item in configured_olts()):
                    raise ValueError("Esta OLT já está cadastrada.")
            except ValueError as exc:
                self.admin_page(session, str(exc), status=400)
                return
            except (OSError, subprocess.TimeoutExpired):
                self.admin_page(session, "Tempo limite ou falha na consulta SNMP.", status=504)
                return
            with LOCK: PROBES[session["token"]] = (time.monotonic(), discovery)
            self.admin_page(session, "Diagnóstico concluído. Confira os resultados antes de cadastrar.", discovery)
            return
        if path == "/admin/olts/add":
            with LOCK: candidate = PROBES.pop(session["token"], None)
            if not candidate or time.monotonic() - candidate[0] > 600:
                self.admin_page(session, "Teste expirado. Faça uma nova consulta SNMP.", status=400)
                return
            try:
                olt_registry.register(candidate[1])
            except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                self.admin_page(session, str(exc), status=500)
                return
            self.redirect("/admin?updated=olt")
            return
        if path == "/admin/viewer/password":
            try: auth_store.set_password(VIEWER_USERNAME, form.get("password", ""))
            except ValueError as exc:
                self.send_body(400, html.escape(str(exc)))
                return
            self.redirect("/admin?updated=password")
            return
        if path == "/admin/viewer/enable":
            if form.get("enabled") not in ("0", "1"):
                self.send_error(400)
                return
            auth_store.set_enabled(VIEWER_USERNAME, form["enabled"] == "1")
            self.redirect("/admin?updated=status")
            return
        self.send_error(404)

    def do_GET(self):
        request = urlsplit(self.path)
        state = license_manager.status()
        if request.path == "/license":
            if state.get("active"): self.redirect("/login")
            else: self.license_page(state)
            return
        if not state.get("active"):
            self.redirect("/license")
            return
        session = self.session()
        if request.path == "/login":
            if session: self.redirect("/")
            else: self.login_page()
            return
        if not session:
            if request.path == "/api/state": self.send_body(401, b"{}", "application/json; charset=utf-8")
            else: self.redirect("/login")
            return
        if request.path == "/api/autofind":
            olt_id = parse_qs(request.query).get("olt", [None])[0]
            config = next((item for item in configured_olts() if item["id"] == olt_id), None)
            if not config:
                self.send_body(404, b'{"error":"OLT nao encontrada"}', "application/json; charset=utf-8")
                return
            with AUTOFIND_LOCK:
                now = time.monotonic()
                remaining = max(0, AUTOFIND_COOLDOWN - int(now - AUTOFIND_LAST.get(olt_id, 0)))
                if olt_id in AUTOFIND_RUNNING:
                    self.send_body(409, json.dumps({"error":"Esta OLT já está sendo consultada"}).encode(), "application/json; charset=utf-8")
                    return
                if remaining:
                    self.send_body(429, json.dumps({"error":f"Aguarde {remaining} segundos para consultar novamente", "retry_after":remaining}).encode(), "application/json; charset=utf-8")
                    return
                AUTOFIND_RUNNING.add(olt_id)
                AUTOFIND_LAST[olt_id] = now
            try:
                data = autofind_query.query(config)
                data["queried_at"] = datetime.now(timezone.utc).isoformat()
                self.send_body(200, json.dumps(data, ensure_ascii=False), "application/json; charset=utf-8")
            except Exception as exc:
                self.send_body(502, json.dumps({"error":str(exc)}, ensure_ascii=False), "application/json; charset=utf-8")
            finally:
                with AUTOFIND_LOCK:
                    AUTOFIND_RUNNING.discard(olt_id)
            return
        if request.path == "/api/state":
            self.send_body(200, json.dumps(dashboard_olts(), ensure_ascii=False), "application/json; charset=utf-8")
            return
        if request.path == "/api/onts":
            params = parse_qs(request.query)
            olt_id, sfp = params.get("olt", [None])[0], params.get("sfp", [None])[0]
            by_id = {olt["id"]: olt for olt in configured_olts()}
            if olt_id not in by_id or not sfp or not re.fullmatch(r"\d+/\d+/\d+", sfp):
                self.send_body(400, b'{"error":"OLT ou S/F/P invalido"}', "application/json; charset=utf-8")
                return
            data = read_olt(by_id[olt_id])
            pon = next((item for item in data["pons"] if item.get("sfp") == sfp), None)
            if pon is None:
                self.send_body(404, b'{"error":"PON nao encontrada"}', "application/json; charset=utf-8")
                return
            if not data["ont_collected_at"]:
                self.send_body(503, b'{"error":"Aguardando coleta de ONTs"}', "application/json; charset=utf-8")
                return
            onts = [{
                "number": ont.get("ont_number"),
                "name": ont.get("description") or "Sem descricao",
                "serial": ont.get("serial_text") or ont.get("serial_hex") or "Sem leitura",
                "status": ont.get("status"), "rx_power": ont.get("rx_power"),
                "temperature": ont.get("temperature"),
                "vlans": ont.get("vlans", []),
                "disconnect_reason": ont.get("disconnect_reason_text") or disconnect_reason_text(ont.get("disconnect_reason")),
            } for ont in data["onts"] if ont.get("pon_index") == pon["index"]]
            onts.sort(key=lambda item: item["number"] if isinstance(item["number"], int) else 999999)
            self.send_body(200, json.dumps({"olt": olt_id, "sfp": sfp, "collected_at": data["ont_collected_at"], "onts": onts}, ensure_ascii=False), "application/json; charset=utf-8")
            return
        if request.path in ("/admin", "/options"):
            if session["role"] not in ("superadmin", "admin"):
                self.send_error(403)
                return
            updated = parse_qs(request.query).get("updated", [""])[0]
            notice = "OLT cadastrada. A primeira coleta pode levar alguns minutos." if updated == "olt" else "Usuário cadastrado." if updated == "user" else "Senha alterada." if updated == "password" else "Alteração salva." if updated == "status" else ""
            self.admin_page(session, notice)
            return
        if request.path == "/onts.txt":
            params = parse_qs(request.query)
            olt_id = params.get("olt", [None])[0]
            sfp = params.get("sfp", [None])[0]
            by_id = {olt["id"]:olt for olt in configured_olts()}
            if olt_id not in by_id or not sfp or not re.fullmatch(r"\d+/\d+/\d+", sfp):
                self.send_error(400, "Informe OLT e S/F/P válidos")
                return
            data = read_olt(by_id[olt_id])
            pon = next((pon for pon in data["pons"] if pon.get("sfp") == sfp), None)
            if pon is None:
                self.send_error(404, "PON não encontrada")
                return
            if not data["ont_collected_at"]:
                self.send_error(503, "Aguardando primeira coleta de ONTs")
                return
            pon_index = pon["index"]
            onts = [ont for ont in data["onts"] if ont["pon_index"] == pon_index]
            inherited = sum(bool(ont.get("_status_inherited")) for ont in onts)
            report = {**data,"onts":onts,"pon_number":sfp,"pon_label":sfp,"collected_at":data["ont_collected_at"],
                      "status_warning":f"Estado de {inherited} ONT(s) obtido da última leitura válida no banco" if inherited else None}
            body = ("\ufeff" + onts_text(report)).encode("utf-8")
            safe_sfp = sfp.replace("/", "-")
            self.send_body(200, body, "text/plain; charset=utf-8", {"Content-Disposition": f'attachment; filename="onts-{olt_id}-pon-{safe_sfp}.txt"'})
            return
        if request.path != "/":
            self.send_error(404)
            return
        payload = json.dumps(dashboard_olts(), ensure_ascii=False).replace("</", "<\\/")
        admin_link = '<a href="/options">Opções</a>' if session["role"] in ("superadmin", "admin") else ""
        body = (HTML.replace("__OLTS_DATA__", payload)
                .replace("__USERNAME__", html.escape(session["username"]))
                .replace("__ADMIN_LINK__", admin_link)
                .replace("__CSRF__", html.escape(session["csrf"])))
        self.send_body(200, body)

if __name__ == "__main__":
    auth_store.initialize()
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "6000"))), Handler).serve_forever()
