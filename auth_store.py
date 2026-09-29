"""Identidades, senhas e sessões locais do painel."""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(os.environ.get("AUTH_DB", "/var/lib/olt-vision/auth.db"))
SESSION_SECONDS = 12 * 60 * 60
ROLES = ("superadmin", "admin", "viewer")
SESSION_LIMITS = {"superadmin": None, "admin": 1, "viewer": 2}

@contextmanager
def database():
    db = sqlite3.connect(DB_PATH, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=5000")
    try:
        yield db
        db.commit()
    finally:
        db.close()

def initialize():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with database() as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('superadmin','admin','viewer')),
            salt BLOB NOT NULL, password_hash BLOB NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
            csrf TEXT NOT NULL, expires_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        CREATE TABLE IF NOT EXISTS login_failures (
            id INTEGER PRIMARY KEY, username TEXT NOT NULL,
            ip TEXT NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_failures_time ON login_failures(created_at);
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "created_by" not in columns:
            # Migração da versão com apenas admin/viewer. As sessões são removidas
            # para que a troca de perfil seja aplicada já no próximo login.
            db.execute("DELETE FROM sessions")
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("""CREATE TABLE users_new (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('superadmin','admin','viewer')),
                salt BLOB NOT NULL, password_hash BLOB NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1, created_by INTEGER,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
            db.execute("""INSERT INTO users_new(id,username,role,salt,password_hash,enabled,created_at,updated_at)
                        SELECT id,username,CASE WHEN role='admin' THEN 'superadmin' ELSE 'viewer' END,
                        salt,password_hash,enabled,created_at,updated_at FROM users""")
            db.execute("DROP TABLE users")
            db.execute("ALTER TABLE users_new RENAME TO users")
            db.execute("PRAGMA foreign_keys=ON")
        columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "must_change_password" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
    os.chmod(DB_PATH, 0o600)

def password_hash(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)

def seed_user(username, password, role, must_change_password=False):
    if not password or len(password) < 8: raise ValueError("Senha deve ter ao menos 8 caracteres")
    now = int(time.time())
    salt = os.urandom(16)
    with database() as db:
        db.execute("INSERT OR IGNORE INTO users(username,role,salt,password_hash,must_change_password,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                   (username,role,salt,password_hash(password,salt),int(must_change_password),now,now))

def create_user(actor, username, password, role):
    username = (username or "").strip()
    if role not in ROLES: raise ValueError("Perfil inválido")
    if not 3 <= len(username) <= 64 or not all(char.isalnum() or char in "._-" for char in username):
        raise ValueError("Usuário deve ter entre 3 e 64 caracteres e usar somente letras, números, ponto, hífen ou sublinhado")
    if not password or len(password) < 8: raise ValueError("Senha deve ter ao menos 8 caracteres")
    if actor["role"] == "admin":
        if role != "viewer": raise ValueError("Administradores podem criar somente usuários de visualização")
        with database() as db:
            count = db.execute("SELECT count(*) FROM users WHERE created_by=? AND role='viewer'", (actor["id"],)).fetchone()[0]
            if count >= 3: raise ValueError("Este administrador já cadastrou o limite de 3 usuários de visualização")
    elif actor["role"] != "superadmin": raise ValueError("Sem permissão para cadastrar usuários")
    salt = os.urandom(16); now = int(time.time())
    try:
        with database() as db:
            db.execute("INSERT INTO users(username,role,salt,password_hash,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                       (username,role,salt,password_hash(password,salt),actor["id"],now,now))
    except sqlite3.IntegrityError as exc: raise ValueError("Este usuário já existe") from exc

def managed_users(actor):
    with database() as db:
        if actor["role"] == "superadmin":
            rows = db.execute("SELECT username,role,enabled,created_at FROM users ORDER BY role,username").fetchall()
        elif actor["role"] == "admin":
            rows = db.execute("SELECT username,role,enabled,created_at FROM users WHERE created_by=? OR id=? ORDER BY username", (actor["id"], actor["id"])).fetchall()
        else: rows = []
        return [dict(row) for row in rows]

def user_info(username):
    with database() as db:
        row = db.execute("SELECT id,username,role,enabled,updated_at FROM users WHERE username=?",(username,)).fetchone()
        return dict(row) if row else None

def authenticate(username, password, ip):
    now = int(time.time())
    with database() as db:
        db.execute("DELETE FROM login_failures WHERE created_at < ?", (now-86400,))
        failures = db.execute("SELECT count(*) FROM login_failures WHERE created_at >= ? AND (username=? OR ip=?)",
                              (now-900,username,ip)).fetchone()[0]
        if failures >= 5: return None
        row = db.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        if row and row["enabled"] and hmac.compare_digest(password_hash(password,row["salt"]),row["password_hash"]):
            db.execute("DELETE FROM login_failures WHERE username=? AND ip=?",(username,ip))
            return {"id":row["id"],"username":row["username"],"role":row["role"],"must_change_password":bool(row["must_change_password"])}
        db.execute("INSERT INTO login_failures(username,ip,created_at) VALUES(?,?,?)",(username,ip,now))
        return None

def create_session(user_id):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = int(time.time())
    with database() as db:
        db.execute("DELETE FROM sessions WHERE expires_at < ?",(now,))
        user = db.execute("SELECT role FROM users WHERE id=? AND enabled=1", (user_id,)).fetchone()
        if not user: return None
        limit = SESSION_LIMITS.get(user["role"])
        if limit is not None and db.execute("SELECT count(*) FROM sessions WHERE user_id=?", (user_id,)).fetchone()[0] >= limit:
            return None
        db.execute("INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)",
                   (hashlib.sha256(token.encode()).hexdigest(),user_id,csrf,now+SESSION_SECONDS))
    return token

def current_session(token):
    if not token or len(token) > 200: return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    with database() as db:
        row = db.execute("SELECT s.csrf,s.expires_at,u.id,u.username,u.role,u.enabled,u.must_change_password FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",(digest,)).fetchone()
        if not row or not row["enabled"] or row["expires_at"] < int(time.time()): return None
        return {"id":row["id"],"username":row["username"],"role":row["role"],"csrf":row["csrf"],"token":token,"must_change_password":bool(row["must_change_password"])}

def revoke_session(token):
    if not token: return
    with database() as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(token.encode()).hexdigest(),))

def set_password(username, new_password):
    if len(new_password) < 8: raise ValueError("Senha deve ter ao menos 8 caracteres")
    salt = os.urandom(16)
    with database() as db:
        db.execute("UPDATE users SET salt=?,password_hash=?,must_change_password=0,updated_at=? WHERE username=?",
                   (salt,password_hash(new_password,salt),int(time.time()),username))
        db.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)",(username,))

def set_password_scoped(actor, username, new_password):
    with database() as db:
        target = db.execute("SELECT id,role,created_by FROM users WHERE username=?", (username,)).fetchone()
    if not target: raise ValueError("Usuário não encontrado")
    if actor["role"] == "admin" and not (target["id"] == actor["id"] or (target["role"] == "viewer" and target["created_by"] == actor["id"])):
        raise ValueError("Administradores podem alterar somente a senha dos usuários de visualização que cadastraram")
    if actor["role"] not in ("superadmin", "admin"): raise ValueError("Sem permissão para alterar senha")
    set_password(username, new_password)

def change_own_password(user_id, new_password):
    if len(new_password) < 8: raise ValueError("Senha deve ter ao menos 8 caracteres")
    salt = os.urandom(16)
    with database() as db:
        db.execute("UPDATE users SET salt=?,password_hash=?,must_change_password=0,updated_at=? WHERE id=?",
                   (salt,password_hash(new_password,salt),int(time.time()),user_id))
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))

def set_enabled(username, enabled):
    if username == "admin": raise ValueError("Admin não pode ser desativado")
    with database() as db:
        db.execute("UPDATE users SET enabled=?,updated_at=? WHERE username=?",
                   (int(bool(enabled)),int(time.time()),username))
        if not enabled:
            db.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)",(username,))
