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
            role TEXT NOT NULL CHECK(role IN ('admin','viewer')),
            salt BLOB NOT NULL, password_hash BLOB NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
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
    os.chmod(DB_PATH, 0o600)

def password_hash(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)

def seed_user(username, password, role):
    if not password or len(password) < 8: raise ValueError("Senha deve ter ao menos 8 caracteres")
    now = int(time.time())
    salt = os.urandom(16)
    with database() as db:
        db.execute("INSERT OR IGNORE INTO users(username,role,salt,password_hash,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                   (username,role,salt,password_hash(password,salt),now,now))

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
            return {"id":row["id"],"username":row["username"],"role":row["role"]}
        db.execute("INSERT INTO login_failures(username,ip,created_at) VALUES(?,?,?)",(username,ip,now))
        return None

def create_session(user_id):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = int(time.time())
    with database() as db:
        db.execute("DELETE FROM sessions WHERE expires_at < ?",(now,))
        db.execute("INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)",
                   (hashlib.sha256(token.encode()).hexdigest(),user_id,csrf,now+SESSION_SECONDS))
    return token

def current_session(token):
    if not token or len(token) > 200: return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    with database() as db:
        row = db.execute("SELECT s.csrf,s.expires_at,u.id,u.username,u.role,u.enabled FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",(digest,)).fetchone()
        if not row or not row["enabled"] or row["expires_at"] < int(time.time()): return None
        return {"id":row["id"],"username":row["username"],"role":row["role"],"csrf":row["csrf"],"token":token}

def revoke_session(token):
    if not token: return
    with database() as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(token.encode()).hexdigest(),))

def set_password(username, new_password):
    if len(new_password) < 8: raise ValueError("Senha deve ter ao menos 8 caracteres")
    salt = os.urandom(16)
    with database() as db:
        db.execute("UPDATE users SET salt=?,password_hash=?,updated_at=? WHERE username=?",
                   (salt,password_hash(new_password,salt),int(time.time()),username))
        db.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)",(username,))

def set_enabled(username, enabled):
    if username == "admin": raise ValueError("Admin não pode ser desativado")
    with database() as db:
        db.execute("UPDATE users SET enabled=?,updated_at=? WHERE username=?",
                   (int(bool(enabled)),int(time.time()),username))
        if not enabled:
            db.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)",(username,))
