"""
Authentication, session management, and audit logging utilities.

- hash_password(): Hash passwords using bcrypt
- verify_password(): Verify password against hash
- create_session(): Create admin session tokens
- verify_session(): Verify session validity
- log_audit(): Log administrative actions
- _write_analytics_conf_key(): Update analytics.conf settings
"""

import json
import secrets
import sqlite3
import sys
from typing import Any

from homelinkwg.config import (
    ANALYTICS_CONFIG, SESSION_TIMEOUT_MINUTES, _db_connect, _now_ts
)

try:
    import bcrypt  # type: ignore
except Exception:
    bcrypt = None  # type: ignore


# ---------------------------------------------------------------------------
# Password hashing and verification
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    if bcrypt is None:
        raise RuntimeError("bcrypt module missing")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hash_str: str) -> bool:
    """Verify password against hash."""
    if bcrypt is None:
        return False
    try:
        return bcrypt.checkpw(password.encode(), hash_str.encode())
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def create_session(ip_address: str, user_agent: str) -> str:
    """Create admin session and return token."""
    token = secrets.token_urlsafe(32)
    now = _now_ts()
    expires_at = now + (SESSION_TIMEOUT_MINUTES * 60)

    try:
        with _db_connect() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (now,))
            conn.execute(
                """
                INSERT INTO admin_sessions (token, created_at, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
                """,
                (token, now, expires_at, ip_address, user_agent),
            )
    except sqlite3.Error as e:
        print(f"[homelinkwg-dashboard] session creation error: {e}", file=sys.stderr)
        return ""

    return token


def verify_session(token: str) -> bool:
    """Verify if session token is valid and not expired."""
    if not token:
        return False

    try:
        now = _now_ts()
        with _db_connect() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (now,))
            result = conn.execute(
                """
                SELECT expires_at FROM admin_sessions
                WHERE token = ? AND expires_at > ?
                """,
                (token, now),
            ).fetchone()
        return bool(result)
    except sqlite3.Error:
        return False


# ---------------------------------------------------------------------------
# Configuration management
# ---------------------------------------------------------------------------

def _write_analytics_conf_key(key: str, value: str) -> None:
    """Update or append a single key=value in analytics.conf (thread-safe best-effort)."""
    try:
        text = ANALYTICS_CONFIG.read_text(encoding="utf-8") if ANALYTICS_CONFIG.exists() else ""
        lines = text.splitlines()
        found = False
        new_lines = []
        for line in lines:
            if line.startswith(f"{key}="):
                new_lines.append(f"{key}={value}")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"{key}={value}")
        ANALYTICS_CONFIG.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"[homelinkwg-dashboard] analytics.conf write error: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def log_audit(action: str, admin_ip: str, target: str, details: dict[str, Any], status: str) -> None:
    """Log administrative action to audit_log table."""
    try:
        with _db_connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (timestamp, action, admin, target, details, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (_now_ts(), action, admin_ip, target, json.dumps(details), status),
            )
    except sqlite3.Error as e:
        print(f"[homelinkwg-dashboard] audit log error: {e}", file=sys.stderr)
