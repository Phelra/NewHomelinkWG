"""
Configuration loading, caching, and management utilities.

- load_config(): Load and cache config.json
- load_auth_config(): Load admin password and TOTP settings from analytics.conf
- Threshold management: load_thresholds(), get_threshold(), set_threshold()
- Mode flags: is_light_mode_enabled(), is_ultra_light_mode_enabled()
- Adaptive ultra-light mode: auto-enables on sustained CPU pressure
- Database initialization: init_db()
"""

import json
import sqlite3
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from homelinkwg.utils import flog, log_buffer

# ---------------------------------------------------------------------------
# Configuration paths and constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = SCRIPT_DIR / "config.json"
DB_FILE = SCRIPT_DIR / "homelinkwg-metrics.db"
ANALYTICS_CONFIG = SCRIPT_DIR / "analytics.conf"
RELEASE_NOTES_FILE = SCRIPT_DIR / "RELEASE_NOTES.md"

# Auth settings
SESSION_TIMEOUT_MINUTES = 60
ADMIN_PASSWORD_HASH = None  # Loaded from config
TOTP_SECRET: str | None = None   # Loaded from analytics.conf
TOTP_ENABLED: bool = False        # Loaded from analytics.conf

# Cache TTL constants
CONFIG_CACHE_TTL_SECONDS = 2.0
ANALYTICS_CACHE_TTL_SECONDS = 5.0
LIGHT_TARGET_TTL_SECONDS = 30.0
LIGHT_STATUS_CACHE_TTL_SECONDS = 20      # Increased from 15s for 50% fewer snapshot calls
ULTRA_STATUS_CACHE_TTL_SECONDS = 30
DEFAULT_STATUS_CACHE_TTL_SECONDS = 15    # Increased from 5s for 3x fewer snapshot calls

# Client refresh intervals (milliseconds)
DEFAULT_REFRESH_MS = 5000
LIGHT_REFRESH_MS = 15000
ULTRA_REFRESH_MS = 30000
DEFAULT_ANALYTICS_REFRESH_MS = 30000
LIGHT_ANALYTICS_REFRESH_MS = 90000
ULTRA_ANALYTICS_REFRESH_MS = 300000

# ---------------------------------------------------------------------------
# Global caches and locks
# ---------------------------------------------------------------------------
_config_cache_lock = threading.Lock()
_config_cache: dict[str, Any] = {"value": None, "mtime_ns": None, "loaded_at": 0.0}
_analytics_cache: dict[str, Any] = {"enabled": False, "mtime_ns": None, "loaded_at": 0.0}
_analytics_init_lock = threading.Lock()
_collector_thread: threading.Thread | None = None
# (host,port) -> (expires_at_epoch_seconds, reachable)
_target_probe_cache: dict[tuple[str, int], tuple[float, bool]] = {}
_target_probe_lock = threading.Lock()

# Thresholds cache
thresholds_cache = {
    "latency_threshold_ms": 50.0,
    "uptime_threshold_percent": 95.0
}

# Adaptive ultra-light mode: auto-enable on sustained CPU pressure
_adaptive_state = {
    "active": False,
    "high_streak": 0,
    "low_streak": 0,
    "last_cpu_pct": None,
    "last_change_ts": 0.0,
    "reason": None,
}
_adaptive_lock = threading.Lock()
_ADAPT_HIGH_PCT = 70.0
_ADAPT_LOW_PCT = 25.0
_ADAPT_HIGH_READS = 3
_ADAPT_LOW_READS = 5


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _now_ts() -> int:
    """Current UNIX timestamp in seconds."""
    return int(time.time())


def _safe_mtime_ns(path: Path) -> int | None:
    """Return mtime in nanoseconds, or None when file does not exist."""
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return None


def _parse_kv_config(path: Path) -> dict[str, str]:
    """Parse simple key=value config files."""
    parsed: dict[str, str] = {}
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            parsed[key.strip()] = value.strip()
    except OSError:
        return {}
    return parsed


def _db_connect(*, row_factory: bool = False) -> sqlite3.Connection:
    """Create a SQLite connection with a shared timeout policy."""
    conn = sqlite3.connect(str(DB_FILE), timeout=10.0)
    conn.execute("PRAGMA busy_timeout=10000")
    if row_factory:
        conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

def load_auth_config() -> None:
    """Load admin password hash and TOTP settings from config."""
    global ADMIN_PASSWORD_HASH, TOTP_SECRET, TOTP_ENABLED
    flog("INFO", "config", f"Loading auth config from: {ANALYTICS_CONFIG}")
    if not ANALYTICS_CONFIG.exists():
        flog("WARN", "config", f"Analytics config file NOT FOUND at {ANALYTICS_CONFIG}")
        return
    try:
        cfg = _parse_kv_config(ANALYTICS_CONFIG)
        flog("INFO", "config", f"Parsed config file, found {len(cfg)} keys")
        ADMIN_PASSWORD_HASH = cfg.get("ADMIN_PASSWORD") or None
        TOTP_SECRET = cfg.get("TOTP_SECRET") or None
        TOTP_ENABLED = cfg.get("TOTP_ENABLED", "false").lower() == "true"
        flog("INFO", "config", f"Auth loaded: password_hash={'✓ set' if ADMIN_PASSWORD_HASH else '✗ NOT SET'}, totp={'enabled' if TOTP_ENABLED else 'disabled'}")
    except Exception as e:
        flog("ERROR", "config", f"Failed to load auth config: {e}")


def load_config() -> dict[str, Any]:
    """Load and cache config.json with TTL-based invalidation."""
    mtime_ns = _safe_mtime_ns(CONFIG_FILE)
    now = time.time()
    with _config_cache_lock:
        cached = _config_cache.get("value")
        if (
            cached is not None
            and _config_cache.get("mtime_ns") == mtime_ns
            and now - float(_config_cache.get("loaded_at", 0.0)) < CONFIG_CACHE_TTL_SECONDS
        ):
            return cached

    _default: dict[str, Any] = {
        "ports": [],
        "dashboard": {"port": 5555, "bind_address": "0.0.0.0"},
        "vpn": {"interface": "wg0", "config_file": "yourconfwg/wg0.conf"},
        "analytics": {"enabled": True},
    }

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as f:
            raw = f.read().strip()

        if not raw:
            print(
                f"[homelinkwg-dashboard] config.json is empty — starting with no ports. "
                f"Edit {CONFIG_FILE} to add services.",
                file=sys.stderr,
            )
            loaded: dict[str, Any] = _default
        else:
            loaded = json.loads(raw)

    except FileNotFoundError:
        print(f"[homelinkwg-dashboard] config not found: {CONFIG_FILE} — exiting.", file=sys.stderr)
        sys.exit(1)
    except PermissionError as exc:
        print(
            f"[homelinkwg-dashboard] permission denied reading config ({exc}) — "
            f"running with defaults; fix file permissions to load real config.",
            file=sys.stderr,
        )
        loaded = _default
    except json.JSONDecodeError as exc:
        print(
            f"[homelinkwg-dashboard] invalid JSON in config ({exc}) — "
            f"starting with no ports until the file is fixed.",
            file=sys.stderr,
        )
        loaded = _default

    with _config_cache_lock:
        _config_cache["value"] = loaded
        _config_cache["mtime_ns"] = mtime_ns
        _config_cache["loaded_at"] = now
    return loaded


# ---------------------------------------------------------------------------
# Threshold management
# ---------------------------------------------------------------------------

def load_thresholds() -> None:
    """Load thresholds from database into cache."""
    global thresholds_cache
    try:
        with _db_connect() as conn:
            rows = conn.execute("SELECT key, value FROM thresholds").fetchall()
        for key, value in rows:
            thresholds_cache[key] = float(value)
        print(f"[homelinkwg-dashboard] thresholds loaded: {thresholds_cache}", file=sys.stderr)
    except sqlite3.Error as e:
        print(f"[homelinkwg-dashboard] load_thresholds error: {e}", file=sys.stderr)


def get_threshold(key: str, default: float = 0.0) -> float:
    """Get a threshold value from cache."""
    return thresholds_cache.get(key, default)


def set_threshold(key: str, value: float) -> bool:
    """Update a threshold in database and cache."""
    try:
        with _db_connect() as conn:
            conn.execute(
                """
                UPDATE thresholds SET value = ?, updated_at = ? WHERE key = ?
                """,
                (float(value), _now_ts(), key),
            )
        thresholds_cache[key] = float(value)
        log_buffer.add("systemd", f"⚙️ Threshold updated: {key} = {value}")
        return True
    except sqlite3.Error as e:
        print(f"[homelinkwg-dashboard] set_threshold error: {e}", file=sys.stderr)
        return False


def get_threshold_int(key: str, default: int = 0) -> int:
    """Get a threshold value as integer."""
    try:
        return int(get_threshold(key, float(default)))
    except (TypeError, ValueError):
        return default


def alerts_muted_until_ts() -> int:
    """Return UNIX timestamp until which alerts are muted."""
    return get_threshold_int("alerts_muted_until_ts", 0)


def is_alerts_muted() -> bool:
    """Return True if alerts are currently muted."""
    return alerts_muted_until_ts() > _now_ts()


def alerts_status() -> dict[str, Any]:
    """Expose mute state for UI."""
    until_ts = alerts_muted_until_ts()
    return {
        "muted": until_ts > _now_ts(),
        "until_ts": until_ts,
        "until_iso": datetime.fromtimestamp(until_ts).isoformat(timespec="seconds") if until_ts > 0 else None,
    }


# ---------------------------------------------------------------------------
# Mode flags (light, ultra-light, analytics)
# ---------------------------------------------------------------------------

def is_analytics_enabled() -> bool:
    """Check if analytics is enabled. Atomic cache read+write under one lock."""
    now = time.time()
    mtime_ns = _safe_mtime_ns(ANALYTICS_CONFIG)
    with _config_cache_lock:
        if (
            _analytics_cache["mtime_ns"] == mtime_ns
            and now - _analytics_cache["loaded_at"] < ANALYTICS_CACHE_TTL_SECONDS
        ):
            return bool(_analytics_cache["enabled"])
        # Re-read under the same lock to keep cache state consistent across threads.
        settings = _parse_kv_config(ANALYTICS_CONFIG)
        enabled = settings.get("ENABLE_ANALYTICS", "").strip().lower() == "true"
        _analytics_cache["enabled"] = enabled
        _analytics_cache["mtime_ns"] = mtime_ns
        _analytics_cache["loaded_at"] = now
        return enabled


def _resolve_mode_flag(env_key: str, json_key: str) -> bool:
    """Single source of truth for mode flags (light / ultra-light)."""
    settings = _parse_kv_config(ANALYTICS_CONFIG)
    val = settings.get(env_key, "").strip().lower()
    if val == "true":
        return True
    if val == "false":
        return False
    try:
        cfg = load_config()
    except (OSError, PermissionError):
        return False
    return bool(cfg.get("dashboard", {}).get(json_key, False))


def is_light_mode_enabled() -> bool:
    """Return True if light mode is enabled."""
    return _resolve_mode_flag("LIGHT_MODE", "light_mode") or is_ultra_light_mode_enabled()


def is_ultra_light_mode_enabled() -> bool:
    """Ultra-light is stricter than light mode: minimizes UI + analytics work.

    Effective state = explicit config OR adaptive override (sustained high CPU).
    """
    if _resolve_mode_flag("ULTRA_LIGHT", "ultra_light"):
        return True
    return _adaptive_ultra_light_active()


# ---------------------------------------------------------------------------
# Adaptive ultra-light mode
# ---------------------------------------------------------------------------

def _adaptive_ultra_light_active() -> bool:
    """Check if adaptive ultra-light mode is currently active."""
    with _adaptive_lock:
        return _adaptive_state["active"]


def _adaptive_ultra_light_record(cpu_pct: float | None) -> None:
    """Update adaptive state from a fresh CPU reading. Called by status path.

    Hysteresis prevents oscillation: enter when CPU stays >= 70% for 3 reads,
    leave when CPU stays <= 25% for 5 reads.
    """
    if cpu_pct is None:
        return
    with _adaptive_lock:
        _adaptive_state["last_cpu_pct"] = cpu_pct
        if cpu_pct >= _ADAPT_HIGH_PCT:
            _adaptive_state["high_streak"] += 1
            _adaptive_state["low_streak"] = 0
            if (not _adaptive_state["active"]
                    and _adaptive_state["high_streak"] >= _ADAPT_HIGH_READS):
                _adaptive_state["active"] = True
                _adaptive_state["last_change_ts"] = time.time()
                _adaptive_state["reason"] = (
                    f"CPU sustained {cpu_pct:.0f}% >= {_ADAPT_HIGH_PCT:.0f}% "
                    f"for {_ADAPT_HIGH_READS} reads"
                )
                flog("WARN", "adaptive",
                     "auto-enabling ultra-light mode (sustained CPU pressure)",
                     {"cpu_pct": cpu_pct, "threshold": _ADAPT_HIGH_PCT})
        elif cpu_pct <= _ADAPT_LOW_PCT:
            _adaptive_state["low_streak"] += 1
            _adaptive_state["high_streak"] = 0
            if (_adaptive_state["active"]
                    and _adaptive_state["low_streak"] >= _ADAPT_LOW_READS):
                _adaptive_state["active"] = False
                _adaptive_state["last_change_ts"] = time.time()
                _adaptive_state["reason"] = (
                    f"CPU recovered to {cpu_pct:.0f}% <= {_ADAPT_LOW_PCT:.0f}% "
                    f"for {_ADAPT_LOW_READS} reads"
                )
                flog("INFO", "adaptive",
                     "auto-disabling ultra-light mode (CPU recovered)",
                     {"cpu_pct": cpu_pct, "threshold": _ADAPT_LOW_PCT})
        else:
            # In the dead-zone — slowly decay both streaks toward zero.
            _adaptive_state["high_streak"] = max(0, _adaptive_state["high_streak"] - 1)
            _adaptive_state["low_streak"] = max(0, _adaptive_state["low_streak"] - 1)


def adaptive_ultra_light_status() -> dict[str, Any]:
    """Snapshot for the UI / diagnostic bundle."""
    with _adaptive_lock:
        return dict(_adaptive_state)


# ---------------------------------------------------------------------------
# Status refresh intervals
# ---------------------------------------------------------------------------

def status_refresh_ms() -> int:
    """Client refresh interval (ms) depending on runtime mode."""
    if is_ultra_light_mode_enabled():
        return ULTRA_REFRESH_MS
    return LIGHT_REFRESH_MS if is_light_mode_enabled() else DEFAULT_REFRESH_MS


def analytics_refresh_ms() -> int:
    """Client analytics refresh interval (ms) depending on runtime mode."""
    if is_ultra_light_mode_enabled():
        return ULTRA_ANALYTICS_REFRESH_MS
    return LIGHT_ANALYTICS_REFRESH_MS if is_light_mode_enabled() else DEFAULT_ANALYTICS_REFRESH_MS


def _is_heavy_analytics_allowed() -> bool:
    """Return True if we should run heavier analytics features."""
    return is_analytics_enabled() and (not is_light_mode_enabled()) and (not is_ultra_light_mode_enabled())


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Initialize metrics database with proper schema and WAL mode."""
    try:
        with _db_connect() as conn:
            # Enable WAL mode for concurrent access (read during write)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")

            c = conn.cursor()
            # Metrics table: track availability and latency over time
            c.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                port_id TEXT,
                service_name TEXT,
                service_active BOOLEAN,
                port_listening BOOLEAN,
                target_reachable BOOLEAN,
                latency_ms INTEGER
            )
        """)
            # Create index for faster queries
            c.execute("""
            CREATE INDEX IF NOT EXISTS idx_port_time
            ON metrics(port_id, timestamp)
        """)

            # Admin sessions table
            c.execute("""
            CREATE TABLE IF NOT EXISTS admin_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                created_at INTEGER,
                expires_at INTEGER,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
            c.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_token
            ON admin_sessions(token)
        """)
            c.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_expires
            ON admin_sessions(expires_at)
        """)

            # Audit log table
            c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                action TEXT,
                admin TEXT,
                target TEXT,
                details TEXT,
                status TEXT
            )
        """)
            c.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_log(timestamp)
        """)

            # Incidents table
            c.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port_id TEXT,
                service_name TEXT,
                event_type TEXT,
                timestamp INTEGER,
                duration_ms INTEGER,
                severity TEXT,
                description TEXT
            )
        """)
            c.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_port
            ON incidents(port_id, timestamp)
        """)

            # Thresholds table
            c.execute("""
            CREATE TABLE IF NOT EXISTS thresholds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value REAL,
                description TEXT,
                updated_at INTEGER
            )
        """)
            c.execute("""
            CREATE INDEX IF NOT EXISTS idx_thresholds_key
            ON thresholds(key)
        """)

            # Insert default thresholds if not exist
            now = _now_ts()
            c.execute(
                "INSERT OR IGNORE INTO thresholds (key, value, description, updated_at) VALUES (?, ?, ?, ?)",
                ("latency_threshold_ms", 50.0, "Latency threshold in milliseconds", now),
            )
            c.execute(
                "INSERT OR IGNORE INTO thresholds (key, value, description, updated_at) VALUES (?, ?, ?, ?)",
                ("uptime_threshold_percent", 95.0, "Uptime threshold in percentage", now),
            )
            c.execute(
                "INSERT OR IGNORE INTO thresholds (key, value, description, updated_at) VALUES (?, ?, ?, ?)",
                ("alerts_muted_until_ts", 0.0, "Mute alerts until UNIX timestamp", now),
            )
            c.execute(
                "INSERT OR IGNORE INTO thresholds (key, value, description, updated_at) VALUES (?, ?, ?, ?)",
                ("session_timeout_minutes", 30.0, "Auto-logout after inactivity (minutes)", now),
            )
        print("[homelinkwg-dashboard] Database initialized with WAL mode (timeout=10s)", file=sys.stderr)
    except sqlite3.Error as e:
        print(f"[homelinkwg-dashboard] DB init error: {e}", file=sys.stderr)
