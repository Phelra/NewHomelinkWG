"""
Logging, correlation IDs, timing, and rate limiting utilities.

- LogBuffer: In-memory circular buffer for structured logs
- flog(): Unified structured logging function
- timed(): Timing context manager decorator
- RateLimiter: IP-based rate limiting
- LoginLimiter: Progressive login lockout
"""

import json
import logging
import logging.handlers
import os
import sys
import threading
import time
import traceback
import uuid
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any

# Get script directory (will be initialized by dashboard.py)
SCRIPT_DIR = Path(__file__).parent.parent.resolve()

# ---------------------------------------------------------------------------
LOG_LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")
LOG_LEVEL_RANK = {lvl: i for i, lvl in enumerate(LOG_LEVELS)}

LOG_FILE = Path(os.environ.get("HomelinkWG_LOG_FILE", "/var/log/homelinkwg-dashboard.log"))
LOG_FILE_FALLBACK = SCRIPT_DIR / "homelinkwg-dashboard.log"
LOG_MAX_BYTES = 10 * 1024 * 1024   # 10 MB per file
LOG_BACKUP_COUNT = 5

# Per-thread correlation ID (set by request hook / collector cycle)
_log_local = threading.local()

def set_correlation_id(cid: str | None) -> None:
    _log_local.cid = cid

def get_correlation_id() -> str:
    return getattr(_log_local, "cid", "-") or "-"

def new_correlation_id(prefix: str = "req") -> str:
    cid = f"{prefix}-{uuid.uuid4().hex[:8]}"
    set_correlation_id(cid)
    return cid

class LogBuffer:
    """In-memory circular buffer with structured records (level/ctx/timestamp).

    Keeps backward compatibility: ``add(log_type, message)`` still works and
    stores an INFO-level record. New code should use ``log()`` or the
    ``homelinkwg_log`` helper which writes both to file and to this buffer.
    """
    def __init__(self, max_per_type: int = 200, max_total: int = 5000):
        self.max_per_type = max_per_type
        self.max_total = max_total
        self.logs: dict[str, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=max_per_type)
        )
        self._lock = threading.Lock()
        self._next_id = 1
        self._total = 0

    def _evict_global_locked(self) -> None:
        """Evict from the largest type until total <= max_total."""
        while self._total > self.max_total:
            biggest = max(self.logs.values(), key=len, default=None)
            if not biggest:
                return
            try:
                biggest.popleft()
                self._total -= 1
            except IndexError:
                return

    def log(self, level: str, log_type: str, message: str,
            ctx: dict[str, Any] | None = None) -> dict[str, Any]:
        level = (level or "INFO").upper()
        if level not in LOG_LEVEL_RANK:
            level = "INFO"
        ts = datetime.now().isoformat(timespec="milliseconds")
        cid = get_correlation_id()
        entry: dict[str, Any] = {
            "id": 0,
            "ts": ts,
            "level": level,
            "type": log_type,
            "cid": cid,
            "ctx": ctx or {},
            "message": message,
        }
        with self._lock:
            entry["id"] = self._next_id
            self._next_id += 1
            self.logs[log_type].append(entry)
            self._total += 1
            self._evict_global_locked()
        # Render a compact text view (used by legacy SSE consumers)
        ctx_part = ""
        if ctx:
            ctx_part = " " + " ".join(f"{k}={v}" for k, v in ctx.items())
        entry["text"] = f"[{ts}] [{level}] [{cid}] {message}{ctx_part}"
        return entry

    def add(self, log_type: str, message: str) -> None:
        """Legacy API — defaults to INFO level."""
        self.log("INFO", log_type, message)

    def get_all(self) -> list[dict]:
        with self._lock:
            result: list[dict] = []
            for messages in self.logs.values():
                result.extend(messages)
        result.sort(key=lambda item: item["id"])
        # Preserve backward-compat: legacy clients expected "message" to be the
        # rendered text. We expose both the structured fields and a "message"
        # text for legacy consumers.
        out = []
        for e in result:
            legacy = {
                "id": e["id"],
                "type": e["type"],
                "message": e.get("text") or e.get("message", ""),
                "level": e.get("level", "INFO"),
                "ts": e.get("ts"),
                "cid": e.get("cid", "-"),
                "ctx": e.get("ctx", {}),
            }
            out.append(legacy)
        return out

    def get_recent(self, limit: int = 50) -> list[dict]:
        all_logs = self.get_all()
        return all_logs[-limit:] if all_logs else []

    def get_since(self, last_id: int, limit: int = 200) -> list[dict]:
        recent = [entry for entry in self.get_all() if entry["id"] > last_id]
        return recent[:limit]

    def filtered(self, *, min_level: str = "DEBUG",
                 type_in: list[str] | None = None,
                 limit: int = 500) -> list[dict]:
        rank = LOG_LEVEL_RANK.get(min_level.upper(), 0)
        out: list[dict] = []
        for entry in self.get_all():
            if LOG_LEVEL_RANK.get(entry.get("level", "INFO"), 1) < rank:
                continue
            if type_in and entry.get("type") not in type_in:
                continue
            out.append(entry)
        return out[-limit:]

log_buffer = LogBuffer()


def _build_file_logger() -> logging.Logger:
    """Create the rotating file logger. Falls back to a local file if /var/log
    is not writable (typical in dev). Plain text + JSON-line side-car."""
    logger = logging.getLogger("homelinkwg")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    if logger.handlers:
        return logger

    target = LOG_FILE
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # Touch to validate permission
        with open(target, "a", encoding="utf-8"):
            pass
    except (OSError, PermissionError):
        target = LOG_FILE_FALLBACK
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            target = SCRIPT_DIR / "homelinkwg-dashboard.log"

    try:
        handler = logging.handlers.RotatingFileHandler(
            str(target), maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        fmt = logging.Formatter(
            "%(asctime)s.%(msecs)03d %(levelname)-5s [%(cid)s] [%(log_type)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)

        json_handler = logging.handlers.RotatingFileHandler(
            str(target) + ".jsonl", maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )

        class _JsonFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                return json.dumps({
                    "ts": datetime.fromtimestamp(record.created).isoformat(timespec="milliseconds"),
                    "level": record.levelname,
                    "type": getattr(record, "log_type", "app"),
                    "cid": getattr(record, "cid", "-"),
                    "ctx": getattr(record, "ctx", {}),
                    "message": record.getMessage(),
                }, ensure_ascii=False, default=str)
        json_handler.setFormatter(_JsonFormatter())
        logger.addHandler(json_handler)
    except OSError as e:
        sys.stderr.write(f"[homelinkwg] could not open log file {target}: {e}\n")
    return logger

_file_logger = _build_file_logger()


def flog(level: str, log_type: str, message: str,
         ctx: dict[str, Any] | None = None,
         exc: BaseException | None = None) -> None:
    """Unified structured log: writes to LogBuffer + rotating file + stderr.

    Use everywhere instead of ``print`` or ``log_buffer.add``. Provides a
    correlation id (per-thread), a level, a type bucket and free-form context.
    """
    level = (level or "INFO").upper()
    if level not in LOG_LEVEL_RANK:
        level = "INFO"
    final_ctx = dict(ctx or {})
    if exc is not None:
        final_ctx["exc_type"] = type(exc).__name__
        final_ctx["exc_msg"] = str(exc)
        final_ctx["traceback"] = traceback.format_exc(limit=8).strip()
    entry = log_buffer.log(level, log_type, message, final_ctx)

    py_level = {
        "DEBUG": logging.DEBUG, "INFO": logging.INFO,
        "WARN": logging.WARNING, "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }[level]
    try:
        _file_logger.log(
            py_level,
            message + (
                "" if not final_ctx else " " + " ".join(f"{k}={v}" for k, v in final_ctx.items() if k != "traceback")
            ),
            extra={"cid": get_correlation_id(), "log_type": log_type, "ctx": final_ctx},
        )
        if exc is not None and final_ctx.get("traceback"):
            _file_logger.log(py_level, final_ctx["traceback"],
                             extra={"cid": get_correlation_id(), "log_type": log_type, "ctx": {}})
    except Exception:
        pass

    if level in ("ERROR", "CRITICAL", "WARN"):
        try:
            sys.stderr.write(entry["text"] + "\n")
            if exc is not None:
                sys.stderr.write(traceback.format_exc())
            sys.stderr.flush()
        except Exception:
            pass


class _Timer:
    """Context manager that logs elapsed milliseconds at DEBUG."""
    def __init__(self, log_type: str, label: str, ctx: dict[str, Any] | None = None,
                 warn_above_ms: float | None = None):
        self.log_type = log_type
        self.label = label
        self.ctx = dict(ctx or {})
        self.warn_above_ms = warn_above_ms
        self.t0 = 0.0

    def __enter__(self) -> "_Timer":
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        elapsed_ms = (time.perf_counter() - self.t0) * 1000.0
        self.ctx["elapsed_ms"] = round(elapsed_ms, 1)
        if exc:
            flog("ERROR", self.log_type, f"{self.label} failed", self.ctx, exc=exc)
            return
        level = "DEBUG"
        if self.warn_above_ms is not None and elapsed_ms > self.warn_above_ms:
            level = "WARN"
            flog(level, self.log_type, f"{self.label} slow", self.ctx)
        else:
            flog(level, self.log_type, self.label, self.ctx)

def timed(log_type: str, label: str, ctx: dict[str, Any] | None = None,
          warn_above_ms: float | None = None) -> _Timer:
    return _Timer(log_type, label, ctx, warn_above_ms)

class RateLimiter:
    """Rate limiter with per-IP tracking and automatic cleanup."""
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = {}  # IP -> [timestamps]
        self.last_cleanup = time.time()
        self._lock = threading.Lock()

    def _cleanup(self):
        """Remove old IPs and expired entries (called periodically)."""
        now = time.time()
        with self._lock:
            if now - self.last_cleanup < 60:  # Cleanup every 60 seconds
                return

            ips_to_remove = []
            for ip, attempts in self.attempts.items():
                self.attempts[ip] = [t for t in attempts if now - t < self.window_seconds]
                if not self.attempts[ip]:
                    ips_to_remove.append(ip)

            for ip in ips_to_remove:
                del self.attempts[ip]

            self.last_cleanup = now

    def is_allowed(self, ip: str) -> bool:
        """Check if IP is allowed to make a request."""
        self._cleanup()  # Cleanup expired entries
        now = time.time()
        with self._lock:
            if ip not in self.attempts:
                self.attempts[ip] = []

            self.attempts[ip] = [t for t in self.attempts[ip] if now - t < self.window_seconds]

            if len(self.attempts[ip]) >= self.max_attempts:
                return False

            self.attempts[ip].append(now)
            return True

    def get_remaining(self, ip: str) -> int:
        """Get remaining attempts for IP."""
        now = time.time()
        with self._lock:
            if ip not in self.attempts:
                return self.max_attempts
            attempts = [t for t in self.attempts[ip] if now - t < self.window_seconds]
            return max(0, self.max_attempts - len(attempts))

class LoginLimiter:
    """Progressive lockout: 3 failures→30s, 6→2min, 9+→10min."""
    TIERS = [(3, 30), (6, 120), (9, 600)]

    def __init__(self) -> None:
        self._data: dict[str, dict] = {}  # ip → {failures, locked_until}
        self._lock = threading.Lock()

    def _lockout_for(self, failures: int) -> int:
        for threshold, duration in reversed(self.TIERS):
            if failures >= threshold:
                return duration
        return 0

    def _next_threshold(self, failures: int) -> int:
        for threshold, _ in self.TIERS:
            if failures < threshold:
                return threshold
        return self.TIERS[-1][0]  # already past all tiers

    def check(self, ip: str) -> dict:
        """Return current gate status without modifying state."""
        now = time.time()
        with self._lock:
            entry = self._data.get(ip, {"failures": 0, "locked_until": 0.0})
            locked_until = entry["locked_until"]
            failures = entry["failures"]
            if locked_until > now:
                return {
                    "allowed": False,
                    "locked_until": locked_until,
                    "retry_after": int(locked_until - now) + 1,
                    "failures": failures,
                    "remaining": 0,
                }
            nxt = self._next_threshold(failures)
            return {
                "allowed": True,
                "locked_until": 0.0,
                "retry_after": 0,
                "failures": failures,
                "remaining": max(0, nxt - failures),
            }

    def record_failure(self, ip: str) -> dict:
        """Increment failure counter, apply lockout tier if reached. Returns new status."""
        now = time.time()
        with self._lock:
            entry = dict(self._data.get(ip, {"failures": 0, "locked_until": 0.0}))
            entry["failures"] += 1
            duration = self._lockout_for(entry["failures"])
            entry["locked_until"] = (now + duration) if duration else 0.0
            self._data[ip] = entry
            failures = entry["failures"]
            locked_until = entry["locked_until"]
            nxt = self._next_threshold(failures)
            return {
                "allowed": duration == 0,
                "locked_until": locked_until,
                "retry_after": int(locked_until - now) + 1 if duration else 0,
                "failures": failures,
                "remaining": max(0, nxt - failures) if duration == 0 else 0,
            }

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._data.pop(ip, None)


# Global rate limiters
login_limiter = LoginLimiter()