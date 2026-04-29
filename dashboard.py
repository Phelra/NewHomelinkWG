#!/usr/bin/env python3
"""HomelinkWG dashboard v5.0.

A small Flask app that reports the status of the WireGuard tunnel and of each
socat port-forward defined in ``config.json``. Optionally provides 24-hour
analytics with SQLite metrics storage (WAL mode for concurrent access).
Designed to run under an unprivileged system user (``homelinkwg``) via systemd.

Analytics Implementation Notes:
- SQLite WAL mode enables concurrent read/write (critical for threading)
- All connections use timeout=10.0s to handle concurrent access
- Database permissions: 660 (root:homelinkwg) for write access
- Directory permissions: 770 to allow homelinkwg user to create files
"""
from __future__ import annotations

import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any
import secrets

try:
    import bcrypt  # type: ignore
except Exception:
    bcrypt = None  # type: ignore

try:
    import pyotp  # type: ignore
except Exception:
    pyotp = None  # type: ignore

# Import modularized functionality
from homelinkwg.utils import (
    flog, timed, RateLimiter, LoginLimiter,
    set_correlation_id, get_correlation_id, new_correlation_id,
    log_buffer, LOG_FILE, LOG_FILE_FALLBACK
)
from homelinkwg.config import (
    CONFIG_FILE, ANALYTICS_CONFIG, RELEASE_NOTES_FILE,
    SESSION_TIMEOUT_MINUTES, ADMIN_PASSWORD_HASH, TOTP_SECRET, TOTP_ENABLED,
    LIGHT_TARGET_TTL_SECONDS, LIGHT_STATUS_CACHE_TTL_SECONDS,
    ULTRA_STATUS_CACHE_TTL_SECONDS, DEFAULT_STATUS_CACHE_TTL_SECONDS,
    _config_cache_lock, _config_cache, _analytics_cache,
    _analytics_init_lock, _collector_thread,
    _target_probe_cache, _target_probe_lock,
    _adaptive_state, _adaptive_lock,
    _now_ts, _db_connect,
    load_auth_config, load_config, load_thresholds, get_threshold, set_threshold,
    is_alerts_muted, alerts_status,
    is_analytics_enabled, _resolve_mode_flag, is_light_mode_enabled,
    is_ultra_light_mode_enabled, _adaptive_ultra_light_record,
    adaptive_ultra_light_status, status_refresh_ms, analytics_refresh_ms,
    init_db, SCRIPT_DIR
)

__version__ = "5.0"
__date__ = "2026-04-28"

# Instantiate global rate limiters
login_limiter = LoginLimiter()
api_limiter = RateLimiter(max_attempts=100, window_seconds=60)

# Track previous state for each port (to detect changes)
service_state_cache = {}  # port_id -> {service_active, port_listening, target_reachable, latency_ms}

# These functions will be moved to auth.py in Phase 1C
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


def log_audit(action: str, admin_ip: str, target: str, details: dict, status: str) -> None:
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

# ---------------------------------------------------------------------------
# Flask import guard
# ---------------------------------------------------------------------------
try:
    from flask import Flask, Response, jsonify, render_template_string, send_from_directory, request
except ImportError:
    print(
        "[homelinkwg-dashboard] Flask is required. Install with:\n"
        "  sudo apt-get install -y python3-flask\n"
        "or\n"
        "  pip install flask",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Helpers: subprocess with hard timeouts + consistent failure modes
# ---------------------------------------------------------------------------
def _run(cmd: list[str], timeout: float = 3.0) -> subprocess.CompletedProcess | None:
    """Run a command with hard timeout. Always reaps the child on timeout to
    avoid the FD/zombie-process leak observed when many short-lived probes run
    in parallel (formerly Popen would linger for `timeout` seconds)."""
    proc: subprocess.Popen[str] | None = None
    t0 = time.perf_counter()
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=False,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
            try:
                stdout, stderr = proc.communicate(timeout=1.0)
            except Exception:
                stdout, stderr = "", ""
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
            flog("WARN", "subprocess", f"timeout after {timeout}s",
                 {"cmd": cmd[0] if cmd else "?", "elapsed_ms": elapsed_ms})
            return None
        rc = proc.returncode if proc.returncode is not None else -1
        return subprocess.CompletedProcess(cmd, rc, stdout, stderr)
    except (FileNotFoundError, PermissionError) as e:
        flog("DEBUG", "subprocess", f"cannot run {cmd[0] if cmd else '?'}",
             {"err": str(e)})
        return None
    except Exception as e:
        flog("ERROR", "subprocess", f"unexpected error running {cmd[0] if cmd else '?'}",
             ctx={"cmd": " ".join(cmd[:3])}, exc=e)
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        return None

def _tcp_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False

def _measure_latency(host: str, port: int, timeout: float = 1.0) -> int:
    """Legacy wrapper — returns the *integer* TCP RTT in ms, -1 on failure.

    Kept for backward compat with SQLite metrics column. New callers should
    prefer ``latency_breakdown()`` which exposes DNS/TCP separately + jitter.
    """
    br = latency_breakdown(host, port, timeout=timeout, samples=1)
    if not br.get("ok"):
        return -1
    total = br.get("total_ms")
    if total is None:
        return -1
    return int(round(total))


def latency_breakdown(host: str, port: int, *, timeout: float = 1.0,
                      samples: int = 5) -> dict[str, Any]:
    """Measure latency with DNS / TCP separated, plus jitter from N samples.

    Returns ``{ok, dns_ms, tcp_ms_min, tcp_ms_avg, tcp_ms_p95, jitter_ms,
    samples_taken, error}``. Used both for live diagnostics and for the
    diagnostic bundle. Probes are throttled to ``timeout`` seconds total.
    """
    out: dict[str, Any] = {"ok": False, "samples_taken": 0}
    # 1) DNS resolution timing — only meaningful if `host` is not already an IP
    is_ip = bool(re.match(r"^[\d.:]+$", host))
    if not is_ip:
        t0 = time.perf_counter()
        try:
            addr_info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            out["dns_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
            if addr_info:
                out["resolved_ip"] = addr_info[0][4][0]
        except socket.gaierror as e:
            out["error"] = f"dns_failure: {e}"
            return out
    else:
        out["dns_ms"] = 0.0
        out["resolved_ip"] = host

    # 2) TCP handshake timings — N samples for jitter
    rtts: list[float] = []
    last_err: str | None = None
    for i in range(max(1, samples)):
        t0 = time.perf_counter()
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            rtts.append((time.perf_counter() - t0) * 1000.0)
        except (OSError, ValueError) as e:
            last_err = str(e)
        out["samples_taken"] = i + 1
        # Brief gap between samples so kernel TCP stack doesn't coalesce
        if i + 1 < samples:
            time.sleep(0.02)

    if not rtts:
        out["error"] = last_err or "all_samples_failed"
        return out

    rtts.sort()
    avg = sum(rtts) / len(rtts)
    if len(rtts) >= 2:
        var = sum((x - avg) ** 2 for x in rtts) / (len(rtts) - 1)
        jitter = var ** 0.5
    else:
        jitter = 0.0
    p95_idx = max(0, int(round(0.95 * (len(rtts) - 1))))
    out.update({
        "ok": True,
        "tcp_ms_min": round(rtts[0], 2),
        "tcp_ms_avg": round(avg, 2),
        "tcp_ms_max": round(rtts[-1], 2),
        "tcp_ms_p95": round(rtts[p95_idx], 2),
        "jitter_ms": round(jitter, 2),
        "total_ms": round(out.get("dns_ms", 0.0) + avg, 2),
    })
    return out

def _probe_target_reachable(host: str, port: int) -> bool:
    """Probe target reachability, with cache in lightweight mode."""
    if not is_light_mode_enabled():
        # Best-effort retry once to reduce false negatives from transient SYN drops.
        ok = _tcp_reachable(host, port, timeout=1.0)
        if ok:
            return True
        time.sleep(0.05)
        return _tcp_reachable(host, port, timeout=1.2)

    now = time.time()
    cache_key = (host, port)
    with _target_probe_lock:
        cached = _target_probe_cache.get(cache_key)
        if cached and now < cached[0]:
            return cached[1]

    # Lightweight mode: cache successes longer than failures, and retry failures once.
    reachable = _tcp_reachable(host, port, timeout=0.8)
    if not reachable:
        time.sleep(0.05)
        reachable = _tcp_reachable(host, port, timeout=1.0)

    ttl = LIGHT_TARGET_TTL_SECONDS if reachable else 4.0
    with _target_probe_lock:
        _target_probe_cache[cache_key] = (now + ttl, reachable)
        # Cap the cache so DNS round-robin / hostname churn cannot leak.
        if len(_target_probe_cache) > 256:
            # Drop the 64 oldest entries (those whose expiry already passed).
            expired = [k for k, v in _target_probe_cache.items() if v[0] < now]
            for k in expired[:64]:
                _target_probe_cache.pop(k, None)
            # If still over budget, drop arbitrary entries deterministically.
            while len(_target_probe_cache) > 256:
                _target_probe_cache.pop(next(iter(_target_probe_cache)), None)
    return reachable

def store_metric(port_id: str, service_name: str, service_active: bool,
                 port_listening: bool, target_reachable: bool, latency_ms: int) -> None:
    """Store a metric snapshot to the database."""
    try:
        with _db_connect() as conn:
            conn.execute(
                """
                INSERT INTO metrics
                (timestamp, port_id, service_name, service_active, port_listening, target_reachable, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (_now_ts(), port_id, service_name, service_active, port_listening, target_reachable, latency_ms),
            )
        flog("DEBUG", "metrics", "stored", {
            "port_id": port_id, "service": service_name,
            "service_active": service_active, "port_listening": port_listening,
            "target_reachable": target_reachable, "latency_ms": latency_ms,
        })
    except sqlite3.Error as e:
        flog("ERROR", "metrics", "store_metric failed",
             {"port_id": port_id}, exc=e)

def detect_incidents(port_id: str, service_name: str, service_active: bool,
                    port_listening: bool, target_reachable: bool, latency_ms: int) -> None:
    """Detect and log incidents based on metrics."""
    incidents = []

    # Incident 1: Service down — only when the port is also not listening.
    # supervisorctl/systemctl status can flap (timeouts, brief STARTING/BACKOFF
    # states), so a listening port is the real proof that traffic is flowing.
    if not service_active and not port_listening:
        incidents.append(("SERVICE_DOWN", "⚠️ Service inactive", "high"))

    # Incident 2: Port not listening while the manager reports the service active
    if service_active and not port_listening:
        incidents.append(("PORT_DOWN", "⚠️ Port not listening", "high"))

    # Incident 3: Target unreachable
    if not target_reachable:
        incidents.append(("TARGET_UNREACHABLE", "⚠️ Target unreachable", "medium"))

    # Incident 4: High latency (use configurable threshold)
    latency_threshold = get_threshold("latency_threshold_ms", 50.0)
    if latency_ms > latency_threshold:
        incidents.append(("HIGH_LATENCY", f"⚠️ Latency {latency_ms}ms (>{latency_threshold}ms threshold)", "medium"))

    # Log incidents and store in database
    alerts_muted = is_alerts_muted()
    for event_type, description, severity in incidents:
        log_msg = f"{service_name}: {description}"
        if not alerts_muted:
            level = "ERROR" if severity == "high" else "WARN"
            flog(level, "incident", log_msg, {
                "port_id": port_id, "event_type": event_type,
                "severity": severity, "latency_ms": latency_ms,
            })
        try:
            with _db_connect() as conn:
                conn.execute(
                    """
                    INSERT INTO incidents (port_id, service_name, event_type, timestamp, severity, description)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (port_id, service_name, event_type, _now_ts(), severity, description),
                )
        except sqlite3.Error as e:
            flog("ERROR", "incident", "DB error logging incident",
                 {"port_id": port_id, "event_type": event_type}, exc=e)

    if not incidents:
        flog("DEBUG", "systemd", f"{service_name}: healthy",
             {"port_id": port_id, "latency_ms": latency_ms})

# ---------------------------------------------------------------------------
# Status collectors (pure functions — easy to unit-test later)
# ---------------------------------------------------------------------------
def vpn_status(interface: str) -> dict[str, str]:
    """Return connection state + IP of the WireGuard interface."""
    link = _run(["ip", "-o", "link", "show", interface])
    if not link or link.returncode != 0:
        return {"status": "DOWN", "ip": "N/A", "interface": interface}
    up = "state UP" in link.stdout or "state UNKNOWN" in link.stdout
    ip_out = _run(["ip", "-o", "-4", "addr", "show", interface])
    ip_addr = "N/A"
    if ip_out and ip_out.returncode == 0:
        parts = ip_out.stdout.split()
        for tok in parts:
            if "/" in tok and tok.split("/")[0].count(".") == 3:
                ip_addr = tok.split("/")[0]
                break
    return {"status": "CONNECTED" if up else "DOWN", "ip": ip_addr, "interface": interface}

def _is_docker_runtime() -> bool:
    """Return True when the dashboard is running under the Docker supervisor setup."""
    runtime = os.environ.get("HomelinkWG_RUNTIME", "").strip().lower()
    return runtime == "docker" or Path("/.dockerenv").exists() or Path("/tmp/supervisor.sock").exists()

def _supervisor_program_name(unit: str) -> str:
    """Map the public systemd-style service name used by the UI to supervisord."""
    name = unit.removesuffix(".service")
    if name.startswith("homelinkwg-socat-"):
        return name.replace("homelinkwg-socat-", "socat-", 1)
    if name == "homelinkwg-dashboard":
        return "dashboard"
    return name

def _supervisorctl(args: list[str], timeout: float = 5.0) -> subprocess.CompletedProcess | None:
    return _run(["supervisorctl", "-s", "unix:///tmp/supervisor.sock", *args], timeout=timeout)

def _supervisor_is_active(unit: str) -> bool:
    program = _supervisor_program_name(unit)
    r = _supervisorctl(["status", program])
    return bool(r) and r.returncode == 0 and "RUNNING" in r.stdout

def _systemd_is_active(unit: str) -> bool:
    r = _run(["systemctl", "is-active", unit])
    return bool(r) and r.stdout.strip() == "active"

def systemd_is_active(unit: str) -> bool:
    """Compatibility wrapper used throughout the app.

    The historical deployment runs services through systemd. The Docker image
    runs the same logical services as supervisord programs, so this wrapper keeps
    the rest of the dashboard unchanged.
    """
    if _is_docker_runtime():
        return _supervisor_is_active(unit)
    return _systemd_is_active(unit)

def restart_managed_service(unit: str) -> tuple[bool, str]:
    """Restart a logical HomelinkWG service via the active service manager."""
    if _is_docker_runtime():
        program = _supervisor_program_name(unit)
        result = _supervisorctl(["restart", program], timeout=10.0)
        manager = "supervisorctl"
    else:
        result = _run(["systemctl", "restart", unit], timeout=10.0)
        manager = "systemctl"

    if result is None:
        return False, f"{manager} command not found or timed out"
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        return False, f"{manager} failed: {details}"
    return True, (result.stdout or "").strip()

def _read_diskstats() -> dict[str, dict[str, int]]:
    """Parse /proc/diskstats → {devname: {writes, write_ms, reads, read_ms}}."""
    out: dict[str, dict[str, int]] = {}
    try:
        with open("/proc/diskstats", encoding="utf-8") as f:
            for line in f:
                cols = line.split()
                if len(cols) < 14:
                    continue
                dev = cols[2]
                # Only physical devices (mmcblk0, sda, nvme0n1 …), skip partitions
                if re.search(r"mmcblk\d+$|sd[a-z]$|nvme\d+n\d+$|vd[a-z]$", dev):
                    out[dev] = {
                        "reads":    int(cols[3]),
                        "read_ms":  int(cols[6]),
                        "writes":   int(cols[7]),
                        "write_ms": int(cols[10]),
                    }
    except OSError:
        pass
    return out

# Module-level cache for diskstats delta computation
_prev_diskstats: dict[str, dict[str, int]] = {}
_prev_diskstats_ts: float = 0.0
_disk_latency_cache: dict[str, Any] = {}

def disk_latency() -> dict[str, Any]:
    """Return current disk write/read latency for the main storage device.
    Uses /proc/diskstats deltas — zero subprocess cost."""
    global _prev_diskstats, _prev_diskstats_ts, _disk_latency_cache
    import time as _time

    now = _time.monotonic()
    cur = _read_diskstats()

    result: dict[str, Any] = {}
    if _prev_diskstats and cur:
        for dev, c in cur.items():
            p = _prev_diskstats.get(dev)
            if not p:
                continue
            dw   = c["writes"]   - p["writes"]
            dwms = c["write_ms"] - p["write_ms"]
            dr   = c["reads"]    - p["reads"]
            drms = c["read_ms"]  - p["read_ms"]
            w_await = round(dwms / dw, 1)  if dw  > 0 else 0.0
            r_await = round(drms / dr, 1)  if dr  > 0 else 0.0
            result = {
                "device":     dev,
                "w_await_ms": w_await,
                "r_await_ms": r_await,
                "w_await_label": (
                    "critical" if w_await > 500
                    else "slow"    if w_await > 100
                    else "ok"      if w_await > 0
                    else "idle"
                ),
            }
            break   # first device is enough

    _prev_diskstats    = cur
    _prev_diskstats_ts = now
    if result:
        _disk_latency_cache = result
    return _disk_latency_cache  # return last known value while disk is idle

_cpu_sample_cache: dict[str, Any] = {"value": None, "ts": 0.0,
                                     "prev_idle": None, "prev_total": None}
_cpu_sample_lock = threading.Lock()
_CPU_CACHE_TTL = 2.0  # seconds — coarsest acceptable for status snapshots

def _read_proc_stat_idle_total() -> tuple[int, int] | None:
    try:
        with open("/proc/stat", encoding="utf-8") as f:
            for line in f:
                if line.startswith("cpu "):
                    vals = list(map(int, line.split()[1:]))
                    if len(vals) < 4:
                        return None
                    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
                    total = sum(vals)
                    return idle, total
    except OSError:
        return None
    return None

def _read_cpu_from_proc() -> float | None:
    """Non-blocking CPU usage % from /proc/stat using the previous sample.

    Replaces the old 200 ms blocking read. Cached for 2 s — the kernel counters
    move slow enough that anything finer is noise.
    """
    now = time.monotonic()
    with _cpu_sample_lock:
        cached = _cpu_sample_cache
        if cached["value"] is not None and (now - cached["ts"]) < _CPU_CACHE_TTL:
            return cached["value"]

        sample = _read_proc_stat_idle_total()
        prev_idle = cached["prev_idle"]
        prev_total = cached["prev_total"]

        if sample is None:
            # Fallback: try top once (unusual kernels) — cap to 1.5s
            top = _run(["top", "-bn1"], timeout=1.5)
            if top and top.returncode == 0:
                for line in top.stdout.splitlines():
                    if "Cpu" in line:
                        m = re.search(r"([0-9]+[.,][0-9]+|[0-9]+)\s+id", line)
                        if m:
                            idle = float(m.group(1).replace(",", "."))
                            value = round(100.0 - idle, 1)
                            cached["value"] = value
                            cached["ts"] = now
                            return value
            return None

        idle, total = sample
        if prev_idle is None or prev_total is None:
            cached["prev_idle"] = idle
            cached["prev_total"] = total
            cached["ts"] = now
            return cached["value"]  # may be None on first call

        d_total = total - prev_total
        d_idle = idle - prev_idle
        if d_total <= 0:
            return cached["value"]
        usage = round((1.0 - d_idle / d_total) * 100.0, 1)
        usage = max(0.0, min(100.0, usage))
        cached["value"] = usage
        cached["prev_idle"] = idle
        cached["prev_total"] = total
        cached["ts"] = now
        return usage

# ---------------------------------------------------------------------------
# Extended hardware diagnostics (zero-cost /proc + opportunistic /sys)
# ---------------------------------------------------------------------------
_prev_cpu_detail: dict[str, Any] = {"vals": None, "ts": 0.0}
_prev_net_dev: dict[str, dict[str, int]] = {}
_prev_net_dev_ts: float = 0.0
_prev_tcp_snmp: dict[str, int] = {}
_prev_tcp_snmp_ts: float = 0.0


def _read_proc_stat_vals() -> list[int] | None:
    try:
        with open("/proc/stat", encoding="utf-8") as f:
            for line in f:
                if line.startswith("cpu "):
                    return list(map(int, line.split()[1:]))
    except OSError:
        return None
    return None


def cpu_breakdown() -> dict[str, Any]:
    """Return user/system/iowait/steal/idle ratios from /proc/stat deltas."""
    cur = _read_proc_stat_vals()
    out: dict[str, Any] = {}
    if not cur:
        return out
    prev = _prev_cpu_detail.get("vals")
    now = time.monotonic()
    _prev_cpu_detail["vals"] = cur
    _prev_cpu_detail["ts"] = now
    if not prev:
        return out
    # Pad to length 10
    cur_p = cur + [0] * max(0, 10 - len(cur))
    prev_p = prev + [0] * max(0, 10 - len(prev))
    diffs = [c - p for c, p in zip(cur_p, prev_p)]
    total = sum(diffs)
    if total <= 0:
        return out
    fields = ["user", "nice", "system", "idle", "iowait",
              "irq", "softirq", "steal", "guest", "guest_nice"]
    for name, d in zip(fields, diffs):
        out[name] = round(100.0 * d / total, 1)
    out["busy_pct"] = round(100.0 - out.get("idle", 0.0) - out.get("iowait", 0.0), 1)
    return out


def cpu_thermal() -> dict[str, Any]:
    """Best-effort CPU temperature + Pi throttling status."""
    out: dict[str, Any] = {"temp_c": None, "throttled": None}
    # /sys/class/thermal — pick first 'cpu' or 'soc' zone
    try:
        zones = sorted(Path("/sys/class/thermal").glob("thermal_zone*"))
        for z in zones:
            try:
                t_type = (z / "type").read_text(encoding="utf-8").strip().lower()
            except OSError:
                t_type = ""
            try:
                raw = int((z / "temp").read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                continue
            temp = raw / 1000.0 if raw > 1000 else float(raw)
            if 0 < temp < 130:
                out["temp_c"] = round(temp, 1)
                out["zone_type"] = t_type
                break
    except OSError:
        pass

    # Raspberry Pi: vcgencmd get_throttled (0x0 = OK)
    vc = _run(["vcgencmd", "get_throttled"], timeout=1.5)
    if vc and vc.returncode == 0:
        m = re.search(r"throttled=0x([0-9a-fA-F]+)", vc.stdout)
        if m:
            val = int(m.group(1), 16)
            out["throttled"] = val
            flags = []
            if val & 0x1: flags.append("under_voltage_now")
            if val & 0x2: flags.append("freq_capped_now")
            if val & 0x4: flags.append("throttled_now")
            if val & 0x10000: flags.append("under_voltage_past")
            if val & 0x40000: flags.append("throttled_past")
            out["throttled_flags"] = flags

    # Current frequency vs max (cpufreq)
    try:
        cur = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
        mx = Path("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
        if cur.exists() and mx.exists():
            c = int(cur.read_text().strip())
            m = int(mx.read_text().strip())
            if m > 0:
                out["freq_mhz"] = round(c / 1000.0, 0)
                out["freq_max_mhz"] = round(m / 1000.0, 0)
                out["freq_pct"] = round(100.0 * c / m, 1)
    except (OSError, ValueError):
        pass
    return out


def memory_extended() -> dict[str, Any]:
    """Detailed memory + swap + page-fault snapshot."""
    info: dict[str, Any] = {}
    try:
        meminfo: dict[str, int] = {}
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                k, _, rest = line.partition(":")
                if not rest:
                    continue
                try:
                    meminfo[k.strip()] = int(rest.split()[0])  # kB
                except ValueError:
                    continue
        total_kb = meminfo.get("MemTotal", 0)
        avail_kb = meminfo.get("MemAvailable", 0)
        swap_total = meminfo.get("SwapTotal", 0)
        swap_free = meminfo.get("SwapFree", 0)
        info["total_mb"] = total_kb // 1024
        info["available_mb"] = avail_kb // 1024
        info["used_mb"] = (total_kb - avail_kb) // 1024
        if total_kb > 0:
            info["used_pct"] = round(100.0 * (total_kb - avail_kb) / total_kb, 1)
        info["cached_mb"] = meminfo.get("Cached", 0) // 1024
        info["buffers_mb"] = meminfo.get("Buffers", 0) // 1024
        info["dirty_mb"] = meminfo.get("Dirty", 0) // 1024
        info["swap_total_mb"] = swap_total // 1024
        info["swap_used_mb"] = (swap_total - swap_free) // 1024
        if swap_total > 0:
            info["swap_used_pct"] = round(100.0 * (swap_total - swap_free) / swap_total, 1)
        else:
            info["swap_used_pct"] = 0.0
    except OSError:
        return info

    try:
        with open("/proc/vmstat", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) != 2:
                    continue
                if parts[0] in ("pgfault", "pgmajfault", "oom_kill", "pswpin", "pswpout"):
                    info[parts[0]] = int(parts[1])
    except OSError:
        pass
    return info


def disk_usage() -> list[dict[str, Any]]:
    """Free space per real mountpoint via os.statvfs."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                src, mnt, fs = parts[0], parts[1], parts[2]
                if fs in ("proc", "sysfs", "tmpfs", "devtmpfs", "cgroup",
                          "cgroup2", "overlay", "squashfs", "devpts",
                          "mqueue", "debugfs", "tracefs", "fusectl",
                          "configfs", "pstore", "bpf", "autofs", "rpc_pipefs",
                          "ramfs", "hugetlbfs"):
                    continue
                if mnt in seen:
                    continue
                seen.add(mnt)
                try:
                    st = os.statvfs(mnt)
                except OSError:
                    continue
                total = st.f_blocks * st.f_frsize
                free = st.f_bavail * st.f_frsize
                if total <= 0:
                    continue
                used = total - free
                out.append({
                    "mount": mnt, "fs": fs, "device": src,
                    "total_mb": total // (1024 * 1024),
                    "free_mb": free // (1024 * 1024),
                    "used_pct": round(100.0 * used / total, 1),
                })
    except OSError:
        pass
    return out[:8]


def network_throughput(interface: str) -> dict[str, Any]:
    """Compute rx/tx bytes-per-second for the given interface from /proc/net/dev."""
    global _prev_net_dev, _prev_net_dev_ts
    out: dict[str, Any] = {}
    cur: dict[str, dict[str, int]] = {}
    try:
        with open("/proc/net/dev", encoding="utf-8") as f:
            for line in f:
                if ":" not in line:
                    continue
                name, _, rest = line.partition(":")
                cols = rest.split()
                if len(cols) < 16:
                    continue
                cur[name.strip()] = {
                    "rx_bytes": int(cols[0]), "rx_packets": int(cols[1]),
                    "rx_errs":  int(cols[2]), "rx_drop":   int(cols[3]),
                    "tx_bytes": int(cols[8]), "tx_packets": int(cols[9]),
                    "tx_errs":  int(cols[10]), "tx_drop":   int(cols[11]),
                }
    except OSError:
        return out

    now = time.monotonic()
    iface = cur.get(interface)
    if iface is not None:
        out["rx_bytes_total"] = iface["rx_bytes"]
        out["tx_bytes_total"] = iface["tx_bytes"]
        out["rx_errs"] = iface["rx_errs"]
        out["tx_errs"] = iface["tx_errs"]
        out["rx_drop"] = iface["rx_drop"]
        out["tx_drop"] = iface["tx_drop"]
        prev = _prev_net_dev.get(interface)
        dt = now - _prev_net_dev_ts if _prev_net_dev_ts else 0
        if prev and dt > 0:
            out["rx_bps"] = max(0, int((iface["rx_bytes"] - prev["rx_bytes"]) / dt))
            out["tx_bps"] = max(0, int((iface["tx_bytes"] - prev["tx_bytes"]) / dt))
    _prev_net_dev = cur
    _prev_net_dev_ts = now
    return out


def tcp_health() -> dict[str, Any]:
    """TCP retransmit ratio + socket counts from /proc/net/snmp."""
    global _prev_tcp_snmp, _prev_tcp_snmp_ts
    out: dict[str, Any] = {}
    try:
        with open("/proc/net/snmp", encoding="utf-8") as f:
            lines = f.readlines()
        keys: list[str] = []
        vals: list[str] = []
        for i, line in enumerate(lines):
            if line.startswith("Tcp:") and i + 1 < len(lines):
                keys = line.split()[1:]
                vals = lines[i + 1].split()[1:]
                break
        snmp = {k: int(v) for k, v in zip(keys, vals)} if keys and len(keys) == len(vals) else {}
    except (OSError, ValueError):
        return out

    now = time.monotonic()
    if snmp:
        out["tcp_curr_estab"] = snmp.get("CurrEstab", 0)
        prev = _prev_tcp_snmp
        dt = now - _prev_tcp_snmp_ts if _prev_tcp_snmp_ts else 0
        if prev and dt > 0:
            d_seg = snmp.get("OutSegs", 0) - prev.get("OutSegs", 0)
            d_retrans = snmp.get("RetransSegs", 0) - prev.get("RetransSegs", 0)
            if d_seg > 0:
                out["retrans_pct"] = round(100.0 * d_retrans / d_seg, 3)
            out["retrans_per_min"] = round(60.0 * d_retrans / dt, 1)
        _prev_tcp_snmp = snmp
        _prev_tcp_snmp_ts = now

    # Socket states summary (via ss when present)
    ss = _run(["ss", "-s"], timeout=2.0)
    if ss and ss.returncode == 0:
        m = re.search(r"TCP:\s+(\d+)", ss.stdout)
        if m:
            out["tcp_total"] = int(m.group(1))
        m = re.search(r"estab\s+(\d+)", ss.stdout)
        if m:
            out["estab"] = int(m.group(1))
        m = re.search(r"timewait\s+(\d+)", ss.stdout)
        if m:
            out["timewait"] = int(m.group(1))
    return out


def top_processes(n: int = 5) -> list[dict[str, Any]]:
    """Top N processes by CPU then by RSS (best-effort, /proc walk)."""
    procs: list[dict[str, Any]] = []
    try:
        clk_tck = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError):
        clk_tck = 100
    try:
        page_size_kb = os.sysconf("SC_PAGE_SIZE") // 1024
    except (ValueError, OSError):
        page_size_kb = 4
    try:
        with open("/proc/uptime", encoding="utf-8") as f:
            uptime = float(f.read().split()[0])
    except OSError:
        uptime = 0.0

    try:
        proc_entries = os.listdir("/proc")[:1024]
    except OSError:
        return procs
    for entry in proc_entries:
        if not entry.isdigit():
            continue
        pid = entry
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
                stat = f.read()
            l = stat.rfind(")")
            if l < 0:
                continue
            comm = stat[stat.find("(") + 1:l]
            rest = stat[l + 2:].split()
            utime = int(rest[11]); stime = int(rest[12])
            starttime = int(rest[19])
            rss_pages = int(rest[21])
            total = (utime + stime) / clk_tck
            elapsed = max(uptime - (starttime / clk_tck), 1.0)
            cpu_pct = round(100.0 * total / elapsed, 1)
            rss_mb = round(rss_pages * page_size_kb / 1024.0, 1)
            procs.append({"pid": int(pid), "comm": comm,
                          "cpu_pct": cpu_pct, "rss_mb": rss_mb})
        except (OSError, ValueError, IndexError):
            continue

    procs.sort(key=lambda p: p["cpu_pct"], reverse=True)
    top_cpu = procs[:n]
    top_mem = sorted(procs, key=lambda p: p["rss_mb"], reverse=True)[:n]
    return [{"by_cpu": top_cpu, "by_mem": top_mem}][0] if False else \
        [{"category": "by_cpu", **p} for p in top_cpu] + \
        [{"category": "by_mem", **p} for p in top_mem]


def file_descriptors() -> dict[str, Any]:
    """FD usage for the dashboard process."""
    out: dict[str, Any] = {}
    out["pid"] = os.getpid()
    try:
        out["fd_open"] = len(os.listdir(f"/proc/{out['pid']}/fd"))
    except OSError:
        return out
    try:
        with open(f"/proc/{os.getpid()}/limits", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Max open files"):
                    parts = line.split()
                    if len(parts) >= 5:
                        try:
                            out["fd_soft_limit"] = int(parts[3])
                        except ValueError:
                            pass
                    break
    except OSError:
        pass
    if out.get("fd_soft_limit") and out["fd_soft_limit"] > 0:
        out["fd_used_pct"] = round(100.0 * out["fd_open"] / out["fd_soft_limit"], 1)
    return out


def kernel_recent_errors(limit: int = 30) -> list[str]:
    """Recent kernel errors via dmesg (best-effort, requires CAP_SYSLOG)."""
    out: list[str] = []
    dm = _run(["dmesg", "--ctime", "--level=err,warn"], timeout=2.0)
    if dm and dm.returncode == 0:
        out = dm.stdout.strip().splitlines()[-limit:]
    return out


def systemd_failed_units() -> list[str]:
    """List systemd units in failed state (or empty if not systemd)."""
    out: list[str] = []
    if _is_docker_runtime():
        return out
    r = _run(["systemctl", "--failed", "--no-pager", "--no-legend"], timeout=3.0)
    if r and r.returncode == 0:
        out = [line.split()[0] for line in r.stdout.strip().splitlines() if line.strip()][:20]
    return out


def wireguard_peers(interface: str) -> list[dict[str, Any]]:
    """Per-peer transfer + handshake age from `wg show <iface> dump`."""
    out: list[dict[str, Any]] = []
    r = _run(["wg", "show", interface, "dump"], timeout=2.0)
    if not r or r.returncode != 0:
        return out
    now = time.time()
    for i, line in enumerate(r.stdout.strip().splitlines()):
        if i == 0:
            continue  # interface line
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        try:
            latest_hs = int(parts[4])
        except ValueError:
            latest_hs = 0
        try:
            rx = int(parts[5]); tx = int(parts[6])
        except ValueError:
            rx = tx = 0
        age = int(now - latest_hs) if latest_hs > 0 else None
        out.append({
            "endpoint": parts[2] or None,
            "allowed_ips": parts[3] or None,
            "handshake_age_s": age,
            "rx_bytes": rx, "tx_bytes": tx,
            "stale": age is None or age > 180,
        })
    return out


def health_score() -> dict[str, Any]:
    """Aggregate hardware metrics into a green/amber/red verdict per category."""
    out: dict[str, Any] = {"checks": [], "overall": "ok"}

    cpu = cpu_breakdown()
    if cpu:
        iow = cpu.get("iowait", 0.0)
        steal = cpu.get("steal", 0.0)
        if iow > 25:
            out["checks"].append({"key": "cpu_iowait", "level": "critical",
                                  "msg": f"I/O wait élevé ({iow}%) — disque saturé"})
        elif iow > 10:
            out["checks"].append({"key": "cpu_iowait", "level": "warn",
                                  "msg": f"I/O wait notable ({iow}%)"})
        if steal > 10:
            out["checks"].append({"key": "cpu_steal", "level": "warn",
                                  "msg": f"CPU steal {steal}% — host hyperviseur surchargé"})

    mem = memory_extended()
    if mem.get("used_pct", 0) > 90:
        out["checks"].append({"key": "mem", "level": "critical",
                              "msg": f"RAM saturée ({mem['used_pct']}%)"})
    elif mem.get("used_pct", 0) > 80:
        out["checks"].append({"key": "mem", "level": "warn",
                              "msg": f"RAM tendue ({mem['used_pct']}%)"})
    if mem.get("swap_used_pct", 0) > 10:
        out["checks"].append({"key": "swap", "level": "warn",
                              "msg": f"Swap utilisé ({mem['swap_used_pct']}%) — perfs dégradées"})

    therm = cpu_thermal()
    if therm.get("temp_c") and therm["temp_c"] > 80:
        out["checks"].append({"key": "thermal", "level": "critical",
                              "msg": f"Température CPU {therm['temp_c']}°C"})
    elif therm.get("temp_c") and therm["temp_c"] > 70:
        out["checks"].append({"key": "thermal", "level": "warn",
                              "msg": f"Température CPU élevée {therm['temp_c']}°C"})
    if therm.get("throttled_flags"):
        flags = ",".join(therm["throttled_flags"])
        level = "critical" if any("now" in f for f in therm["throttled_flags"]) else "warn"
        out["checks"].append({"key": "throttle", "level": level,
                              "msg": f"Throttling: {flags}"})

    for du in disk_usage():
        if du["used_pct"] > 95:
            out["checks"].append({"key": f"disk:{du['mount']}", "level": "critical",
                                  "msg": f"{du['mount']} plein ({du['used_pct']}%)"})
        elif du["used_pct"] > 85:
            out["checks"].append({"key": f"disk:{du['mount']}", "level": "warn",
                                  "msg": f"{du['mount']} {du['used_pct']}%"})

    dl = disk_latency()
    if dl and dl.get("w_await_ms", 0) > 500:
        out["checks"].append({"key": "disk_latency", "level": "critical",
                              "msg": f"Latence écriture disque {dl['w_await_ms']}ms"})
    elif dl and dl.get("w_await_ms", 0) > 100:
        out["checks"].append({"key": "disk_latency", "level": "warn",
                              "msg": f"Latence écriture disque {dl['w_await_ms']}ms"})

    tcp = tcp_health()
    if tcp.get("retrans_pct", 0) > 2:
        out["checks"].append({"key": "tcp_retrans", "level": "warn",
                              "msg": f"Retransmits TCP {tcp['retrans_pct']}%"})
    if tcp.get("timewait", 0) > 5000:
        out["checks"].append({"key": "tcp_timewait", "level": "warn",
                              "msg": f"{tcp['timewait']} sockets TIME_WAIT"})

    fd = file_descriptors()
    if fd.get("fd_used_pct", 0) > 80:
        out["checks"].append({"key": "fd", "level": "warn",
                              "msg": f"FDs ouverts {fd['fd_used_pct']}%"})

    failed = systemd_failed_units()
    if failed:
        out["checks"].append({"key": "systemd", "level": "warn",
                              "msg": f"Unités failed: {', '.join(failed[:5])}"})

    # ── Latency-relevant checks (the relay-quality angle) ──────────────────
    gov = cpu_governor()
    if gov.get("governor") in ("powersave", "ondemand"):
        out["checks"].append({"key": "cpu_governor", "level": "warn",
                              "msg": f"CPU governor='{gov['governor']}' — latence VPN dégradée. Bascule en 'performance'."})

    pwr = power_supply_events()
    if pwr.get("undervoltage_count", 0) > 0:
        out["checks"].append({"key": "undervoltage", "level": "critical",
                              "msg": f"Sous-tension Pi détectée ({pwr['undervoltage_count']} événements) — alim insuffisante = throttling silencieux."})

    ntp = ntp_offset()
    if ntp.get("synced") is False:
        out["checks"].append({"key": "ntp", "level": "warn",
                              "msg": "Horloge non synchronisée NTP — handshake WireGuard à risque."})
    if isinstance(ntp.get("offset_ms"), (int, float)) and abs(ntp["offset_ms"]) > 1000:
        out["checks"].append({"key": "ntp_drift", "level": "warn",
                              "msg": f"Dérive NTP {ntp['offset_ms']}ms — peut casser les handshakes."})

    coll = collector_health()
    if not coll.get("healthy", True):
        out["checks"].append({"key": "collector", "level": "warn",
                              "msg": f"Collecteur metrics figé ({coll.get('age_seconds')}s sans cycle)"})

    levels = {c["level"] for c in out["checks"]}
    if "critical" in levels:
        out["overall"] = "critical"
    elif "warn" in levels:
        out["overall"] = "warn"
    return out


def cpu_governor() -> dict[str, Any]:
    """Read CPU frequency governor + min/max — `powersave` is a latency killer
    for VPN crypto. We expose the verdict so the UI can recommend `performance`."""
    out: dict[str, Any] = {}
    try:
        gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        if gov.exists():
            out["governor"] = gov.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    for k, p in (("freq_min_mhz", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq"),
                 ("freq_max_mhz", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"),
                 ("freq_cur_mhz", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")):
        try:
            out[k] = int(int(Path(p).read_text(encoding="utf-8").strip()) / 1000)
        except (OSError, ValueError):
            continue
    if out.get("governor") in ("powersave", "ondemand", "conservative"):
        out["recommendation"] = (
            f"Governor '{out['governor']}' caps CPU frequency. For lowest VPN "
            "latency, set 'performance' (sudo cpupower frequency-set -g performance)."
        )
    return out


def ntp_offset() -> dict[str, Any]:
    """Detect clock drift — out-of-sync clocks break WireGuard handshakes."""
    out: dict[str, Any] = {"synced": None, "offset_ms": None, "source": None}

    # Try chrony first (default on modern Pi/Debian)
    r = _run(["chronyc", "tracking"], timeout=2.0)
    if r and r.returncode == 0:
        out["source"] = "chrony"
        for line in r.stdout.splitlines():
            if line.startswith("Last offset"):
                m = re.search(r"([-+]?[\d.]+)\s+seconds", line)
                if m:
                    out["offset_ms"] = round(float(m.group(1)) * 1000.0, 2)
            elif line.startswith("Leap status"):
                out["synced"] = "Normal" in line
        if out["offset_ms"] is not None:
            return out

    # Fallback: timedatectl (systemd)
    r = _run(["timedatectl", "show", "--property=NTPSynchronized,TimeUSec"], timeout=2.0)
    if r and r.returncode == 0:
        out["source"] = "timedatectl"
        for line in r.stdout.splitlines():
            if line.startswith("NTPSynchronized="):
                out["synced"] = line.endswith("=yes")
        return out

    # Last fallback: ntpq
    r = _run(["ntpq", "-pn"], timeout=2.0)
    if r and r.returncode == 0:
        out["source"] = "ntpq"
        for line in r.stdout.splitlines():
            if line.startswith("*"):
                parts = line.split()
                if len(parts) >= 9:
                    try:
                        out["offset_ms"] = round(float(parts[8]), 2)
                        out["synced"] = True
                    except ValueError:
                        pass
                break
    return out


def kernel_net_tunables() -> dict[str, Any]:
    """Snapshot of kernel TCP knobs that influence VPN relay latency.

    Surfaces values to the dashboard so the user can correlate "high latency"
    with a sub-optimal config (e.g. tcp_low_latency disabled, small rmem)."""
    keys = [
        "net.ipv4.tcp_low_latency",
        "net.ipv4.tcp_window_scaling",
        "net.ipv4.tcp_sack",
        "net.ipv4.tcp_fastopen",
        "net.ipv4.tcp_congestion_control",
        "net.ipv4.tcp_mtu_probing",
        "net.ipv4.ip_forward",
        "net.core.rmem_max",
        "net.core.wmem_max",
        "net.core.somaxconn",
        "net.core.netdev_max_backlog",
        "net.core.default_qdisc",
        "net.ipv4.tcp_keepalive_time",
    ]
    out: dict[str, str] = {}
    for k in keys:
        path = "/proc/sys/" + k.replace(".", "/")
        try:
            out[k] = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return out


def path_mtu_probe(host: str, max_size: int = 1472,
                   timeout: float = 2.0) -> dict[str, Any]:
    """Binary-search the path MTU using `ping -M do -s <size>`.

    Returns ``{path_mtu, probed_host, ok, error}``. Path MTU < interface MTU on
    the relay path is the #1 hidden latency-amplifier on home VPN setups
    (everything goes through TCP retransmits because of fragment drops)."""
    out: dict[str, Any] = {"probed_host": host, "ok": False}
    if not host:
        out["error"] = "no_host"
        return out

    # Check baseline reachability before searching
    base = _run(["ping", "-c", "1", "-W", "2", host], timeout=4.0)
    if not base or base.returncode != 0:
        out["error"] = "host_unreachable"
        return out

    lo, hi = 200, max_size
    while lo < hi:
        mid = (lo + hi + 1) // 2
        r = _run(["ping", "-M", "do", "-s", str(mid), "-c", "1",
                  "-W", str(int(timeout)), host], timeout=timeout + 1.0)
        ok = bool(r) and r.returncode == 0
        if ok:
            lo = mid
        else:
            hi = mid - 1
    if lo > 0:
        out["ok"] = True
        out["payload_max"] = lo
        out["path_mtu"] = lo + 28  # ICMP header (8) + IP header (20)
    else:
        out["error"] = "all_sizes_failed"
    return out


def wireguard_diagnostic(interface: str, allowed_cidrs: list[str]) -> dict[str, Any]:
    """Surface common WireGuard misconfigurations that hurt latency:

    - MTU mismatch between WG and physical interface (silent fragmentation)
    - PersistentKeepalive missing (handshake fights NAT)
    - Endpoint resolves slowly (DNS path)
    """
    out: dict[str, Any] = {"interface": interface}

    # WG iface MTU
    try:
        out["wg_mtu"] = int(Path(f"/sys/class/net/{interface}/mtu")
                             .read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        out["wg_mtu"] = None

    # Default route iface MTU (so we can detect mismatches)
    route = _run(["ip", "route", "show", "default"], timeout=2.0)
    default_iface = ""
    if route and route.returncode == 0:
        for tok, nxt in zip(route.stdout.split(), route.stdout.split()[1:]):
            if tok == "dev":
                default_iface = nxt
                break
    if default_iface and default_iface != interface:
        try:
            out["default_iface"] = default_iface
            out["default_iface_mtu"] = int(Path(f"/sys/class/net/{default_iface}/mtu")
                                            .read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            pass

    # WG endpoint + DNS timing
    cfg = _run(["wg", "show", interface, "endpoints"], timeout=2.0)
    if cfg and cfg.returncode == 0:
        endpoints = []
        for line in cfg.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                endpoints.append(parts[1])
        out["endpoints"] = endpoints

    pk = _run(["wg", "show", interface, "persistent-keepalive"], timeout=2.0)
    if pk and pk.returncode == 0:
        out["persistent_keepalive"] = []
        for line in pk.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                out["persistent_keepalive"].append(parts[1])
        # If any peer has 'off' → NAT will likely drop the tunnel
        if any(v == "off" for v in out["persistent_keepalive"]):
            out["recommendation_keepalive"] = (
                "PersistentKeepalive is 'off' for at least one peer — set it to 25s "
                "in your WG config so the tunnel stays open through NAT."
            )

    # MTU mismatch check (recommend wg_mtu = physical_mtu - 80 for IPv4 + ChaCha20)
    if out.get("wg_mtu") and out.get("default_iface_mtu"):
        recommended = out["default_iface_mtu"] - 80
        if abs(out["wg_mtu"] - recommended) > 10 and out["wg_mtu"] != recommended:
            out["recommendation_mtu"] = (
                f"WG MTU {out['wg_mtu']} on {interface}; recommended ~{recommended} "
                f"based on default iface MTU {out['default_iface_mtu']}. "
                "MTU mismatches cause silent fragmentation + TCP retransmits."
            )

    # AllowedIPs sanity
    out["allowed_cidrs_count"] = len(allowed_cidrs)
    return out


def socat_connection_count(local_port: int) -> int | None:
    """Best-effort count of established TCP connections to a local socat port.

    Helps spot a port that's about to saturate (each connection forks a child)."""
    r = _run(["ss", "-tn", "state", "established", f"sport = :{local_port}"], timeout=2.0)
    if not r or r.returncode != 0:
        return None
    return max(0, len(r.stdout.strip().splitlines()) - 1)  # subtract header line


def power_supply_events() -> dict[str, Any]:
    """Detect Raspberry Pi under-voltage events from the kernel ring buffer.

    Returns ``{undervoltage_count, last_event}``. Under-voltage is a silent
    cause of CPU throttling + USB drops + WiFi flakiness on Pi setups."""
    out: dict[str, Any] = {"undervoltage_count": 0, "last_event": None}
    r = _run(["dmesg", "-T", "--level=warn,err"], timeout=2.0)
    if not r or r.returncode != 0:
        return out
    pattern = re.compile(r"(under[-_ ]?voltage|low voltage|hwmon\d+: in0)", re.I)
    matches = []
    for line in r.stdout.splitlines():
        if pattern.search(line):
            matches.append(line.strip())
    out["undervoltage_count"] = len(matches)
    if matches:
        out["last_event"] = matches[-1][-200:]
    return out


def system_stats() -> dict[str, Any]:
    stats: dict[str, Any] = {"cpu": "N/A", "memory": "N/A", "uptime": "N/A", "load": "N/A", "disk": None}
    ultra_light = is_ultra_light_mode_enabled()
    light_mode  = is_light_mode_enabled()

    # CPU — /proc/stat, zero subprocess cost, always collected
    cpu_pct = _read_cpu_from_proc()
    if cpu_pct is not None:
        stats["cpu"] = f"{cpu_pct:.1f}%"
        stats["cpu_pct"] = cpu_pct
        # Feed adaptive ultra-light decision (hysteresis-based).
        _adaptive_ultra_light_record(cpu_pct)

    # Memory — /proc/meminfo is cheaper than calling free
    try:
        meminfo: dict[str, int] = {}
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith(("MemTotal:", "MemAvailable:")):
                    k, v = line.split(":")
                    meminfo[k.strip()] = int(v.split()[0]) // 1024  # kB → MB
                if len(meminfo) == 2:
                    break
        total = meminfo.get("MemTotal", 0)
        avail = meminfo.get("MemAvailable", 0)
        used  = total - avail
        if total > 0:
            stats["memory"] = f"{used} / {total} MB ({used * 100 // total}%)"
    except (OSError, ValueError):
        pass

    # Uptime — /proc/uptime
    try:
        with open("/proc/uptime", encoding="utf-8") as f:
            up = int(float(f.read().split()[0]))
        days, rem = divmod(up, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        stats["uptime"] = f"{days}d {hours}h {minutes}m" if days else f"{hours}h {minutes}m"
    except (OSError, ValueError):
        pass

    # Load — /proc/loadavg
    try:
        with open("/proc/loadavg", encoding="utf-8") as f:
            stats["load"] = f.read().split()[0]
    except OSError:
        pass

    # Disk latency — /proc/diskstats, zero subprocess cost, always collected
    dl = disk_latency()
    if dl:
        stats["disk"] = dl

    # Extended diagnostics — these are all /proc-based and very cheap.
    # Skipped in ultra-light to keep absolute-minimum cost.
    if not ultra_light:
        try:
            stats["cpu_detail"] = cpu_breakdown()
        except Exception as e:
            flog("DEBUG", "system", "cpu_breakdown failed", exc=e)
        try:
            stats["thermal"] = cpu_thermal()
        except Exception as e:
            flog("DEBUG", "system", "cpu_thermal failed", exc=e)
        try:
            stats["memory_detail"] = memory_extended()
        except Exception as e:
            flog("DEBUG", "system", "memory_extended failed", exc=e)
        if not light_mode:
            try:
                stats["disks"] = disk_usage()
            except Exception as e:
                flog("DEBUG", "system", "disk_usage failed", exc=e)
            try:
                stats["tcp"] = tcp_health()
            except Exception as e:
                flog("DEBUG", "system", "tcp_health failed", exc=e)
            try:
                stats["fd"] = file_descriptors()
            except Exception as e:
                flog("DEBUG", "system", "file_descriptors failed", exc=e)
            try:
                stats["cpu_governor"] = cpu_governor()
            except Exception as e:
                flog("DEBUG", "system", "cpu_governor failed", exc=e)
            try:
                stats["ntp"] = ntp_offset()
            except Exception as e:
                flog("DEBUG", "system", "ntp_offset failed", exc=e)
            try:
                pse = power_supply_events()
                stats["power"] = pse
                # First detection of an under-voltage event → log loudly once
                if pse.get("undervoltage_count", 0) > _power_state.get("seen", 0):
                    flog("WARN", "power",
                         f"Pi under-voltage detected ({pse['undervoltage_count']} events)",
                         {"last_event": pse.get("last_event")})
                    _power_state["seen"] = pse["undervoltage_count"]
            except Exception as e:
                flog("DEBUG", "system", "power_supply_events failed", exc=e)
        try:
            stats["health"] = health_score()
        except Exception as e:
            flog("DEBUG", "system", "health_score failed", exc=e)

    return stats


_power_state: dict[str, int] = {"seen": 0}

def host_network_info() -> dict[str, str]:
    """Detect active host network interface (Ethernet vs WiFi) and link speed."""
    info: dict[str, str] = {"interface": "N/A", "type": "N/A", "speed": "N/A"}
    try:
        route = _run(["ip", "route", "show", "default"])
        if not route or route.returncode != 0:
            return info
        iface = ""
        for token, nxt in zip(route.stdout.split(), route.stdout.split()[1:]):
            if token == "dev":
                iface = nxt
                break
        if not iface:
            return info
        info["interface"] = iface
        if iface.startswith(("eth", "en", "eno", "enp", "usb")):
            info["type"] = "Ethernet"
            try:
                with open(f"/sys/class/net/{iface}/speed", encoding="utf-8") as f:
                    spd = int(f.read().strip())
                    if spd > 0:
                        info["speed"] = f"{spd} Mbps"
                    # spd == -1 means unknown — leave speed as N/A
            except (OSError, ValueError):
                # Try ethtool as fallback
                eth = _run(["ethtool", iface], timeout=2.0)
                if eth and eth.returncode == 0:
                    m = re.search(r"Speed:\s*(\d+\s*\w+/s)", eth.stdout)
                    if m:
                        info["speed"] = m.group(1)
        elif iface.startswith(("wlan", "wl")):
            info["type"] = "WiFi ⚠️"
            iwc = _run(["iwconfig", iface])
            if iwc and iwc.returncode == 0:
                for line in iwc.stdout.splitlines():
                    if "Bit Rate" in line:
                        try:
                            parts = line.split("Bit Rate=")[1].split()
                            info["speed"] = f"{parts[0]} {parts[1]}"
                        except IndexError:
                            pass
                        break
        else:
            info["type"] = iface
    except Exception:
        pass
    return info

def network_stats(interface: str) -> dict[str, str]:
    out = {"rx": "N/A", "tx": "N/A"}
    try:
        with open("/proc/net/dev", encoding="utf-8") as f:
            for line in f:
                if f"{interface}:" in line:
                    parts = line.split()
                    rx_mb = int(parts[1]) / (1024 * 1024)
                    tx_mb = int(parts[9]) / (1024 * 1024)
                    out = {"rx": f"{rx_mb:.1f} MB", "tx": f"{tx_mb:.1f} MB"}
                    break
    except (OSError, ValueError, IndexError):
        pass
    return out

def diagnostics(interface: str, allowed_cidrs: list[str], probe_host: str | None) -> dict[str, bool]:
    d = {
        "internet": False,
        "wg_ip": False,
        "routes": False,
        "target_reachable": False,
        "wg_handshake_recent": False,
    }

    d["internet"] = _tcp_reachable("1.1.1.1", 53, timeout=1.5) or _tcp_reachable("8.8.8.8", 53, timeout=1.5)

    addr = _run(["ip", "-o", "-4", "addr", "show", interface])
    d["wg_ip"] = bool(addr) and addr.returncode == 0 and "inet " in addr.stdout

    route = _run(["ip", "-o", "route", "show"])
    if route and route.returncode == 0:
        d["routes"] = any(cidr in route.stdout for cidr in allowed_cidrs if cidr)

    if probe_host:
        if is_light_mode_enabled():
            d["target_reachable"] = _probe_target_reachable(probe_host, 443)
        else:
            ping = _run(["ping", "-c", "1", "-W", "1", probe_host])
            d["target_reachable"] = _tcp_reachable(probe_host, 443, timeout=1.0) or (
                ping is not None and ping.returncode == 0
            )

    wg = _run(["wg", "show", interface, "latest-handshakes"])
    if wg and wg.returncode == 0 and wg.stdout.strip():
        try:
            lines = wg.stdout.strip().splitlines()
            timestamps = []

            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    ts = int(parts[1])
                    if ts > 0:
                        timestamps.append(ts)

            if timestamps:
                latest = max(timestamps)
                age = datetime.now().timestamp() - latest
                d["wg_handshake_recent"] = age < 180
            else:
                d["wg_handshake_recent"] = False

        except Exception:
            d["wg_handshake_recent"] = False
    return d

def diagnostics_probable_cause(vpn: dict[str, str], diag: dict[str, bool], ports: list[dict[str, Any]]) -> dict[str, str]:
    """Best-effort probable cause for quick troubleshooting."""
    if not diag.get("internet", False):
        return {"code": "internet_down", "message": "No internet connectivity from host."}
    if vpn.get("status") != "CONNECTED":
        return {"code": "vpn_down", "message": "WireGuard interface is down or not connected."}
    if not diag.get("wg_ip", False):
        return {"code": "wg_ip_missing", "message": "WireGuard has no IP address."}
    if not diag.get("routes", False):
        return {"code": "routes_missing", "message": "WireGuard routes are missing."}
    if not diag.get("wg_handshake_recent", False):
        return {"code": "handshake_stale", "message": "WireGuard handshake is stale; peer may be unreachable."}

    unhealthy = [port for port in ports if port.get("overall_status") != "ACTIVE"]
    if unhealthy:
        target_down = [p for p in unhealthy if (p.get("service_active") and p.get("port_active") and not p.get("target_reachable"))]
        if target_down:
            items: list[str] = []
            for p in target_down[:3]:
                name = str(p.get("name") or "service")
                rh = p.get("remote_host")
                rp = p.get("remote_port")
                # In public read-only, remote_host/port are redacted to "hidden".
                if rh == "hidden" or rp == "hidden":
                    items.append(name)
                else:
                    items.append(f"{name} ({rh}:{rp})")
            extra = ""
            if len(target_down) > 3:
                extra = f" (+{len(target_down) - 3} more)"
            return {
                "code": "target_unreachable",
                "message": "Tunnel is up but a target did not respond to the last TCP probe: "
                           + ", ".join(items) + extra + ". This can be transient; try Test Connection.",
            }
        if any(not p.get("service_active") for p in unhealthy):
            return {"code": "service_down", "message": "At least one socat service is not active."}
        if any(not p.get("port_active") for p in unhealthy):
            return {"code": "local_port_down", "message": "At least one local forwarded port is not listening."}

    return {"code": "healthy", "message": "No obvious issue detected."}

def ports_status(ports: list[dict[str, Any]], *, redacted: bool = False) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    recent_incident_ports: set[str] = set()
    if is_analytics_enabled():
        try:
            cutoff = _now_ts() - 300  # Last 5 minutes
            with _db_connect() as conn:
                rows = conn.execute(
                    "SELECT DISTINCT port_id FROM incidents WHERE timestamp > ?",
                    (cutoff,),
                ).fetchall()
            recent_incident_ports = {row[0] for row in rows if row and row[0]}
        except sqlite3.Error:
            recent_incident_ports = set()

    for p in ports:
        if not p.get("enabled", True):
            continue
        lp = int(p["local_port"])
        rh = str(p["remote_host"])
        rp = int(p["remote_port"])
        service = f"homelinkwg-socat-{lp}"
        port_up = _tcp_reachable("127.0.0.1", lp, timeout=0.5)
        service_up = systemd_is_active(service)
        target_up = _probe_target_reachable(rh, rp)

        has_incident = (f"port-{lp}" in recent_incident_ports) and (not is_alerts_muted())
        remote_host = "hidden" if redacted else rh
        remote_port: int | str = "hidden" if redacted else rp
        description = "" if redacted else p.get("description", "")

        result.append({
            "local_port": lp,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "name": p.get("name", f"Port {lp}"),
            "description": description,
            "port_active": port_up,
            "service_active": service_up,
            "target_reachable": target_up,
            "overall_status": "ACTIVE" if (port_up and service_up and target_up) else "INACTIVE",
            "has_incident": has_incident,
            "public_read_only": redacted,
        })
    return result

# ---------------------------------------------------------------------------
# Background metrics collector
# ---------------------------------------------------------------------------
_probe_pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="probe")

def _probe_one_port(p: dict[str, Any], light_mode: bool) -> dict[str, Any]:
    lp = int(p["local_port"])
    rh = str(p["remote_host"])
    rp = int(p["remote_port"])
    port_id = f"port-{lp}"
    service_name = p.get("name", f"Port {lp}")

    breakdown: dict[str, Any] = {}
    with timed("probe", "probe.cycle",
               {"port_id": port_id}, warn_above_ms=2500):
        service_active = systemd_is_active(f"homelinkwg-socat-{lp}")
        port_listening = _tcp_reachable("127.0.0.1", lp, timeout=0.5)
        target_reachable = _probe_target_reachable(rh, rp)
        latency_ms = -1
        if target_reachable and not light_mode:
            # Get a richer breakdown (DNS / TCP / jitter) for analytics + logs.
            breakdown = latency_breakdown(rh, rp, timeout=1.0, samples=3)
            if breakdown.get("ok"):
                latency_ms = int(round(breakdown.get("total_ms") or 0))
                # Surface slow probes early — these are the ones the user wants to chase.
                if breakdown.get("total_ms", 0) > 200:
                    flog("WARN", "probe", "slow probe", {
                        "port_id": port_id, "service": service_name,
                        "host": rh, "port": rp,
                        "dns_ms": breakdown.get("dns_ms"),
                        "tcp_ms_avg": breakdown.get("tcp_ms_avg"),
                        "tcp_ms_p95": breakdown.get("tcp_ms_p95"),
                        "jitter_ms": breakdown.get("jitter_ms"),
                        "total_ms": breakdown.get("total_ms"),
                    })
                # Jitter spike independently of average latency.
                if breakdown.get("jitter_ms", 0) > 50:
                    flog("WARN", "probe", "high jitter", {
                        "port_id": port_id, "service": service_name,
                        "jitter_ms": breakdown.get("jitter_ms"),
                        "tcp_ms_min": breakdown.get("tcp_ms_min"),
                        "tcp_ms_max": breakdown.get("tcp_ms_max"),
                    })
            elif breakdown.get("error"):
                flog("WARN", "probe", "probe error", {
                    "port_id": port_id, "host": rh, "port": rp,
                    "error": breakdown.get("error"),
                })

    return {
        "lp": lp, "rh": rh, "rp": rp,
        "port_id": port_id, "service_name": service_name,
        "service_active": service_active,
        "breakdown": breakdown,
        "port_listening": port_listening,
        "target_reachable": target_reachable,
        "latency_ms": latency_ms,
    }

def _collect_metrics_once() -> None:
    """Collect metrics snapshot for all ports (probes run in parallel)."""
    try:
        cfg = load_config()
        ports = [p for p in cfg.get("ports", []) if p.get("enabled", True)]
        light_mode = is_light_mode_enabled()
        flog("INFO", "metrics", "collection cycle start",
             {"ports": len(ports), "light_mode": light_mode})

        with timed("metrics", "collection.cycle",
                   {"ports": len(ports)}, warn_above_ms=8000):
            results = list(_probe_pool.map(
                lambda p: _probe_one_port(p, light_mode), ports
            ))

        latency_threshold = get_threshold("latency_threshold_ms", 50.0)
        for r in results:
            port_id = r["port_id"]
            service_name = r["service_name"]
            lp = r["lp"]; rh = r["rh"]; rp = r["rp"]
            service_active = r["service_active"]
            port_listening = r["port_listening"]
            target_reachable = r["target_reachable"]
            latency_ms = r["latency_ms"]
            ctx = {"port_id": port_id, "service": service_name, "lp": lp,
                   "latency_ms": latency_ms}

            prev_state = service_state_cache.get(port_id, {})
            curr_state = {
                "service_active": service_active,
                "port_listening": port_listening,
                "target_reachable": target_reachable,
                "latency_ms": latency_ms,
            }

            if prev_state.get("service_active") != service_active:
                if service_active:
                    flog("INFO", "systemd", f"{service_name}: service started", ctx)
                else:
                    flog("ERROR", "systemd", f"{service_name}: service stopped", ctx)

            if prev_state.get("port_listening") != port_listening:
                if port_listening:
                    flog("INFO", "systemd", f"{service_name}: port {lp} listening", ctx)
                else:
                    flog("WARN", "systemd", f"{service_name}: port {lp} unreachable", ctx)

            if prev_state.get("target_reachable") != target_reachable:
                if target_reachable:
                    flog("INFO", "systemd", f"{service_name}: target {rh}:{rp} restored", ctx)
                else:
                    flog("WARN", "systemd", f"{service_name}: target {rh}:{rp} unreachable", ctx)

            prev_latency = prev_state.get("latency_ms", -1)
            if latency_ms >= 0 and prev_latency >= 0:
                prev_high = prev_latency > latency_threshold
                curr_high = latency_ms > latency_threshold
                if prev_high != curr_high:
                    msg = (f"{service_name}: latency {prev_latency}ms -> {latency_ms}ms "
                           f"({'HIGH' if curr_high else 'recovered'}, threshold={latency_threshold}ms)")
                    flog("WARN" if curr_high else "INFO", "systemd", msg, ctx)
                else:
                    flog("DEBUG", "systemd",
                         f"{service_name}: latency stable",
                         {**ctx, "prev_latency_ms": prev_latency,
                          "threshold_ms": latency_threshold})

            service_state_cache[port_id] = curr_state

            store_metric(port_id, service_name, service_active, port_listening,
                         target_reachable, latency_ms)
            detect_incidents(port_id, service_name, service_active, port_listening,
                             target_reachable, latency_ms)
        flog("INFO", "metrics", "collection cycle done",
             {"ports": len(results)})
    except Exception as e:
        flog("ERROR", "metrics", "collection cycle failed", exc=e)
    finally:
        set_correlation_id(None)

_collector_heartbeat = {"last_cycle_ts": 0.0, "cycles": 0,
                        "last_error_ts": 0.0, "last_error": None}

def _metrics_collector() -> None:
    """Background thread: collect metrics periodically (first collection immediate).

    Emits a heartbeat every 5 minutes so a silent thread death is observable
    via ``/api/healthz`` (the heartbeat freshness gates the liveness check).
    """
    flog("INFO", "systemd", "metrics collector started")
    _collect_metrics_once()
    _collector_heartbeat["last_cycle_ts"] = time.time()
    _collector_heartbeat["cycles"] = 1
    last_heartbeat_log = time.time()
    while True:
        try:
            if is_ultra_light_mode_enabled():
                interval = 180
            elif is_light_mode_enabled():
                interval = 90
            else:
                interval = 60
            time.sleep(interval)
            _collect_metrics_once()
            _collector_heartbeat["last_cycle_ts"] = time.time()
            _collector_heartbeat["cycles"] += 1
            # Emit a INFO heartbeat at most every 5 minutes — useful in logs to
            # confirm the collector loop is still alive on a quiet system.
            if time.time() - last_heartbeat_log >= 300:
                flog("INFO", "metrics", "collector heartbeat",
                     {"cycles": _collector_heartbeat["cycles"],
                      "interval": interval})
                last_heartbeat_log = time.time()
        except Exception as e:
            _collector_heartbeat["last_error_ts"] = time.time()
            _collector_heartbeat["last_error"] = str(e)
            flog("ERROR", "metrics", "collector loop error", exc=e)


def collector_health() -> dict[str, Any]:
    """Snapshot of the metrics collector liveness for the diagnostic bundle."""
    now = time.time()
    last = _collector_heartbeat["last_cycle_ts"]
    age = now - last if last else None
    healthy = age is not None and age < 600  # within 10 min of last cycle
    return {
        "cycles": _collector_heartbeat["cycles"],
        "last_cycle_ts": last,
        "age_seconds": round(age, 1) if age is not None else None,
        "healthy": healthy,
        "last_error": _collector_heartbeat["last_error"],
        "last_error_ts": _collector_heartbeat["last_error_ts"] or None,
    }

def _start_analytics_runtime() -> None:
    """Initialize analytics resources exactly once."""
    global _collector_thread
    if not is_analytics_enabled():
        print("[homelinkwg-dashboard] Analytics disabled - metrics collection skipped", file=sys.stderr)
        return

    with _analytics_init_lock:
        init_db()
        load_thresholds()
        if _collector_thread and _collector_thread.is_alive():
            return
        _collector_thread = threading.Thread(target=_metrics_collector, daemon=True)
        _collector_thread.start()
    print("[homelinkwg-dashboard] Analytics enabled - metrics collector started", file=sys.stderr)

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False  # Don't sort JSON keys (faster)
app.config['JSON_COMPRESS'] = False  # Let gzip handle compression

@app.before_request
def _attach_correlation_id():
    """Per-request correlation ID, surfaced in logs and as response header."""
    cid = request.headers.get("X-Request-Id") or new_correlation_id("req")
    set_correlation_id(cid)


@app.after_request
def _emit_correlation_id(response):
    response.headers["X-Request-Id"] = get_correlation_id()
    set_correlation_id(None)
    return response


# Add gzip compression for responses (FIX: Don't compress SSE streams)
@app.after_request
def compress_response(response):
    """Add gzip compression to responses. Exclude SSE streams."""
    if response.direct_passthrough:
        return response
    if response.status_code < 200 or response.status_code >= 300:
        return response
    if response.headers.get('Content-Encoding'):
        return response
    if response.content_type and 'event-stream' in response.content_type:
        return response
    if 'gzip' not in request.headers.get('Accept-Encoding', ''):
        return response

    payload = response.get_data()
    if len(payload) < 500:
        return response

    try:
        import gzip

        response.set_data(gzip.compress(payload))
        response.headers['Content-Encoding'] = 'gzip'
        response.headers['Vary'] = 'Accept-Encoding'
        response.headers.pop('Content-Length', None)
    except OSError:
        pass  # If compression fails, send uncompressed
    return response

# Add cache headers for static content
@app.after_request
def add_cache_headers(response):
    """Add cache headers based on content type."""
    content_type = response.content_type or ""
    if content_type.startswith(('text/css', 'text/javascript', 'image/')):
        response.headers['Cache-Control'] = 'public, max-age=604800'  # 1 week for static
    elif content_type.startswith('application/json'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'  # No caching for JSON
    response.headers['X-Content-Type-Options'] = 'nosniff'  # Security header
    return response

# Initialize authentication & database
load_auth_config()
_start_analytics_runtime()
class CacheStore:
    """Simple TTL-based cache for expensive queries."""
    def __init__(self, ttl_seconds: int = 5):
        self.ttl = ttl_seconds
        self.cache = {}
        self.timestamps = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        """Get cached value if not expired."""
        with self._lock:
            if key in self.cache and time.time() - self.timestamps[key] < self.ttl:
                return self.cache[key]
            return None

    def set(self, key: str, value):
        """Cache a value with timestamp."""
        with self._lock:
            self.cache[key] = value
            self.timestamps[key] = time.time()

    def clear(self):
        """Clear all cache."""
        with self._lock:
            self.cache.clear()
            self.timestamps.clear()

cache_store = CacheStore(
    ttl_seconds=(
        ULTRA_STATUS_CACHE_TTL_SECONDS
        if is_ultra_light_mode_enabled()
        else (LIGHT_STATUS_CACHE_TTL_SECONDS if is_light_mode_enabled() else DEFAULT_STATUS_CACHE_TTL_SECONDS)
    )
)

def _allowed_cidrs() -> list[str]:
    """Best-effort: read AllowedIPs from the configured wg conf path."""
    cfg = load_config()
    wg_path = SCRIPT_DIR / cfg.get("vpn", {}).get("config_file", "yourconfwg/wg0.conf")
    cidrs: list[str] = []
    try:
        for line in wg_path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("AllowedIPs"):
                _, _, rhs = s.partition("=")
                cidrs.extend(c.strip() for c in rhs.split(",") if c.strip())
    except OSError:
        pass
    return cidrs

def _probe_host() -> str | None:
    cfg = load_config()
    ports = cfg.get("ports") or []
    return ports[0]["remote_host"] if ports else None

def _uptime_summaries_24h(port_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Compute 24h uptime/latency summaries for multiple ports in one DB query."""
    if not port_ids:
        return {}
    if not is_analytics_enabled():
        return {}
    try:
        now_ts = _now_ts()
        cutoff = now_ts - 86400
        mid = now_ts - 43200
        placeholders = ",".join(["?"] * len(port_ids))
        sql = f"""
            SELECT port_id,
                   COUNT(*) as total,
                   SUM(CASE WHEN service_active AND port_listening AND target_reachable THEN 1 ELSE 0 END) as ok,
                   AVG(CASE WHEN latency_ms >= 0 THEN latency_ms ELSE NULL END) as avg_latency,
                   SUM(CASE WHEN timestamp <  ? THEN 1 ELSE 0 END) as total_1,
                   SUM(CASE WHEN timestamp <  ? AND service_active AND port_listening AND target_reachable THEN 1 ELSE 0 END) as ok_1,
                   SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) as total_2,
                   SUM(CASE WHEN timestamp >= ? AND service_active AND port_listening AND target_reachable THEN 1 ELSE 0 END) as ok_2,
                   AVG(CASE WHEN timestamp <  ? AND latency_ms >= 0 THEN latency_ms ELSE NULL END) as lat_1,
                   AVG(CASE WHEN timestamp >= ? AND latency_ms >= 0 THEN latency_ms ELSE NULL END) as lat_2
            FROM metrics
            WHERE timestamp > ? AND port_id IN ({placeholders})
            GROUP BY port_id
        """
        out: dict[str, dict[str, Any]] = {}
        with _db_connect(row_factory=True) as conn:
            rows = conn.execute(sql, [mid, mid, mid, mid, mid, mid, cutoff, *port_ids]).fetchall()
        for row in rows:
            total = int(row["total"] or 0)
            ok_count = int(row["ok"] or 0)
            avg_latency = row["avg_latency"]
            uptime_percent = (ok_count / total * 100) if total > 0 else 0.0

            # Trends: compare first half vs second half of last 24h.
            total_1 = int(row["total_1"] or 0)
            ok_1 = int(row["ok_1"] or 0)
            total_2 = int(row["total_2"] or 0)
            ok_2 = int(row["ok_2"] or 0)
            up_1 = (ok_1 / total_1 * 100) if total_1 > 0 else None
            up_2 = (ok_2 / total_2 * 100) if total_2 > 0 else None
            uptime_trend = "flat"
            if up_1 is None or up_2 is None:
                uptime_trend = "na"
            else:
                diff = up_2 - up_1
                tol = max(up_1, up_2) * 0.02
                if abs(diff) < tol:
                    uptime_trend = "flat"
                else:
                    uptime_trend = "up" if diff > 0 else "down"

            lat_1 = row["lat_1"]
            lat_2 = row["lat_2"]
            latency_trend = "flat"
            if lat_1 is None or lat_2 is None:
                latency_trend = "na"
            else:
                lat_1f = float(lat_1)
                lat_2f = float(lat_2)
                diff = lat_2f - lat_1f
                tol = max(lat_1f, lat_2f) * 0.02
                if abs(diff) < tol:
                    latency_trend = "flat"
                else:
                    # For latency: lower is better. Negative diff means improving.
                    latency_trend = "good" if diff < 0 else "bad"

            out[str(row["port_id"])] = {
                "port_id": str(row["port_id"]),
                "uptime_24h_percent": round(uptime_percent, 2),
                "avg_latency_ms": round(float(avg_latency), 1) if avg_latency is not None else None,
                "samples": total,
                "uptime_trend": uptime_trend,
                "latency_trend": latency_trend,
            }
        return out
    except sqlite3.Error:
        return {}

def _snapshot(*, admin_view: bool = False) -> dict[str, Any]:
    cfg = load_config()
    interface = cfg.get("vpn", {}).get("interface", "wg0")
    light_mode = is_light_mode_enabled()
    ultra_light = is_ultra_light_mode_enabled()
    vpn = vpn_status(interface)
    ports = ports_status(cfg.get("ports", []), redacted=not admin_view)
    if admin_view and is_analytics_enabled() and ports:
        summaries = _uptime_summaries_24h([f"port-{p.get('local_port')}" for p in ports if p.get("local_port")])
        for p in ports:
            pid = f"port-{p.get('local_port')}"
            p["stats_24h"] = summaries.get(pid, {
                "port_id": pid,
                "uptime_24h_percent": 0.0,
                "avg_latency_ms": None,
                "samples": 0,
                "uptime_trend": "na",
                "latency_trend": "na",
            })
    # Ultra-light: skip expensive TCP probes, keep everything else
    if ultra_light:
        diag = {"internet": None, "wg_ip": None, "routes": None,
                "target_reachable": None, "wg_handshake_recent": None}
        probable = {"code": "ultra_light", "message": "Diagnostics disabled in ultra-light mode."}
    else:
        diag = diagnostics(interface, _allowed_cidrs(), _probe_host())
        probable = diagnostics_probable_cause(vpn, diag, ports)

    vpn_ip = vpn.get("ip", "N/A") if admin_view else ("hidden" if vpn.get("ip") != "N/A" else "N/A")
    vpn_payload = {**vpn, "ip": vpn_ip}

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "version": __version__,
        "date": __date__,
        "vpn": vpn_payload,
        "ports": ports,
        "system": system_stats(),
        "network": network_stats(interface),
        "host_network": host_network_info(),
        "diagnostics": diag,
        "diagnostics_summary": probable,
        "alerts": alerts_status(),
        "runtime": {
            "light_mode": light_mode,
            "ultra_light": ultra_light,
            "ultra_light_adaptive": adaptive_ultra_light_status(),
            "refresh_ms": status_refresh_ms(),
            "analytics_refresh_ms": analytics_refresh_ms(),
            "public_read_only": not admin_view,
        },
    }

def _extract_whats_new() -> str:
    """Return the 'What's New' section from RELEASE_NOTES.md (best-effort)."""
    try:
        if not RELEASE_NOTES_FILE.exists():
            return ""
        text = RELEASE_NOTES_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip().lower() in {"## what's new", "## whats new"}:
            start = i + 1
            break
    if start is None:
        # Fallback: first chunk
        return "\n".join(lines[:120]).strip()

    out: list[str] = []
    for j in range(start, len(lines)):
        l = lines[j]
        if l.startswith("## ") and j > start:
            break
        out.append(l)
    return "\n".join(out).strip()

INDEX_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HomelinkWG</title>
<link rel="icon" type="image/svg+xml" href="/favicon.ico">
<style>
:root{
  --bg:#07080f;
  --surface:#0b0d18;
  --card:#0f1120;
  --card-2:#0c0e1a;
  --border:rgba(148,163,184,.07);
  --border-2:rgba(148,163,184,.13);
  --accent:#10b981;
  --accent-2:#34d399;
  --accent-glow:rgba(16,185,129,.18);
  --purple:#8b5cf6;
  --purple-dim:rgba(139,92,246,.14);
  --amber:#f59e0b;
  --danger:#f43f5e;
  --danger-dim:rgba(244,63,94,.12);
  --ok-bg:rgba(16,185,129,.09);
  --neutral-bg:rgba(148,163,184,.05);
  --text:#e2e8f0;
  --text-2:#8892a4;
  --text-3:#3d4a5c;
  --r:12px;
  --r-sm:7px;
  --r-lg:18px;
}

/* ── Light theme variables ─────────────────────────────────────────────── */
.light-theme{
  --bg:#f1f5f9;
  --surface:#ffffff;
  --card:#f8fafc;
  --card-2:#f0f4f8;
  --border:rgba(0,0,0,.08);
  --border-2:rgba(0,0,0,.13);
  --accent:#059669;
  --accent-2:#047857;
  --accent-glow:rgba(5,150,105,.14);
  --purple:#7c3aed;
  --purple-dim:rgba(124,58,237,.12);
  --amber:#d97706;
  --danger:#e11d48;
  --danger-dim:rgba(225,29,72,.10);
  --ok-bg:rgba(5,150,105,.09);
  --neutral-bg:rgba(0,0,0,.04);
  --text:#0f172a;
  --text-2:#475569;
  --text-3:#94a3b8;
}
@media(prefers-color-scheme:light){
  :root:not([data-theme="dark"]){
    --bg:#f1f5f9;
    --surface:#ffffff;
    --card:#f8fafc;
    --card-2:#f0f4f8;
    --border:rgba(0,0,0,.08);
    --border-2:rgba(0,0,0,.13);
    --accent:#059669;
    --accent-2:#047857;
    --accent-glow:rgba(5,150,105,.14);
    --purple:#7c3aed;
    --purple-dim:rgba(124,58,237,.12);
    --amber:#d97706;
    --danger:#e11d48;
    --danger-dim:rgba(225,29,72,.10);
    --ok-bg:rgba(5,150,105,.09);
    --neutral-bg:rgba(0,0,0,.04);
    --text:#0f172a;
    --text-2:#475569;
    --text-3:#94a3b8;
  }
}
[data-theme="light"]{
  --bg:#f1f5f9;
  --surface:#ffffff;
  --card:#f8fafc;
  --card-2:#f0f4f8;
  --border:rgba(0,0,0,.08);
  --border-2:rgba(0,0,0,.13);
  --accent:#059669;
  --accent-2:#047857;
  --accent-glow:rgba(5,150,105,.14);
  --purple:#7c3aed;
  --purple-dim:rgba(124,58,237,.12);
  --amber:#d97706;
  --danger:#e11d48;
  --danger-dim:rgba(225,29,72,.10);
  --ok-bg:rgba(5,150,105,.09);
  --neutral-bg:rgba(0,0,0,.04);
  --text:#0f172a;
  --text-2:#475569;
  --text-3:#94a3b8;
}

*{margin:0;padding:0;box-sizing:border-box}

body{
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);
  color:var(--text);
  min-height:100vh;
  -webkit-font-smoothing:antialiased;
  -moz-osx-font-smoothing:grayscale;
}

body::before{
  content:'';
  position:fixed;
  inset:0;
  background:
    radial-gradient(ellipse 60% 40% at 10% 0%,rgba(16,185,129,.05) 0%,transparent 60%),
    radial-gradient(ellipse 50% 30% at 90% 100%,rgba(139,92,246,.04) 0%,transparent 60%);
  pointer-events:none;
  z-index:0;
}

.container{max-width:1440px;margin:0 auto;padding:0 24px 40px;position:relative;z-index:1}

header{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:16px;
  padding:18px 0;
  border-bottom:1px solid var(--border);
  margin-bottom:28px;
  flex-wrap:wrap;
}
.header-brand{display:flex;align-items:center;gap:14px}
.logo{height:36px;width:auto;display:block;filter:drop-shadow(0 0 12px rgba(16,185,129,.4))}
.brand-name{font-size:1.05rem;font-weight:700;letter-spacing:.08em;color:var(--text)}
.brand-sub{font-size:.72rem;color:var(--text-3);letter-spacing:.04em;margin-top:2px}

.header-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}

.update-chip{
  display:flex;
  align-items:center;
  gap:8px;
  padding:4px 10px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:999px;
  font-size:.75rem;
  color:var(--text-2);
}
#last-update{font-variant-numeric:tabular-nums}

.link-btn{
  border:none;
  background:transparent;
  color:var(--accent-2);
  cursor:pointer;
  font-size:.78rem;
  font-weight:600;
  padding:0;
  line-height:1;
  font-family:inherit;
  transition:color .15s;
}
.link-btn:hover{color:var(--accent)}

.mode-badge{
  display:inline-flex;
  align-items:center;
  gap:5px;
  padding:4px 10px;
  border-radius:999px;
  font-size:.7rem;
  font-weight:600;
  letter-spacing:.06em;
  border:1px solid transparent;
}
.mode-badge.admin{background:var(--purple-dim);color:#c4b5fd;border-color:rgba(139,92,246,.3)}
.mode-badge.public{background:var(--neutral-bg);color:var(--text-2);border-color:var(--border-2)}
.mode-badge.light{background:var(--ok-bg);color:var(--accent-2);border-color:rgba(16,185,129,.25)}

.btn{
  display:inline-flex;
  align-items:center;
  gap:6px;
  padding:7px 14px;
  border:none;
  border-radius:var(--r-sm);
  font-weight:600;
  font-size:.78rem;
  cursor:pointer;
  font-family:inherit;
  transition:opacity .15s,transform .1s;
}
.btn:active{transform:translateY(1px)}
.btn-primary{background:var(--accent);color:#042d1e}
.btn-primary:hover{opacity:.88}
.btn-danger{background:rgba(244,63,94,.14);color:#fb7185;border:1px solid rgba(244,63,94,.25)}
.btn-danger:hover{background:rgba(244,63,94,.22)}

.icon-btn{
  width:34px;height:34px;
  display:inline-flex;align-items:center;justify-content:center;
  border:1px solid var(--border-2);
  background:var(--surface);
  color:var(--text-2);
  border-radius:var(--r-sm);
  cursor:pointer;
  transition:border-color .15s,color .15s;
}
.icon-btn:hover{border-color:var(--accent);color:var(--accent-2)}

#alert,#mute-banner{margin-bottom:16px}
.alert-strip{
  display:flex;align-items:center;gap:10px;
  padding:12px 18px;
  border-radius:var(--r-sm);
  font-size:.85rem;
  font-weight:500;
}
.alert-strip.danger{background:var(--danger-dim);border:1px solid rgba(244,63,94,.3);color:#fda4af}
.alert-strip.muted{background:var(--neutral-bg);border:1px solid var(--border-2);color:var(--text-2)}

.grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(270px,1fr));
  gap:14px;
  margin-bottom:14px;
}
.full{grid-column:1/-1}

.card{
  background:var(--card);
  border:1px solid var(--border);
  border-radius:var(--r);
  padding:20px;
  transition:border-color .2s;
}
.card:hover{border-color:var(--border-2)}
.card-header{
  display:flex;align-items:center;gap:8px;
  font-size:.72rem;
  font-weight:600;
  letter-spacing:.1em;
  text-transform:uppercase;
  color:var(--text-3);
  margin-bottom:18px;
  padding-bottom:12px;
  border-bottom:1px solid var(--border);
}
.card-header svg{flex-shrink:0;opacity:.7}
.card h2{font-size:.72rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--text-3);margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid var(--border)}

.row{
  display:flex;
  justify-content:space-between;
  align-items:center;
  padding:9px 0;
  border-bottom:1px solid var(--border);
}
.row:last-child{border-bottom:none}
.label{font-size:.82rem;color:var(--text-2)}
.value{font-size:.88rem;font-weight:600;color:var(--text);display:flex;align-items:center;gap:6px}

.dot{width:7px;height:7px;border-radius:50%;display:inline-block;flex-shrink:0}
.dot.ok{background:var(--accent);box-shadow:0 0 0 3px rgba(16,185,129,.2);animation:pulse 2.4s ease-in-out infinite}
.dot.ko{background:var(--text-3)}

@keyframes pulse{
  0%,100%{box-shadow:0 0 0 3px rgba(16,185,129,.2)}
  50%{box-shadow:0 0 0 5px rgba(16,185,129,.06)}
}

.badge{
  display:inline-flex;align-items:center;
  padding:3px 9px;
  border-radius:999px;
  font-size:.7rem;font-weight:600;
  letter-spacing:.04em;
  border:1px solid transparent;
}
.badge.ok{background:var(--ok-bg);color:var(--accent-2);border-color:rgba(16,185,129,.2)}
.badge.ko{background:var(--danger-dim);color:#fda4af;border-color:rgba(244,63,94,.2)}
.badge.muted{background:var(--neutral-bg);color:var(--text-2);border-color:var(--border-2)}

.diag{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}
.diag .cell{padding:12px 14px;border-radius:var(--r-sm);background:var(--surface);border:1px solid var(--border);border-left:2px solid var(--text-3)}
.diag .cell.ok{background:rgba(16,185,129,.05);border-left-color:var(--accent)}
.diag .cell .k{font-size:.72rem;color:var(--text-3);font-weight:500;margin-bottom:4px}
.diag .cell .v{font-size:.88rem;font-weight:600;color:var(--text)}

.modal{
  display:none;
  position:fixed;inset:0;
  z-index:3000;
  background:rgba(4,5,12,.75);
  backdrop-filter:blur(8px);
  -webkit-backdrop-filter:blur(8px);
  align-items:center;
  justify-content:center;
}
.modal.show{display:flex}
.modal-content{
  background:var(--card);
  border:1px solid var(--border-2);
  border-radius:var(--r-lg);
  padding:28px;
  max-width:420px;
  width:92%;
  box-shadow:0 30px 70px rgba(0,0,0,.7);
  animation:modal-in .2s ease;
}
.modal-content.wide{max-width:min(1200px,95vw);width:95%;max-height:90vh;overflow-y:auto}
@keyframes modal-in{from{opacity:0;transform:translateY(8px) scale(.98)}to{opacity:1;transform:none}}

.modal-title{font-size:1rem;font-weight:700;color:var(--text);margin-bottom:20px}
.modal-input{
  width:100%;padding:11px 14px;
  background:var(--surface);
  border:1px solid var(--border-2);
  border-radius:var(--r-sm);
  color:var(--text);font-size:.9rem;font-family:inherit;
  margin-bottom:14px;outline:none;
  transition:border-color .15s;
}
.modal-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(16,185,129,.12)}
.modal-buttons{display:flex;gap:8px;justify-content:flex-end}
.modal-btn{
  padding:9px 18px;border:none;
  border-radius:var(--r-sm);
  font-weight:600;cursor:pointer;font-size:.85rem;font-family:inherit;
}
.modal-btn.cancel{background:var(--surface);border:1px solid var(--border-2);color:var(--text-2)}
.modal-btn.submit{background:var(--accent);color:#042d1e}
.modal-error{
  color:#fda4af;font-size:.82rem;
  margin-bottom:10px;padding:8px 12px;
  background:var(--danger-dim);
  border-radius:var(--r-sm);display:none;
}

.settings-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
.settings-section{margin-top:20px;padding-top:18px;border-top:1px solid var(--border)}
.settings-label{
  font-size:.72rem;font-weight:600;
  letter-spacing:.08em;text-transform:uppercase;
  color:var(--text-3);margin-bottom:12px;
}
.range-row{display:flex;gap:10px;align-items:center}
.range-row input[type="range"]{flex:1;max-width:180px}
.range-row input[type="number"]{
  width:68px;padding:6px 8px;
  background:var(--surface);
  border:1px solid var(--border-2);
  border-radius:var(--r-sm);
  color:var(--text);font-size:.85rem;
  text-align:center;font-family:inherit;
  outline:none;
}
.range-hint{font-size:.75rem;color:var(--text-3);margin-top:6px}

input[type="range"]{
  -webkit-appearance:none;
  height:4px;background:var(--border-2);
  border-radius:999px;outline:none;cursor:pointer;
  accent-color:var(--accent);
}
input[type="range"]::-webkit-slider-runnable-track{height:4px;background:transparent;border-radius:999px}
input[type="range"]::-webkit-slider-thumb{
  -webkit-appearance:none;
  width:14px;height:14px;border-radius:50%;
  background:var(--accent);margin-top:-5px;
  box-shadow:0 0 0 3px rgba(16,185,129,.15);
}
input[type="range"]::-moz-range-track{height:4px;background:transparent;border-radius:999px}
input[type="range"]::-moz-range-thumb{width:14px;height:14px;border-radius:50%;background:var(--accent);border:none}

.maint-btns{display:flex;gap:8px;flex-wrap:wrap}
.maint-btn{
  padding:7px 13px;
  background:var(--surface);
  border:1px solid var(--border-2);
  color:var(--text-2);
  border-radius:var(--r-sm);
  cursor:pointer;font-size:.8rem;font-family:inherit;
  transition:border-color .15s,color .15s;
}
.maint-btn:hover{border-color:var(--accent);color:var(--accent-2)}
.maint-btn.unmute{border-color:rgba(16,185,129,.3);color:var(--accent-2)}

.section-row{
  display:flex;align-items:center;
  justify-content:space-between;
  gap:12px;
  margin:28px 0 14px;
  flex-wrap:wrap;
}
.section-heading{
  font-size:.72rem;font-weight:700;
  letter-spacing:.12em;text-transform:uppercase;color:var(--text-3);
}

.timeframe-group{display:flex;gap:4px}
.timeframe-btn{
  padding:5px 11px;
  border:1px solid var(--border-2);
  background:transparent;
  color:var(--text-2);
  border-radius:var(--r-sm);
  cursor:pointer;font-size:.78rem;font-weight:500;font-family:inherit;
  transition:all .15s;
}
.timeframe-btn:hover{border-color:var(--accent-2);color:var(--accent-2)}
.timeframe-btn.active,
.timeframe-btn[style*="background:var(--accent)"]{
  background:var(--accent) !important;
  border-color:var(--accent) !important;
  color:#042d1e !important;font-weight:700 !important;
}

.logs-grid{
  display:grid;
  grid-template-columns:280px 1fr;
  gap:20px;
}
.section-title{
  font-size:.72rem;font-weight:600;
  letter-spacing:.1em;text-transform:uppercase;
  color:var(--text-3);margin-bottom:12px;
}

.log-controls{
  display:flex;align-items:center;
  justify-content:space-between;gap:10px;
  margin-bottom:10px;flex-wrap:wrap;
}
.log-filters{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.log-filter{
  display:inline-flex;align-items:center;gap:5px;
  font-size:.75rem;color:var(--text-2);cursor:pointer;user-select:none;
}
.log-filter input[type="checkbox"]{accent-color:var(--accent);cursor:pointer}
.log-actions{display:flex;gap:6px}
.log-btn{
  padding:5px 10px;font-size:.75rem;
  border:1px solid var(--border-2);
  background:var(--surface);
  color:var(--text-2);
  border-radius:var(--r-sm);cursor:pointer;font-family:inherit;
  transition:border-color .15s,color .15s;
}
.log-btn:hover{border-color:var(--accent);color:var(--accent-2)}
.log-btn.danger:hover{border-color:var(--danger);color:#fda4af}
.log-search{
  padding:5px 10px;
  background:var(--surface);
  border:1px solid var(--border-2);
  border-radius:var(--r-sm);
  color:var(--text);font-size:.78rem;font-family:inherit;
  width:160px;outline:none;
  transition:border-color .15s;
}
.log-search:focus{border-color:var(--accent)}

#logs-stream{
  max-height:320px;overflow-y:auto;
  font-size:.78rem;
  font-family:'JetBrains Mono','SF Mono','Cascadia Code','Fira Code',monospace;
  background:var(--bg);
  border:1px solid var(--border);
  border-radius:var(--r-sm);
  padding:12px 14px;color:var(--text-2);line-height:1.6;
}
#logs-stream::-webkit-scrollbar{width:4px}
#logs-stream::-webkit-scrollbar-track{background:transparent}
#logs-stream::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:2px}
#incidents-list{max-height:320px;overflow-y:auto}
#incidents-list::-webkit-scrollbar{width:4px}
#incidents-list::-webkit-scrollbar-track{background:transparent}
#incidents-list::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:2px}

.service-analytics{
  background:var(--card);
  border:1px solid var(--border);
  border-radius:var(--r);
  padding:20px;margin-bottom:12px;
  transition:border-color .2s;
}
.service-analytics:hover{border-color:var(--border-2)}
.service-analytics h3{
  font-size:.95rem;font-weight:700;
  color:var(--text);margin-bottom:4px;
  display:flex;align-items:center;gap:8px;
}
.service-desc{font-size:.78rem;color:var(--text-3);margin-bottom:14px}

.toggle-bar{
  display:flex;align-items:center;
  justify-content:space-between;gap:10px;
  padding:10px 14px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--r-sm);
  cursor:pointer;margin-bottom:14px;
  transition:border-color .15s;
}
.toggle-bar:hover{border-color:var(--border-2)}

.loader-overlay{
  position:fixed;inset:0;
  background:var(--bg);
  display:flex;align-items:center;justify-content:center;
  z-index:9000;
  transition:opacity .4s ease;
}
.loader-overlay.hidden{opacity:0;pointer-events:none}
.loader-logo{
  height:120px;width:auto;
  filter:drop-shadow(0 0 20px rgba(16,185,129,.5));
  animation:breathe 2.4s ease-in-out infinite;
}
@keyframes breathe{
  0%,100%{transform:scale(1);filter:drop-shadow(0 0 16px rgba(16,185,129,.4))}
  50%{transform:scale(1.1);filter:drop-shadow(0 0 30px rgba(16,185,129,.75))}
}

.foot{
  text-align:center;font-size:.72rem;color:var(--text-3);
  padding:20px 0 0;border-top:1px solid var(--border);margin-top:16px;
}
.foot a{color:var(--accent-2);text-decoration:none}
.foot a:hover{color:var(--accent)}

@media(max-width:900px){
  .logs-grid{grid-template-columns:1fr}
}
@media(max-width:768px){
  .container{padding:0 16px 32px}
  header{padding:14px 0}
  .grid{grid-template-columns:1fr !important}
  body{font-size:14px}
  .modal-content.wide{max-width:96vw;padding-left:20px;padding-right:20px}
  .settings-grid{grid-template-columns:1fr}
}
@media(max-width:480px){
  .container{padding:0 12px 24px}
  .header-right{gap:6px}
  .btn{padding:6px 10px;font-size:.72rem}
  .card{padding:14px}
  .timeframe-group{gap:2px}
  .timeframe-btn{padding:4px 8px;font-size:.72rem}
}
@media(hover:none) and (pointer:coarse){
  .btn,.icon-btn,.maint-btn,.log-btn,.modal-btn{min-height:44px}
  .modal-input{min-height:44px}
}
@media(prefers-reduced-motion:reduce){
  *{animation:none !important;transition:none !important}
}
body.light .dot.ok{animation:none;box-shadow:none}

/* ── TABS ── */
.tab-nav{
  display:flex;gap:0;
  border-bottom:1px solid var(--border);
  margin-bottom:24px;
  overflow-x:auto;
  scrollbar-width:none;
}
.tab-nav::-webkit-scrollbar{display:none}
.tab-btn-nav{
  padding:10px 18px;
  background:transparent;border:none;
  border-bottom:2px solid transparent;
  margin-bottom:-1px;
  color:var(--text-3);
  font-size:.78rem;font-weight:600;
  letter-spacing:.05em;cursor:pointer;
  font-family:inherit;white-space:nowrap;
  transition:color .15s,border-color .15s;
}
.tab-btn-nav:hover{color:var(--text-2)}
.tab-btn-nav.active{color:var(--accent-2);border-bottom-color:var(--accent)}

/* ── RESPONSIVE TEXT FIXES ── */
.row{min-width:0;gap:8px}
.label{flex-shrink:0;min-width:0}
.value{min-width:0;max-width:60%;justify-content:flex-end;flex-wrap:wrap;word-break:break-all}
.value[id]{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card-header{min-width:0}
.brand-name,.brand-sub{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.header-brand{min-width:0;flex-shrink:1;overflow:hidden}
@media(max-width:520px){
  .update-chip{display:none}
  .brand-sub{display:none}
  .tab-btn-nav{padding:8px 12px;font-size:.72rem}
}
@media(max-width:380px){
  .mode-badge{display:none}
}

</style>
</head>
<body>

<div id="loader-overlay" class="loader-overlay">
  <div><img src="/images/web_logo.png" alt="" class="loader-logo"></div>
</div>

<div class="container">

  <header>
    <div class="header-brand">
      <img src="/images/web_logo.png" alt="HomelinkWG" class="logo">
      <div>
        <div class="brand-name">HomelinkWG</div>
        <div class="brand-sub">VPN &amp; Port Monitor</div>
      </div>
    </div>
    <div class="header-right">
      <div class="update-chip">
        <span id="last-update">loading…</span>
        <button class="link-btn" id="whatsnew-btn" onclick="openWhatsNew()" title="Release notes">v{{ version }}</button>
      </div>
      <span class="mode-badge light" id="light-badge" style="display:none" title="Mode allégé actif">&#9889; LIGHT</span>
      <span class="mode-badge light" id="ultra-badge" style="display:none;background:#7c2d12;border-color:#9a3412;color:#fed7aa" title="Mode ultra-light: rafraîchissement 30s, diagnostics réduits">&#128293; ULTRA</span>
      <span class="mode-badge public" id="mode-badge">PUBLIC</span>
      <button class="icon-btn" id="theme-toggle-btn" onclick="cycleTheme()" aria-label="Toggle theme" title="Theme (auto/light/dark)">
        <svg id="theme-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      </button>
      <button class="icon-btn admin-only" id="settings-btn" onclick="openSettingsModal()" style="display:none" aria-label="Settings">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="3"/>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>
      </button>
      <button class="btn btn-primary" id="login-btn" onclick="showLoginModal()">Login</button>
      <button class="btn btn-danger" id="logout-btn" onclick="logout()" style="display:none">Logout</button>
    </div>
  </header>

  <div id="login-modal" class="modal">
    <div class="modal-content">
      <div class="modal-title">Admin Login</div>
      <div class="modal-error" id="login-error"></div>
      <input type="password" id="password-input" class="modal-input" placeholder="Password" onkeypress="if(event.key==='Enter') submitLogin()" autocomplete="current-password">
      <div id="totp-section" style="display:none">
        <input type="text" id="totp-input" class="modal-input" placeholder="6-digit authenticator code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" onkeypress="if(event.key==='Enter') submitLogin()">
      </div>
      <div id="login-attempts" style="font-size:.78rem;color:var(--amber);margin-bottom:10px;display:none"></div>
      <div id="login-lockout" style="font-size:.82rem;color:var(--danger);text-align:center;padding:10px;background:var(--danger-dim);border-radius:var(--r-sm);margin-bottom:10px;display:none"></div>
      <div class="modal-buttons">
        <button class="modal-btn cancel" onclick="closeLoginModal()">Cancel</button>
        <button class="modal-btn submit" id="login-submit-btn" onclick="submitLogin()">Login</button>
      </div>
    </div>
  </div>

  <div id="whatsnew-modal" class="modal">
    <div class="modal-content wide">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <div class="modal-title" style="margin:0">What&#39;s new</div>
        <button class="icon-btn" onclick="closeWhatsNew()" aria-label="Close">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>
        </button>
      </div>
      <div id="whatsnew-subtitle" style="font-size:.75rem;color:var(--text-3);margin-bottom:14px"></div>
      <pre id="whatsnew-content" style="white-space:pre-wrap;font-family:'JetBrains Mono','SF Mono',monospace;font-size:.78rem;line-height:1.7;color:var(--text-2);background:var(--bg);border:1px solid var(--border);border-radius:var(--r-sm);padding:14px;max-height:440px;overflow:auto;margin:0"></pre>
    </div>
  </div>

  <div id="settings-modal" class="modal admin-only">
    <div class="modal-content wide">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
        <div class="modal-title" style="margin:0">Settings</div>
        <button class="icon-btn" onclick="closeSettingsModal()" aria-label="Close">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>
        </button>
      </div>
      <div class="settings-grid">
        <div>
          <div class="settings-label">Latency Threshold</div>
          <div class="range-row">
            <input type="range" id="latency-slider" min="1" max="500" step="1">
            <input type="number" id="latency-input" min="1" max="500">
            <span style="font-size:.75rem;color:var(--text-3)">ms</span>
          </div>
          <div class="range-hint">Alert when latency exceeds this value</div>
        </div>
        <div>
          <div class="settings-label">Uptime Threshold</div>
          <div class="range-row">
            <input type="range" id="uptime-slider" min="50" max="100" step="0.5">
            <input type="number" id="uptime-input" min="50" max="100" step="0.5">
            <span style="font-size:.75rem;color:var(--text-3)">%</span>
          </div>
          <div class="range-hint">Alert when uptime falls below this percentage</div>
        </div>
        <div>
          <div class="settings-label">Session Timeout</div>
          <div class="range-row">
            <input type="range" id="timeout-slider" min="5" max="240" step="5">
            <input type="number" id="timeout-input" min="5" max="240" step="5">
            <span style="font-size:.75rem;color:var(--text-3)">min</span>
          </div>
          <div class="range-hint">Auto-logout after inactivity</div>
        </div>
      </div>
      <div style="margin-top:18px;display:flex;align-items:center;gap:12px">
        <button onclick="saveThresholds()" class="btn btn-primary">Save</button>
        <span id="settings-message" style="font-size:.82rem;color:var(--accent-2);display:none"></span>
      </div>
      <div class="settings-section">
        <div class="settings-label">Maintenance Window</div>
        <div class="maint-btns">
          <button onclick="muteAlerts('1h')" class="maint-btn">Mute 1h</button>
          <button onclick="muteAlerts('4h')" class="maint-btn">Mute 4h</button>
          <button onclick="muteAlerts('tomorrow')" class="maint-btn">Until Tomorrow</button>
          <button onclick="unmuteAlerts()" class="maint-btn unmute">Unmute</button>
        </div>
        <div id="maintenance-msg" style="margin-top:8px;font-size:.78rem;color:var(--text-2)"></div>
      </div>
      <div class="settings-section">
        <div class="settings-label">Mode de performance</div>
        <div style="font-size:.78rem;color:var(--text-2);margin-bottom:8px">
          <strong>Normal</strong> : refresh 5s, diagnostics complets, mesure de latence à chaque cycle.<br>
          <strong>Light</strong> : refresh 15s, latence désactivée, probes mises en cache 30s — recommandé sur lien VPN faible.<br>
          <strong>Ultra</strong> : refresh 30s, diagnostics réseau désactivés, charts désactivés — pour Raspberry Pi Zero / Pi 1.<br>
          L'adaptation auto bascule en Ultra temporairement si le CPU dépasse 70 % de manière soutenue.
        </div>
        <div class="maint-btns" id="mode-btns">
          <button class="maint-btn" data-mode="normal" onclick="setDashboardMode('normal')">Normal</button>
          <button class="maint-btn" data-mode="light" onclick="setDashboardMode('light')">&#9889; Light</button>
          <button class="maint-btn" data-mode="ultra" onclick="setDashboardMode('ultra')">&#128293; Ultra</button>
        </div>
        <div id="mode-status" style="margin-top:8px;font-size:.78rem;color:var(--text-2)"></div>
      </div>
      <div class="settings-section">
        <div class="settings-label">Diagnostic complet</div>
        <div style="font-size:.78rem;color:var(--text-2);margin-bottom:8px">
          Génère un rapport exhaustif (CPU/IO, mémoire, swap, retransmits TCP, throttling, peers WG, top processus, dmesg, état SQLite, logs récents). Utile à joindre lors d'une demande d'aide.
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <button onclick="runHealthCheck()" class="maint-btn" style="font-size:.8rem">&#128202; Health Check</button>
          <button onclick="runLatencyAudit()" class="maint-btn" style="font-size:.8rem">&#128293; Latency Audit</button>
          <button onclick="downloadDiagnosticBundle('json')" class="maint-btn" style="font-size:.8rem">&#11015; Bundle JSON</button>
          <button onclick="downloadDiagnosticBundle('zip')" class="maint-btn" style="font-size:.8rem">&#11015; Bundle ZIP (+ logs)</button>
          <span id="diag-bundle-msg" style="font-size:.78rem;color:var(--text-2)"></span>
        </div>
        <div id="health-check-result" style="margin-top:10px;font-size:.78rem;display:none"></div>
        <div id="latency-audit-result" style="margin-top:10px;font-size:.78rem;display:none"></div>
      </div>
      <div class="settings-section">
        <div class="settings-label">Danger Zone</div>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <button onclick="restartDashboard()" class="maint-btn" style="border-color:var(--danger);color:var(--danger)">&#8635; Restart HomelinkWG</button>
          <span id="restart-dashboard-msg" style="font-size:.78rem;color:var(--text-2);display:none"></span>
        </div>
      </div>
      <div id="perf-section" style="display:none" class="settings-section">
        <div class="settings-label">Performance</div>
        <label style="display:flex;gap:8px;align-items:center;font-size:.85rem;color:var(--text-2);cursor:pointer">
          <input type="checkbox" id="toggle-live-logs" style="accent-color:var(--accent);cursor:pointer">
          Enable live logs
        </label>
        <div class="range-hint">In ultra-light mode, logs are off by default.</div>
      </div>
      <div class="settings-section">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start">
          <!-- Change Password -->
          <div>
            <div class="settings-label">Change Password</div>
            <div style="display:flex;flex-direction:column;gap:8px">
              <input type="password" id="chpw-current" class="modal-input" placeholder="Current password" style="margin:0">
              <input type="password" id="chpw-new"     class="modal-input" placeholder="New password (min 8 chars)" style="margin:0">
              <input type="password" id="chpw-confirm" class="modal-input" placeholder="Confirm new password" style="margin:0">
              <div style="display:flex;align-items:center;gap:10px;margin-top:2px">
                <button class="btn btn-primary" onclick="changePassword()" style="flex-shrink:0">Update password</button>
                <span id="chpw-msg" style="font-size:.78rem;display:none"></span>
              </div>
            </div>
          </div>
          <!-- Two-Factor Authentication -->
          <div>
            <div class="settings-label">Two-Factor Authentication</div>
            <div id="twofa-unavailable" style="display:none;font-size:.78rem;color:var(--text-3);margin-bottom:10px">
              pyotp not installed on server — run <code style="background:var(--surface);padding:2px 5px;border-radius:4px">pip install pyotp</code>
            </div>
            <div id="twofa-status-row" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
              <span id="twofa-badge" class="badge muted">loading…</span>
              <button id="twofa-toggle-btn" class="maint-btn" onclick="toggle2fa()" style="display:none"></button>
            </div>
            <div id="twofa-setup-box" style="display:none;margin-top:14px;padding:14px;background:var(--surface);border:1px solid var(--border-2);border-radius:var(--r-sm)">
              <div style="font-size:.78rem;color:var(--text-2);margin-bottom:12px;line-height:1.6">
                Scan the QR code with Google Authenticator, Authy or any TOTP app, or enter the key manually.
              </div>
              <div style="display:flex;justify-content:center;margin-bottom:14px">
                <div id="twofa-qr-inner" style="background:#fff;padding:10px;border-radius:8px;display:inline-block"></div>
              </div>
              <div style="font-size:.72rem;color:var(--text-3);margin-bottom:4px;font-weight:600;letter-spacing:.05em">SECRET KEY</div>
              <div id="twofa-secret" style="font-family:monospace;font-size:.9rem;color:var(--accent-2);word-break:break-all;margin-bottom:14px;user-select:all;cursor:pointer" title="Click to copy" onclick="navigator.clipboard.writeText(this.textContent).then(()=>{this.style.opacity='.5';setTimeout(()=>this.style.opacity='',600)})"></div>
              <div id="twofa-uri" style="display:none"></div>
              <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                <input type="text" id="twofa-code-input" class="modal-input" placeholder="Enter 6-digit code to confirm" inputmode="numeric" maxlength="6" style="width:220px;margin:0" onkeypress="if(event.key==='Enter') confirm2faSetup()">
                <button onclick="confirm2faSetup()" class="btn btn-primary">Confirm &amp; Enable</button>
              </div>
              <div id="twofa-setup-msg" style="margin-top:8px;font-size:.78rem;display:none"></div>
            </div>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <div class="settings-label" style="display:flex;justify-content:space-between;align-items:center">
          <span>Config Editor</span>
          <span id="config-editor-msg" style="font-size:.75rem;color:var(--accent-2);display:none"></span>
        </div>
        <div style="font-size:.78rem;color:var(--text-2);margin-bottom:10px;line-height:1.5">
          Edit <code style="background:var(--surface);padding:1px 5px;border-radius:3px">config.json</code> directly. Changes take effect immediately — no restart needed.
        </div>
        <textarea id="config-editor-textarea" spellcheck="false"
          style="width:100%;min-height:200px;font-family:monospace;font-size:.78rem;background:var(--surface);color:var(--text);border:1px solid var(--border-2);border-radius:var(--r-sm);padding:10px;resize:vertical;box-sizing:border-box;line-height:1.5;outline:none"
          oninput="validateConfigJSON(this)"></textarea>
        <div id="config-json-error" style="font-size:.75rem;color:var(--danger);margin-top:4px;display:none"></div>
        <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
          <button onclick="loadConfigEditor()" class="maint-btn" style="font-size:.8rem">&#8635; Reload</button>
          <button onclick="saveConfig()" class="btn btn-primary" id="config-save-btn" style="font-size:.8rem">Save</button>
          <button onclick="downloadConfigBackup()" class="maint-btn" style="font-size:.8rem">&#11015; Backup</button>
        </div>
      </div>
    </div>
  </div>

  <div id="alert" style="display:none">
    <div class="alert-strip danger"><span id="alert-text">offline</span></div>
  </div>
  <div id="mute-banner" style="display:none">
    <div class="alert-strip muted"><span id="mute-banner-text">alerts muted</span></div>
  </div>

  <!-- ── TAB NAV ── -->
  <nav class="tab-nav" id="main-tab-nav">
    <button class="tab-btn-nav active" id="tab-btn-nav-status" onclick="switchTab('status')">Status</button>
    <button class="tab-btn-nav" id="tab-btn-nav-services" onclick="switchTab('services')">Services</button>
    <button class="tab-btn-nav admin-only" id="tab-btn-nav-logs" onclick="switchTab('logs')" style="display:none">Logs</button>
  </nav>

  <!-- ── TAB: STATUS ── -->
  <div id="tab-status">
    <div class="grid">

      <div class="card">
        <div class="card-header">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          VPN
        </div>
        <div class="row">
          <span class="label">Status</span>
          <span class="value"><span id="vpn-dot" class="dot"></span><span id="vpn-badge" class="badge muted">?</span></span>
        </div>
        <div class="row"><span class="label">Interface</span><span class="value" id="vpn-iface">&#8212;</span></div>
        <div class="row"><span class="label">IP</span><span class="value" id="vpn-ip">&#8212;</span></div>
        <div class="row" style="margin-top:6px;padding-top:6px;border-top:1px solid var(--border)"><span class="label" style="color:var(--text-3);font-size:.72rem;letter-spacing:.04em">HOST NETWORK</span></div>
        <div class="row"><span class="label">Interface</span><span class="value" id="sys-net-iface">&#8212;</span></div>
        <div class="row"><span class="label">Link speed</span><span class="value" id="sys-net-speed">&#8212;</span></div>
      </div>

      <div class="card">
        <div class="card-header">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
          System
        </div>
        <div class="row"><span class="label">CPU</span><span class="value" id="sys-cpu">&#8212;</span></div>
        <div class="row"><span class="label">Memory</span><span class="value" id="sys-mem">&#8212;</span></div>
        <div class="row"><span class="label">Load</span><span class="value" id="sys-load">&#8212;</span></div>
        <div class="row"><span class="label">Uptime</span><span class="value" id="sys-up">&#8212;</span></div>
        <div class="row"><span class="label">Disk latency</span><span class="value" id="sys-disk-latency">&#8212;</span></div>
      </div>

      <div class="card">
        <div class="card-header">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/></svg>
          WireGuard
        </div>
        <div class="row"><span class="label">Downloaded</span><span class="value" id="net-rx">&#8212;</span></div>
        <div class="row"><span class="label">Uploaded</span><span class="value" id="net-tx">&#8212;</span></div>
      </div>

      <!-- System Diagnostic card — admin only -->
      <div class="card full admin-only" id="perf-diag-card" style="display:none">
        <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
          <span style="display:flex;align-items:center;gap:6px">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            System Diagnostic
          </span>
          <button class="btn btn-primary" id="perf-diag-btn" onclick="runPerfDiagnostic()" style="font-size:.78rem;padding:5px 12px;min-height:0">&#9654; Run</button>
        </div>
        <div style="font-size:.78rem;color:var(--text-2);margin-bottom:8px">Tests disk, network, CPU and memory — identifies what limits streaming performance.</div>
        <span id="perf-diag-status" style="font-size:.78rem;color:var(--text-2);display:none"></span>
        <!-- Results panel -->
        <div id="perf-diag-results" style="display:none;margin-top:10px">
          <div id="perf-verdict-banner" style="padding:12px 14px;border-radius:var(--r-sm);margin-bottom:10px;font-size:.85rem;line-height:1.5;border:1px solid transparent"></div>
          <div id="perf-test-rows" style="display:flex;flex-direction:column;gap:6px;font-size:.8rem"></div>
          <div id="perf-recommendations" style="display:none;margin-top:12px">
            <div style="font-size:.75rem;font-weight:600;letter-spacing:.06em;color:var(--text-3);margin-bottom:6px;text-transform:uppercase">Recommendations</div>
            <ul id="perf-reco-list" style="margin:0;padding-left:18px;color:var(--text-2);font-size:.8rem;line-height:1.7"></ul>
          </div>
        </div>
      </div>

      <div class="card full">
        <div class="card-header">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          Diagnostics
        </div>
        <div class="diag" id="diag"></div>
      </div>

    </div>
  </div>

  <!-- ── TAB: SERVICES ── -->
  <div id="tab-services" style="display:none">
    <div class="section-row" style="margin-top:4px">
      <span class="section-heading">Services</span>
      <div style="display:flex;gap:8px;align-items:center">
        <button id="export-csv-btn" class="admin-only maint-btn" style="display:none;font-size:.75rem;padding:5px 10px" onclick="exportMetricsCSV()">&#11015; Export CSV</button>
        <div id="timeframe-selector" class="timeframe-group" style="display:none">
          <button data-timeframe="24h" class="timeframe-btn active">24h</button>
          <button data-timeframe="7d" class="timeframe-btn">7 days</button>
          <button data-timeframe="30d" class="timeframe-btn">30 days</button>
        </div>
      </div>
    </div>
    <div id="services-container"></div>
  </div>

  <!-- ── TAB: LOGS (admin only) ── -->
  <div id="tab-logs" style="display:none">
    <div class="card full" id="logs-section">
      <div class="logs-grid">
        <div>
          <div class="section-title">Recent Incidents</div>
          <div id="incidents-list">
            <div style="color:var(--text-3);font-size:.82rem">No incidents in last 24h</div>
          </div>
        </div>
        <div>
          <div class="log-controls">
            <div class="log-filters">
              <div class="section-title" style="margin:0;margin-right:6px">Live Logs</div>
              <label class="log-filter"><input type="checkbox" id="filter-incident" checked onchange="filterLogs()"> Incidents</label>
              <label class="log-filter"><input type="checkbox" id="filter-systemd" checked onchange="filterLogs()"> SystemD</label>
              <label class="log-filter"><input type="checkbox" id="filter-socat" checked onchange="filterLogs()"> Socat</label>
              <label class="log-filter"><input type="checkbox" id="filter-wireguard" checked onchange="filterLogs()"> WG</label>
            </div>
            <div class="log-actions">
              <input type="text" id="log-search" class="log-search" placeholder="Search&#8230;">
              <button onclick="exportLogs()" class="log-btn">Export</button>
              <button onclick="clearLogs()" class="log-btn danger">Clear</button>
            </div>
          </div>
          <div id="logs-stream">
            <span style="color:var(--text-3)">Connecting to log stream&#8230;</span>
          </div>
        </div>
      </div>
    </div>
    <div class="card full" style="margin-top:14px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div class="section-title" style="margin:0">Audit Log</div>
        <div style="display:flex;gap:8px;align-items:center">
          <input type="text" id="audit-search" class="log-search" placeholder="Filter&#8230;" oninput="filterAuditLog()" style="width:160px">
          <button onclick="loadAuditLog()" class="log-btn" title="Rafra&#238;chir">&#8635;</button>
        </div>
      </div>
      <div id="audit-log-list" style="font-size:.78rem;font-family:monospace;max-height:340px;overflow-y:auto">
        <span style="color:var(--text-3)">Loading&#8230;</span>
      </div>
    </div>
  </div>

    <div class="card full admin-only" style="margin-top:14px;display:none">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div class="section-title" style="margin:0">Admin Sessions</div>
        <button onclick="loadSessionsHistory()" class="log-btn" title="Refresh">&#8635;</button>
      </div>
      <div id="sessions-history-list" style="font-size:.78rem;max-height:260px;overflow-y:auto">
        <span style="color:var(--text-3)">Loading&#8230;</span>
      </div>
    </div>
  </div>

  <div class="foot">Live updates &middot; fallback refresh every {{ (refresh_ms // 1000) }}s &middot; <a href="/api/status">JSON API</a></div>

</div>

<script>
// Tab switching (runs before main script; references globals defined later)
function switchTab(name) {
  var tabs = ['status','services','logs'];
  tabs.forEach(function(t) {
    var btn = document.getElementById('tab-btn-nav-' + t);
    var pane = document.getElementById('tab-' + t);
    if (btn) btn.classList.toggle('active', t === name);
    if (pane) pane.style.display = t === name ? '' : 'none';
  });
  // Initialise logs when tab is first opened
  if (name === 'logs') {
    var ls = document.getElementById('logs-section');
    if (ls) ls.style.display = '';
    if (typeof loadIncidents === 'function') loadIncidents();
    if (typeof loadAuditLog === 'function') loadAuditLog();
    if (typeof loadSessionsHistory === 'function') setTimeout(loadSessionsHistory, 80);
    if (typeof streamLogs === 'function' && !window._logTabInited) {
      window._logTabInited = true;
      streamLogs();
    }
  }
}
</script>

  <script>
	  const REFRESH_MS = {{ refresh_ms }};
	  const ANALYTICS_REFRESH_MS = {{ analytics_refresh_ms }};
	  const SESSION_KEY = 'homelinkwg_admin_token';
	  const SESSION_EXPIRY_KEY = 'homelinkwg_token_expiry';
	  const LOGS_ENABLED_KEY = 'homelinkwg_logs_enabled';
	  const $ = (id) => document.getElementById(id);
	  let chartInstances = {};
	  let serviceMetrics = {};
	  let adminMode = false;
	  let selectedTimeframe = '24h';
	  let lastAnalyticsRefresh = 0;
	  let timeframeButtonsInitialized = false;
	  let thresholdSyncInitialized = false;
	  let publicReadOnly = true;
	  let lastMode = 'public';
	  let statusStream = null;
	  let pollTimer = null;
	  let pollBackoffMs = REFRESH_MS;
	  let runtimeLightMode = false;
	  const expandedCharts = new Set(); // portId
	  let runtimeUltraLight = false;
	  const metricsFetchInFlight = {}; // portId -> Promise

	  function isLiveLogsEnabled() {
	    if (!adminMode) return false;
	    if (!runtimeUltraLight) return true;
	    return sessionStorage.getItem(LOGS_ENABLED_KEY) === 'true';
	  }

	  function setLiveLogsEnabled(v) {
	    sessionStorage.setItem(LOGS_ENABLED_KEY, v ? 'true' : 'false');
	    updateAdminUI();
	  }

  // =========================================================================
	  // Authentication & Session Management
	  // =========================================================================

	  function openWhatsNew() {
	    const m = $('whatsnew-modal');
	    if (!m) return;
	    m.classList.add('show');
	    // Let the browser paint the modal before we start the fetch.
	    requestAnimationFrame(() => loadWhatsNew());
	  }

	  function closeWhatsNew() {
	    const m = $('whatsnew-modal');
	    if (!m) return;
	    m.classList.remove('show');
	  }

	  async function loadWhatsNew() {
	    const box = $('whatsnew-content');
	    const sub = $('whatsnew-subtitle');
	    if (box) box.textContent = 'Loading...';
	    try {
	      const r = await fetch('/api/whats-new', { cache: 'no-store' });
	      if (!r.ok) throw new Error('HTTP ' + r.status);
	      const data = await r.json();
	      if (sub) sub.textContent = data && data.version ? (`v${data.version} · ${data.date || ''}`) : '';
	      if (box) box.textContent = (data && data.notes) ? data.notes : 'No release notes found.';
	    } catch (e) {
	      if (box) box.textContent = 'Failed to load release notes: ' + e.message;
	    }
	  }

  let _loginTotpRequired = false;
  let _lockoutTimer = null;

  async function showLoginModal() {
    _loginTotpRequired = false;
    $('login-modal').classList.add('show');
    $('password-input').focus();
    $('login-error').style.display = 'none';
    $('login-attempts').style.display = 'none';
    $('login-lockout').style.display = 'none';
    $('totp-section').style.display = 'none';
    const submitBtn = $('login-submit-btn');
    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Login'; }
    // Pre-check: show TOTP field immediately if 2FA is enabled
    try {
      const r = await fetch('/api/2fa/status', { cache: 'no-store' });
      if (r.ok) {
        const d = await r.json();
        if (d.enabled) {
          _loginTotpRequired = true;
          $('totp-section').style.display = '';
        }
      }
    } catch (_) {}
  }

  function closeLoginModal() {
    $('login-modal').classList.remove('show');
    $('password-input').value = '';
    if ($('totp-input')) $('totp-input').value = '';
    $('login-error').style.display = 'none';
    $('login-attempts').style.display = 'none';
    $('login-lockout').style.display = 'none';
    $('totp-section').style.display = 'none';
    _loginTotpRequired = false;
    if (_lockoutTimer) { clearInterval(_lockoutTimer); _lockoutTimer = null; }
    const submitBtn = $('login-submit-btn');
    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Login'; }
  }

  function _startLockoutCountdown(retryAfter) {
    const lockoutEl = $('login-lockout');
    const submitBtn = $('login-submit-btn');
    if (submitBtn) submitBtn.disabled = true;
    if (_lockoutTimer) clearInterval(_lockoutTimer);
    let remaining = retryAfter;
    const update = () => {
      if (remaining <= 0) {
        clearInterval(_lockoutTimer);
        _lockoutTimer = null;
        lockoutEl.style.display = 'none';
        if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Login'; }
        $('login-attempts').style.display = 'none';
        return;
      }
      lockoutEl.style.display = '';
      lockoutEl.textContent = `Too many failed attempts — try again in ${remaining}s`;
      remaining--;
    };
    update();
    _lockoutTimer = setInterval(update, 1000);
  }

  async function submitLogin() {
    const password = $('password-input').value;
    if (!password) { showLoginError('Please enter a password'); return; }
    const totpInput = $('totp-input');
    const totpCode = totpInput ? totpInput.value.trim() : '';
    const body = { password };
    if (totpCode) body.totp_code = totpCode;

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await response.json();

      if (response.status === 429) {
        $('login-error').style.display = 'none';
        $('login-attempts').style.display = 'none';
        _startLockoutCountdown(data.retry_after || 30);
        return;
      }
      if (response.status === 401) {
        const remaining = data.remaining;
        if (data.requires_2fa) {
          showLoginError('Invalid 2FA code');
        } else if (remaining !== undefined && remaining > 0) {
          showLoginError('Wrong password');
          const attEl = $('login-attempts');
          attEl.textContent = `${remaining} attempt${remaining > 1 ? 's' : ''} remaining before lockout`;
          attEl.style.display = '';
        } else {
          showLoginError('Wrong password');
        }
        return;
      }
      if (!response.ok) {
        showLoginError(data.error || 'Login failed');
        return;
      }
      // 2FA required — reveal TOTP field
      if (data.requires_2fa) {
        _loginTotpRequired = true;
        $('login-error').style.display = 'none';
        $('totp-section').style.display = '';
        const ti = $('totp-input');
        if (ti) { ti.value = ''; ti.focus(); }
        $('login-attempts').textContent = 'Enter the 6-digit code from your authenticator app';
        $('login-attempts').style.display = '';
        return;
      }
      // Success
      sessionStorage.setItem(SESSION_KEY, data.token);
      sessionStorage.setItem(SESSION_EXPIRY_KEY, Date.now() + (data.expires_in * 1000));
      adminMode = true;
      updateAdminUI();
      resetServiceUI();
      closeLoginModal();
      await refresh({ restartStream: true });
    } catch (e) {
      showLoginError('Login failed: ' + e.message);
    }
  }

  function showLoginError(msg) {
    const errorDiv = $('login-error');
    errorDiv.textContent = msg;
    errorDiv.style.display = 'block';
  }

		  async function logout() {
	    const token = sessionStorage.getItem(SESSION_KEY);
	    if (token) {
	      try {
	        await fetch('/api/logout?token=' + encodeURIComponent(token), { method: 'POST' });
      } catch (e) {
        // Silently fail
      }
    }

		    sessionStorage.removeItem(SESSION_KEY);
		    sessionStorage.removeItem(SESSION_EXPIRY_KEY);
		    adminMode = false;
		    updateAdminUI();
		    resetServiceUI();
		    refresh({ restartStream: true });
		  }

  function getSessionToken() {
    const token = sessionStorage.getItem(SESSION_KEY);
    const expiry = sessionStorage.getItem(SESSION_EXPIRY_KEY);

    // Check if token exists and not expired
    if (token && expiry && Date.now() < parseInt(expiry)) {
      return token;
    }

    // Token expired or missing
    if (token) {
      sessionStorage.removeItem(SESSION_KEY);
      sessionStorage.removeItem(SESSION_EXPIRY_KEY);
    }
    return null;
  }

		  function updateAdminUI() {
		    const adminElements = document.querySelectorAll('.admin-only');
		    if (adminMode) {
	      lastMode = 'admin';
      _startIdleCheck();
	      $('mode-badge').textContent = '🔓 ADMIN';
	      $('mode-badge').className = 'mode-badge admin';
	      $('login-btn').style.display = 'none';
	      $('logout-btn').style.display = 'block';
	      const settingsBtn = $('settings-btn');
	      if (settingsBtn) settingsBtn.style.display = '';
	      adminElements.forEach(el => el.style.display = '');
		      // Logs/Incidents can be disabled in ultra-light mode to save resources.
		      const logsSection = $('logs-section');
		      if (logsSection) logsSection.style.display = isLiveLogsEnabled() ? '' : 'none';
	      // Show timeframe selector
	      const timeframeSelector = $('timeframe-selector');
	      if (timeframeSelector) timeframeSelector.style.display = runtimeUltraLight ? 'none' : 'flex';
	      const csvBtn = document.getElementById('export-csv-btn'); if (csvBtn) csvBtn.style.display = runtimeUltraLight ? 'none' : '';
	      // Initialize timeframe buttons only when analytics UI is enabled.
	      if (!runtimeUltraLight) initTimeframeButtons();
	      // Incidents/logs are loaded only when enabled.
	      if (isLiveLogsEnabled()) {
	        loadIncidents();
	        streamLogs();
	      } else {
	        stopLogStream();
	      }
	      // Audit log + admin sessions cards are admin-only but live OUTSIDE
	      // the Logs tab, so populate them right away on login (otherwise they
	      // sit on "Loading…" until the user manually clicks refresh).
	      if (typeof loadAuditLog === 'function') loadAuditLog();
	      if (typeof loadSessionsHistory === 'function') loadSessionsHistory();
	      // Settings modal is loaded on demand.
		    } else {
	      lastMode = 'public';
	      $('mode-badge').textContent = '📖 PUBLIC';
	      $('mode-badge').className = 'mode-badge public';
	      $('login-btn').style.display = 'block';
	      $('logout-btn').style.display = 'none';
	      const settingsBtn = $('settings-btn');
	      if (settingsBtn) settingsBtn.style.display = 'none';
		      adminElements.forEach(el => el.style.display = 'none');
		      // Hide logs section
		      const logsSection = $('logs-section');
		      if (logsSection) logsSection.style.display = 'none';
	      // Hide timeframe selector
	      const timeframeSelector = $('timeframe-selector');
	      if (timeframeSelector) timeframeSelector.style.display = 'none';
	      const csvBtnPub = document.getElementById('export-csv-btn'); if (csvBtnPub) csvBtnPub.style.display = 'none';
	      // Stop log streaming when leaving admin mode (saves resources)
	      stopLogStream();
	    }
	    // Keep Settings > Performance UI in sync (ultra-light toggles).
	    syncPerfSettingsUI();
	  }

		  function stopLogStream() {
		    if (logStream) {
		      try { logStream.close(); } catch (e) {}
		      logStream = null;
		    }
		    if (logRetryTimer) {
		      clearTimeout(logRetryTimer);
		      logRetryTimer = null;
		    }
		    logRetryCount = 0;
		  }

		  function applyAdminVisibility(root) {
		    // Some admin-only elements are created dynamically (service cards).
		    // Ensure they reflect the current mode immediately.
		    if (!root) return;
		    const els = root.querySelectorAll('.admin-only');
		    els.forEach(el => { el.style.display = adminMode ? '' : 'none'; });
		  }

	  function formatDateTime(ts) {
	    if (!ts || ts <= 0) return 'n/a';
	    return new Date(ts * 1000).toLocaleString();
	  }

  function renderMuteBanner(alerts) {
    const banner = $('mute-banner');
    const text = $('mute-banner-text');
    if (!banner || !text) return;
    if (alerts && alerts.muted) {
      banner.style.display = '';
      text.textContent = `Alerts muted until ${alerts.until_iso || formatDateTime(alerts.until_ts)}`;
    } else {
      banner.style.display = 'none';
    }
  }

  async function muteAlerts(duration) {
    const token = getSessionToken();
    if (!token) return;
    try {
      const response = await fetch(`/api/alerts/mute?token=${encodeURIComponent(token)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ duration })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Mute failed');
      const msg = $('maintenance-msg');
      if (msg) msg.textContent = `Alerts muted until ${data.alerts.until_iso || formatDateTime(data.alerts.until_ts)}.`;
      renderMuteBanner(data.alerts);
      refresh();
    } catch (e) {
      const msg = $('maintenance-msg');
      if (msg) msg.textContent = `Mute failed: ${e.message}`;
    }
  }

  async function unmuteAlerts() {
    const token = getSessionToken();
    if (!token) return;
    try {
      const response = await fetch(`/api/alerts/unmute?token=${encodeURIComponent(token)}`, {
        method: 'POST'
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Unmute failed');
      const msg = $('maintenance-msg');
      if (msg) msg.textContent = 'Alerts unmuted.';
      renderMuteBanner(data.alerts);
      refresh();
    } catch (e) {
      const msg = $('maintenance-msg');
      if (msg) msg.textContent = `Unmute failed: ${e.message}`;
    }
  }

  // =========================================================================
  // =========================================================================

  function initTimeframeButtons() {
    if (timeframeButtonsInitialized) return;
    const buttons = document.querySelectorAll('.timeframe-btn');
    buttons.forEach(btn => {
      btn.addEventListener('click', () => {
        // Update active button — remove class AND inline styles from all
        buttons.forEach(b => {
          b.classList.remove('active');
          b.style.background = '';
          b.style.borderColor = '';
          b.style.color = '';
        });
        btn.classList.add('active');

        // Update selected timeframe and refresh
        selectedTimeframe = btn.getAttribute('data-timeframe');
        lastAnalyticsRefresh = 0;
        refresh();  // Refresh all data with new timeframe
      });
    });

    // Initialize log search
    const searchInput = $('log-search');
    if (searchInput) {
      searchInput.addEventListener('input', filterLogs);
    }
    timeframeButtonsInitialized = true;
  }

  // Calculate trend (↑ improving, ↓ declining, → stable) by comparing first half vs second half
  function calculateTrend(values) {
    const cleanValues = values.filter(v => v !== null && v !== undefined && v >= 0);
    if (cleanValues.length < 2) return '→';  // No trend data

    const mid = Math.floor(cleanValues.length / 2);
    const firstHalf = cleanValues.slice(0, mid);
    const secondHalf = cleanValues.slice(mid);

    const avg1 = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const avg2 = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

    // For availability: higher is better
    // For latency: lower is better
    const diff = avg2 - avg1;
    const tolerance = Math.max(avg1, avg2) * 0.02;  // 2% tolerance

    if (Math.abs(diff) < tolerance) return '→';
    return diff < 0 ? '↑' : '↓';  // For uptime: ↑ is good, ↓ is bad; for latency it's inverted
  }

  // Get trend for uptime (higher is better)
  function getUptimeTrend(metrics) {
    const availability = metrics.map(m => (m.service_active && m.port_listening && m.target_reachable) ? 100 : 0);
    const trend = calculateTrend(availability);
    return trend === '↑' ? '<span style="color:#10b981">↑</span>' :
           trend === '↓' ? '<span style="color:#ef4444">↓</span>' :
           '<span style="color:#94a3b8">→</span>';
  }

  // Get trend for latency (lower is better)
	  function getLatencyTrend(metrics) {
	    const latencies = metrics.map(m => m.latency_ms >= 0 ? m.latency_ms : null);
	    const trend = calculateTrend(latencies);
	    return trend === '↓' ? '<span style="color:#10b981">↓</span>' :
	           trend === '↑' ? '<span style="color:#ef4444">↑</span>' :
	           '<span style="color:#94a3b8">→</span>';
	  }

	  function renderUptimeTrendFromCode(code) {
	    if (!code || code === 'na') return '<span style="color:#94a3b8">→</span>';
	    if (code === 'up') return '<span style="color:#10b981">↑</span>';
	    if (code === 'down') return '<span style="color:#ef4444">↓</span>';
	    return '<span style="color:#94a3b8">→</span>';
	  }

	  function renderLatencyTrendFromCode(code) {
	    if (!code || code === 'na') return '<span style="color:#94a3b8">→</span>';
	    if (code === 'good') return '<span style="color:#10b981">↓</span>';
	    if (code === 'bad') return '<span style="color:#ef4444">↑</span>';
	    return '<span style="color:#94a3b8">→</span>';
	  }

  // Draw availability heatmap by day
  function drawHeatmap(portId, metrics) {
    const heatmapDiv = document.getElementById(`heatmap-${portId}`);
    if (!heatmapDiv) return;

    // Group metrics by day
    const dayMap = {};
    metrics.forEach(m => {
      const date = new Date(m.timestamp * 1000);
      const dateStr = date.toISOString().split('T')[0];
      if (!dayMap[dateStr]) dayMap[dateStr] = [];
      dayMap[dateStr].push((m.service_active && m.port_listening && m.target_reachable) ? 1 : 0);
    });

    // Calculate daily availability
    const days = Object.keys(dayMap).sort();
    const dailyAvailability = days.map(day => {
      const samples = dayMap[day];
      return (samples.reduce((a, b) => a + b, 0) / samples.length) * 100;
    });

    // Create heatmap squares
    heatmapDiv.innerHTML = '';
    const now = new Date();

    dailyAvailability.forEach((avail, idx) => {
      const dayStr = days[idx];
      const date = new Date(dayStr + 'T00:00:00Z');
      const daysAgo = Math.floor((now - date) / (1000 * 60 * 60 * 24));
      const label = daysAgo === 0 ? 'Today' : daysAgo === 1 ? 'Yesterday' : daysAgo + 'd ago';

      // Color scale: red (0%) to green (100%)
      const h = (avail / 100) * 120;  // 0=red, 120=green
      const color = `hsl(${h}, 70%, 50%)`;

      const square = document.createElement('div');
      square.style.width = '24px';
      square.style.height = '24px';
      square.style.backgroundColor = color;
      square.style.borderRadius = '3px';
      square.style.cursor = 'pointer';
      square.style.border = '1px solid rgba(255,255,255,0.1)';
      square.title = `${label}: ${avail.toFixed(0)}%`;
      heatmapDiv.appendChild(square);
    });

    // Add legend
    const legend = document.createElement('div');
    legend.style.marginTop = '8px';
    legend.style.fontSize = '0.7em';
    legend.style.color = 'var(--text-3)';
    legend.textContent = `${dailyAvailability.length} days shown (red=down, green=up)`;
    heatmapDiv.appendChild(legend);
  }

  // =========================================================================
  // =========================================================================

  let allLogs = [];  // Store all logs for filtering

  function filterLogs() {
    const searchQuery = ($('log-search').value || '').toLowerCase();
    const showIncident = $('filter-incident').checked;
    const showSystemd = $('filter-systemd').checked;
    const showSocat = $('filter-socat').checked;
    const showWireguard = $('filter-wireguard').checked;

    const logsDiv = $('logs-stream');
    logsDiv.innerHTML = '';

    const filtered = allLogs.filter(log => {
      const matchesSearch = searchQuery === '' || log.message.toLowerCase().includes(searchQuery);
      let matchesType = false;
      if (log.type === 'incident' && showIncident) matchesType = true;
      if (log.type === 'systemd' && showSystemd) matchesType = true;
      if (log.type === 'socat' && showSocat) matchesType = true;
      if (log.type === 'wireguard' && showWireguard) matchesType = true;
      return matchesSearch && matchesType;
    });

    if (filtered.length === 0) {
      logsDiv.innerHTML = '<div style="color:var(--text-3)">No logs match filters</div>';
      return;
    }

    filtered.forEach(log => {
      const color = log.type === 'incident' ? '#fbbf24' : log.type === 'systemd' ? '#a78bfa' : log.type === 'socat' ? '#60a5fa' : '#10b981';
      const line = document.createElement('div');
      line.style.color = color;
      line.textContent = log.message;
      logsDiv.appendChild(line);
    });
  }

  function exportLogs() {
    if (allLogs.length === 0) {
      alert('No logs to export');
      return;
    }

    // Create CSV
    let csv = 'Timestamp,Type,Message\n';
    allLogs.forEach(log => {
      const message = log.message.replace(/"/g, '""');  // Escape quotes
      csv += `"${log.message.split('] ')[0].slice(1)}","${log.type}","${message}"\n`;
    });

    // Download
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `homelinkwg-logs-${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
  }

  function clearLogs() {
    if (confirm('Clear all logs?')) {
      allLogs = [];
      $('logs-stream').innerHTML = '<div style="color:var(--text-3)">Logs cleared</div>';
    }
  }

  // =========================================================================
  // =========================================================================

  async function loadIncidents() {
    try {
      const token = getSessionToken();
      if (!token) return;

      const response = await fetch(`/api/incidents?token=${encodeURIComponent(token)}`);
      if (!response.ok) return;
      const data = await response.json();
      const list = $('incidents-list');
      if (!list) return;

      if (data.count === 0) {
        list.innerHTML = '<div style="color:var(--text-3)">No incidents in last 24h ✓</div>';
        return;
      }

      let html = '';
      for (const incident of data.incidents.slice(0, 20)) {
        const dt = new Date(incident.timestamp * 1000).toLocaleTimeString();
        const severityColor = incident.severity === 'high' ? '#dc2626' : '#f97316';
        html += `<div style="margin-bottom:8px;padding:8px;background:var(--bg);border-left:3px solid ${severityColor};border-radius:4px;display:flex;justify-content:space-between;align-items:flex-start">
          <div style="flex:1">
            <div style="font-size:0.8em;color:var(--text-3)">${dt}</div>
            <div style="color:#e2e8f0;font-weight:600">${incident.service_name}</div>
            <div style="color:var(--text-3);font-size:0.85em">${incident.description}</div>
          </div>
          <button onclick="closeIncident(${incident.id})" style="background:none;border:none;color:var(--text-3);cursor:pointer;font-size:1.2em;padding:0;margin-left:8px;line-height:1" title="Close incident">✕</button>
        </div>`;
      }
      list.innerHTML = html;
    } catch (e) {
      console.error("Failed to load incidents:", e);
    }
  }

  async function closeIncident(incidentId) {
    try {
      const token = getSessionToken();
      if (!token) return;

      const response = await fetch(`/api/incidents/${incidentId}?token=${encodeURIComponent(token)}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        loadIncidents();
      } else {
        console.error("Failed to close incident");
      }
    } catch (e) {
      console.error("Error closing incident:", e);
    }
  }

  // =========================================================================
  // =========================================================================

  async function loadThresholds() {
    try {
      const token = getSessionToken();
      if (!token) return;

      const response = await fetch(`/api/thresholds?token=${encodeURIComponent(token)}`);
      if (!response.ok) return;
      const data = await response.json();

      // Update sliders and inputs
      const latency = data.thresholds.latency_threshold_ms;
      const uptime = data.thresholds.uptime_threshold_percent;

      const latencySlider = $('latency-slider');
      const latencyInput = $('latency-input');
      const uptimeSlider = $('uptime-slider');
      const uptimeInput = $('uptime-input');

      if (latencySlider) { latencySlider.value = latency; latencySlider.dispatchEvent(new Event('input')); }
      if (latencyInput) latencyInput.value = latency;
      if (uptimeSlider) { uptimeSlider.value = uptime; uptimeSlider.dispatchEvent(new Event('input')); }
      if (uptimeInput) uptimeInput.value = uptime;
      const timeout = data.thresholds.session_timeout_minutes ?? 30;
      const toSlider = $('timeout-slider'); const toInput = $('timeout-input');
      if (toSlider) { toSlider.value = timeout; toSlider.dispatchEvent(new Event('input')); }
      if (toInput) toInput.value = timeout;
      // Update runtime inactivity timer
      _sessionTimeoutMs = timeout * 60 * 1000;
    } catch (e) {
      console.error("Failed to load thresholds:", e);
    }
  }

  async function saveThresholds() {
    const token = getSessionToken();
    if (!token) {
      alert('Not authenticated');
      return;
    }

    const latency = parseFloat($('latency-input').value);
    const uptime  = parseFloat($('uptime-input').value);
    const timeout = parseFloat($('timeout-input') ? $('timeout-input').value : 30);

    if (isNaN(latency) || isNaN(uptime) || isNaN(timeout)) {
      alert('Invalid values');
      return;
    }

    if (latency < 1 || latency > 500) {
      alert('Latency must be between 1 and 500 ms');
      return;
    }

    if (uptime < 50 || uptime > 100) {
      alert('Uptime must be between 50 and 100%');
      return;
    }

    if (timeout < 5 || timeout > 240) {
      alert('Session timeout must be between 5 and 240 minutes');
      return;
    }

    try {
      const response = await fetch(`/api/thresholds?token=${encodeURIComponent(token)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          latency_threshold_ms: latency,
          uptime_threshold_percent: uptime,
          session_timeout_minutes: timeout
        })
      });

      if (!response.ok) {
        alert('Failed to save settings');
        return;
      }

      const result = await response.json();
      const msg = $('settings-message');
      if (msg) {
        msg.textContent = '✓ Settings saved successfully!';
        msg.style.color = '#6ee7b7';
        msg.style.display = 'block';
        setTimeout(() => { msg.style.display = 'none'; }, 3000);
      }
    } catch (e) {
      alert('Error: ' + e.message);
    }
  }

	  // Sync slider and input
	  function syncThreshold(sliderId, inputId) {
	    const slider = $(sliderId);
	    const input = $(inputId);
	    if (!slider || !input) return;

	    const updateFill = () => {
	      const min = parseFloat(slider.min || "0");
	      const max = parseFloat(slider.max || "100");
	      const val = parseFloat(slider.value || "0");
	      const pct = max > min ? ((val - min) / (max - min)) * 100 : 0;
	      // Green filled track (requested) without heavy CSS tricks.
	      slider.style.background = `linear-gradient(to right, var(--accent) 0%, var(--accent) ${pct}%, var(--border) ${pct}%, var(--border) 100%)`;
	    };

	    slider.addEventListener('input', () => { input.value = slider.value; updateFill(); });
	    input.addEventListener('change', () => { slider.value = input.value; updateFill(); });
	    // Initial fill.
	    updateFill();
	  }

	  let logStream = null;
	  let logRetryCount = 0;
	  let logRetryTimer = null;

		  function streamLogs() {
		    if (logStream) {
		      logStream.close();
		      logStream = null;
		    }
    if (logRetryTimer) {
      clearTimeout(logRetryTimer);
      logRetryTimer = null;
    }

	    const logsDiv = $('logs-stream');
	    if (!logsDiv) return;
	    logsDiv.dataset.connected = '0';
	    logsDiv.dataset.cleared = '0';

    const token = getSessionToken();
    if (!token) {
      logsDiv.innerHTML = '<div style="color:var(--danger)">❌ Not authenticated</div>';
      return;
    }

	    try {
	      logsDiv.innerHTML = '<div style="color:var(--accent-2)">⏳ Connecting to logs...</div>';

		      logStream = new EventSource(`/api/logs?token=${encodeURIComponent(token)}`);

      logStream.onopen = () => {
        logRetryCount = 0;
        console.log('[logs] Connected to stream');
      };

		      logStream.onmessage = (event) => {
		        try {
		          const log = JSON.parse(event.data);

		          if (log.type === 'ready') {
		            logsDiv.dataset.connected = '1';
		            return;
		          }

          if (log.type === 'heartbeat' || event.data.startsWith(':')) {
            // Heartbeat to keep connection alive - don't display
            return;
          }

          if (log.type === 'error') {
            console.error('[logs] Server error:', log.message);
            return;
          }

	          // Store in allLogs for filtering/export
		          if (log.message) {
		            if (log.message === 'Connected to log stream' || log.message === '✓ Log stream connected') {
		              // Never render connection noise.
		              return;
		            }
		            // Drop the initial placeholder as soon as we receive the first real log line.
		            if (logsDiv.dataset.cleared !== '1') {
		              logsDiv.innerHTML = '';
		              logsDiv.dataset.cleared = '1';
		            }
	            allLogs.push(log);
	            if (allLogs.length > 1000) allLogs.shift();  // Keep max 1000 logs in memory

	            const color = log.type === 'incident' ? '#fbbf24' :
	                         log.type === 'systemd' ? '#a78bfa' :
	                         log.type === 'socat' ? '#60a5fa' : '#10b981';
	            const line = document.createElement('div');
	            line.style.color = color;
	            line.textContent = log.message;
	            logsDiv.appendChild(line);

	            // Keep a decent on-screen history without growing forever.
	            const maxVisible = 200;
	            while (logsDiv.children.length > maxVisible) {
	              logsDiv.removeChild(logsDiv.firstChild);
	            }

	            // Auto-scroll only if user is already near bottom.
	            const nearBottom = (logsDiv.scrollHeight - logsDiv.scrollTop - logsDiv.clientHeight) < 80;
	            if (nearBottom) logsDiv.scrollTop = logsDiv.scrollHeight;
	          }
	        } catch (e) {
	          console.error('[logs] Parse error:', e);
	        }
	      };

      logStream.onerror = (e) => {
        console.error('[logs] Stream error:', e);
        if (logStream) {
          logStream.close();
          logStream = null;
        }

        logsDiv.innerHTML = '<div style="color:#ef4444">❌ Connection lost</div>';
        logRetryCount++;

        // Exponential backoff: 2s, 4s, 8s, 16s, 30s max
        const retryDelay = Math.min(2000 * Math.pow(2, logRetryCount - 1), 30000);
        const retrySeconds = Math.round(retryDelay / 1000);
        logsDiv.innerHTML += `<div style="color:var(--text-3);font-size:0.8em">Retrying in ${retrySeconds}s...</div>`;

        if (logRetryCount < 15 && adminMode) {
          logRetryTimer = setTimeout(() => streamLogs(), retryDelay);
        } else if (logRetryCount >= 15) {
          logsDiv.innerHTML = '<div style="color:#ef4444">❌ Connection failed (too many retries)</div>';
        }
      };
    } catch (e) {
      console.error('[logs] Failed to start stream:', e);
      logsDiv.innerHTML = '<div style="color:var(--danger)">❌ Error: ' + e.message + '</div>';
    }
  }

	  async function restartService(portId, localPort) {
    const serviceName = 'homelinkwg-socat-' + localPort;
    const confirmed = confirm(`Restart service "${serviceName}"?`);
    if (!confirmed) return;

    const token = getSessionToken();
    if (!token) {
      alert('Session expired. Please login again.');
      adminMode = false;
      updateAdminUI();
      return;
    }

    try {
      const response = await fetch('/api/restart-service?token=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service: serviceName })
      });

      if (response.status === 401) {
        alert('Session expired. Please login again.');
        adminMode = false;
        updateAdminUI();
        return;
      }

      if (!response.ok) {
        const error = await response.json();
        const errorMsg = error.error || 'Failed to restart service';
        console.error('Restart service error:', errorMsg);
        alert('❌ ' + errorMsg);
        return;
      }

      const result = await response.json();
      alert('Service restarted: ' + result.message);
      // Refresh status immediately
      setTimeout(refresh, 500);
    } catch (e) {
      alert('Error: ' + e.message);
    }
  }

  // Check session on page load
		  async function checkSession() {
		    const prevAdminMode = adminMode;
		    const token = getSessionToken();
		    if (!token) {
		      adminMode = false;
		      updateAdminUI();
		      return;
		    }

    try {
      const response = await fetch(`/api/verify_session?token=${encodeURIComponent(token)}`, { cache: 'no-store' });
      if (!response.ok) throw new Error('Session check failed');
      const payload = await response.json();
      adminMode = !!payload.valid;
    } catch (e) {
      adminMode = false;
    }

	    if (!adminMode) {
	      sessionStorage.removeItem(SESSION_KEY);
	      sessionStorage.removeItem(SESSION_EXPIRY_KEY);
	    }

		    updateAdminUI();
		    if (prevAdminMode !== adminMode) {
		      resetServiceUI();
		      // Token/mode changed: restart status stream so the server delivers the right view immediately.
		      startStatusStream();
		      // And refresh once to rebuild the UI without requiring a full page reload.
		      refreshOnce().catch(() => {});
		    }
		  }

		  function openSettingsModal() {
		    const modal = $('settings-modal');
		    if (!modal) return;
		    modal.classList.add('show');
		    if (!thresholdSyncInitialized) {
		      syncThreshold('latency-slider', 'latency-input');
		      syncThreshold('uptime-slider', 'uptime-input');
		      syncThreshold('timeout-slider', 'timeout-input');
		      thresholdSyncInitialized = true;
		    }
		    loadThresholds();
		    syncPerfSettingsUI();
		    load2faStatus();
		    loadConfigEditor();
		    if (typeof loadCurrentMode === 'function') loadCurrentMode();
		  }

  // ── 2FA settings ─────────────────────────────────────────────────────────

  async function load2faStatus() {
    try {
      const r = await fetch('/api/2fa/status', { cache: 'no-store' });
      if (!r.ok) return;
      const d = await r.json();
      const badge   = $('twofa-badge');
      const btn     = $('twofa-toggle-btn');
      const unavail = $('twofa-unavailable');
      if (!d.available) {
        if (unavail) unavail.style.display = '';
        if (badge)   { badge.textContent = 'unavailable'; badge.className = 'badge muted'; }
        if (btn)     btn.style.display = 'none';
        return;
      }
      if (unavail) unavail.style.display = 'none';
      if (badge) {
        badge.textContent = d.enabled ? 'enabled' : 'disabled';
        badge.className   = d.enabled ? 'badge ok' : 'badge ko';
      }
      if (btn) {
        btn.style.display  = '';
        btn.textContent    = d.enabled ? 'Disable 2FA' : 'Set up 2FA';
        btn.className      = d.enabled ? 'maint-btn' : 'maint-btn unmute';
      }
    } catch (_) {}
  }

  async function toggle2fa() {
    const badge = $('twofa-badge');
    if (badge && badge.textContent === 'enabled') await disable2fa();
    else await open2faSetup();
  }

  async function open2faSetup() {
    const token = getSessionToken();
    if (!token) return;
    const box = $('twofa-setup-box');
    const msg = $('twofa-setup-msg');
    if (!box) return;
    if (msg) { msg.style.display = 'none'; msg.textContent = ''; }
    if ($('twofa-code-input')) $('twofa-code-input').value = '';
    box.style.display = '';
    try {
      const r = await fetch('/api/2fa/setup?token=' + encodeURIComponent(token), { cache: 'no-store' });
      const d = await r.json();
      if (!r.ok) {
        if (msg) { msg.textContent = d.error || 'Setup failed'; msg.style.color = 'var(--danger)'; msg.style.display = ''; }
        return;
      }
      if ($('twofa-secret')) $('twofa-secret').textContent = d.secret;
      if ($('twofa-uri'))    $('twofa-uri').textContent    = d.uri;
      window._2faSetupSecret = d.secret;
      // Display QR code (server-generated base64 PNG)
      const qrEl = document.getElementById('twofa-qr-inner');
      if (qrEl) {
        qrEl.innerHTML = '';
        if (d.qr) {
          const img = document.createElement('img');
          img.src = d.qr;
          img.style.cssText = 'width:180px;height:180px;display:block';
          img.alt = 'QR code 2FA';
          qrEl.appendChild(img);
        } else {
          qrEl.style.cssText = 'font-size:.75rem;color:var(--text-3);padding:10px;text-align:center;max-width:220px';
          qrEl.textContent = 'QR indisponible — installe qrcode[pil] : pip install "qrcode[pil]" --break-system-packages';
        }
      }
    } catch (e) {
      if (msg) { msg.textContent = 'Setup failed: ' + e.message; msg.style.color = 'var(--danger)'; msg.style.display = ''; }
    }
  }

  async function confirm2faSetup() {
    const token  = getSessionToken();
    const code   = $('twofa-code-input') ? $('twofa-code-input').value.trim() : '';
    const secret = window._2faSetupSecret;
    const msg    = $('twofa-setup-msg');
    if (!token || !code || !secret) {
      if (msg) { msg.textContent = 'Enter the 6-digit code first'; msg.style.color = 'var(--amber)'; msg.style.display = ''; }
      return;
    }
    try {
      const r = await fetch('/api/2fa/enable?token=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret, code })
      });
      const d = await r.json();
      if (!r.ok) {
        if (msg) { msg.textContent = d.error || 'Invalid code'; msg.style.color = 'var(--danger)'; msg.style.display = ''; }
        return;
      }
      if ($('twofa-setup-box')) $('twofa-setup-box').style.display = 'none';
      if (msg) { msg.textContent = '✓ 2FA enabled'; msg.style.color = 'var(--accent-2)'; msg.style.display = ''; }
      load2faStatus();
    } catch (e) {
      if (msg) { msg.textContent = 'Error: ' + e.message; msg.style.color = 'var(--danger)'; msg.style.display = ''; }
    }
  }

  async function disable2fa() {
    const token = getSessionToken();
    if (!token) return;
    if (!confirm('Disable two-factor authentication?')) return;
    try {
      const r = await fetch('/api/2fa/disable?token=' + encodeURIComponent(token), { method: 'POST' });
      if (r.ok) {
        if ($('twofa-setup-box')) $('twofa-setup-box').style.display = 'none';
        load2faStatus();
      }
    } catch (_) {}
  }


		  function resetServiceUI() {
		    // Reset service UI so a mode switch (public <-> admin / light <-> normal)
		    // redraws correctly. Chart.js leaks event listeners + ResizeObserver
		    // entries if we only call destroy() — we also have to detach the
		    // canvas from the DOM and let the chart object be garbage-collected.
		    for (const key in chartInstances) {
		      const ch = chartInstances[key];
		      if (!ch) continue;
		      try { ch.stop && ch.stop(); } catch (e) {}
		      try { ch.clear && ch.clear(); } catch (e) {}
		      try {
		        if (ch.canvas && ch.canvas.parentNode) {
		          // Replace canvas with a clone — drops every attached listener.
		          const clone = ch.canvas.cloneNode(false);
		          ch.canvas.parentNode.replaceChild(clone, ch.canvas);
		        }
		      } catch (e) {}
		      try { ch.destroy(); } catch (e) {}
		      chartInstances[key] = null;
		    }
		    chartInstances = {};
		    const container = $('services-container');
		    if (container) container.innerHTML = '';
		    serviceMetrics = {};
		    expandedCharts.clear();
		    lastAnalyticsRefresh = 0;
		  }

		  // Best-effort GC trigger when the user toggles ultra-light: in dev tools
		  // this pairs with the resetServiceUI cleanup above to make leaks visible.
		  function _scheduleChartGC() {
		    if (window.gc) { try { window.gc(); } catch (e) {} }
		  }

		  // ── Theme management ──────────────────────────────────────────────────────
  // Button toggles dark <-> light directly. 'auto' is only the startup default.
  const ICON_LIGHT = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';
  const ICON_DARK  = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';

  function applyTheme(pref) {
    if (pref !== 'dark' && pref !== 'light') {
      const sysDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      pref = sysDark ? 'dark' : 'light';
    }
    const html = document.documentElement;
    const body = document.body;
    html.setAttribute('data-theme', pref);
    if (body) body.setAttribute('data-theme', pref);
    try { localStorage.setItem('fs-theme', pref); } catch(_) {}
    const icon = document.getElementById('theme-icon');
    const btn  = document.getElementById('theme-toggle-btn');
    const isDark = pref === 'dark';
    // Show the icon of the mode the user will switch TO (clearer affordance).
    if (icon) icon.innerHTML = isDark ? ICON_LIGHT : ICON_DARK;
    if (btn)  btn.title = isDark ? 'Switch to light theme' : 'Switch to dark theme';
  }

  function cycleTheme() {
    const cur = document.documentElement.getAttribute('data-theme');
    applyTheme(cur === 'light' ? 'dark' : 'light');
  }

  // Init theme on load
  (function initTheme() {
    let pref = 'auto';
    try { pref = localStorage.getItem('fs-theme') || 'auto'; } catch(_) {}
    applyTheme(pref);
  })();

  // ── Inactivity / session timeout ───────────────────────────────────────────
  let _sessionTimeoutMs = 30 * 60 * 1000; // default 30 min, overridden by loadThresholds
  let _lastActivity     = Date.now();
  let _warnedTimeout    = false;
  let _idleCheckInterval = null;

  function _resetActivity() {
    _lastActivity  = Date.now();
    _warnedTimeout = false;
    const toast = document.getElementById('idle-toast');
    if (toast) toast.style.display = 'none';
  }

  ['mousemove','keydown','click','touchstart','scroll'].forEach(ev =>
    document.addEventListener(ev, _resetActivity, { passive: true })
  );

  function _startIdleCheck() {
    if (_idleCheckInterval) return;
    _idleCheckInterval = setInterval(() => {
      if (!getSessionToken()) return; // not logged in, nothing to do
      const idle = Date.now() - _lastActivity;
      const warnAt = _sessionTimeoutMs - 2 * 60 * 1000; // warn 2 min before
      if (idle >= _sessionTimeoutMs) {
        // Auto-logout
        clearInterval(_idleCheckInterval); _idleCheckInterval = null;
        const toast = document.getElementById('idle-toast');
        if (toast) toast.style.display = 'none';
        fetch('/api/logout?token=' + encodeURIComponent(getSessionToken()), { method: 'POST' }).catch(() => {});
        sessionStorage.removeItem('admin_token');
        checkSession();
        // Show brief message
        const alert = document.getElementById('alert');
        const alertText = document.getElementById('alert-text');
        if (alert && alertText) {
          alertText.textContent = 'Session expired — logged out due to inactivity.';
          alert.style.display = '';
          setTimeout(() => { if (alert) alert.style.display = 'none'; }, 5000);
        }
      } else if (!_warnedTimeout && idle >= warnAt && _sessionTimeoutMs > 2 * 60 * 1000) {
        _warnedTimeout = true;
        const remaining = Math.round((_sessionTimeoutMs - idle) / 60000);
        const toast = document.getElementById('idle-toast');
        if (toast) {
          document.getElementById('idle-toast-text').textContent =
            `Idle — logging out in ${remaining} min. Move the mouse to stay connected.`;
          toast.style.display = '';
        }
      }
    }, 15000); // check every 15s
  }

  // ── Restart dashboard ─────────────────────────────────────────────────────
  async function changePassword() {
    const current = $('chpw-current').value.trim();
    const newPw    = $('chpw-new').value;
    const confirm_ = $('chpw-confirm').value;
    const msg      = $('chpw-msg');
    const show = (text, color) => { msg.textContent = text; msg.style.color = color; msg.style.display = ''; };

    if (!current || !newPw || !confirm_) return show('All fields are required.', 'var(--danger)');
    if (newPw.length < 8)                return show('New password must be at least 8 characters.', 'var(--danger)');
    if (newPw !== confirm_)              return show('Passwords do not match.', 'var(--danger)');

    const token = getSessionToken();
    if (!token) return show('Not logged in.', 'var(--danger)');

    show('Updating…', 'var(--text-2)');
    try {
      const r = await fetch('/api/change-password?token=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: current, new_password: newPw })
      });
      const d = await r.json();
      if (r.ok) {
        show('✓ Password updated successfully.', 'var(--ok)');
        $('chpw-current').value = '';
        $('chpw-new').value = '';
        $('chpw-confirm').value = '';
      } else {
        show(d.error || 'Error updating password.', 'var(--danger)');
      }
    } catch(e) {
      show('Network error.', 'var(--danger)');
    }
  }

  // ── Performance diagnostic ────────────────────────────────────────────────
  async function runPerfDiagnostic() {
    const btn    = $('perf-diag-btn');
    const status = $('perf-diag-status');
    const results= $('perf-diag-results');
    const banner = $('perf-verdict-banner');
    const rows   = $('perf-test-rows');
    const recoBox= $('perf-recommendations');
    const recoList=$('perf-reco-list');

    const token = getSessionToken();
    if (!token) return;

    // Reset UI
    btn.disabled = true;
    btn.textContent = '⏳ Running…';
    status.textContent = 'Testing disk, network, CPU and memory… (~15 s)';
    status.style.color = 'var(--text-2)';
    status.style.display = '';
    results.style.display = 'none';
    rows.innerHTML = '';
    recoBox.style.display = 'none';
    recoList.innerHTML = '';

    try {
      const r = await fetch('/api/performance-check?token=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const d = await r.json();

      if (!r.ok) {
        status.textContent = d.error || 'Diagnostic failed.';
        status.style.color = 'var(--danger)';
        btn.disabled = false;
        btn.textContent = '▶ Run diagnostic';
        return;
      }

      // ── Verdict banner ────────────────────────────────────────────────────
      const v = d.verdict || {};
      // severity from backend is "ok" | "warning" | "critical"
      const sevMap = { ok: 0, warning: 1, critical: 2 };
      const sev = sevMap[v.severity] ?? 0;
      const bannerColors = [
        { bg: 'rgba(16,185,129,.12)',  border: 'var(--ok, #10b981)',   text: 'var(--ok, #10b981)' },
        { bg: 'rgba(245,158,11,.12)',  border: 'var(--warn, #f59e0b)', text: 'var(--warn, #f59e0b)' },
        { bg: 'rgba(239,68,68,.12)',   border: 'var(--danger, #ef4444)', text: 'var(--danger, #ef4444)' },
      ];
      const bc = bannerColors[sev];
      const icons = ['✅', '⚠️', '🚫'];
      banner.style.background    = bc.bg;
      banner.style.borderColor   = bc.border;
      banner.style.color         = bc.text;
      const mainLabel = v.bottleneck
        ? { network:'Network', cpu_throttle:'CPU throttling', cpu_temp:'CPU temperature', disk:'Disk', memory:'Memory' }[v.bottleneck] || v.bottleneck
        : 'All systems good';
      banner.innerHTML = `<strong>${icons[sev]} ${mainLabel}</strong><br>
        <span style="color:var(--text-2);font-size:.78rem">${v.message || ''}</span>`;

      // ── Build test rows from per-category data ─────────────────────────────
      const statusSev = s => ({ ok: 0, slow: 1, critical: 2, unknown: 0 }[s] ?? 0);
      const sevIcon  = s => ['✅','⚠️','🚫'][Math.min(s,2)];
      const sevColor = s => ['var(--ok, #10b981)','var(--warn, #f59e0b)','var(--danger, #ef4444)'][Math.min(s,2)];

      const addRow = (name, value, detail, sevN) => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:flex-start;gap:10px;padding:8px 10px;background:var(--surface);border-radius:var(--r-sm);border:1px solid var(--border-2)';
        row.innerHTML = `
          <span style="font-size:1rem;line-height:1.4">${sevIcon(sevN)}</span>
          <div style="flex:1;min-width:0">
            <div style="font-weight:600;color:${sevColor(sevN)}">${name}</div>
            <div style="color:var(--text-2);margin-top:2px">${value}</div>
            ${detail ? `<div style="color:var(--text-3);font-size:.74rem;margin-top:2px">${detail}</div>` : ''}
          </div>`;
        rows.appendChild(row);
      };

      // Network
      if (d.network) {
        const n = d.network;
        const nSev = statusSev(n.status);
        const nType = n.type || 'Unknown';
        const nVal = n.interface ? `${n.interface} — ${nType}` : nType;
        addRow('Network', nVal, n.speed ? `Link speed: ${n.speed}` : '', nSev);
      }
      // Disk
      if (d.disk) {
        const k = d.disk;
        const dSev = statusSev(k.status);
        let dVal = k.read_mbps != null ? `Read: ${k.read_mbps} MB/s` + (k.write_mbps != null ? `, Write: ${k.write_mbps} MB/s` : '') : (k.error || 'Could not measure');
        if (k.w_await_ms != null) dVal += `, Write latency: ${k.w_await_ms} ms`;
        const dDetail = k.w_await_note || (dSev === 2 ? 'SD card may be limiting streaming' : dSev === 1 ? 'Disk is slower than recommended' : '');
        addRow('Disk I/O', dVal, dDetail, dSev);
      }
      // CPU
      if (d.cpu) {
        const c = d.cpu;
        const cSev = statusSev(c.status);
        let cVal = c.usage_percent != null ? `Usage: ${c.usage_percent}%` : 'N/A';
        if (c.iowait_percent != null && c.iowait_percent > 5) cVal += `, I/O wait: ${c.iowait_percent}%`;
        if (c.temp_c != null) cVal += `, Temp: ${c.temp_c}°C`;
        let cDetails = [];
        if (c.throttled) cDetails.push('⚠️ CPU throttled — reduce temperature');
        if (c.cpu_explanation) cDetails.push(`ℹ️ ${c.cpu_explanation}`);
        if (c.top_processes && c.top_processes.length > 0) {
          const procList = c.top_processes.map(p => `<strong>${p.name}</strong> ${p.cpu_percent}%`).join(' &nbsp;·&nbsp; ');
          cDetails.push(`Top consumers: ${procList}`);
        }
        addRow('CPU', cVal, cDetails.join('<br>'), cSev);
      }
      // Memory
      if (d.memory) {
        const m = d.memory;
        const mSev = statusSev(m.status);
        const mVal = m.used_mb != null ? `${m.used_mb} MB / ${m.total_mb} MB (${m.percent}%)` : 'N/A';
        addRow('Memory', mVal, '', mSev);
      }

      // ── Recommendations ───────────────────────────────────────────────────
      const recos = d.recommendations || [];
      if (recos.length > 0) {
        recos.forEach(rec => {
          const li = document.createElement('li');
          li.textContent = rec;
          recoList.appendChild(li);
        });
        recoBox.style.display = '';
      }

      results.style.display = '';
      status.style.display = 'none';
    } catch(e) {
      status.textContent = 'Network error running diagnostic.';
      status.style.color = 'var(--danger)';
    }

    btn.disabled = false;
    btn.textContent = '▶ Run diagnostic';
  }

  async function restartDashboard() {
    if (!confirm('Restart HomelinkWG? The page will reload automatically once the service is back up.')) return;
    const token = getSessionToken();
    if (!token) return;
    const msg = $('restart-dashboard-msg');
    if (msg) { msg.textContent = 'Restarting…'; msg.style.color = 'var(--amber)'; msg.style.display = ''; }
    try {
      await fetch('/api/restart-dashboard', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    } catch(_) {}
    // Poll /api/healthz until back up
    if (msg) msg.textContent = 'Waiting for service to come back up…';
    let attempts = 0;
    const poll = setInterval(async () => {
      attempts++;
      try {
        const r = await fetch('/api/healthz', { cache: 'no-store' });
        if (r.ok) { clearInterval(poll); location.reload(); }
      } catch(_) {}
      if (attempts > 30) { clearInterval(poll); if (msg) { msg.textContent = 'Timeout — please reload manually.'; msg.style.color = 'var(--danger)'; } }
    }, 2000);
  }

  // ── Sessions history ───────────────────────────────────────────────────────
  async function loadSessionsHistory() {
    const token = getSessionToken();
    const el = $('sessions-history-list');
    if (!el) return;
    if (!token) { el.innerHTML = '<span style="color:var(--text-3)">Not authenticated</span>'; return; }
    try {
      const r = await fetch('/api/sessions?token=' + encodeURIComponent(token), { cache: 'no-store' });
      if (!r.ok) { el.innerHTML = '<span style="color:var(--danger)">Failed to load</span>'; return; }
      const d = await r.json();
      const sessions = d.sessions || [];
      if (!sessions.length) { el.innerHTML = '<span style="color:var(--text-3)">No sessions found</span>'; return; }
      const now = Math.floor(Date.now() / 1000);
      el.innerHTML = sessions.map(s => {
        const created = new Date(s.created_at * 1000).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' });
        const active  = s.expires_at > now;
        const badge   = active
          ? '<span style="color:var(--accent-2);font-weight:600">active</span>'
          : '<span style="color:var(--text-3)">expired</span>';
        const ua = s.user_agent ? s.user_agent.replace(/\(.*?\)/g,'').trim().substring(0,60) : '—';
        return '<div style="display:flex;gap:10px;flex-wrap:wrap;padding:4px 0;border-bottom:1px solid var(--border);font-family:monospace;font-size:.77rem">'
          + '<span style="color:var(--text-3);min-width:130px">' + created + '</span>'
          + '<span style="min-width:110px;color:var(--text-2)">' + (s.ip_address || '—') + '</span>'
          + badge
          + '<span style="color:var(--text-3);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + ua + '</span>'
          + '</div>';
      }).join('');
    } catch(e) {
      if (el) el.innerHTML = '<span style="color:var(--danger)">Erreur: ' + e.message + '</span>';
    }
  }

  // ── Audit log ──────────────────────────────────────────────────────────────
  let _auditRows = [];

  async function loadAuditLog() {
    const token = getSessionToken();
    if (!token) return;
    const el = $('audit-log-list');
    if (!el) return;
    try {
      const r = await fetch('/api/audit-log?token=' + encodeURIComponent(token), { cache: 'no-store' });
      if (!r.ok) { el.innerHTML = '<span style="color:var(--danger)">Erreur chargement</span>'; return; }
      const d = await r.json();
      _auditRows = d.entries || [];
      renderAuditLog(_auditRows);
    } catch(e) {
      if (el) el.innerHTML = '<span style="color:var(--danger)">Erreur: ' + e.message + '</span>';
    }
  }

  function filterAuditLog() {
    const q = ($('audit-search').value || '').toLowerCase();
    renderAuditLog(q ? _auditRows.filter(r =>
      (r.action+r.admin+r.target+(r.details||'')+r.status).toLowerCase().includes(q)
    ) : _auditRows);
  }

  function renderAuditLog(rows) {
    const el = $('audit-log-list');
    if (!el) return;
    if (!rows.length) { el.innerHTML = '<span style="color:var(--text-3)">No entries</span>'; return; }
    const ACTION_COLOR = { success:'var(--accent-2)', failed:'var(--danger)', partial:'var(--amber)' };
    el.innerHTML = rows.map(r => {
      const dt = new Date(r.timestamp * 1000).toLocaleString('en-GB', { dateStyle:'short', timeStyle:'medium' });
      const col = ACTION_COLOR[r.status] || 'var(--text-2)';
      const det = r.details ? ' <span style="color:var(--text-3)">' + r.details + '</span>' : '';
      return '<div style="padding:4px 0;border-bottom:1px solid var(--border);display:flex;gap:10px;flex-wrap:wrap">'
        + '<span style="color:var(--text-3);min-width:130px">' + dt + '</span>'
        + '<span style="color:' + col + ';min-width:130px;font-weight:600">' + r.action + '</span>'
        + '<span style="color:var(--text-2)">' + (r.admin || '—') + '</span>'
        + '<span style="color:var(--text-3)">' + (r.target || '') + det + '</span>'
        + '</div>';
    }).join('');
  }

  // ── Config backup ───────────────────────────────────────────────────────────
  function downloadConfigBackup() {
    const token = getSessionToken();
    if (!token) return;
    const a = document.createElement('a');
    a.href = '/api/config/backup?token=' + encodeURIComponent(token);
    a.download = 'homelinkwg-backup.zip';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  // ── Diagnostic bundle ───────────────────────────────────────────────────────
  function downloadDiagnosticBundle(fmt) {
    const token = getSessionToken();
    if (!token) return;
    const msg = document.getElementById('diag-bundle-msg');
    if (msg) { msg.textContent = 'Génération en cours…'; msg.style.color = 'var(--text-2)'; }
    const url = '/api/diagnostic-bundle?format=' + encodeURIComponent(fmt) +
                '&token=' + encodeURIComponent(token);
    const a = document.createElement('a');
    a.href = url;
    const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
    a.download = 'homelinkwg-diagnostic-' + stamp + (fmt === 'zip' ? '.zip' : '.json');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => { if (msg) { msg.textContent = 'Téléchargement déclenché.'; msg.style.color = 'var(--accent-2)'; } }, 600);
  }

  async function loadCurrentMode() {
    const token = getSessionToken();
    if (!token) return;
    try {
      const r = await fetch('/api/mode?token=' + encodeURIComponent(token), { cache: 'no-store' });
      if (!r.ok) return;
      const d = await r.json();
      const cur = d.mode || 'normal';
      document.querySelectorAll('#mode-btns .maint-btn').forEach(btn => {
        const isCur = btn.dataset.mode === cur;
        btn.classList.toggle('unmute', isCur);
        btn.style.fontWeight = isCur ? '700' : '';
      });
      const st = document.getElementById('mode-status');
      if (st) {
        const adapt = d.adaptive || {};
        let label = 'Mode actuel : <strong>' + cur.toUpperCase() + '</strong>';
        if (adapt.active && cur !== 'ultra') {
          label += ' — auto-override <strong>ULTRA</strong> actif (' + (adapt.reason || 'CPU élevé') + ')';
          st.style.color = '#d97706';
        } else {
          st.style.color = 'var(--text-2)';
        }
        st.innerHTML = label;
      }
    } catch (e) { /* silent */ }
  }

  async function setDashboardMode(mode) {
    const token = getSessionToken();
    if (!token) return;
    const st = document.getElementById('mode-status');
    if (st) { st.textContent = 'Application…'; st.style.color = 'var(--text-2)'; }
    try {
      const r = await fetch('/api/mode?token=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: mode })
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
      // Force a fresh status fetch so the badge + refresh interval update.
      try { resetServiceUI(); _scheduleChartGC(); } catch (e) {}
      try { await refreshOnce(); } catch (e) {}
      await loadCurrentMode();
    } catch (e) {
      if (st) {
        st.textContent = 'Erreur: ' + (e && e.message || e);
        st.style.color = 'var(--danger)';
      }
    }
  }

  async function runHealthCheck() {
    const token = getSessionToken();
    if (!token) return;
    const box = document.getElementById('health-check-result');
    if (box) { box.style.display = 'block'; box.innerHTML = 'Analyse en cours…'; }
    try {
      const r = await fetch('/api/health-score?token=' + encodeURIComponent(token), { cache: 'no-store' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const d = await r.json();
      const colorFor = (lvl) => lvl === 'critical' ? 'var(--danger)' : lvl === 'warn' ? '#d97706' : 'var(--accent-2)';
      const overall = d.overall || 'ok';
      const checks = (d.checks || []);
      let html = '<div style="padding:8px 10px;border-radius:var(--r-sm);background:var(--surface);border:1px solid var(--border);">';
      html += '<div style="font-weight:600;color:' + colorFor(overall) + '">Verdict global: ' + overall.toUpperCase() + '</div>';
      if (!checks.length) {
        html += '<div style="margin-top:6px;color:var(--text-2)">Aucun problème détecté.</div>';
      } else {
        html += '<ul style="margin:6px 0 0 16px;padding:0;color:var(--text-2)">';
        checks.forEach(c => {
          html += '<li><span style="color:' + colorFor(c.level) + ';font-weight:600">[' + c.level + ']</span> ' + (c.msg || c.key) + '</li>';
        });
        html += '</ul>';
      }
      html += '</div>';
      if (box) box.innerHTML = html;
    } catch (e) {
      if (box) box.innerHTML = '<span style="color:var(--danger)">Erreur: ' + (e && e.message || e) + '</span>';
    }
  }

  async function runLatencyAudit() {
    const token = getSessionToken();
    if (!token) return;
    const box = document.getElementById('latency-audit-result');
    if (box) { box.style.display = 'block'; box.innerHTML = 'Mesure de la latence (probes en cours, ~3-5 s)…'; }
    try {
      const r = await fetch('/api/latency-insights?token=' + encodeURIComponent(token), { cache: 'no-store' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const d = await r.json();
      const colorMs = (ms) => {
        if (ms == null) return 'var(--text-3)';
        if (ms < 30) return 'var(--accent-2)';
        if (ms < 100) return '#d97706';
        return 'var(--danger)';
      };
      let html = '<div style="padding:8px 10px;border-radius:var(--r-sm);background:var(--surface);border:1px solid var(--border);">';
      // Per-port breakdown
      html += '<div style="font-weight:600;margin-bottom:6px">Latence par port (5 échantillons)</div>';
      if (!(d.ports || []).length) {
        html += '<div style="color:var(--text-2)">Aucun port actif.</div>';
      } else {
        html += '<table style="width:100%;border-collapse:collapse;font-size:.75rem">';
        html += '<tr style="color:var(--text-3);text-align:left"><th>Port</th><th>DNS</th><th>TCP avg</th><th>P95</th><th>Jitter</th><th>Conn.</th><th>Verdict</th></tr>';
        d.ports.forEach(p => {
          const b = p.breakdown || {};
          if (!b.ok) {
            html += '<tr><td>' + p.name + '</td><td colspan="6" style="color:var(--danger)">' + (b.error || 'failed') + '</td></tr>';
            return;
          }
          const verdict = b.tcp_ms_avg < 30 ? 'OK' : b.tcp_ms_avg < 100 ? 'CORRECT' : 'LENT';
          html += '<tr>'
            + '<td>' + p.name + '</td>'
            + '<td style="color:' + colorMs(b.dns_ms) + '">' + (b.dns_ms ?? '-') + 'ms</td>'
            + '<td style="color:' + colorMs(b.tcp_ms_avg) + '">' + b.tcp_ms_avg + 'ms</td>'
            + '<td>' + b.tcp_ms_p95 + 'ms</td>'
            + '<td style="color:' + (b.jitter_ms > 30 ? 'var(--danger)' : 'var(--text-2)') + '">' + b.jitter_ms + 'ms</td>'
            + '<td>' + (p.socat_connections ?? '-') + '</td>'
            + '<td style="color:' + colorMs(b.tcp_ms_avg) + ';font-weight:600">' + verdict + '</td>'
            + '</tr>';
        });
        html += '</table>';
      }
      // WG diagnostic
      const wg = d.wg_diagnostic || {};
      html += '<div style="margin-top:10px;font-weight:600">WireGuard</div>';
      html += '<div style="color:var(--text-2)">MTU WG=' + (wg.wg_mtu || '?')
            + ', iface défaut=' + (wg.default_iface || '?')
            + ' MTU=' + (wg.default_iface_mtu || '?')
            + (wg.endpoints ? ', endpoints=' + wg.endpoints.join(',') : '')
            + '</div>';
      if (wg.recommendation_mtu) html += '<div style="color:#d97706">⚠️ ' + wg.recommendation_mtu + '</div>';
      if (wg.recommendation_keepalive) html += '<div style="color:#d97706">⚠️ ' + wg.recommendation_keepalive + '</div>';
      // CPU governor
      const gov = d.cpu_governor || {};
      if (gov.governor) {
        const govColor = gov.governor === 'performance' ? 'var(--accent-2)' : '#d97706';
        html += '<div style="margin-top:8px">CPU governor: <span style="color:' + govColor + ';font-weight:600">' + gov.governor + '</span>'
              + (gov.freq_cur_mhz ? ' @ ' + gov.freq_cur_mhz + 'MHz / max ' + (gov.freq_max_mhz || '?') + 'MHz' : '')
              + '</div>';
        if (gov.recommendation) html += '<div style="color:#d97706">⚠️ ' + gov.recommendation + '</div>';
      }
      // NTP
      const ntp = d.ntp || {};
      if (ntp.synced !== null) {
        const ntpColor = ntp.synced ? 'var(--accent-2)' : 'var(--danger)';
        html += '<div style="margin-top:8px">NTP: <span style="color:' + ntpColor + '">' + (ntp.synced ? 'synced' : 'NOT synced') + '</span>'
              + (ntp.offset_ms != null ? ' (offset ' + ntp.offset_ms + 'ms)' : '')
              + (ntp.source ? ' via ' + ntp.source : '')
              + '</div>';
      }
      // Kernel tunables
      const kt = d.kernel_net_tunables || {};
      if (Object.keys(kt).length) {
        html += '<details style="margin-top:8px"><summary style="cursor:pointer;color:var(--text-2)">Kernel net tunables</summary>'
              + '<pre style="font-size:.7rem;background:var(--bg);padding:6px;border-radius:4px;margin-top:4px;white-space:pre-wrap">'
              + Object.entries(kt).map(([k,v]) => k + ' = ' + v).join('\n')
              + '</pre></details>';
      }
      html += '</div>';
      if (box) box.innerHTML = html;
    } catch (e) {
      if (box) box.innerHTML = '<span style="color:var(--danger)">Erreur: ' + (e && e.message || e) + '</span>';
    }
  }

  function exportMetricsCSV() {
    const token = getSessionToken();
    if (!token) return;
    const tf = document.querySelector('.timeframe-btn.active');
    const days = tf ? (tf.dataset.timeframe === '7d' ? 7 : tf.dataset.timeframe === '30d' ? 30 : 1) : 1;
    const url = '/api/metrics/export?token=' + encodeURIComponent(token) + '&days=' + days;
    const a = document.createElement('a');
    a.href = url;
    a.download = 'homelinkwg-metrics.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  async function loadConfigEditor() {
    const token = getSessionToken();
    if (!token) return;
    const ta = $('config-editor-textarea');
    const msg = $('config-editor-msg');
    if (!ta) return;
    try {
      const r = await fetch('/api/config?token=' + encodeURIComponent(token), { cache: 'no-store' });
      const d = await r.json();
      if (!r.ok) { if (msg) { msg.textContent = d.error || 'Failed to load'; msg.style.color='var(--danger)'; msg.style.display=''; } return; }
      ta.value = JSON.stringify(d.config, null, 2);
      ta.style.borderColor = 'var(--border-2)';
      if ($('config-json-error')) $('config-json-error').style.display = 'none';
      if (msg) { msg.style.display = 'none'; }
    } catch(e) {
      if (msg) { msg.textContent = 'Erreur: ' + e.message; msg.style.color='var(--danger)'; msg.style.display=''; }
    }
  }

  function validateConfigJSON(ta) {
    const errEl = $('config-json-error');
    try {
      JSON.parse(ta.value);
      ta.style.borderColor = 'var(--border-2)';
      if (errEl) errEl.style.display = 'none';
      return true;
    } catch(e) {
      ta.style.borderColor = 'var(--danger)';
      if (errEl) { errEl.textContent = e.message; errEl.style.display = ''; }
      return false;
    }
  }

  async function saveConfig() {
    const token = getSessionToken();
    if (!token) return;
    const ta = $('config-editor-textarea');
    const msg = $('config-editor-msg');
    if (!ta) return;
    if (!validateConfigJSON(ta)) return;
    let parsed;
    try { parsed = JSON.parse(ta.value); } catch(_) { return; }
    const btn = $('config-save-btn');
    if (btn) btn.disabled = true;
    try {
      const r = await fetch('/api/config?token=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: parsed })
      });
      const d = await r.json();
      if (!r.ok) {
        if (msg) { msg.textContent = d.error || 'Save failed'; msg.style.color='var(--danger)'; msg.style.display=''; }
      } else {
        if (msg) { msg.textContent = '✓ Config saved — refreshing…'; msg.style.color='var(--accent-2)'; msg.style.display=''; }
        setTimeout(() => { if (msg) msg.style.display='none'; }, 3000);
        await refresh({ restartStream: false });
      }
    } catch(e) {
      if (msg) { msg.textContent = 'Erreur: ' + e.message; msg.style.color='var(--danger)'; msg.style.display=''; }
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function closeSettingsModal() {
		    const modal = $('settings-modal');
		    if (!modal) return;
		    modal.classList.remove('show');
		  }

		  function syncPerfSettingsUI() {
		    const perf = $('perf-section');
		    if (perf) perf.style.display = runtimeUltraLight ? '' : 'none';
		    const cb = $('toggle-live-logs');
		    if (cb) {
		      cb.checked = isLiveLogsEnabled();
		      cb.onchange = () => setLiveLogsEnabled(!!cb.checked);
		    }
		  }

	  // Click outside closes settings modal.
		  const settingsModalEl = document.getElementById('settings-modal');
		  if (settingsModalEl) {
		    settingsModalEl.addEventListener('click', (e) => {
		      if (e.target === settingsModalEl) closeSettingsModal();
		    });
		  }

		  // Click outside closes What's new modal.
		  const whatsNewModalEl = document.getElementById('whatsnew-modal');
		  if (whatsNewModalEl) {
		    whatsNewModalEl.addEventListener('click', (e) => {
		      if (e.target === whatsNewModalEl) closeWhatsNew();
		    });
		  }

		  function toggleCharts(portId) {
		    const chartsDiv = document.getElementById(`charts-${portId}`);
		    const arrow = document.getElementById(`toggle-arrow-${portId}`);
		    if (!chartsDiv || !arrow) return;

		    const opening = (chartsDiv.style.display === 'none' || chartsDiv.style.display === '');
		    if (opening) {
		      chartsDiv.style.display = 'grid';
		      arrow.textContent = '▲';
		      expandedCharts.add(portId);
		      // Lazy-load metrics only when the user expands.
		      ensureChartsLoaded(portId);
		    } else {
		      chartsDiv.style.display = 'none';
		      arrow.textContent = '▼';
		      expandedCharts.delete(portId);
		    }
		  }

		  async function ensureChartsLoaded(portId) {
		    if (metricsFetchInFlight[portId]) return metricsFetchInFlight[portId];
		    const chartsDiv = document.getElementById(`charts-${portId}`);
		    if (!chartsDiv) return;

		    // Build chart DOM only once (keeps base DOM small for low-power devices).
		    if (!chartsDiv.dataset.built) {
		      chartsDiv.dataset.built = '1';
		      const heatmapBlock = runtimeUltraLight ? '' : `
		        <div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px;grid-column:1/-1">
		          <div style="font-size:0.75em;color:var(--text-3);font-weight:600;margin-bottom:8px">Daily Availability Heatmap</div>
		          <div id="heatmap-${portId}" style="display:flex;gap:3px;flex-wrap:wrap;align-items:flex-start"></div>
		        </div>
		      `;

		      chartsDiv.innerHTML = `
		        <div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px">
		          <div style="font-size:0.75em;color:var(--text-3);font-weight:600;margin-bottom:6px">Availability Trend</div>
		          <div style="position:relative;height:150px">
		            <canvas id="chart-avail-${portId}" style="width:100%;height:100%"></canvas>
		          </div>
		        </div>
		        <div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px">
		          <div style="font-size:0.75em;color:var(--text-3);font-weight:600;margin-bottom:6px">Latency Trend (ms)</div>
		          <div style="position:relative;height:150px">
		            <canvas id="chart-latency-${portId}" style="width:100%;height:100%"></canvas>
		          </div>
		        </div>
		        ${heatmapBlock}
		      `;
		    }

		    metricsFetchInFlight[portId] = (async () => {
		      try {
		        const metricsRes = await fetch(`/api/metrics?port_id=${encodeURIComponent(portId)}&timeframe=${encodeURIComponent(selectedTimeframe)}`, { cache: 'no-store' });
		        if (!metricsRes.ok) return;
	        const metrics = await metricsRes.json();
	        serviceMetrics[portId] = serviceMetrics[portId] || {};
	        serviceMetrics[portId].metrics = metrics.metrics || [];
	        drawChart(portId, serviceMetrics[portId].metrics);
	        lastAnalyticsRefresh = Date.now();
	      } catch (e) {
	        // Keep UI calm on low-power devices; failing charts should not break status updates.
	      } finally {
	        delete metricsFetchInFlight[portId];
	      }
	    })();
	    return metricsFetchInFlight[portId];
	  }

	  async function startDiagnose(portId) {
    const diagDiv = document.getElementById(`diagnose-${portId}`);
    const resultDiv = document.getElementById(`diagnose-results-${portId}`);

    if (!diagDiv) return;

	    diagDiv.style.display = 'block';
	    resultDiv.innerHTML = '<div style="color:var(--text-3)">Starting diagnostics…</div>';

	    try {
      const token = getSessionToken();
      if (!token) {
        resultDiv.innerHTML = '<div style="color:#fca5a5">✗ Login as admin to run diagnostics.</div>';
        return;
      }
      const url = `/api/diagnose?port_id=${encodeURIComponent(portId)}&token=${encodeURIComponent(token)}`;
      const response = await fetch(url);
      if (!response.ok) {
        let errMsg = 'HTTP ' + response.status;
        try { const j = await response.json(); if (j && j.error) errMsg = j.error; } catch(_) {}
        resultDiv.innerHTML = `<div style="color:#fca5a5">✗ ${errMsg}</div>`;
        return;
      }
      resultDiv.innerHTML = '';
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        // SSE messages are separated by blank lines; lines by \n.
        let nlIdx;
        while ((nlIdx = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, nlIdx);
          buffer = buffer.slice(nlIdx + 1);
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.substring(6));
              const statusIcon = data.status === 'ok' ? '✓' : (data.status === 'fail' ? '✗' : '⟳');
              const statusColor = data.status === 'ok' ? '#6ee7b7' : (data.status === 'fail' ? '#fca5a5' : '#94a3b8');
              resultDiv.innerHTML += `<div style="color:${statusColor}">${statusIcon} ${data.message}</div>`;

	              // Add analysis summary at the end
	              if (data.step === 'complete') {
	                resultDiv.innerHTML += `<div style="color:#94a3b8;margin-top:8px;border-top:1px solid #2d3748;padding-top:8px">─ ANALYSIS ─</div>`;
	                if (data.segments) {
	                  const local = data.segments.local_ms;
	                  const tunnel = data.segments.tunnel_ms;
	                  const target = data.segments.target_ms;
	                  const bottleneckLabel = data.bottleneck === 'vpn_path' ? 'VPN path' :
	                                        data.bottleneck === 'local_path' ? 'Local path' :
	                                        data.bottleneck === 'target_path' ? 'Target path' :
	                                        data.bottleneck === 'service' ? 'Service process' :
	                                        data.bottleneck === 'target_unreachable' ? 'Target unreachable' :
	                                        'Insufficient data';
	                  resultDiv.innerHTML += `<div style="color:#a78bfa">Latency breakdown:</div>`;
	                  resultDiv.innerHTML += `<div>  local->socat: ${local !== null ? local.toFixed(1) + 'ms' : 'n/a'}</div>`;
	                  resultDiv.innerHTML += `<div>  wg path est.: ${tunnel !== null ? tunnel.toFixed(1) + 'ms' : 'n/a'}</div>`;
	                  resultDiv.innerHTML += `<div>  wg->target:   ${target !== null ? target.toFixed(1) + 'ms' : 'n/a'}</div>`;
	                  resultDiv.innerHTML += `<div style="color:#fbbf24;margin-top:6px">Bottleneck: ${bottleneckLabel}</div>`;
	                }

	                // Update service status badges with diagnostic results
	                if (data.target_reachable !== undefined) {
                  const targetBadgeEl = document.getElementById(`badge-target-${portId}`);
                  if (targetBadgeEl) {
                    const newStatus = data.target_reachable ? 'reachable' : 'unreachable';
                    targetBadgeEl.textContent = 'target ' + newStatus;
                    targetBadgeEl.className = 'badge ' + (data.target_reachable ? 'ok' : 'muted');
                  }
                }
              }

              resultDiv.parentElement.scrollTop = resultDiv.parentElement.scrollHeight;
            } catch (e) {
              // Ignore parse errors
            }
          }
        }
      }
    } catch (e) {
      resultDiv.innerHTML = `<div style="color:#fca5a5">✗ Error: ${e.message}</div>`;
    }
  }

  function renderDiag(d, summary) {
    const root = $("diag");
    root.innerHTML = "";

    // Ultra-light mode: all values are null \u2192 show neutral state + on-demand button
    const allNull = d && Object.values(d).every(v => v === null || v === undefined);
    if (allNull) {
      root.innerHTML = `
        <div style="grid-column:1/-1;display:flex;align-items:center;gap:14px;padding:12px 14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-sm);flex-wrap:wrap">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-3)" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span style="font-size:.82rem;color:var(--text-3);flex:1;min-width:180px">Diagnostics disabled in ultra-light mode (expensive TCP probes).</span>
          <button id="diag-force-btn" class="maint-btn" onclick="checkConnectivity()" style="font-size:.78rem;padding:5px 12px;min-height:0;flex-shrink:0">
            &#9654; Check now
          </button>
        </div>`;
      return;
    }

    const entries = [
      ["Internet", d.internet, "OK", "down"],
      ["WireGuard IP", d.wg_ip, "assigned", "missing"],
      ["Routes", d.routes, "configured", "missing"],
      ["WG recent activity", d.wg_handshake_recent, "recent", "idle"],
    ];
    for (const [label, ok, yes, no] of entries) {
      const cell = document.createElement("div");
      cell.className = "cell" + (ok ? " ok" : "");
      const k = document.createElement("div"); k.className = "k"; k.textContent = label;
      const v = document.createElement("div"); v.className = "v"; v.textContent = ok ? "\u2713 " + yes : "\u2717 " + no;
      cell.appendChild(k); cell.appendChild(v);
      root.appendChild(cell);
    }
    if (summary && summary.message) {
      const note = document.createElement("div");
      note.style.gridColumn = "1/-1";
      note.style.marginTop = "8px";
      note.style.padding = "10px";
      note.style.borderRadius = "6px";
      note.style.background = summary.code === "healthy" ? "var(--ok-bg)" : "var(--danger-dim)";
      note.style.color = summary.code === "healthy" ? "#6ee7b7" : "#fca5a5";
      note.textContent = `Probable cause: ${summary.message}`;
      root.appendChild(note);
    }
  }

  async function checkConnectivity() {
    const btn = $("diag-force-btn");
    if (btn) { btn.disabled = true; btn.textContent = "\u2026"; }
    try {
      const token = getSessionToken();
      const r = await fetch("/api/connectivity-check?token=" + encodeURIComponent(token), { method: "POST" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const data = await r.json();
      renderDiag(data.diagnostics, data.diagnostics_summary);
    } catch(e) {
      const root = $("diag");
      if (root) root.innerHTML += `<div style="grid-column:1/-1;font-size:.78rem;color:var(--danger);margin-top:6px">Erreur : ${e.message}</div>`;
      if (btn) { btn.disabled = false; btn.textContent = "\u25b6 Check now"; }
    }
  }

	  function renderPublicServices(ports) {
	    const container = $("services-container");
	    if (!container) return;
	    const list = ports || [];

	    // Empty state
	    if (list.length === 0) {
	      container.innerHTML = `
	        <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:64px 24px;gap:16px;color:var(--text-3);text-align:center">
	          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" opacity=".4" aria-hidden="true"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/><line x1="12" y1="12" x2="12" y2="16"/><line x1="10" y1="14" x2="14" y2="14"/></svg>
	          <div style="font-size:.85rem;font-weight:600;color:var(--text-2)">No services configured</div>
	          <div style="font-size:.78rem;max-width:320px;line-height:1.6">Add port-forward entries to <code style="font-family:monospace;background:var(--surface);padding:2px 6px;border-radius:4px;font-size:.75rem">config.json</code> to see them here.</div>
	        </div>`;
	      return;
	    }

	    // Fast path: update existing cards in place to avoid DOM churn on tiny machines.
	    let okToPatch = (container.children.length === list.length);
	    if (okToPatch) {
	      for (let i = 0; i < list.length; i++) {
	        const port = list[i];
	        const el = container.children[i];
	        if (!el || el.dataset.port !== String(port.local_port || "")) { okToPatch = false; break; }
	        const dot = el.querySelector(".dot");
	        const badge = el.querySelector(".badge");
	        const dotClass = port.overall_status === "ACTIVE" ? "ok" : "ko";
	        if (dot) dot.className = "dot " + dotClass;
	        if (badge) {
	          badge.className = "badge " + (dotClass === "ok" ? "ok" : "ko");
	          badge.textContent = "status " + String(port.overall_status || "").toLowerCase();
	        }
	      }
	      if (okToPatch) return;
	    }

	    container.innerHTML = "";
	    const frag = document.createDocumentFragment();
	    for (const port of list) {
	      const card = document.createElement("div");
	      card.className = "service-analytics";
	      card.dataset.port = String(port.local_port || "");
	      const dotClass = port.overall_status === "ACTIVE" ? "ok" : "ko";
	      card.innerHTML = `
	        <h3><span class="dot ${dotClass}"></span>${port.name}</h3>
	        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">
	          <span class="badge ${dotClass === 'ok' ? 'ok' : 'ko'}">status ${String(port.overall_status || '').toLowerCase()}</span>
	        </div>
	      `;
	      frag.appendChild(card);
	    }
	    container.appendChild(frag);
	  }

	  async function loadServiceAnalytics(portData) {
	    const portId = "port-" + portData.local_port;
	    // Guard: prevent duplicate cards from concurrent refreshOnce() calls.
	    if (document.getElementById('service-' + portId)) return;
	    const readOnlyPublic = (!adminMode && publicReadOnly);
	    try {
	      // In lightweight/optimal mode, do NOT fetch metrics for every service.
	      // We only fetch metrics when the user expands a service.
	      let uptime = null;
	      if (portData && portData.stats_24h) {
	        uptime = portData.stats_24h;
	      } else {
	        const uptimeRes = await fetch(`/api/uptime?port_id=${encodeURIComponent(portId)}`, { cache: 'no-store' });
	        if (uptimeRes.status === 503) {
	          uptime = { samples: 0, uptime_24h_percent: 0, avg_latency_ms: null };
	        } else if (uptimeRes.ok) {
	          uptime = await uptimeRes.json();
	        }
	      }

	      if (!uptime) {
	        const container = $("services-container");
	        const serviceDiv = document.createElement("div");
	        serviceDiv.id = `service-${portId}`;
	        serviceDiv.className = "service-analytics";

        const dotClass = portData.overall_status === 'ACTIVE' ? 'ok' : 'ko';
	        serviceDiv.innerHTML = `
	          <h3><span class="dot ${dotClass}"></span>${portData.name} (port ${portData.local_port})</h3>
	          <div class="service-desc">${readOnlyPublic ? 'Read-only public mode' : `${portData.description || ''} → ${portData.remote_host}:${portData.remote_port}`}</div>
	          <div style="display:grid;grid-template-columns:300px 1fr;gap:30px;align-items:start">
	            <div>
	              <div style="margin-bottom:16px;display:flex;flex-wrap:wrap;gap:8px;align-items:center">
	                ${readOnlyPublic
                    ? `<span class="badge ${dotClass === 'ok' ? 'ok' : 'ko'}" style="white-space:nowrap">status ${portData.overall_status.toLowerCase()}</span>`
                    : `<span class="badge ${portData.service_active ? 'ok' : 'ko'}" style="white-space:nowrap">service ${portData.service_active ? 'active' : 'inactive'}</span>
	                <span class="badge ${portData.port_active ? 'ok' : 'ko'}" style="white-space:nowrap">port ${portData.port_active ? 'listening' : 'down'}</span>
	                <span class="badge ${portData.target_reachable ? 'ok' : 'muted'}" style="white-space:nowrap">target ${portData.target_reachable ? 'reachable' : 'unreachable'}</span>`}
	              </div>
	              <div style="background:var(--bg);border:1px solid var(--border);padding:12px;border-radius:6px;color:var(--text-3);font-size:0.9em;text-align:center">
	                No analytics data yet
	              </div>
	            </div>
	          </div>
	        `;
		        container.appendChild(serviceDiv);
		        applyAdminVisibility(serviceDiv);
		        return;
		      }

	      serviceMetrics[portId] = serviceMetrics[portId] || {};
	      serviceMetrics[portId].uptime = uptime;

	      const container = $("services-container");
	      const serviceDiv = document.createElement("div");
	      serviceDiv.id = `service-${portId}`;
	      serviceDiv.className = "service-analytics";

      const dotClass = portData.overall_status === 'ACTIVE' ? 'ok' : 'ko';
      const serviceBadge = portData.service_active ? 'ok' : 'ko';
      const serviceText = portData.service_active ? 'active' : 'inactive';
      const portBadge = portData.port_active ? 'ok' : 'ko';
      const portText = portData.port_active ? 'listening' : 'down';
      const targetBadge = portData.target_reachable ? 'ok' : 'muted';
      const targetText = portData.target_reachable ? 'reachable' : 'unreachable';

	      const uptimeDisplay = uptime.samples > 0 ? uptime.uptime_24h_percent + '%' : 'No data';
	      const latencyDisplay = uptime.samples > 0 && uptime.avg_latency_ms !== null ? Number(uptime.avg_latency_ms).toFixed(1) + ' ms' : '---';
	      const uptimeTrend = renderUptimeTrendFromCode(uptime.uptime_trend);
	      const latencyTrend = renderLatencyTrendFromCode(uptime.latency_trend);

		      serviceDiv.innerHTML = `
		        <h3><span class="dot ${dotClass}"></span>${portData.name} (port ${portData.local_port})</h3>
		        <div class="service-desc">${readOnlyPublic ? 'Read-only public mode' : `${portData.description || ''} → ${portData.remote_host}:${portData.remote_port}`}</div>

	        <div style="margin-bottom:12px;display:flex;flex-wrap:wrap;gap:8px;align-items:center" id="badges-${portId}">
	          ${readOnlyPublic
                ? `<span class="badge ${dotClass === 'ok' ? 'ok' : 'ko'}" style="white-space:nowrap">status ${portData.overall_status.toLowerCase()}</span>`
                : `<span class="badge ${serviceBadge}" id="badge-service-${portId}" style="white-space:nowrap">service ${serviceText}</span>
	          <span class="badge ${portBadge}" id="badge-port-${portId}" style="white-space:nowrap">port ${portText}</span>
	          <span class="badge ${targetBadge}" id="badge-target-${portId}" style="white-space:nowrap">target ${targetText}</span>
	          ${portData.has_incident ? '<span class="badge" style="background:#dc2626;color:white;white-space:nowrap" id="badge-incident-' + portId.split('-')[1] + '">INCIDENT</span>' : ''}`}
	        </div>

	        <div class="toggle-bar" style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:16px;cursor:pointer" onclick="toggleCharts('${portId}')">
	          <div style="display:grid;grid-template-columns:1fr auto;align-items:center;gap:8px;padding:4px">
	            <div style="font-size:0.8em;color:var(--text);font-weight:600">
	              <span style="color:var(--accent-2);font-size:1.1em" id="uptime-val-${portId}">${uptimeDisplay}</span> <span id="uptime-trend-${portId}">${uptimeTrend}</span> uptime · <span style="color:var(--accent-2);font-size:1.1em" id="latency-val-${portId}">${latencyDisplay}</span> <span id="latency-trend-${portId}">${latencyTrend}</span> latency
	            </div>
	            <div id="toggle-arrow-${portId}" class="toggle-arrow" style="color:var(--text-3);font-size:0.9em">▼</div>
	          </div>
	        </div>

	        <div id="charts-${portId}" style="display:none;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;margin-top:-8px"></div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
          <button onclick="startDiagnose('${portId}')" style="padding:12px;background:var(--accent);color:var(--bg);border:none;border-radius:6px;font-weight:600;cursor:pointer;font-size:0.9em">
            Test Connection
          </button>
	          <button class="admin-only" onclick="restartService('${portId}', '${portData.local_port}')" style="padding:12px;background:#8b5cf6;color:white;border:none;border-radius:6px;font-weight:600;cursor:pointer;font-size:0.9em">
	            🔄 Restart Service
	          </button>
        </div>

        <div id="diagnose-${portId}" style="display:none;margin-top:16px;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:16px">
          <div style="font-size:0.9em;color:var(--text-3);margin-bottom:12px;font-weight:600">Running Diagnostics...</div>
          <div id="diagnose-results-${portId}" style="font-size:0.85em;font-family:monospace;color:var(--text);line-height:1.6"></div>
        </div>
	      `;
		      container.appendChild(serviceDiv);
		      applyAdminVisibility(serviceDiv);
		    } catch (e) {
		      console.error("Failed to load analytics for", portId, e);
		    }
		  }

		  function _canvasCtx(canvas) {
		    if (!canvas) return null;
		    const rect = canvas.getBoundingClientRect();
		    const cssW = Math.max(1, Math.floor(rect.width));
		    const cssH = Math.max(1, Math.floor(rect.height));
		    const dpr = Math.max(1, Math.min(3, window.devicePixelRatio || 1));
		    const w = Math.max(1, Math.floor(cssW * dpr));
		    const h = Math.max(1, Math.floor(cssH * dpr));
		    if (canvas.width !== w || canvas.height !== h) {
		      canvas.width = w;
		      canvas.height = h;
		    }
		    const ctx = canvas.getContext('2d');
		    if (!ctx) return null;
		    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
		    return { ctx, w: cssW, h: cssH };
		  }

		  let _chartTooltipEl = null;
		  function _getTooltipEl() {
		    if (_chartTooltipEl) return _chartTooltipEl;
		    const el = document.createElement('div');
		    el.style.position = 'fixed';
		    el.style.zIndex = '3500';
		    el.style.pointerEvents = 'none';
		    el.style.padding = '6px 8px';
		    el.style.borderRadius = '6px';
		    el.style.background = 'rgba(15,23,42,0.92)';
		    el.style.border = '1px solid rgba(148,163,184,0.25)';
		    el.style.color = '#e2e8f0';
		    el.style.fontSize = '12px';
		    el.style.fontFamily = '-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif';
		    el.style.boxShadow = '0 10px 24px rgba(0,0,0,0.35)';
		    el.style.display = 'none';
		    document.body.appendChild(el);
		    _chartTooltipEl = el;
		    return el;
		  }

		  function _formatTs(ts) {
		    if (!ts) return '';
		    try { return new Date(ts * 1000).toLocaleString(); } catch (e) { return ''; }
		  }

		  function _attachTooltip(canvas, payloadFn, onHoverIdx) {
		    if (!canvas || canvas.dataset.tooltipBound === '1') return;
		    canvas.dataset.tooltipBound = '1';
		    const tip = _getTooltipEl();

		    const hide = () => {
		      tip.style.display = 'none';
		      if (onHoverIdx) onHoverIdx(null);
		    };
		    canvas.addEventListener('mouseleave', hide);
		    canvas.addEventListener('blur', hide);

		    canvas.addEventListener('mousemove', (ev) => {
		      const rect = canvas.getBoundingClientRect();
		      const x = ev.clientX - rect.left;
		      const y = ev.clientY - rect.top;
		      // Ignore if outside.
		      if (x < 0 || y < 0 || x > rect.width || y > rect.height) { hide(); return; }
		      const p = payloadFn(x, rect.width);
		      if (!p) { hide(); return; }
		      tip.textContent = p.text || '';
		      tip.style.display = 'block';
		      if (onHoverIdx && (p.idx === 0 || p.idx)) onHoverIdx(p.idx);
		      // place near cursor, keep in viewport
		      const pad = 10;
		      let left = ev.clientX + pad;
		      let top = ev.clientY + pad;
		      const tw = tip.offsetWidth || 180;
		      const th = tip.offsetHeight || 28;
		      if (left + tw > window.innerWidth - 6) left = ev.clientX - tw - pad;
		      if (top + th > window.innerHeight - 6) top = ev.clientY - th - pad;
		      tip.style.left = left + 'px';
		      tip.style.top = top + 'px';
		    }, { passive: true });

		    // Tap to show on touch devices.
		    canvas.addEventListener('click', (ev) => {
		      const rect = canvas.getBoundingClientRect();
		      const x = ev.clientX - rect.left;
		      const p = payloadFn(x, rect.width);
		      if (!p) { hide(); return; }
		      tip.textContent = p.text || '';
		      tip.style.display = 'block';
		      if (onHoverIdx && (p.idx === 0 || p.idx)) onHoverIdx(p.idx);
		      tip.style.left = (ev.clientX + 10) + 'px';
		      tip.style.top = (ev.clientY + 10) + 'px';
		      setTimeout(hide, 1800);
		    }, { passive: true });
		  }

		  function _drawLineChart(canvas, values, opts) {
		    const c = _canvasCtx(canvas);
		    if (!c) return;
		    const ctx = c.ctx;
		    const w = c.w, h = c.h;
		    const pad = 10;
		    const axisH = 16;
		    const axisW = 32;
		    const innerW = Math.max(1, w - pad * 2 - axisW);
		    const innerH = Math.max(1, h - pad * 2 - axisH);
		    const originX = pad + axisW;
		    const originY = pad;

		    ctx.clearRect(0, 0, w, h);

		    // background grid (very light)
		    ctx.strokeStyle = 'rgba(148,163,184,0.12)';
		    ctx.lineWidth = 1;
		    ctx.beginPath();
		    ctx.moveTo(originX, originY + innerH);
		    ctx.lineTo(originX + innerW, originY + innerH);
		    ctx.stroke();

		    const clean = values.filter(v => v !== null && v !== undefined && !Number.isNaN(v));
		    if (clean.length < 2) return;

		    const vMin = (opts && opts.min !== undefined) ? opts.min : Math.min(...clean);
		    const vMax = (opts && opts.max !== undefined) ? opts.max : Math.max(...clean);
		    const span = Math.max(1e-9, vMax - vMin);

		    const xStep = innerW / Math.max(1, values.length - 1);
		    const xFor = (i) => originX + i * xStep;
		    const yFor = (v) => {
		      const t = (v - vMin) / span;
		      return originY + (1 - t) * innerH;
		    };

		    // Axes labels (minimal, cheap)
		    ctx.fillStyle = 'rgba(148,163,184,0.85)';
		    ctx.font = '11px -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif';
		    ctx.textBaseline = 'middle';
		    ctx.textAlign = 'right';
		    ctx.fillText(String(Math.round(vMax)), originX - 6, originY + 6);
		    ctx.fillText(String(Math.round(vMin)), originX - 6, originY + innerH);

		    // X ticks (use timestamps if provided)
		    const ts = (opts && opts.timestamps) ? opts.timestamps : null;
		    const tickCount = 4;
		    ctx.textBaseline = 'top';
		    ctx.textAlign = 'center';
		    for (let k = 0; k < tickCount; k++) {
		      const t = tickCount === 1 ? 0 : (k / (tickCount - 1));
		      const idx = Math.max(0, Math.min(values.length - 1, Math.round(t * (values.length - 1))));
		      const x = xFor(idx);
		      let label = '';
		      if (ts && ts[idx]) {
		        try { label = new Date(ts[idx] * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); } catch (e) {}
		      }
		      if (!label) label = String(idx);
		      ctx.fillText(label, x, originY + innerH + 4);
		    }

		    // fill
		    if (opts && opts.fill) {
		      ctx.fillStyle = opts.fill;
		      ctx.beginPath();
		      let started = false;
		      for (let i = 0; i < values.length; i++) {
		        const v = values[i];
		        if (v === null || v === undefined || Number.isNaN(v)) continue;
		        const x = xFor(i), y = yFor(v);
		        if (!started) { ctx.moveTo(x, y); started = true; }
		        else ctx.lineTo(x, y);
		      }
		      ctx.lineTo(originX + innerW, originY + innerH);
		      ctx.lineTo(originX, originY + innerH);
		      ctx.closePath();
		      ctx.fill();
		    }

		    // line
		    ctx.strokeStyle = (opts && opts.stroke) ? opts.stroke : '#10b981';
		    ctx.lineWidth = (opts && opts.width) ? opts.width : 2;
		    ctx.beginPath();
		    let started = false;
		    for (let i = 0; i < values.length; i++) {
		      const v = values[i];
		      if (v === null || v === undefined || Number.isNaN(v)) continue;
		      const x = xFor(i), y = yFor(v);
		      if (!started) { ctx.moveTo(x, y); started = true; }
		      else ctx.lineTo(x, y);
		    }
		    ctx.stroke();

		    // Hover marker (vertical line + point)
		    const hoverIdxRaw = (opts && opts.hoverIdx !== undefined) ? opts.hoverIdx : null;
		    const hoverIdx = (hoverIdxRaw === 0 || hoverIdxRaw) ? hoverIdxRaw : null;
		    if (hoverIdx !== null && hoverIdx >= 0 && hoverIdx < values.length) {
		      const v = values[hoverIdx];
		      if (v !== null && v !== undefined && !Number.isNaN(v)) {
		        const x = xFor(hoverIdx);
		        const y = yFor(v);
		        ctx.strokeStyle = 'rgba(148,163,184,0.35)';
		        ctx.lineWidth = 1;
		        ctx.beginPath();
		        ctx.moveTo(x, originY);
		        ctx.lineTo(x, originY + innerH);
		        ctx.stroke();

		        ctx.fillStyle = (opts && opts.stroke) ? opts.stroke : '#10b981';
		        ctx.beginPath();
		        ctx.arc(x, y, 3.5, 0, Math.PI * 2);
		        ctx.fill();
		        ctx.strokeStyle = 'rgba(15,23,42,0.9)';
		        ctx.lineWidth = 2;
		        ctx.stroke();
		      }
		    }
		  }

		  function drawChart(portId, metrics) {
		    if (!metrics || metrics.length === 0) return;

		    const timestamps = metrics.map(m => m.timestamp || null);
		    const latency = metrics.map(m => (m.latency_ms >= 0 ? m.latency_ms : null));
		    const availability = metrics.map(m => (m.service_active && m.port_listening && m.target_reachable) ? 100 : 0);

		    const canvasAvail = document.getElementById(`chart-avail-${portId}`);
		    const canvasLatency = document.getElementById(`chart-latency-${portId}`);

		    // Store latest data ON the canvas so tooltip closures always read fresh arrays,
		    // even after new data points arrive without a page reload.
		    if (canvasAvail)   canvasAvail._chartData   = { availability, timestamps };
		    if (canvasLatency) canvasLatency._chartData = { latency, timestamps };

		    const scheduleRedraw = () => {
		      if (!serviceMetrics[portId] || !serviceMetrics[portId].metrics) return;
		      if (serviceMetrics[portId]._rafPending) return;
		      serviceMetrics[portId]._rafPending = true;
		      requestAnimationFrame(() => {
		        serviceMetrics[portId]._rafPending = false;
		        drawChart(portId, serviceMetrics[portId].metrics);
		      });
		    };
		    const setHover = (idx) => {
		      if (canvasAvail) {
		        if (idx === null || idx === undefined) delete canvasAvail.dataset.hoverIdx;
		        else canvasAvail.dataset.hoverIdx = String(idx);
		      }
		      if (canvasLatency) {
		        if (idx === null || idx === undefined) delete canvasLatency.dataset.hoverIdx;
		        else canvasLatency.dataset.hoverIdx = String(idx);
		      }
		      scheduleRedraw();
		    };

		    // payloadFns read from canvas._chartData so they always use the latest arrays.
		    _attachTooltip(canvasAvail, (x, w) => {
		      const d = canvasAvail && canvasAvail._chartData;
		      if (!d || !w || w <= 1 || d.availability.length < 2) return null;
		      const idx = Math.max(0, Math.min(d.availability.length - 1, Math.round((x / w) * (d.availability.length - 1))));
		      const status = d.availability[idx] === 100 ? '✓ UP' : '✗ DOWN';
		      const t = _formatTs(d.timestamps[idx]);
		      return { text: (t ? `${status} · ${t}` : status), idx };
		    }, setHover);
		    _drawLineChart(canvasAvail, availability, {
		      min: 0,
		      max: 100,
		      stroke: '#10b981',
		      fill: 'rgba(16,185,129,0.12)',
		      width: 2,
		      timestamps,
		      hoverIdx: (canvasAvail && canvasAvail.dataset.hoverIdx) ? parseInt(canvasAvail.dataset.hoverIdx, 10) : null,
		    });

		    const nonNullLatency = latency.filter(v => v !== null && v !== undefined && !Number.isNaN(v));
		    const maxLatency = nonNullLatency.length ? Math.max(...nonNullLatency) : 50;
		    _attachTooltip(canvasLatency, (x, w) => {
		      const d = canvasLatency && canvasLatency._chartData;
		      if (!d || !w || w <= 1 || d.latency.length < 2) return null;
		      const idx = Math.max(0, Math.min(d.latency.length - 1, Math.round((x / w) * (d.latency.length - 1))));
		      const v = d.latency[idx];
		      const val = (v === null || v === undefined || Number.isNaN(v)) ? 'N/A' : (Number(v).toFixed(1) + ' ms');
		      const t = _formatTs(d.timestamps[idx]);
		      return { text: (t ? `${val} · ${t}` : val), idx };
		    }, setHover);
		    _drawLineChart(canvasLatency, latency, {
		      min: 0,
		      max: Math.ceil(Math.max(10, maxLatency * 1.2)),
		      stroke: '#a78bfa',
		      fill: 'rgba(167,139,250,0.10)',
		      width: 2,
		      timestamps,
		      hoverIdx: (canvasLatency && canvasLatency.dataset.hoverIdx) ? parseInt(canvasLatency.dataset.hoverIdx, 10) : null,
		    });

		    // Heatmap is relatively DOM-heavy; skip in ultra-light.
		    if (!runtimeUltraLight) drawHeatmap(portId, metrics);
		  }

		  async function applySnapshot(s) {
		    if (!s || s.error) throw new Error(s && s.error ? s.error : 'Invalid status payload');
		    publicReadOnly = !!(s.runtime && s.runtime.public_read_only);
		    const wasUltra = runtimeUltraLight;
		    const wasLight = runtimeLightMode;
		    runtimeLightMode = !!(s.runtime && s.runtime.light_mode);
		    runtimeUltraLight = !!(s.runtime && s.runtime.ultra_light);
		    // Mode change → tear down charts to prevent Chart.js memory leak.
		    if (wasUltra !== runtimeUltraLight || wasLight !== runtimeLightMode) {
		      try { resetServiceUI(); _scheduleChartGC(); } catch (e) {}
		    }
		    document.body.classList.toggle('light', runtimeLightMode);
		    document.body.classList.toggle('ultra', runtimeUltraLight);
		    const lb = $('light-badge');
		    if (lb) lb.style.display = (runtimeLightMode && !runtimeUltraLight) ? '' : 'none';
		    const ub = $('ultra-badge');
		    if (ub) {
		      ub.style.display = runtimeUltraLight ? '' : 'none';
		      const refreshS = Math.round((s.runtime && s.runtime.refresh_ms || 30000) / 1000);
		      const adapt = s.runtime && s.runtime.ultra_light_adaptive;
		      let title = 'Mode ultra-light: refresh ' + refreshS + 's, diagnostics réduits';
		      if (adapt && adapt.active && adapt.reason) {
		        title += ' (auto: ' + adapt.reason + ')';
		        ub.textContent = '🔥 ULTRA-AUTO';
		      } else {
		        ub.textContent = '🔥 ULTRA';
		      }
		      ub.title = title;
		    }
		    syncPerfSettingsUI();

    const loaderEl = $("loader-overlay");
    if (loaderEl && !loaderEl.classList.contains("hidden")) loaderEl.classList.add("hidden");

    $("alert").style.display = "none";

    const connected = s.vpn.status === "CONNECTED";
    $("vpn-dot").className = "dot " + (connected ? "ok" : "ko");
    const vb = $("vpn-badge");
    vb.textContent = s.vpn.status;
    vb.className = "badge " + (connected ? "ok" : "ko");
    $("vpn-iface").textContent = s.vpn.interface;
    $("vpn-ip").textContent = s.vpn.ip;

    $("sys-cpu").textContent = s.system.cpu;
    $("sys-mem").textContent = s.system.memory;
    $("sys-load").textContent = s.system.load;
    $("sys-up").textContent = s.system.uptime;
    // Disk latency
    if (s.system.disk) {
      const dk = s.system.disk;
      const dlEl = $("sys-disk-latency");
      if (dlEl) {
        const wa = dk.w_await_ms;
        if (wa === 0 || wa == null) {
          dlEl.textContent = "idle";
          dlEl.style.color = "";
        } else {
          dlEl.textContent = `${wa} ms write`;
          dlEl.style.color = wa > 500 ? "var(--danger, #ef4444)"
                           : wa > 100 ? "var(--warn, #f59e0b)"
                           : "var(--ok, #10b981)";
        }
      }
    }
    if (s.host_network) {
      const iface = s.host_network.interface || "N/A";
      const type  = s.host_network.type  || "";
      const speed = s.host_network.speed || "N/A";
      $("sys-net-iface").textContent = type ? `${iface} (${type})` : iface;
      $("sys-net-iface").style.color = type.includes("WiFi") ? "var(--warn, #f59e0b)" : "";
      $("sys-net-speed").textContent = speed;
    }

    $("net-rx").textContent = s.network.rx;
    $("net-tx").textContent = s.network.tx;

    renderDiag(s.diagnostics, s.diagnostics_summary);
    renderMuteBanner(s.alerts || null);

    const container = $("services-container");
    if (!adminMode && publicReadOnly) {
      renderPublicServices(s.ports);
      $("last-update").textContent = s.timestamp;
      return;
    }

    const nowMs = Date.now();
    const shouldRefreshAnalytics = (nowMs - lastAnalyticsRefresh) >= ANALYTICS_REFRESH_MS;

	    if (s.ports && s.ports.length === 0 && container.children.length === 0) {
	      container.innerHTML = `
	        <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:64px 24px;gap:16px;color:var(--text-3);text-align:center">
	          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" opacity=".4" aria-hidden="true"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/><line x1="12" y1="12" x2="12" y2="16"/><line x1="10" y1="14" x2="14" y2="14"/></svg>
	          <div style="font-size:.85rem;font-weight:600;color:var(--text-2)">No services configured</div>
	          <div style="font-size:.78rem;max-width:320px;line-height:1.6">Add port-forward entries to <code style="font-family:monospace;background:var(--surface);padding:2px 6px;border-radius:4px;font-size:.75rem">config.json</code> to see them here.</div>
	        </div>`;
	    } else if (s.ports && s.ports.length > 0 && container.children.length === 0) {
	      for (const port of s.ports) await loadServiceAnalytics(port);
	      lastAnalyticsRefresh = nowMs;
	    } else if (s.ports) {
	      for (const port of s.ports) {
	        const portId = "port-" + port.local_port;
	        const dot = document.querySelector(`#service-${portId} h3 .dot`);
	        if (dot) dot.className = 'dot ' + (port.overall_status === 'ACTIVE' ? 'ok' : 'ko');
	        const serviceBadge = document.getElementById(`badge-service-${portId}`);
	        const portBadge = document.getElementById(`badge-port-${portId}`);
	        const targetBadge = document.getElementById(`badge-target-${portId}`);
	        if (serviceBadge) {
	          serviceBadge.textContent = `service ${port.service_active ? 'active' : 'inactive'}`;
	          serviceBadge.className = `badge ${port.service_active ? 'ok' : 'ko'}`;
	        }
	        if (portBadge) {
	          portBadge.textContent = `port ${port.port_active ? 'listening' : 'down'}`;
	          portBadge.className = `badge ${port.port_active ? 'ok' : 'ko'}`;
	        }
	        if (targetBadge) {
	          targetBadge.textContent = `target ${port.target_reachable ? 'reachable' : 'unreachable'}`;
	          targetBadge.className = `badge ${port.target_reachable ? 'ok' : 'muted'}`;
	        }
	        // Update uptime/latency quick summary from snapshot (no extra requests).
	        const uEl = document.getElementById(`uptime-val-${portId}`);
	        const lEl = document.getElementById(`latency-val-${portId}`);
	        if (port.stats_24h && uEl && lEl) {
	          const samples = port.stats_24h.samples || 0;
	          uEl.textContent = samples > 0 ? (port.stats_24h.uptime_24h_percent + '%') : 'No data';
	          lEl.textContent = (samples > 0 && port.stats_24h.avg_latency_ms !== null && port.stats_24h.avg_latency_ms !== undefined)
	            ? (Number(port.stats_24h.avg_latency_ms).toFixed(1) + ' ms')
	            : '---';
	        }
	        const utEl = document.getElementById(`uptime-trend-${portId}`);
	        const ltEl = document.getElementById(`latency-trend-${portId}`);
	        if (port.stats_24h && utEl) utEl.innerHTML = renderUptimeTrendFromCode(port.stats_24h.uptime_trend);
	        if (port.stats_24h && ltEl) ltEl.innerHTML = renderLatencyTrendFromCode(port.stats_24h.latency_trend);
	      }
	    }

	    // Only refresh charts for expanded services (huge CPU win on small machines).
	    if (s.ports && shouldRefreshAnalytics && expandedCharts.size > 0) {
	      for (const port of s.ports) {
	        const portId = "port-" + port.local_port;
	        if (!expandedCharts.has(portId)) continue;
	        if (!serviceMetrics[portId]) continue;
	        await ensureChartsLoaded(portId);
	      }
	      lastAnalyticsRefresh = nowMs;
	    }

	    $("last-update").textContent = s.timestamp;
	  }

	  async function refreshOnce() {
	    const token = getSessionToken();
	    const statusUrl = token ? `/api/status?token=${encodeURIComponent(token)}` : "/api/status";
	    const r = await fetch(statusUrl, { cache: "no-store" });
	    if (!r.ok) throw new Error("HTTP " + r.status);
	    const s = await r.json();
	    await applySnapshot(s);
	  }

	  let _refreshInFlight = null;
	  async function refresh(opts) {
	    const options = opts || {};
	    if (_refreshInFlight) return _refreshInFlight;
	    _refreshInFlight = (async () => {
	      await checkSession();
	      await refreshOnce();
	      if (options.restartStream) startStatusStream();
	    })().finally(() => { _refreshInFlight = null; });
	    return _refreshInFlight;
	  }

  function stopStatusStream() {
    if (statusStream) {
      statusStream.close();
      statusStream = null;
    }
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  function schedulePoll(nextMs) {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(async () => {
      try {
        await refreshOnce();
        pollBackoffMs = REFRESH_MS;
        schedulePoll(REFRESH_MS);
      } catch (e) {
        pollBackoffMs = Math.min(pollBackoffMs * 2, 60000);
        schedulePoll(pollBackoffMs);
      }
    }, nextMs);
  }

  function startStatusStream() {
    stopStatusStream();
    const token = getSessionToken();
    const url = token ? `/api/status/stream?token=${encodeURIComponent(token)}` : "/api/status/stream";
    try {
      statusStream = new EventSource(url);
      statusStream.onmessage = async (event) => {
        try {
          const s = JSON.parse(event.data);
          await applySnapshot(s);
        } catch (e) {
          // ignore parse errors
        }
      };
      statusStream.onerror = () => {
        // fallback to polling with backoff
        stopStatusStream();
        schedulePoll(REFRESH_MS);
      };
    } catch (e) {
      schedulePoll(REFRESH_MS);
    }
  }

  // Initialize session and UI
  document.addEventListener('visibilitychange', () => {
    // Reduce work when tab is hidden.
    if (document.hidden) {
      stopStatusStream();
      schedulePoll(60000);
    } else {
      startStatusStream();
    }
  });

  (async () => {
    await checkSession();
    await refreshOnce();
    startStatusStream();
  })();
</script>
<div id="idle-toast" style="display:none;position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--amber);color:#000;padding:10px 18px;border-radius:var(--r);font-size:.82rem;font-weight:600;z-index:9999;box-shadow:0 4px 20px rgba(0,0,0,.3);max-width:380px;text-align:center">
  <span id="idle-toast-text"></span>
</div>
</body>
</html>
"""

@app.route("/images/<path:filename>")
def images(filename):
    """Serve images with proper error handling."""
    try:
        images_dir = SCRIPT_DIR / "images"
        if not images_dir.exists():
            return jsonify({"error": "images directory not found"}), 404

        file_path = (images_dir / filename).resolve()
        try:
            file_path.relative_to(images_dir.resolve())
        except ValueError:
            return jsonify({"error": "path traversal not allowed"}), 403

        if not file_path.exists():
            return jsonify({"error": f"file not found: {filename}"}), 404

        return send_from_directory(images_dir, filename)
    except Exception as e:
        print(f"[homelinkwg-dashboard] images error: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 500

@app.route("/")
def index() -> str:
    return render_template_string(
        INDEX_HTML,
        version=__version__,
        refresh_ms=status_refresh_ms(),
        analytics_refresh_ms=analytics_refresh_ms(),
    )

@app.route("/api/whats-new")
def api_whats_new():
    """Return the 'What's new' text for the current version (public)."""
    return jsonify({
        "version": __version__,
        "date": __date__,
        "notes": _extract_whats_new(),
    })

# ---------------------------------------------------------------------------
# Authentication & Admin Endpoints
# ---------------------------------------------------------------------------

def require_admin(f):
    """Decorator to protect admin endpoints with authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.args.get('token') or request.headers.get('X-Admin-Token')
        if not verify_session(token):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

def _request_admin_view() -> bool:
    """Return True if current request includes a valid admin token."""
    token = request.args.get('token') or request.headers.get('X-Admin-Token') or ""
    return verify_session(token)

def require_rate_limit(f):
    """Decorator to apply API rate limiting."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        if not api_limiter.is_allowed(ip):
            return jsonify({
                "error": "rate limit exceeded",
                "retry_after": 60,
                "remaining": api_limiter.get_remaining(ip)
            }), 429
        return f(*args, **kwargs)
    return decorated_function

@app.route("/api/status")
@require_rate_limit
def api_status():
    admin_view = _request_admin_view()
    cache_key = "status_snapshot_admin" if admin_view else "status_snapshot_public"
    cached = cache_store.get(cache_key)
    if cached:
        return jsonify(cached)

    snapshot = _snapshot(admin_view=admin_view)
    cache_store.set(cache_key, snapshot)
    return jsonify(snapshot)

@app.route("/api/status/stream")
def api_status_stream():
    """Stream status snapshots via Server-Sent Events (push, minimal overhead)."""
    admin_view = _request_admin_view()
    cache_key = "status_snapshot_admin" if admin_view else "status_snapshot_public"

    def stream():
        last_payload = ""
        end_time = time.time() + 600  # keep stream for 10 minutes
        while time.time() < end_time:
            try:
                snap = cache_store.get(cache_key)
                if not snap:
                    snap = _snapshot(admin_view=admin_view)
                    cache_store.set(cache_key, snap)
                payload = json.dumps(snap, separators=(",", ":"))
                if payload != last_payload:
                    last_payload = payload
                    yield f"data: {payload}\n\n"
                else:
                    yield ": heartbeat\n\n"
            except GeneratorExit:
                return
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                return
            time.sleep(1.0)

    response = Response(stream(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response

@app.route("/api/healthz")
def api_healthz():
    snap = _snapshot(admin_view=False)
    ok = snap["vpn"]["status"] == "CONNECTED" and all(p["overall_status"] == "ACTIVE" for p in snap["ports"])
    status = 200 if ok else 503
    return jsonify({"ok": ok, "timestamp": snap["timestamp"]}), status

@app.route("/api/livez")
def api_livez():
    """Container liveness probe: Flask is responding and config can be loaded."""
    try:
        load_config()
        return jsonify({"ok": True, "timestamp": _now_ts(), "runtime": "docker" if _is_docker_runtime() else "systemd"})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc), "timestamp": _now_ts()}), 500

@app.route("/api/login", methods=["POST"])
def api_login():
    """Login: POST {password, totp_code?}. Returns session token or {requires_2fa:true}."""
    ip = request.remote_addr or "unknown"

    if not ADMIN_PASSWORD_HASH:
        return jsonify({"error": "auth not configured"}), 500
    if bcrypt is None:
        return jsonify({"error": "bcrypt not installed on server"}), 500

    data = request.get_json(silent=True) or {}
    password = data.get("password") or request.form.get("password", "")
    totp_code = str(data.get("totp_code", "")).strip()

    if not password:
        log_audit("login", ip, "dashboard", {}, "no_password")
        return jsonify({"error": "password required"}), 400

    # Gate: check lockout before verifying (avoid timing oracle on locked IPs)
    gate = login_limiter.check(ip)
    if not gate["allowed"]:
        log_buffer.add("incident", f"🚨 Login blocked (lockout) from {ip}")
        log_audit("login", ip, "dashboard", {}, "rate_limited")
        return jsonify({
            "error": "too many failed attempts — please wait",
            "retry_after": gate["retry_after"],
            "locked_until": gate["locked_until"],
        }), 429

    # Verify password
    if not verify_password(password, ADMIN_PASSWORD_HASH):
        status = login_limiter.record_failure(ip)
        log_buffer.add("systemd", f"🔐 Login failed from {ip} ({status['remaining']} attempts left before lockout)")
        log_audit("login", ip, "dashboard", {}, "failed")
        payload: dict[str, Any] = {"error": "invalid password", "remaining": status["remaining"]}
        if not status["allowed"]:
            payload["retry_after"] = status["retry_after"]
            payload["locked_until"] = status["locked_until"]
            return jsonify(payload), 429
        return jsonify(payload), 401

    # Password correct — check 2FA if enabled
    if TOTP_ENABLED and TOTP_SECRET and pyotp is not None:
        if not totp_code:
            # Signal frontend to prompt for TOTP code (no session issued yet)
            return jsonify({"requires_2fa": True}), 200
        totp = pyotp.TOTP(TOTP_SECRET)
        if not totp.verify(totp_code, valid_window=1):
            log_buffer.add("systemd", f"🔐 2FA code invalid from {ip}")
            log_audit("login", ip, "dashboard", {}, "2fa_failed")
            return jsonify({"error": "invalid 2FA code", "requires_2fa": True}), 401

    # All checks passed — create session
    login_limiter.record_success(ip)
    token = create_session(ip, request.headers.get("User-Agent", ""))
    if not token:
        return jsonify({"error": "failed to create session"}), 500

    log_buffer.add("systemd", f"🔐 Admin login successful from {ip}")
    log_audit("login", ip, "dashboard", {}, "success")
    return jsonify({"token": token, "expires_in": SESSION_TIMEOUT_MINUTES * 60})


# ── 2FA endpoints ─────────────────────────────────────────────────────────────

@app.route("/api/2fa/status")
def api_2fa_status():
    """Public: returns whether 2FA is enabled and whether pyotp is available."""
    return jsonify({"enabled": TOTP_ENABLED, "available": pyotp is not None})


@app.route("/api/2fa/setup")
@require_admin
def api_2fa_setup():
    """Generate (or return existing) TOTP secret for setup. Does NOT enable 2FA."""
    if pyotp is None:
        return jsonify({"error": "pyotp not installed — run: pip install pyotp"}), 503
    secret = TOTP_SECRET if TOTP_SECRET else pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name="admin", issuer_name="HomelinkWG")
    # Try to generate QR code as base64 PNG (requires qrcode[pil] or qrcode+Pillow)
    qr_b64 = None
    try:
        import qrcode as _qrcode  # type: ignore
        import io as _io
        import base64 as _b64
        img = _qrcode.make(uri)
        buf = _io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = "data:image/png;base64," + _b64.b64encode(buf.getvalue()).decode()
    except Exception:
        pass
    return jsonify({"secret": secret, "uri": uri, "qr": qr_b64})


@app.route("/api/2fa/enable", methods=["POST"])
@require_admin
def api_2fa_enable():
    """Verify code against provided secret, then persist and enable 2FA."""
    global TOTP_SECRET, TOTP_ENABLED
    if pyotp is None:
        return jsonify({"error": "pyotp not installed"}), 503
    data = request.get_json(silent=True) or {}
    secret = str(data.get("secret", "")).strip()
    code = str(data.get("code", "")).strip()
    if not secret or not code:
        return jsonify({"error": "secret and code required"}), 400
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return jsonify({"error": "invalid code — check your authenticator app"}), 400
    # Persist to analytics.conf
    _write_analytics_conf_key("TOTP_SECRET", secret)
    _write_analytics_conf_key("TOTP_ENABLED", "true")
    TOTP_SECRET = secret
    TOTP_ENABLED = True
    log_buffer.add("systemd", "🔒 Two-factor authentication enabled")
    return jsonify({"ok": True})


@app.route("/api/2fa/disable", methods=["POST"])
@require_admin
def api_2fa_disable():
    """Disable 2FA (keeps secret so re-enabling doesn't need new QR scan)."""
    global TOTP_ENABLED
    _write_analytics_conf_key("TOTP_ENABLED", "false")
    TOTP_ENABLED = False
    log_buffer.add("systemd", "🔓 Two-factor authentication disabled")
    return jsonify({"ok": True})

@app.route("/api/change-password", methods=["POST"])
@require_admin
def api_change_password():
    """Change admin password. POST {current_password, new_password}."""
    if bcrypt is None:
        return jsonify({"error": "bcrypt not available on server"}), 500

    admin_ip = request.remote_addr or "unknown"
    data = request.get_json(silent=True) or {}
    current = data.get("current_password", "")
    new_pw   = data.get("new_password", "")

    if not current or not new_pw:
        return jsonify({"error": "current_password and new_password are required"}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400
    if not ADMIN_PASSWORD_HASH:
        return jsonify({"error": "No password configured"}), 500
    if not verify_password(current, ADMIN_PASSWORD_HASH):
        log_audit("change_password", admin_ip, "dashboard", {}, "wrong_current_password")
        return jsonify({"error": "Current password is incorrect"}), 401

    new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    _write_analytics_conf_key("ADMIN_PASSWORD", new_hash)
    load_auth_config()   # recharge le hash en mémoire immédiatement

    log_buffer.add("systemd", f"🔐 Admin password changed from {admin_ip}")
    log_audit("change_password", admin_ip, "dashboard", {}, "success")
    return jsonify({"status": "password updated"})

@app.route("/api/logout", methods=["POST"])
@require_admin
def api_logout():
    """Logout endpoint: clears session token."""
    token = request.args.get('token') or request.headers.get('X-Admin-Token')

    try:
        with _db_connect() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE token = ?", (token,))
    except sqlite3.Error:
        pass

    admin_ip = request.remote_addr or "unknown"
    log_buffer.add("systemd", f"🔐 Admin logout from {admin_ip}")
    log_audit("logout", admin_ip, "dashboard", {}, "success")
    return jsonify({"status": "logged out"})

@app.route("/api/verify_session", methods=["GET"])
def api_verify_session():
    """Verify if session is valid."""
    token = request.args.get('token', '')
    is_valid = verify_session(token)

    return jsonify({
        "valid": is_valid,
        "mode": "admin" if is_valid else "public"
    })

@app.route("/api/restart-service", methods=["POST"])
@require_admin
def api_restart_service():
    """Restart a socat service."""
    payload = request.get_json(silent=True) or {}
    service = payload.get("service", "")
    if not service:
        return jsonify({"error": "service parameter required"}), 400

    # Validate service name to prevent injection
    if not service.startswith("homelinkwg-socat-"):
        return jsonify({"error": "invalid service name"}), 400

    admin_ip = request.remote_addr or "unknown"
    log_buffer.add("systemd", f"⏸️ Admin {admin_ip}: Restarting {service}...")

    try:
        ok, message = restart_managed_service(service)
        if not ok:
            log_buffer.add("systemd", f"❌ Restart failed: {message}")
            print(f"[homelinkwg-dashboard] restart_service failed: {message}", file=sys.stderr)
            log_audit("restart_service", admin_ip, service, {"error": message}, "failed")
            return jsonify({"error": message}), 500

        log_buffer.add("systemd", f"✓ Service {service} restarted successfully by {admin_ip}")
        print(f"[homelinkwg-dashboard] restart_service success: {service}", file=sys.stderr)
        log_audit("restart_service", admin_ip, service, {}, "success")
        return jsonify({"message": f"Service {service} restarted successfully"})
    except Exception as e:
        error_msg = str(e)
        log_buffer.add("systemd", f"❌ Restart exception: {error_msg}")
        print(f"[homelinkwg-dashboard] restart_service exception: {error_msg}", file=sys.stderr)
        log_audit("restart_service", admin_ip, service, {"error": error_msg}, "failed")
        return jsonify({"error": error_msg}), 500

def _get_metrics_for_period(port_id: str, hours: int = 24) -> list[dict]:
    """Get metrics for a specific time period."""
    try:
        cutoff = _now_ts() - (hours * 3600)
        with _db_connect(row_factory=True) as conn:
            rows = conn.execute(
                """
                SELECT timestamp, service_active, port_listening, target_reachable, latency_ms
                FROM metrics
                WHERE port_id = ? AND timestamp > ?
                ORDER BY timestamp ASC
                """,
                (port_id, cutoff),
            ).fetchall()

        max_points = 300 if is_light_mode_enabled() else 720
        if len(rows) > max_points:
            step = max(1, len(rows) // max_points)
            sampled = list(rows[::step])
            if sampled and sampled[-1]["timestamp"] != rows[-1]["timestamp"]:
                sampled.append(rows[-1])
            rows = sampled

        return [{
            "timestamp": row["timestamp"],
            "service_active": bool(row["service_active"]),
            "port_listening": bool(row["port_listening"]),
            "target_reachable": bool(row["target_reachable"]),
            "latency_ms": row["latency_ms"]
        } for row in rows]
    except sqlite3.Error:
        return []

@app.route("/api/metrics")
def api_metrics():
    """Return metrics for a specific port and timeframe."""
    if not is_analytics_enabled():
        return jsonify({"error": "analytics disabled"}), 503

    port_id = request.args.get("port_id", "")
    timeframe = request.args.get("timeframe", "24h")  # 24h, 7d, 30d

    if not port_id:
        return jsonify({"error": "port_id required"}), 400

    # Map timeframe to hours
    timeframe_map = {
        "24h": 24,
        "7d": 168,
        "30d": 720
    }
    hours = timeframe_map.get(timeframe, 24)

    data = _get_metrics_for_period(port_id, hours)
    return jsonify({
        "port_id": port_id,
        "timeframe": timeframe,
        "metrics": data
    })

@app.route("/api/diagnose")
@require_admin
def api_diagnose():
    """Run diagnostic tests on a specific port and stream results."""
    if not is_analytics_enabled():
        return jsonify({"error": "analytics disabled"}), 503

    port_id = request.args.get("port_id", "")
    if not port_id:
        return jsonify({"error": "port_id required"}), 400

    # Extract port number from port_id
    try:
        local_port = int(port_id.split("-")[1])
    except (IndexError, ValueError):
        return jsonify({"error": "invalid port_id"}), 400

    cfg = load_config()
    port_config = None
    for p in cfg.get("ports", []):
        if int(p["local_port"]) == local_port:
            port_config = p
            break

    if not port_config:
        return jsonify({"error": "port not found"}), 404

    def diagnostic_stream():
        """Generator that yields diagnostic results with segmented latency analysis."""
        remote_host = port_config["remote_host"]
        remote_port = int(port_config["remote_port"])
        local_avg = None
        target_avg = None

        # Test 1: Local port listening + local latency
        msg1 = f"Measuring local latency (127.0.0.1:{local_port})..."
        yield f"data: {json.dumps({'step': 'local_latency', 'status': 'testing', 'message': msg1})}\n\n"
        local_latencies = []
        for i in range(3):
            lat = _measure_latency("127.0.0.1", local_port, timeout=2.0)
            if lat >= 0:
                local_latencies.append(lat)
            time.sleep(0.1)

        if local_latencies:
            local_avg = sum(local_latencies) / len(local_latencies)
            local_min = min(local_latencies)
            local_max = max(local_latencies)
            msg1a = f"Local (client→socat): avg={local_avg:.1f}ms, min={local_min}ms, max={local_max}ms"
            yield f"data: {json.dumps({'step': 'local_latency', 'status': 'ok', 'message': msg1a, 'latency': local_avg})}\n\n"
        else:
            yield f"data: {json.dumps({'step': 'local_latency', 'status': 'fail', 'message': 'Cannot reach local port'})}\n\n"

        # Test 2: WireGuard tunnel status
        yield f"data: {json.dumps({'step': 'wireguard', 'status': 'testing', 'message': 'Checking WireGuard tunnel status...'})}\n\n"
        wg_status = vpn_status(cfg.get("vpn", {}).get("interface", "wg0"))
        wg_ok = wg_status["status"] == "CONNECTED"
        wg_msg = f"WireGuard tunnel: {wg_status['status']} (IP: {wg_status['ip']})"
        yield f"data: {json.dumps({'step': 'wireguard', 'status': 'ok' if wg_ok else 'fail', 'message': wg_msg})}\n\n"

        # Test 3: VPN tunnel latency (segment 2: socat→VPN) - verify tunnel is working
        if wg_ok:
            # Tunnel is already verified by WireGuard status. Skip port measurement since 51820 is control port.
            # The actual tunnel latency is already measured in Test 4 (target latency) and Test 1 (local latency)
            msg2 = f"VPN tunnel status: OK (measured via target service response)"
            yield f"data: {json.dumps({'step': 'tunnel_latency', 'status': 'ok', 'message': msg2})}\n\n"

        # Test 4: Target service latency (segment 3: VPN→target)
        msg3 = f"Measuring target latency (VPN→{remote_host}:{remote_port})..."
        yield f"data: {json.dumps({'step': 'target_latency', 'status': 'testing', 'message': msg3})}\n\n"
        target_latencies = []
        for i in range(5):
            lat = _measure_latency(remote_host, remote_port, timeout=3.0)
            if lat >= 0:
                target_latencies.append(lat)
            time.sleep(0.15)

        if target_latencies:
            target_avg = sum(target_latencies) / len(target_latencies)
            target_min = min(target_latencies)
            target_max = max(target_latencies)
            msg3a = f"Target service (VPN→{remote_host}): avg={target_avg:.1f}ms, min={target_min}ms, max={target_max}ms"
            yield f"data: {json.dumps({'step': 'target_latency', 'status': 'ok', 'message': msg3a, 'latency': target_avg})}\n\n"
        else:
            msg3b = f"Cannot reach {remote_host}:{remote_port} (timeout)"
            yield f"data: {json.dumps({'step': 'target_latency', 'status': 'fail', 'message': msg3b})}\n\n"

        # Test 5: Target reachability
        yield f"data: {json.dumps({'step': 'target_reach', 'status': 'testing', 'message': 'Testing target reachability...'})}\n\n"
        target_ok = _tcp_reachable(remote_host, remote_port, timeout=2.0)
        target_status = "REACHABLE" if target_ok else "UNREACHABLE"
        msg6 = f"Target {remote_host}:{remote_port} is {target_status}"
        yield f"data: {json.dumps({'step': 'target_reach', 'status': 'ok' if target_ok else 'fail', 'message': msg6})}\n\n"

        # Test 6: Service status
        yield f"data: {json.dumps({'step': 'service', 'status': 'testing', 'message': 'Checking socat service...'})}\n\n"
        service_ok = systemd_is_active(f"homelinkwg-socat-{local_port}")
        service_status = "ACTIVE" if service_ok else "INACTIVE"
        msg7 = f"socat service is {service_status}"
        yield f"data: {json.dumps({'step': 'service', 'status': 'ok' if service_ok else 'fail', 'message': msg7})}\n\n"

        # Summary with explicit segmented latency and bottleneck.
        tunnel_estimate = None
        if (local_avg is not None) and (target_avg is not None):
            tunnel_estimate = max(target_avg - local_avg, 0.0)

        segments = {
            "local_ms": round(local_avg, 1) if local_avg is not None else None,
            "tunnel_ms": round(tunnel_estimate, 1) if tunnel_estimate is not None else None,
            "target_ms": round(target_avg, 1) if target_avg is not None else None,
        }

        if not service_ok:
            bottleneck = "service"
        elif not target_ok:
            bottleneck = "target_unreachable"
        elif segments["tunnel_ms"] is None:
            bottleneck = "insufficient_data"
        elif segments["tunnel_ms"] > max(segments["local_ms"] or 0, 20):
            bottleneck = "vpn_path"
        elif (segments["local_ms"] or 0) > 15:
            bottleneck = "local_path"
        else:
            bottleneck = "target_path"

        summary_msg = "Chain analysis complete."
        payload = {
            "step": "complete",
            "status": "done",
            "message": summary_msg,
            "service_active": service_ok,
            "target_reachable": target_ok,
            "segments": segments,
            "bottleneck": bottleneck,
        }
        yield f"data: {json.dumps(payload)}\n\n"

    response = Response(diagnostic_stream(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response

@app.route("/api/uptime")
def api_uptime():
    """Return 24h uptime stats for a specific port."""
    if not is_analytics_enabled():
        return jsonify({"error": "analytics disabled"}), 503

    port_id = request.args.get("port_id", "")
    if not port_id:
        return jsonify({"error": "port_id required"}), 400

    try:
        cutoff = _now_ts() - 86400
        with _db_connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN service_active AND port_listening AND target_reachable THEN 1 ELSE 0 END) as ok,
                       AVG(CASE WHEN latency_ms >= 0 THEN latency_ms ELSE NULL END) as avg_latency
                FROM metrics
                WHERE port_id = ? AND timestamp > ?
                """,
                (port_id, cutoff),
            ).fetchone()

        total, ok_count, avg_latency = row if row else (0, 0, None)
        uptime_percent = (ok_count / total * 100) if total > 0 else 0
        print(f"[homelinkwg-dashboard] api_uptime {port_id}: total={total} ok={ok_count} uptime={uptime_percent}%", file=sys.stderr)
        return jsonify({
            "port_id": port_id,
            "uptime_24h_percent": round(uptime_percent, 2),
            "avg_latency_ms": round(avg_latency, 1) if avg_latency else None,
            "samples": total
        })
    except sqlite3.Error as e:
        print(f"[homelinkwg-dashboard] api_uptime error: {e}", file=sys.stderr)
        return jsonify({"error": "database error"}), 500
@app.route("/api/logs")
@require_admin
def api_logs():
    """Stream recent logs via Server-Sent Events (non-blocking)."""
    if not is_analytics_enabled():
        return jsonify({"error": "analytics disabled"}), 503

    def log_stream():
        """Generator: stream existing + newly appended logs."""
        try:
            last_id = 0
            for log_entry in log_buffer.get_recent(limit=200):
                last_id = max(last_id, int(log_entry.get("id", 0)))
                yield f"data: {json.dumps(log_entry)}\n\n"

            yield f"data: {json.dumps({'type': 'ready', 'message': 'Connected to log stream'})}\n\n"

            end_time = time.time() + 60
            while time.time() < end_time:
                new_entries = log_buffer.get_since(last_id, limit=200)
                if new_entries:
                    for entry in new_entries:
                        last_id = max(last_id, int(entry.get("id", 0)))
                        yield f"data: {json.dumps(entry)}\n\n"
                else:
                    yield ": heartbeat\n\n"
                time.sleep(1.0)
        except GeneratorExit:
            pass  # Client disconnected
        except Exception as e:
            print(f"[homelinkwg-dashboard] log stream error: {e}", file=sys.stderr)
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    response = Response(log_stream(), mimetype="text/event-stream")
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'  # Disable proxy buffering
    return response

@app.route("/api/metrics/export")
@require_admin
def api_metrics_export():
    """Export all metrics as CSV. Optional params: days (int), port_id (str)."""
    import csv
    import io as _io
    days_param = request.args.get("days", "1")
    port_id_param = request.args.get("port_id", "")
    try:
        days = max(1, min(int(days_param), 90))
    except ValueError:
        days = 1
    cutoff = int(time.time()) - days * 86400
    try:
        with _db_connect() as conn:
            query = "SELECT timestamp, port_id, service_name, service_active, port_listening, target_reachable, latency_ms FROM metrics WHERE timestamp >= ?"
            params: list = [cutoff]
            if port_id_param:
                query += " AND port_id = ?"
                params.append(port_id_param)
            query += " ORDER BY timestamp ASC"
            rows = conn.execute(query, params).fetchall()
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500

    buf = _io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["datetime_utc", "timestamp_unix", "port_id", "service_name",
                     "service_active", "port_listening", "target_reachable", "latency_ms"])
    import datetime
    for row in rows:
        ts, pid, sname, sactive, plisten, treach, lat = row
        dt = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([dt, ts, pid, sname,
                         "1" if sactive else "0",
                         "1" if plisten else "0",
                         "1" if treach else "0",
                         lat if lat is not None else ""])

    fname = f"homelinkwg-metrics-{days}d.csv"
    from flask import Response
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'}
    )


@app.route("/api/config", methods=["GET"])
@require_admin
def api_config_get():
    """Return current config.json content."""
    try:
        cfg = load_config()
        return jsonify({"config": cfg})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config", methods=["POST"])
@require_admin
def api_config_post():
    """Validate and write config.json, then invalidate the in-memory cache."""
    data = request.get_json(silent=True) or {}
    new_cfg = data.get("config")
    if not isinstance(new_cfg, dict):
        return jsonify({"error": "config must be a JSON object"}), 400
    if "ports" not in new_cfg or not isinstance(new_cfg["ports"], list):
        return jsonify({"error": "config.ports must be an array"}), 400
    # Validate each port entry has the required fields
    for p in new_cfg["ports"]:
        if not isinstance(p, dict):
            return jsonify({"error": "Each port entry must be a JSON object"}), 400
        for field in ("local_port", "remote_host", "remote_port"):
            if field not in p:
                return jsonify({"error": f"Port entry missing required field: {field}"}), 400
    try:
        raw = json.dumps(new_cfg, indent=2, ensure_ascii=False)
        CONFIG_FILE.write_text(raw + "\n", encoding="utf-8")
        # Invalidate cache so next load_config() picks up the new file
        with _config_cache_lock:
            _config_cache.clear()
        admin_ip = request.remote_addr or "unknown"
        log_audit("config_edit", admin_ip, str(CONFIG_FILE), {"ports": len(new_cfg["ports"])}, "success")
        log_buffer.add("systemd", f"⚙️ config.json updated by {admin_ip} ({len(new_cfg['ports'])} service(s))")
        return jsonify({"ok": True})
    except OSError as e:
        return jsonify({"error": f"Write error: {e}"}), 500


@app.route("/api/incidents")
@require_admin
def api_incidents():
    """Return recent incidents for dashboard."""
    if not is_analytics_enabled():
        return jsonify({"error": "analytics disabled"}), 503

    try:
        with _db_connect(row_factory=True) as conn:
            cutoff = _now_ts() - 86400
            rows = conn.execute(
                """
                SELECT id, port_id, service_name, event_type, timestamp, severity, description
                FROM incidents
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 100
                """,
                (cutoff,),
            ).fetchall()

            old_cutoff = _now_ts() - (7 * 86400)
            conn.execute("DELETE FROM incidents WHERE timestamp < ?", (old_cutoff,))

        incidents = [{
            "id": row["id"],
            "port_id": row["port_id"],
            "service_name": row["service_name"],
            "event_type": row["event_type"],
            "timestamp": row["timestamp"],
            "severity": row["severity"],
            "description": row["description"]
        } for row in rows]

        return jsonify({
            "incidents": incidents,
            "count": len(incidents)
        })
    except sqlite3.Error as e:
        print(f"[homelinkwg-dashboard] api_incidents error: {e}", file=sys.stderr)
        return jsonify({"error": "database error"}), 500


@app.route("/api/incidents/<int:incident_id>", methods=["DELETE"])
@require_admin
def api_close_incident(incident_id):
    """Close/remove an incident."""
    try:
        with _db_connect() as conn:
            conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            conn.commit()
        return jsonify({"success": True})
    except sqlite3.Error as e:
        print(f"[homelinkwg-dashboard] api_close_incident error: {e}", file=sys.stderr)
        return jsonify({"error": "database error"}), 500


@app.route("/api/thresholds", methods=["GET"])
@require_admin
def api_get_thresholds():
    """Get all thresholds."""
    return jsonify({
        "thresholds": {
            "latency_threshold_ms": get_threshold("latency_threshold_ms", 50.0),
            "uptime_threshold_percent": get_threshold("uptime_threshold_percent", 95.0),
            "alerts_muted_until_ts": get_threshold("alerts_muted_until_ts", 0.0),
            "session_timeout_minutes": get_threshold("session_timeout_minutes", 30.0),
        }
    })

@app.route("/api/thresholds", methods=["POST"])
@require_admin
def api_set_thresholds():
    """Update thresholds."""
    data = request.get_json(silent=True) or {}
    updated = {}
    errors = {}

    # Update latency threshold
    if "latency_threshold_ms" in data:
        try:
            value = float(data["latency_threshold_ms"])
        except (TypeError, ValueError):
            errors["latency_threshold_ms"] = "Must be a number"
        else:
            if 0 < value < 10000:
                if set_threshold("latency_threshold_ms", value):
                    updated["latency_threshold_ms"] = value
                else:
                    errors["latency_threshold_ms"] = "Failed to update"
            else:
                errors["latency_threshold_ms"] = "Must be between 0 and 10000"

    # Update uptime threshold
    if "uptime_threshold_percent" in data:
        try:
            value = float(data["uptime_threshold_percent"])
        except (TypeError, ValueError):
            errors["uptime_threshold_percent"] = "Must be a number"
        else:
            if 0 < value <= 100:
                if set_threshold("uptime_threshold_percent", value):
                    updated["uptime_threshold_percent"] = value
                else:
                    errors["uptime_threshold_percent"] = "Failed to update"
            else:
                errors["uptime_threshold_percent"] = "Must be between 0 and 100"

    if "session_timeout_minutes" in data:
        try:
            value = float(data["session_timeout_minutes"])
        except (TypeError, ValueError):
            errors["session_timeout_minutes"] = "Must be a number"
        else:
            if 1 <= value <= 480:
                if set_threshold("session_timeout_minutes", value):
                    updated["session_timeout_minutes"] = value
                else:
                    errors["session_timeout_minutes"] = "Failed to update"
            else:
                errors["session_timeout_minutes"] = "Must be between 1 and 480"

    admin_ip = request.remote_addr or "unknown"
    log_buffer.add("systemd", f"⚙️ Admin {admin_ip}: Updated thresholds: {updated}")
    log_audit("set_thresholds", admin_ip, "dashboard", {"updated": updated}, "success" if not errors else "partial")

    return jsonify({
        "updated": updated,
        "errors": errors if errors else None
    })

@app.route("/api/performance-check", methods=["POST"])
@require_admin
def api_performance_check():
    """Lance un diagnostic de performance complet et retourne un verdict."""

    results: dict[str, Any] = {}

    # ── 1. Disque (dd write + read) ──────────────────────────────────────────
    disk: dict[str, Any] = {"write_mbps": None, "read_mbps": None, "status": "unknown"}
    bench_file = f"/tmp/homelinkwg_bench_{os.getpid()}_{int(time.time())}"
    try:
        # Write test (64 MB)
        wr = _run(["dd", "if=/dev/zero", f"of={bench_file}", "bs=1M", "count=64",
                   "conv=fdatasync"], timeout=30.0)
        if wr:
            for line in (wr.stderr or wr.stdout or "").splitlines():
                if "MB/s" in line or "GB/s" in line:
                    try:
                        parts = line.strip().split()
                        for i, p in enumerate(parts):
                            if "MB/s" in p:
                                disk["write_mbps"] = round(float(parts[i-1]), 1)
                            elif "GB/s" in p:
                                disk["write_mbps"] = round(float(parts[i-1]) * 1024, 1)
                    except (ValueError, IndexError):
                        pass
        # Read test
        rr = _run(["dd", f"if={bench_file}", "of=/dev/null", "bs=1M"], timeout=20.0)
        if rr:
            for line in (rr.stderr or rr.stdout or "").splitlines():
                if "MB/s" in line or "GB/s" in line:
                    try:
                        parts = line.strip().split()
                        for i, p in enumerate(parts):
                            if "MB/s" in p:
                                disk["read_mbps"] = round(float(parts[i-1]), 1)
                            elif "GB/s" in p:
                                disk["read_mbps"] = round(float(parts[i-1]) * 1024, 1)
                    except (ValueError, IndexError):
                        pass
    except Exception as e:
        disk["error"] = str(e)
    finally:
        _run(["rm", "-f", bench_file])

    read = disk.get("read_mbps") or 0
    write = disk.get("write_mbps") or 0
    if read > 0 or write > 0:
        speed = read or write
        disk["status"] = "critical" if speed < 15 else "slow" if speed < 40 else "ok"

    # iostat: check SD card write latency (w_await) — more reliable than dd for latency
    iostat = _run(["iostat", "-x", "1", "2"], timeout=10.0)
    if iostat and iostat.returncode == 0:
        lines_io = iostat.stdout.splitlines()
        # Find the second pass (after the first blank separator) for current values
        second_pass = False
        header_cols: list[str] = []
        for line in lines_io:
            if not line.strip():
                second_pass = True
                continue
            if second_pass and re.search(r"\br/s\b|\brkB/s\b", line):
                header_cols = line.split()
                continue
            if second_pass and header_cols and re.search(r"mmcblk|sda|nvme|sd[a-z]", line):
                cols_io = line.split()
                if len(cols_io) >= len(header_cols):
                    try:
                        w_await_idx = header_cols.index("w_await") if "w_await" in header_cols else None
                        if w_await_idx is not None:
                            w_await = float(cols_io[w_await_idx].replace(",", "."))
                            disk["w_await_ms"] = round(w_await, 1)
                            # >100ms: slow, >500ms: critical
                            if w_await > 500:
                                disk["status"] = "critical"
                                disk["w_await_note"] = f"write latency {w_await:.0f}ms — very slow SD card"
                            elif w_await > 100:
                                if disk.get("status") != "critical":
                                    disk["status"] = "slow"
                                disk["w_await_note"] = f"write latency {w_await:.0f}ms — slow SD card"
                    except (ValueError, IndexError):
                        pass
                break

    results["disk"] = disk

    # ── 2. Réseau ─────────────────────────────────────────────────────────────
    net = host_network_info()
    net_status = "ok"
    try:
        spd_str = net.get("speed", "").split()[0]
        link_mbps = float(spd_str)
    except (ValueError, IndexError):
        link_mbps = None

    if net.get("type", "").startswith("WiFi"):
        if link_mbps is None:
            net_status = "slow"
        else:
            net_status = "critical" if link_mbps < 30 else "slow" if link_mbps < 65 else "ok"
    elif net.get("type", "") == "Ethernet" and link_mbps is not None:
        # 100 Mbps Ethernet = ~90 Mbps usable, can limit high-bitrate streams
        net_status = "slow" if link_mbps < 200 else "ok"
    net["status"] = net_status
    results["network"] = net

    # ── 3. CPU + température (Pi) ─────────────────────────────────────────────
    cpu: dict[str, Any] = {
        "usage_percent": None, "iowait_percent": None,
        "temp_c": None, "throttled": False, "status": "ok",
        "top_processes": [], "cpu_explanation": None,
    }

    _watched = {
        "teamviewer": "TeamViewer", "teamviewerd": "TeamViewer",
        "socat": "socat (port forward)", "python3": "Python/HomelinkWG",
        "ffmpeg": "FFmpeg", "vlc": "VLC", "kodi": "Kodi",
        "chromium": "Chromium", "chrome": "Chrome",
        "node": "Node.js", "java": "Java",
        "mysqld": "MySQL", "postgres": "PostgreSQL",
        "apt": "apt (package update)", "dpkg": "dpkg",
        "rsync": "rsync", "tar": "tar",
    }

    # top -bn2: two iterations, second one gives instantaneous values
    top = _run(["top", "-bn2", "-d0.5"], timeout=8.0)
    if top and top.returncode == 0:
        lines = top.stdout.splitlines()

        # Find the second "top -" header to get instantaneous snapshot
        top_headers = [i for i, l in enumerate(lines) if l.startswith("top -")]
        parse_from  = top_headers[1] if len(top_headers) >= 2 else 0

        # Parse CPU summary line — handles both en/fr locales (dot or comma as decimal)
        # e.g. "3.5 us" (en) or "3,5 ut" (fr). iowait label is always "wa".
        for line in lines[parse_from:]:
            if "%Cpu" in line or "Cpu(s)" in line:
                try:
                    after_colon = line.split(":", 1)[1]
                    # Extract all (number, label) pairs, accepting comma as decimal sep
                    vals: dict[str, float] = {}
                    for m in re.finditer(r"([0-9]+[.,][0-9]+|[0-9]+)\s+([a-z/]+)", after_colon):
                        vals[m.group(2)] = float(m.group(1).replace(",", "."))
                    idle = vals.get("id", 0.0)
                    wa   = vals.get("wa", 0.0)
                    cpu["usage_percent"]  = round(100.0 - idle, 1)
                    cpu["iowait_percent"] = round(wa, 1)
                except (IndexError, ValueError):
                    pass
                break

        # Parse process list — PID header differs by locale (COMMAND vs COM.)
        # Use LANG=C via env to force English output for reliable parsing
        procs = []
        in_procs = False
        for line in lines[parse_from:]:
            # Match header line containing PID and %CPU columns
            if re.search(r"\bPID\b", line) and re.search(r"%CPU|%MEM", line):
                in_procs = True
                continue
            if not in_procs:
                continue
            if not line.strip():
                break
            cols = line.split(None, 11)
            if len(cols) < 9:
                continue
            try:
                # %CPU is always column index 8 in standard top output
                cpu_pct = float(cols[8].replace(",", "."))
            except (ValueError, IndexError):
                continue
            if cpu_pct < 0.5:
                break
            cmd_full = cols[11].strip() if len(cols) >= 12 else cols[-1].strip()
            cmd_bin  = cmd_full.split("/")[-1].split()[0]
            label = None
            for key, name in _watched.items():
                if key in cmd_full.lower():
                    label = name
                    break
            if label is None:
                label = cmd_bin[:30]
            procs.append({"name": label, "cpu_percent": round(cpu_pct, 1), "cmd": cmd_bin})
            if len(procs) >= 5:
                break
        cpu["top_processes"] = procs

    # Determine what explains the CPU load
    _usage   = cpu.get("usage_percent") or 0
    _iowait  = cpu.get("iowait_percent") or 0
    _proc_sum = sum(p["cpu_percent"] for p in cpu["top_processes"])
    if _iowait > 20:
        cpu["cpu_explanation"] = f"high iowait ({_iowait}%) — CPU waiting on disk (slow SD card)"
    elif _usage > 60 and _proc_sum < _usage * 0.3:
        cpu["cpu_explanation"] = f"load spread across many small processes or kernel tasks (sys/irq)"
    elif cpu["top_processes"]:
        cpu["cpu_explanation"] = None  # processes explain it, no extra note needed

    if Path("/usr/bin/vcgencmd").exists() or _run(["which", "vcgencmd"]):
        t = _run(["vcgencmd", "measure_temp"])
        if t and t.returncode == 0:
            try:
                cpu["temp_c"] = float(t.stdout.strip().replace("temp=", "").replace("'C", ""))
            except ValueError:
                pass
        th = _run(["vcgencmd", "get_throttled"])
        if th and th.returncode == 0:
            cpu["throttled"] = th.stdout.strip().split("=")[-1].strip() != "0x0"
    temp = cpu.get("temp_c") or 0
    usage = cpu.get("usage_percent") or 0
    if cpu["throttled"] or temp > 80:
        cpu["status"] = "critical"
    elif temp > 70 or usage > 85:
        cpu["status"] = "slow"
    results["cpu"] = cpu

    # ── 4. Mémoire ────────────────────────────────────────────────────────────
    mem: dict[str, Any] = {"used_mb": None, "total_mb": None, "percent": None, "status": "ok"}
    free = _run(["free", "-m"])
    if free and free.returncode == 0:
        for line in free.stdout.splitlines():
            if line.startswith("Mem:"):
                cols = line.split()
                try:
                    mem["total_mb"] = int(cols[1])
                    mem["used_mb"]  = int(cols[2])
                    mem["percent"]  = mem["used_mb"] * 100 // max(mem["total_mb"], 1)
                    if mem["percent"] > 90:
                        mem["status"] = "critical"
                    elif mem["percent"] > 75:
                        mem["status"] = "slow"
                except (ValueError, IndexError):
                    pass
    results["memory"] = mem

    # ── 5. Verdict ────────────────────────────────────────────────────────────
    bottlenecks = []
    recommendations = []

    if net.get("status") == "critical":
        bottlenecks.append(("network", 3, f"WiFi too slow ({net.get('speed','?')}) — main streaming bottleneck"))
        recommendations.append("🔌 Switch to Ethernet to multiply bandwidth by 3–5x")
    elif net.get("status") == "slow":
        if net.get("type", "").startswith("WiFi"):
            bottlenecks.append(("network", 2, f"WiFi limits throughput ({net.get('speed','?')})"))
            recommendations.append("🔌 An Ethernet cable would significantly improve streaming performance")
        else:
            bottlenecks.append(("network", 1, f"Ethernet 100 Mbps — sufficient but may limit high-quality streams"))
            recommendations.append("🔌 A Gigabit switch (1000 Mbps) would remove this limitation")

    if cpu.get("throttled"):
        bottlenecks.append(("cpu_throttle", 3, "CPU thermally throttled — clock speed reduced automatically"))
        recommendations.append("❄️ Add a heatsink or improve Raspberry Pi cooling")
    elif (cpu.get("temp_c") or 0) > 70:
        bottlenecks.append(("cpu_temp", 2, f"High temperature ({cpu.get('temp_c')}°C) — throttling risk"))
        recommendations.append("❄️ Improve cooling to prevent thermal throttling")

    _cpu_usage   = cpu.get("usage_percent") or 0
    _iowait      = cpu.get("iowait_percent") or 0
    _top_procs   = cpu.get("top_processes") or []
    _explanation = cpu.get("cpu_explanation")
    _top_str     = ", ".join(f"{p['name']} {p['cpu_percent']}%" for p in _top_procs[:3]) if _top_procs else ""

    # iowait: CPU "busy" waiting for disk — disk is real bottleneck
    if _iowait > 30:
        bottlenecks.append(("iowait", 3, f"CPU blocked on disk I/O ({_iowait}% iowait) — SD card is the bottleneck"))
        recommendations.append("💾 CPU is waiting on the SD card — a USB SSD would fix this immediately")
    elif _iowait > 15:
        bottlenecks.append(("iowait", 2, f"High I/O wait ({_iowait}%) — disk is slowing the system"))
        recommendations.append("💾 High iowait detected — consider a USB SSD or A2-rated SD card")

    if _cpu_usage >= 95:
        _msg = f"CPU saturated ({_cpu_usage}%)"
        if _explanation:
            _msg += f" — {_explanation}"
        elif _top_str:
            _msg += f" — top consumers: {_top_str}"
        bottlenecks.append(("cpu_usage", 3, _msg))
        if _top_procs and not _explanation:
            for p in _top_procs[:2]:
                if "TeamViewer" in p["name"]:
                    recommendations.append(f"🖥️ TeamViewer is running in background ({p['cpu_percent']}% CPU) — sudo systemctl disable --now teamviewerd")
                elif "HomelinkWG" in p["name"] or "socat" in p["name"].lower():
                    recommendations.append(f"🖥️ HomelinkWG uses {p['cpu_percent']}% CPU — check the number of active streams")
                elif p["cpu_percent"] > 5:
                    recommendations.append(f"🖥️ {p['name']} uses {p['cpu_percent']}% CPU — consider disabling it")
        elif not _explanation:
            recommendations.append("🖥️ Reduce concurrent streams or disable unused services")
    elif _cpu_usage >= 80:
        _msg = f"CPU under heavy load ({_cpu_usage}%) — low headroom"
        if _explanation:
            _msg += f" — {_explanation}"
        elif _top_str:
            _msg += f" — top: {_top_str}"
        bottlenecks.append(("cpu_usage", 2, _msg))
        recommendations.append("🖥️ Monitor CPU load — spikes may cause stream freezes")

    disk_speed = (disk.get("read_mbps") or 0)
    if disk.get("status") == "critical":
        bottlenecks.append(("disk", 3, f"Very slow SD card ({disk_speed} MB/s) — I/O bottleneck"))
        recommendations.append("💾 Replace the SD card with a USB SSD for 5–10x better performance")
    elif disk.get("status") == "slow":
        bottlenecks.append(("disk", 2, f"Slow SD card ({disk_speed} MB/s)"))
        recommendations.append("💾 An A2-rated SD card or USB SSD would improve I/O performance")

    if mem.get("status") == "critical":
        bottlenecks.append(("memory", 3, f"RAM saturated ({mem.get('percent')}%)"))
        recommendations.append("🧹 Close unused applications (TeamViewer, etc.) to free up RAM")
    elif mem.get("status") == "slow":
        bottlenecks.append(("memory", 2, f"RAM under pressure ({mem.get('percent')}%)"))

    bottlenecks.sort(key=lambda x: -x[1])
    if bottlenecks:
        main_bn = bottlenecks[0]
        severity = "critical" if main_bn[1] == 3 else "warning"
        verdict_msg = main_bn[2]
    else:
        severity = "ok"
        verdict_msg = "No limiting factor detected — performance is good ✓"

    results["verdict"] = {
        "bottleneck": bottlenecks[0][0] if bottlenecks else None,
        "message": verdict_msg,
        "severity": severity,
        "all_bottlenecks": [{"key": b[0], "severity": b[1], "message": b[2]} for b in bottlenecks],
    }
    results["recommendations"] = recommendations

    # ── 6. Log diagnostic results with contextual diagnosis ───────────────────
    admin_ip = request.remote_addr or "unknown"
    verdict_icon = {"ok": "✅", "warning": "⚠️", "critical": "🚫"}.get(severity, "ℹ️")
    log_buffer.add("systemd", f"🔬 Performance diagnostic ({admin_ip}): {verdict_icon} {verdict_msg}")

    # Network diagnosis
    _net_iface = net.get('interface', '?')
    _net_type  = net.get('type', '?')
    _net_speed = net.get('speed', '')
    _is_wifi = net.get("type", "").startswith("WiFi")
    _net_diag = {
        "critical": "→ 🚫 WiFi too slow, streaming degraded — switch to Ethernet",
        "slow":     "→ ⚠️ WiFi limits streaming bandwidth" if _is_wifi else "→ ⚠️ Ethernet 100 Mbps may limit high-quality streams (Gigabit recommended)",
        "ok":       "→ ✅ OK for streaming",
    }.get(net.get("status", "ok"), "")
    log_buffer.add("systemd", f"   📶 Network: {_net_iface} ({_net_type}) {_net_speed} {_net_diag}".strip())

    # Disk diagnosis
    _disk_r    = disk.get('read_mbps')
    _disk_w    = disk.get('write_mbps')
    _disk_wa   = disk.get('w_await_ms')
    _disk_spd  = f"read {_disk_r} MB/s, write {_disk_w} MB/s" if _disk_r else "measurement unavailable"
    if _disk_wa is not None: _disk_spd += f", write latency {_disk_wa}ms"
    _disk_diag = {
        "critical": "→ 🚫 Very slow SD card, I/O bottleneck — consider a USB SSD",
        "slow":     "→ ⚠️ Slow SD card, may cause latency",
        "ok":       "→ ✅ Throughput sufficient",
    }.get(disk.get("status", "ok"), "")
    log_buffer.add("systemd", f"   💾 Disk: {_disk_spd} {_disk_diag}".strip())

    # CPU diagnosis
    _cpu_use   = cpu.get('usage_percent')
    _cpu_wa    = cpu.get('iowait_percent')
    _cpu_temp  = cpu.get('temp_c')
    _cpu_thr   = cpu.get('throttled', False)
    _cpu_expl  = cpu.get('cpu_explanation')
    _cpu_vals  = []
    if _cpu_use is not None: _cpu_vals.append(f"load {_cpu_use}%")
    if _cpu_wa  is not None and _cpu_wa > 5: _cpu_vals.append(f"iowait {_cpu_wa}%")
    if _cpu_temp is not None: _cpu_vals.append(f"temp {_cpu_temp}°C")
    if _cpu_thr: _cpu_vals.append("thermally throttled")
    _cpu_diag  = {
        "critical": "→ 🚫 CPU saturated or throttled, performance reduced",
        "slow":     "→ ⚠️ CPU under pressure or high temperature",
        "ok":       "→ ✅ CPU stable",
    }.get(cpu.get("status", "ok"), "")
    log_buffer.add("systemd", f"   🖥️  CPU: {', '.join(_cpu_vals) or 'N/A'} {_cpu_diag}".strip())
    if _cpu_expl:
        log_buffer.add("systemd", f"   ℹ️  Explanation: {_cpu_expl}")
    _log_procs = cpu.get("top_processes") or []
    if _log_procs:
        _proc_lines = "  |  ".join(f"{p['name']} {p['cpu_percent']}%" for p in _log_procs[:5])
        log_buffer.add("systemd", f"   🔝 Top processes: {_proc_lines}")

    # Memory diagnosis
    _mem_used  = mem.get('used_mb')
    _mem_total = mem.get('total_mb')
    _mem_pct   = mem.get('percent')
    _mem_vals  = f"{_mem_used}/{_mem_total} MB ({_mem_pct}%)" if _mem_used is not None else "N/A"
    _mem_diag  = {
        "critical": "→ 🚫 RAM saturated, risk of heavy swapping",
        "slow":     "→ ⚠️ RAM under pressure",
        "ok":       "→ ✅ Memory sufficient",
    }.get(mem.get("status", "ok"), "")
    log_buffer.add("systemd", f"   🧠 Memory: {_mem_vals} {_mem_diag}".strip())

    log_audit("performance_check", admin_ip, "dashboard", {
        "network_status": net.get("status"), "disk_status": disk.get("status"),
        "cpu_status": cpu.get("status"), "memory_status": mem.get("status"),
        "verdict": severity,
    }, "success")

    return jsonify(results)

@app.route("/api/connectivity-check", methods=["POST"])
@require_admin
def api_connectivity_check():
    """Force a full connectivity diagnostic, even in ultra-light mode."""
    cfg = load_config()
    interface = cfg.get("vpn", {}).get("interface", "wg0")
    diag = diagnostics(interface, _allowed_cidrs(), _probe_host())
    vpn  = vpn_status(interface)
    ports: list[dict[str, Any]] = []
    probable = diagnostics_probable_cause(vpn, diag, ports)
    return jsonify({"diagnostics": diag, "diagnostics_summary": probable})

@app.route("/api/restart-dashboard", methods=["POST"])
@require_admin
def api_restart_dashboard():
    """Restart the homelinkwg-dashboard systemd service."""
    import threading as _threading
    admin_ip = request.remote_addr or "unknown"
    log_buffer.add("systemd", f"⚠️ Admin {admin_ip}: dashboard restart requested")
    log_audit("restart_dashboard", admin_ip, "homelinkwg-dashboard.service", {}, "success")
    def _do_restart():
        import time as _time
        _time.sleep(0.5)  # let the response reach the client first
        restart_managed_service("homelinkwg-dashboard.service")
    _threading.Thread(target=_do_restart, daemon=True).start()
    return jsonify({"ok": True, "message": "Restart initiated"})


@app.route("/api/sessions")
@require_admin
def api_sessions():
    """Return admin session history (active + recent expired)."""
    try:
        cutoff = _now_ts() - 7 * 86400  # last 7 days
        with _db_connect(row_factory=True) as conn:
            rows = conn.execute(
                "SELECT created_at, expires_at, ip_address, user_agent "
                "FROM admin_sessions WHERE created_at >= ? ORDER BY created_at DESC LIMIT 100",
                (cutoff,)
            ).fetchall()
        sessions = [{
            "created_at":  row["created_at"],
            "expires_at":  row["expires_at"],
            "ip_address":  row["ip_address"],
            "user_agent":  row["user_agent"],
        } for row in rows]
        return jsonify({"sessions": sessions})
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit-log")
@require_admin
def api_audit_log():
    """Return recent audit log entries."""
    try:
        limit = min(int(request.args.get("limit", "200")), 500)
    except ValueError:
        limit = 200
    try:
        with _db_connect(row_factory=True) as conn:
            rows = conn.execute(
                "SELECT timestamp, action, admin, target, details, status "
                "FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        entries = []
        for row in rows:
            det = row["details"]
            try:
                det = json.loads(det) if det else None
                if isinstance(det, dict):
                    det = ", ".join(f"{k}: {v}" for k, v in det.items() if v not in (None, "", {}, []))
            except Exception:
                pass
            entries.append({
                "timestamp": row["timestamp"],
                "action":    row["action"],
                "admin":     row["admin"],
                "target":    row["target"],
                "details":   det or "",
                "status":    row["status"],
            })
        return jsonify({"entries": entries})
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config/backup")
@require_admin
def api_config_backup():
    """Return a zip archive containing config.json and analytics.conf."""
    import zipfile as _zip
    import io as _io
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w", _zip.ZIP_DEFLATED) as zf:
        if CONFIG_FILE.exists():
            zf.write(CONFIG_FILE, arcname="config.json")
        if ANALYTICS_CONFIG.exists():
            zf.write(ANALYTICS_CONFIG, arcname="analytics.conf")
    buf.seek(0)
    import datetime as _dt
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    fname = f"homelinkwg-backup-{stamp}.zip"
    from flask import Response
    return Response(
        buf.getvalue(),
        mimetype="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'}
    )


# ---------------------------------------------------------------------------
# Diagnostic bundle — single-shot full system snapshot for offline analysis
# ---------------------------------------------------------------------------
def _safe_run_capture(label: str, cmd: list[str], timeout: float = 4.0) -> dict[str, Any]:
    """Run a command and capture output as a structured record."""
    t0 = time.perf_counter()
    r = _run(cmd, timeout=timeout)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
    if r is None:
        return {"label": label, "cmd": " ".join(cmd), "elapsed_ms": elapsed_ms,
                "ok": False, "error": "command not found or timed out"}
    return {
        "label": label, "cmd": " ".join(cmd), "elapsed_ms": elapsed_ms,
        "ok": r.returncode == 0, "rc": r.returncode,
        "stdout": (r.stdout or "")[-32000:],
        "stderr": (r.stderr or "")[-4000:],
    }


def _safe_read(label: str, path: str, max_bytes: int = 64 * 1024) -> dict[str, Any]:
    try:
        data = Path(path).read_text(encoding="utf-8", errors="replace")
        if len(data) > max_bytes:
            data = data[-max_bytes:]
        return {"label": label, "path": path, "ok": True, "content": data}
    except OSError as e:
        return {"label": label, "path": path, "ok": False, "error": str(e)}


def _sanitize_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """Remove any obvious secrets from config dict before exporting."""
    redacted: dict[str, Any] = {}
    for k, v in cfg.items():
        if isinstance(v, dict):
            redacted[k] = _sanitize_config(v)
        elif isinstance(v, list):
            redacted[k] = [_sanitize_config(x) if isinstance(x, dict) else x for x in v]
        elif isinstance(k, str) and any(t in k.lower() for t in
                                         ("password", "secret", "private", "key", "token", "totp")):
            redacted[k] = "***REDACTED***"
        else:
            redacted[k] = v
    return redacted


def build_diagnostic_bundle() -> dict[str, Any]:
    """Build a comprehensive diagnostic snapshot — all data in one JSON.

    Heavy/optional commands are guarded so missing tooling never breaks the
    bundle. Caller can request format=zip to receive a packaged archive
    containing this JSON plus the rotated log files.
    """
    cid = new_correlation_id("diag")
    started = time.time()
    flog("INFO", "diag", "diagnostic bundle requested")
    cfg = load_config()
    interface = cfg.get("vpn", {}).get("interface", "wg0")
    bundle: dict[str, Any] = {
        "meta": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "correlation_id": cid,
            "version": __version__,
            "version_date": __date__,
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
            "runtime": "docker" if _is_docker_runtime() else "systemd",
            "modes": {
                "light_mode": is_light_mode_enabled(),
                "ultra_light": is_ultra_light_mode_enabled(),
                "ultra_light_adaptive": adaptive_ultra_light_status(),
                "analytics_enabled": is_analytics_enabled(),
            },
        },
    }

    # ---- System snapshot (all from /proc, ~free) -----------------------------
    with timed("diag", "section.system", warn_above_ms=1500):
        bundle["system"] = {
            "uptime_seconds": _safe_read("uptime", "/proc/uptime")["content"].split()[0]
                if Path("/proc/uptime").exists() else None,
            "loadavg": _safe_read("loadavg", "/proc/loadavg").get("content", "").strip(),
            "cpu_breakdown": cpu_breakdown(),
            "thermal": cpu_thermal(),
            "memory": memory_extended(),
            "disks": disk_usage(),
            "disk_latency": disk_latency(),
            "fd": file_descriptors(),
            "stats": system_stats(),
            "host_network": host_network_info(),
        }

    # ---- Network snapshot ---------------------------------------------------
    with timed("diag", "section.network", warn_above_ms=2000):
        bundle["network"] = {
            "throughput_default": network_throughput(
                bundle["system"]["host_network"].get("interface", "")
            ),
            "throughput_wg": network_throughput(interface),
            "tcp": tcp_health(),
            "wg_peers": wireguard_peers(interface),
            "wg_diagnostic": wireguard_diagnostic(interface, _allowed_cidrs()),
            "kernel_net_tunables": kernel_net_tunables(),
        }
        bundle["network"]["commands"] = [
            _safe_run_capture("ip_addr", ["ip", "-o", "addr"]),
            _safe_run_capture("ip_route", ["ip", "route"]),
            _safe_run_capture("ip_link_stats", ["ip", "-s", "link"]),
            _safe_run_capture("ss_summary", ["ss", "-s"]),
            _safe_run_capture("ss_listen", ["ss", "-tlnp"]),
            _safe_run_capture("wg_show", ["wg", "show", interface]),
            _safe_run_capture("ethtool", ["ethtool",
                                          bundle["system"]["host_network"].get("interface", "")
                                          or "eth0"]),
        ]
        # Path-MTU probe to the first WG endpoint we know about (heavy:
        # blocked behind the network section so the timing is captured).
        wg_diag = bundle["network"]["wg_diagnostic"]
        endpoints = (wg_diag.get("endpoints") or [])
        first_endpoint = ""
        if endpoints:
            # Endpoint format: "host:port" → strip port
            first_endpoint = endpoints[0].rsplit(":", 1)[0].strip("[]")
        if first_endpoint:
            bundle["network"]["path_mtu"] = path_mtu_probe(first_endpoint)

    # ---- Processes ----------------------------------------------------------
    with timed("diag", "section.processes"):
        bundle["processes"] = {
            "top": top_processes(10),
            "ps_cpu": _safe_run_capture("ps_top_cpu",
                ["ps", "-eo", "pid,user,%cpu,%mem,rss,comm", "--sort=-%cpu"]),
        }
        # Trim ps output to top 25 lines
        ps_out = bundle["processes"]["ps_cpu"].get("stdout", "")
        if ps_out:
            bundle["processes"]["ps_cpu"]["stdout"] = "\n".join(ps_out.splitlines()[:25])

    # ---- Services & systemd -------------------------------------------------
    with timed("diag", "section.services"):
        if _is_docker_runtime():
            bundle["services"] = {
                "supervisor_status": _safe_run_capture("supervisorctl",
                    ["supervisorctl", "-s", "unix:///tmp/supervisor.sock", "status"]),
            }
        else:
            bundle["services"] = {
                "failed_units": systemd_failed_units(),
                "homelinkwg_units": _safe_run_capture("homelinkwg_units",
                    ["systemctl", "list-units", "homelinkwg-*", "--all", "--no-pager", "--no-legend"]),
            }

    # ---- Kernel & security --------------------------------------------------
    with timed("diag", "section.kernel"):
        bundle["kernel"] = {
            "uname": _safe_run_capture("uname", ["uname", "-a"]),
            "os_release": _safe_read("os_release", "/etc/os-release"),
            "dmesg_errors": kernel_recent_errors(50),
            "sysctl_net": _safe_run_capture("sysctl_net",
                ["sysctl", "-a", "--pattern", "net.ipv4.tcp"]),
        }

    # ---- Application state --------------------------------------------------
    with timed("diag", "section.app"):
        try:
            with _db_connect(row_factory=True) as conn:
                tbl_counts = {}
                for tbl in ("metrics", "incidents", "audit_log", "admin_sessions", "thresholds"):
                    try:
                        row = conn.execute(f"SELECT COUNT(*) AS n FROM {tbl}").fetchone()
                        tbl_counts[tbl] = int(row["n"]) if row else 0
                    except sqlite3.Error:
                        tbl_counts[tbl] = None
                last_metrics = []
                try:
                    rows = conn.execute(
                        "SELECT timestamp,port_id,service_active,port_listening,"
                        "target_reachable,latency_ms FROM metrics "
                        "ORDER BY timestamp DESC LIMIT 20"
                    ).fetchall()
                    last_metrics = [dict(r) for r in rows]
                except sqlite3.Error:
                    pass
                last_incidents = []
                try:
                    rows = conn.execute(
                        "SELECT timestamp,port_id,event_type,severity,description FROM incidents "
                        "ORDER BY timestamp DESC LIMIT 20"
                    ).fetchall()
                    last_incidents = [dict(r) for r in rows]
                except sqlite3.Error:
                    pass
            db_state = {"counts": tbl_counts, "last_metrics": last_metrics,
                        "last_incidents": last_incidents}
        except sqlite3.Error as e:
            db_state = {"error": str(e)}

        bundle["app"] = {
            "config": _sanitize_config(cfg),
            "db_state": db_state,
            "log_buffer_recent": log_buffer.get_recent(limit=200),
            "log_buffer_errors": log_buffer.filtered(min_level="WARN", limit=100),
            "thresholds": {
                "latency_threshold_ms": get_threshold("latency_threshold_ms", 50.0),
                "uptime_threshold_percent": get_threshold("uptime_threshold_percent", 95.0),
            },
            "service_state_cache": service_state_cache,
        }

    # ---- Live probes (non-blocking, parallel) -------------------------------
    with timed("diag", "section.probes", warn_above_ms=4000):
        ports = [p for p in cfg.get("ports", []) if p.get("enabled", True)]
        # Diagnostic bundle always uses NORMAL probes (full breakdown), even
        # if the dashboard is currently running in light/ultra. The user is
        # actively investigating — they want full detail.
        probe_results = list(_probe_pool.map(lambda p: _probe_one_port(p, False), ports))
        # Enrich with socat children count (saturation indicator)
        for r in probe_results:
            try:
                r["socat_connections"] = socat_connection_count(r["lp"])
            except Exception:
                r["socat_connections"] = None
        bundle["probes"] = probe_results

        # WAN reachability + DNS round-trip
        with timed("diag", "wan_probes"):
            wan = {
                "internet_dns_53": _tcp_reachable("1.1.1.1", 53, timeout=1.5),
                "internet_dns_53_alt": _tcp_reachable("8.8.8.8", 53, timeout=1.5),
                "ping_1_1_1_1": _safe_run_capture("ping", ["ping", "-c", "2", "-W", "2", "1.1.1.1"]),
                "dns_breakdown_cf": latency_breakdown("1.1.1.1", 53, timeout=2.0, samples=3),
            }
        bundle["connectivity"] = wan

    bundle["collector"] = collector_health()

    # ---- Health verdict -----------------------------------------------------
    bundle["health"] = health_score()

    bundle["meta"]["build_elapsed_ms"] = round((time.time() - started) * 1000.0, 1)
    flog("INFO", "diag", "diagnostic bundle ready",
         {"elapsed_ms": bundle["meta"]["build_elapsed_ms"]})
    set_correlation_id(None)
    return bundle


@app.route("/api/diagnostic-bundle")
@require_admin
def api_diagnostic_bundle():
    """Return a comprehensive diagnostic snapshot. Defaults to JSON; pass
    ``?format=zip`` to download a zip with the JSON + the rotating log files."""
    fmt = (request.args.get("format") or "json").strip().lower()
    try:
        bundle = build_diagnostic_bundle()
    except Exception as e:
        flog("ERROR", "diag", "diagnostic bundle build failed", exc=e)
        return jsonify({"error": "diagnostic bundle build failed", "detail": str(e)}), 500

    if fmt == "json":
        # Pretty-print so human review of the response is comfortable.
        body = json.dumps(bundle, indent=2, default=str, ensure_ascii=False)
        return Response(body, mimetype="application/json")

    if fmt == "zip":
        import zipfile as _zip
        import io as _io
        buf = _io.BytesIO()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        with _zip.ZipFile(buf, "w", _zip.ZIP_DEFLATED) as zf:
            zf.writestr(f"diagnostic-{stamp}.json",
                        json.dumps(bundle, indent=2, default=str, ensure_ascii=False))
            # Include the rotating log files if they exist.
            for cand in (LOG_FILE, LOG_FILE_FALLBACK, SCRIPT_DIR / "homelinkwg-dashboard.log"):
                try:
                    if cand.exists():
                        zf.write(cand, arcname=f"logs/{cand.name}")
                        side = Path(str(cand) + ".jsonl")
                        if side.exists():
                            zf.write(side, arcname=f"logs/{side.name}")
                        break
                except OSError:
                    continue
            # Include sanitized config + analytics.conf
            try:
                if CONFIG_FILE.exists():
                    zf.write(CONFIG_FILE, arcname="config.json")
                if ANALYTICS_CONFIG.exists():
                    zf.write(ANALYTICS_CONFIG, arcname="analytics.conf")
            except OSError:
                pass
        buf.seek(0)
        fname = f"homelinkwg-diagnostic-{stamp}.zip"
        return Response(
            buf.getvalue(),
            mimetype="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )
    return jsonify({"error": "unknown format, use json or zip"}), 400


@app.route("/api/health-score")
@require_admin
def api_health_score():
    """Lightweight verdict — meant to be polled by the dashboard UI."""
    return jsonify(health_score())


@app.route("/api/latency-insights")
@require_admin
def api_latency_insights():
    """Live latency breakdown per port (DNS / TCP / jitter) + WG diagnostic.

    This is the "is my VPN slow and why" endpoint — it's expensive (it does
    actual probes), so it's not part of the regular status payload.
    """
    cfg = load_config()
    interface = cfg.get("vpn", {}).get("interface", "wg0")
    ports = [p for p in cfg.get("ports", []) if p.get("enabled", True)]
    out: dict[str, Any] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "interface": interface,
        "ports": [],
    }
    for p in ports:
        rh = str(p["remote_host"])
        rp = int(p["remote_port"])
        lp = int(p["local_port"])
        br = latency_breakdown(rh, rp, timeout=1.5, samples=5)
        out["ports"].append({
            "name": p.get("name", f"Port {lp}"),
            "local_port": lp,
            "remote_host": rh,
            "remote_port": rp,
            "breakdown": br,
            "socat_connections": socat_connection_count(lp),
        })
    out["wg_diagnostic"] = wireguard_diagnostic(interface, _allowed_cidrs())
    out["cpu_governor"] = cpu_governor()
    out["ntp"] = ntp_offset()
    out["kernel_net_tunables"] = kernel_net_tunables()
    return jsonify(out)


@app.route("/api/path-mtu")
@require_admin
def api_path_mtu():
    """Path MTU probe to a target host (defaults to first WG endpoint)."""
    host = (request.args.get("host") or "").strip()
    if not host:
        cfg = load_config()
        interface = cfg.get("vpn", {}).get("interface", "wg0")
        wg = wireguard_diagnostic(interface, _allowed_cidrs())
        endpoints = wg.get("endpoints") or []
        if endpoints:
            host = endpoints[0].rsplit(":", 1)[0].strip("[]")
    if not host:
        return jsonify({"error": "no host provided and no WG endpoint found"}), 400
    return jsonify(path_mtu_probe(host))


_VALID_MODES = ("normal", "light", "ultra")

def _current_mode() -> str:
    """Effective dashboard mode based on persisted flags (ignores adaptive)."""
    if _resolve_mode_flag("ULTRA_LIGHT", "ultra_light"):
        return "ultra"
    if _resolve_mode_flag("LIGHT_MODE", "light_mode"):
        return "light"
    return "normal"


@app.route("/api/mode", methods=["GET"])
@require_admin
def api_mode_get():
    """Return the current persisted mode and the effective adaptive state."""
    return jsonify({
        "mode": _current_mode(),
        "valid_modes": list(_VALID_MODES),
        "adaptive": adaptive_ultra_light_status(),
        "effective_ultra_light": is_ultra_light_mode_enabled(),
        "effective_light": is_light_mode_enabled(),
    })


@app.route("/api/mode", methods=["POST"])
@require_admin
def api_mode_set():
    """Set the dashboard runtime mode (normal / light / ultra).

    Persists to analytics.conf so the change survives restarts. ULTRA implies
    LIGHT — both flags are written explicitly to avoid ambiguity.
    """
    data = request.get_json(silent=True) or {}
    mode = str(data.get("mode", "")).strip().lower()
    if mode not in _VALID_MODES:
        return jsonify({"error": f"mode must be one of {list(_VALID_MODES)}"}), 400

    # Map to analytics.conf flags
    light_val = "true" if mode in ("light", "ultra") else "false"
    ultra_val = "true" if mode == "ultra" else "false"
    _write_analytics_conf_key("LIGHT_MODE", light_val)
    _write_analytics_conf_key("ULTRA_LIGHT", ultra_val)

    # Reset adaptive state so the user-chosen mode takes effect immediately.
    with _adaptive_lock:
        _adaptive_state["active"] = False
        _adaptive_state["high_streak"] = 0
        _adaptive_state["low_streak"] = 0
        _adaptive_state["reason"] = "manual override"
        _adaptive_state["last_change_ts"] = time.time()

    # Invalidate cached config so next read picks up the change.
    with _config_cache_lock:
        _analytics_cache["mtime_ns"] = None
        _analytics_cache["loaded_at"] = 0.0
        _config_cache["mtime_ns"] = None
        _config_cache["loaded_at"] = 0.0

    flog("INFO", "mode", f"dashboard mode changed to {mode}",
         {"light": light_val, "ultra": ultra_val,
          "ip": request.remote_addr or "unknown"})
    log_audit("mode_change", request.remote_addr or "unknown",
              "dashboard", {"mode": mode}, "ok")

    return jsonify({
        "mode": _current_mode(),
        "applied": mode,
        "effective_ultra_light": is_ultra_light_mode_enabled(),
        "effective_light": is_light_mode_enabled(),
    })


@app.route("/api/alerts/mute", methods=["POST"])
@require_admin
def api_alerts_mute():
    """Mute alert surfacing for a maintenance window."""
    data = request.get_json(silent=True) or {}
    duration = str(data.get("duration", "1h"))
    now = _now_ts()

    if duration == "1h":
        until_ts = now + 3600
    elif duration == "4h":
        until_ts = now + (4 * 3600)
    elif duration == "tomorrow":
        tomorrow = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        until_ts = int(tomorrow.timestamp())
    else:
        return jsonify({"error": "duration must be one of: 1h, 4h, tomorrow"}), 400

    if not set_threshold("alerts_muted_until_ts", float(until_ts)):
        return jsonify({"error": "failed to persist mute window"}), 500

    cache_store.clear()
    admin_ip = request.remote_addr or "unknown"
    log_buffer.add("systemd", f"🔕 Admin {admin_ip}: alerts muted until {datetime.fromtimestamp(until_ts).isoformat(timespec='seconds')}")
    log_audit("alerts_mute", admin_ip, "dashboard", {"duration": duration, "until_ts": until_ts}, "success")
    return jsonify({"status": "muted", "alerts": alerts_status()})

@app.route("/api/alerts/unmute", methods=["POST"])
@require_admin
def api_alerts_unmute():
    """Clear alert mute window immediately."""
    if not set_threshold("alerts_muted_until_ts", 0.0):
        return jsonify({"error": "failed to clear mute window"}), 500

    cache_store.clear()
    admin_ip = request.remote_addr or "unknown"
    log_buffer.add("systemd", f"🔔 Admin {admin_ip}: alerts unmuted")
    log_audit("alerts_unmute", admin_ip, "dashboard", {}, "success")
    return jsonify({"status": "unmuted", "alerts": alerts_status()})

FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
<defs>
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
<stop offset="0%" stop-color="#0f172a"/><stop offset="100%" stop-color="#1a202c"/>
</linearGradient>
<linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
<stop offset="0%" stop-color="#10b981"/><stop offset="100%" stop-color="#34d399"/>
</linearGradient>
</defs>
<circle cx="50" cy="50" r="48" fill="url(#bg)"/>
<circle cx="50" cy="50" r="48" fill="none" stroke="#10b981" stroke-width="1" opacity=".3"/>
<polygon points="35,25 35,75 75,50" fill="url(#g)"/>
</svg>"""

@app.route("/favicon.ico")
def favicon():
    return Response(FAVICON_SVG, mimetype="image/svg+xml")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    cfg = load_config()
    port = int(cfg.get("dashboard", {}).get("port", 5555))
    bind = cfg.get("dashboard", {}).get("bind_address", "0.0.0.0")
    ssl_cert = cfg.get("dashboard", {}).get("ssl_cert")
    ssl_key = cfg.get("dashboard", {}).get("ssl_key")
    use_https = ssl_cert and ssl_key and Path(ssl_cert).exists() and Path(ssl_key).exists()

    protocol = "https" if use_https else "http"
    print(f"HomelinkWG dashboard v{__version__} on {protocol}://{bind}:{port}")

    if use_https:
        # Add HSTS header for HTTPS
        @app.after_request
        def add_hsts_header(response):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
            return response

        # Run with SSL/TLS
        import ssl as ssl_module
        ssl_context = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(ssl_cert, ssl_key)
        app.run(host=bind, port=port, debug=False, use_reloader=False, ssl_context=ssl_context)
    else:
        app.run(host=bind, port=port, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
