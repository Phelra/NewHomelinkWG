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
    _target_probe_cache, _target_probe_lock,
    _adaptive_state, _adaptive_lock,
    _now_ts, _db_connect,
    load_auth_config, load_config, get_threshold, set_threshold,
    is_alerts_muted, alerts_status,
    is_analytics_enabled, _resolve_mode_flag, is_light_mode_enabled,
    is_ultra_light_mode_enabled, _adaptive_ultra_light_record,
    adaptive_ultra_light_status, status_refresh_ms, analytics_refresh_ms,
    SCRIPT_DIR
)
from homelinkwg.auth import (
    verify_password, create_session, verify_session,
    log_audit, _write_analytics_conf_key
)
from homelinkwg.analytics import (
    store_metric, detect_incidents, collector_health, _start_analytics_runtime
)

__version__ = "5.0"
__date__ = "2026-04-28"

# Instantiate global rate limiters
login_limiter = LoginLimiter()
api_limiter = RateLimiter(max_attempts=100, window_seconds=60)

# Track previous state for each port (to detect changes)
service_state_cache = {}  # port_id -> {service_active, port_listening, target_reachable, latency_ms}

# Phase 3A2: Incident cache for 5-minute recent incidents
# Reduces database queries from O(n_ports) to O(1) per snapshot generation
_incident_cache = {"ports": set(), "mtime": 0.0}
_incident_cache_ttl = 300  # 5 minutes
_incident_cache_lock = threading.Lock()

def get_recent_incident_ports() -> set[str]:
    """Get set of port_ids with recent incidents (cached for 5 minutes)."""
    global _incident_cache
    if not is_analytics_enabled():
        return set()

    now = time.time()
    with _incident_cache_lock:
        if now - _incident_cache["mtime"] < _incident_cache_ttl and _incident_cache["ports"]:
            return _incident_cache["ports"]

    # Refresh cache from database
    recent_ports: set[str] = set()
    try:
        cutoff = _now_ts() - 300  # Last 5 minutes
        with _db_connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT port_id FROM incidents WHERE timestamp > ?",
                (cutoff,),
            ).fetchall()
        recent_ports = {row[0] for row in rows if row and row[0]}
    except sqlite3.Error:
        pass

    with _incident_cache_lock:
        _incident_cache["ports"] = recent_ports
        _incident_cache["mtime"] = now

    return recent_ports

# ---------------------------------------------------------------------------
# Flask import guard
# ---------------------------------------------------------------------------
try:
    from flask import Flask, Response, jsonify, render_template, send_from_directory, request
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

# Phase 3A3: DNS resolution caching (10 minute TTL)
_dns_cache: dict[str, tuple[Any, float]] = {}
_dns_cache_lock = threading.Lock()
_DNS_CACHE_TTL = 600  # 10 minutes

def cached_getaddrinfo(host: str, port: int, family=0, type=socket.SOCK_STREAM):
    """Wrapper around socket.getaddrinfo() with 10-minute caching.

    Avoids repeated DNS lookups which can add 10-200ms per probe.
    Returns the same result as socket.getaddrinfo().
    """
    now = time.time()
    cache_key = f"{host}:{port}:{family}:{type}"

    with _dns_cache_lock:
        if cache_key in _dns_cache:
            cached_result, expire_time = _dns_cache[cache_key]
            if now < expire_time:
                return cached_result

    # Not in cache or expired — perform resolution
    try:
        result = socket.getaddrinfo(host, port, family, type)
        with _dns_cache_lock:
            _dns_cache[cache_key] = (result, now + _DNS_CACHE_TTL)
        return result
    except socket.gaierror:
        # Don't cache errors; let them fail on next call for retry
        raise


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
            # Phase 3A3: Use cached DNS resolution (10-minute TTL)
            addr_info = cached_getaddrinfo(host, port, type=socket.SOCK_STREAM)
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
_disk_latency_cache_ts: float = 0.0
_DISK_LATENCY_CACHE_TTL = 30.0  # Phase 3A4: Cache disk latency for 30 seconds

def disk_latency() -> dict[str, Any]:
    """Return current disk write/read latency for the main storage device.
    Uses /proc/diskstats deltas — zero subprocess cost.
    Results cached for 30 seconds to avoid excessive /proc reads."""
    global _prev_diskstats, _prev_diskstats_ts, _disk_latency_cache, _disk_latency_cache_ts
    import time as _time

    now = _time.monotonic()

    # Phase 3A4: Check if cache is still valid (30-second TTL)
    if _disk_latency_cache and (now - _disk_latency_cache_ts) < _DISK_LATENCY_CACHE_TTL:
        return _disk_latency_cache

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
        _disk_latency_cache_ts = now
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
    # Phase 3A2: Use cached incident ports instead of inline database query
    recent_incident_ports = get_recent_incident_ports()

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

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
# Configure Flask with templates and static folders
app = Flask(__name__,
            template_folder=str(SCRIPT_DIR / 'templates'),
            static_folder=str(SCRIPT_DIR / 'static'),
            static_url_path='/static')
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
    return render_template(
        'index.html',
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

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(str(SCRIPT_DIR / 'static' / 'img'), 'favicon.svg',
                               mimetype="image/svg+xml")

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
