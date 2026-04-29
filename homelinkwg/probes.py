"""HomelinkWG probe and diagnostic collection module.

Low-level probes for network services, system metrics, and health diagnostics.
Runs both synchronously (for quick status checks) and asynchronously (background
metrics collection via ThreadPoolExecutor).
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from homelinkwg.config import (
    LIGHT_TARGET_TTL_SECONDS, _target_probe_cache, _target_probe_lock,
    _adaptive_ultra_light_record,
    is_light_mode_enabled, is_ultra_light_mode_enabled, is_analytics_enabled,
    is_alerts_muted, _now_ts, _db_connect, load_config, get_threshold
)
from homelinkwg.utils import flog, timed
from homelinkwg.analytics import store_metric, detect_incidents, collector_health

import sqlite3

__all__ = [
    "_run", "_tcp_reachable", "_measure_latency", "latency_breakdown",
    "_probe_target_reachable", "vpn_status", "_is_docker_runtime",
    "_supervisor_program_name", "_supervisorctl", "_supervisor_is_active",
    "_systemd_is_active", "systemd_is_active", "restart_managed_service",
    "_read_diskstats", "disk_latency", "_read_proc_stat_idle_total",
    "_read_cpu_from_proc", "_read_proc_stat_vals", "cpu_breakdown",
    "cpu_thermal", "memory_extended", "disk_usage", "network_throughput",
    "tcp_health", "top_processes", "file_descriptors", "kernel_recent_errors",
    "systemd_failed_units", "wireguard_peers", "health_score", "cpu_governor",
    "ntp_offset", "kernel_net_tunables", "path_mtu_probe", "wireguard_diagnostic",
    "socat_connection_count", "power_supply_events", "system_stats", "host_network_info",
    "network_stats", "diagnostics", "diagnostics_probable_cause", "ports_status",
    "_probe_one_port", "_collect_metrics_once", "_probe_pool", "service_state_cache",
]

# Track power state across invocations (for detecting under-voltage events)
_power_state: dict[str, int] = {"seen": 0}

# Track previous state for each port (to detect changes)
service_state_cache = {}

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

# Track previous state for each port (to detect changes)
service_state_cache = {}  # port_id -> {service_active, port_listening, target_reachable, latency_ms}

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
    from homelinkwg.utils import set_correlation_id

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
