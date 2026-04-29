"""
Metrics collection, incident detection, and analytics management.

- store_metric(): Store metric snapshots to database
- detect_incidents(): Detect and log service incidents
- collector_health(): Status of the metrics collector thread
- _start_analytics_runtime(): Initialize analytics resources (db, collector thread)
"""

import sqlite3
import sys
import threading
import time
from typing import Any

from homelinkwg.config import (
    _db_connect, _now_ts,
    get_threshold, is_alerts_muted,
    is_analytics_enabled, init_db, load_thresholds,
    _analytics_init_lock, _collector_thread
)
from homelinkwg.utils import flog

# Collector heartbeat for liveness monitoring
_collector_heartbeat = {
    "last_cycle_ts": 0.0,
    "cycles": 0,
    "last_error_ts": 0.0,
    "last_error": None
}


# ---------------------------------------------------------------------------
# Metrics storage
# ---------------------------------------------------------------------------

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


def _start_analytics_runtime(metrics_collector_fn: Any = None) -> None:
    """Initialize analytics resources exactly once.

    Args:
        metrics_collector_fn: Function to run the metrics collector thread (will be passed from dashboard.py)
    """
    global _collector_thread
    if not is_analytics_enabled():
        print("[homelinkwg-dashboard] Analytics disabled - metrics collection skipped", file=sys.stderr)
        return

    with _analytics_init_lock:
        init_db()
        load_thresholds()
        if _collector_thread and _collector_thread.is_alive():
            return
        if metrics_collector_fn:
            _collector_thread = threading.Thread(
                target=metrics_collector_fn,
                daemon=True
            )
            _collector_thread.start()
    print("[homelinkwg-dashboard] Analytics enabled - metrics collector started", file=sys.stderr)
