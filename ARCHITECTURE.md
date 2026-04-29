# HomelinkWG Architecture Guide

## System Overview

HomelinkWG is a Flask-based dashboard for monitoring and managing WireGuard VPN tunnels with per-port health checking, real-time diagnostics, and 24-hour analytics persistence.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      WEB DASHBOARD                          │
│  (Flask App - dashboard.py)                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ • HTTP/SSE Endpoints (45+ routes)                  │   │
│  │ • Authentication & Session Management              │   │
│  │ • Real-time Status Streaming                       │   │
│  │ • Configuration Management UI                      │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
           ▲
           │
    ┌──────┴──────┬──────────────┬──────────────┬──────────────┐
    │             │              │              │              │
    ▼             ▼              ▼              ▼              ▼
  ┌────────┐  ┌────────┐   ┌───────────┐  ┌──────────┐  ┌──────────┐
  │ CONFIG │  │  AUTH  │   │ ANALYTICS │  │ PROBES   │  │   API    │
  ├────────┤  ├────────┤   ├───────────┤  ├──────────┤  ├──────────┤
  │ • Load │  │ • Hash │   │ • Metrics │  │ • Health │  │ • Routing│
  │ • Cache│  │ • Sess │   │ • Incident│  │ • Latency│  │ • Events │
  │ • Mode │  │ • Rate │   │ • Database│  │ • Status │  │ • Cache  │
  │ • TTL  │  │ • TOTP │   │ • Collect │  │ • Thread │  │ • Stream │
  └────────┘  └────────┘   └───────────┘  └──────────┘  └──────────┘
       ▲          ▲              ▲              ▲              ▲
       └──────────┴──────────────┴──────────────┴──────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    UTILS     │
                    ├──────────────┤
                    │ • Logging    │
                    │ • Timing     │
                    │ • Decorators │
                    └──────────────┘
                           │
          ┌────────────────┴────────────────┐
          ▼                                  ▼
    ┌──────────────┐               ┌──────────────┐
    │   SQLite DB  │               │   WireGuard  │
    │ (Metrics)    │               │   Interface  │
    │ (Incidents)  │               │   (systemd)  │
    └──────────────┘               └──────────────┘
```

---

## Module Dependency Graph

### Layer 1: Foundation (No Internal Dependencies)

**`homelinkwg/utils.py`**
- Logging infrastructure (`flog()`, `LogBuffer`)
- Timing utilities (`timed()`, `_Timer`)
- Rate limiting (`RateLimiter`, `LoginLimiter`)
- Correlation ID tracking
- Dependencies: `stdlib` only

**`homelinkwg/config.py`**
- Configuration loading & caching (`load_config()`)
- Cache TTL constants
- Mode flags (`is_light_mode_enabled()`, `is_ultra_light_mode_enabled()`)
- Adaptive mode state management
- Database connection factory (`_db_connect()`)
- Dependencies: `utils`, `stdlib`

### Layer 2: Core Services

**`homelinkwg/auth.py`**
- Password hashing (`hash_password()`, `verify_password()`)
- Session management (`create_session()`, `verify_session()`)
- Audit logging (`log_audit()`)
- TOTP 2FA support
- Rate limiters for login/API
- Dependencies: `config`, `utils`, `bcrypt`, `pyotp`

**`homelinkwg/analytics.py`**
- Metrics storage (`store_metric()`)
- Incident detection (`detect_incidents()`)
- Background metrics collector thread
- Database schema management (`init_db()`)
- Threshold management
- Dependencies: `config`, `utils`, `sqlite3`

### Layer 3: Monitoring & Health Checks

**`homelinkwg/probes.py`**
- Low-level probes: `_tcp_reachable()`, `_measure_latency()`
- Service health: `systemd_is_active()`, `vpn_status()`
- System metrics: `disk_latency()`, `cpu_breakdown()`, `memory_extended()`
- Port aggregation: `ports_status()`
- Diagnostics: `wireguard_diagnostic()`, `network_health()`
- ThreadPoolExecutor (`_probe_pool`) for parallel execution
- Dependencies: `config`, `utils`, `psutil`, `subprocess`

### Layer 4: API & Web Interface

**`homelinkwg/api.py`** (Flask Endpoints)
- Status endpoints (`/api/status`, `/api/status/stream`, `/api/healthz`)
- Diagnostic endpoints (`/api/diagnose`, `/api/uptime`)
- Configuration endpoints (`/api/config`, `/api/config/thresholds`)
- Metrics endpoints (`/api/metrics/export`)
- Admin endpoints (service restart, alert muting)
- Decorators: `@require_admin`, `@require_rate_limit`
- Middleware: compression, cache headers, correlation ID
- SSE streaming setup
- Dependencies: All modules above, `Flask`, `json`

**`dashboard.py`** (Orchestration)
- Flask app initialization
- Route registration
- Server startup (`if __name__ == '__main__'`)
- Global state initialization (config, auth, analytics)
- Minimal business logic (delegated to modules)
- Dependencies: All modules above, `Flask`

### Dependency Diagram

```
dashboard.py (orchestration layer)
    │
    └─→ api.py (REST endpoints)
         ├─→ probes.py (health checks)
         ├─→ analytics.py (metrics & incidents)
         ├─→ auth.py (authentication)
         ├─→ config.py (configuration)
         └─→ utils.py (logging & timing)

probes.py (monitoring)
    ├─→ config.py (settings, cache)
    └─→ utils.py (logging)

analytics.py (database)
    ├─→ config.py (database connection, settings)
    └─→ utils.py (logging)

auth.py (security)
    ├─→ config.py (loaded secrets)
    └─→ utils.py (logging)

config.py (settings)
    └─→ utils.py (logging)

utils.py (foundation)
    └─→ stdlib only
```

---

## Data Flow

### Status Snapshot Generation

```
User requests /api/status
    │
    ├─→ _request_admin_view() [auth check]
    │
    ├─→ cache_store.get(cache_key)
    │   └─→ Return cached dict if TTL valid (5-30s)
    │
    └─→ _snapshot(admin_view=...)
        ├─→ load_config()
        │   └─→ Config cache (2s TTL)
        │
        ├─→ vpn_status(interface)
        │   └─→ Run: ip -o link show, ip -o addr show
        │
        ├─→ ports_status(ports)
        │   ├─→ get_recent_incident_ports() [cached 5 min]
        │   └─→ For each port (parallelized):
        │       ├─→ _tcp_reachable() [local port check]
        │       ├─→ systemd_is_active() [service status]
        │       └─→ _probe_target_reachable() [remote target]
        │
        ├─→ system_stats()
        │   ├─→ _read_cpu_from_proc() [cached 2s]
        │   └─→ memory_extended()
        │
        ├─→ network_stats(interface)
        │   └─→ Parse /proc/net/dev
        │
        └─→ diagnostics() [if not ultra-light mode]
            ├─→ wireguard_diagnostic()
            ├─→ network_health()
            └─→ diagnostics_probable_cause()
    │
    └─→ cache_store.set(cache_key, snapshot)
    │
    └─→ Return jsonify(snapshot)
```

**Performance Characteristics:**
- Snapshot TTL: 5-30s (depending on mode)
- Incident cache: 300s (5 minutes)
- DNS cache: 600s (10 minutes)
- CPU sample cache: 2s
- Disk latency cache: 30s

### Metrics Collection (Background Thread)

```
Metrics Collector Thread (runs every cycle)
    │
    ├─→ For each configured port:
    │   │
    │   ├─→ _probe_one_port(port_config)
    │   │   └─→ Calls latency_breakdown() [3 samples, parallelized]
    │   │
    │   └─→ store_metric(port_id, service_name, ...)
    │       └─→ INSERT INTO metrics table
    │
    └─→ detect_incidents(port_id, ...)
        └─→ INSERT INTO incidents table [only if threshold breached]
```

**Trigger:** Metrics collector runs in background thread (daemon mode)  
**Frequency:** Every ~60s cycle (configurable)  
**Database:** SQLite WAL mode for concurrent access  
**Storage:** Latest 90 days of metrics (with streaming export)

### Authentication & Session Flow

```
Login Request (POST /api/login)
    │
    ├─→ check_login_rate_limit(ip)
    │   └─→ LoginLimiter: 5 attempts per 15 min
    │
    ├─→ verify_password(submitted_password, admin_password_hash)
    │   └─→ bcrypt.checkpw() [constant-time comparison]
    │
    ├─→ IF TOTP_ENABLED:
    │   └─→ verify_totp(submitted_code, TOTP_SECRET)
    │       └─→ pyotp.TOTP() with 30s window + adjacent windows
    │
    └─→ create_session(ip_address, user_agent)
        └─→ Generate random session token
        └─→ Store in-memory with TTL (60 min default)
        └─→ Return to client as HTTP-only cookie

Subsequent API Calls
    │
    └─→ verify_session(session_token, ip, user_agent)
        ├─→ Check if token exists and not expired
        ├─→ Verify IP/User-Agent match (csrf/hijacking protection)
        └─→ Return True if valid, False otherwise
```

---

## Key Design Decisions

### 1. SQLite WAL Mode for Metrics
**Decision:** Use SQLite with Write-Ahead Logging for metrics/incidents table

**Rationale:**
- Allows concurrent reads while writes are in progress
- No external database server required (simpler deployment)
- Sufficient for monitoring use case (<1000 rows/minute)
- Each `_db_connect()` uses `timeout=10.0` for lock contention

**Trade-off:** WAL mode requires 2 extra files (`-wal`, `-shm`) on disk

### 2. ThreadPoolExecutor for Parallel Probes
**Decision:** Use `concurrent.futures.ThreadPoolExecutor` for port probing

**Rationale:**
- Reduces sequential probe time from 15-30s to 3-5s (6x faster)
- Latency samples parallelized (1-3s vs. 5-15s sequential)
- CPU-efficient (I/O-bound work: network, subprocess calls)
- Reuses same pool across multiple probe requests

**Implementation:**
```python
_probe_pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="probe")
```

**Trade-off:** Can't easily interrupt long-running probes mid-execution

### 3. TTL-Based Caching with Adaptive TTLs
**Decision:** Cache expensive operations (snapshots, DNS, disk latency) with mode-dependent TTLs

**Rationale:**
- Snapshot generation is expensive (probes, system queries, DB)
- Different modes have different freshness requirements:
  - Normal: 5s TTL (real-time dashboard)
  - Light: 15s TTL (reduced CPU pressure)
  - Ultra-light: 30s TTL (emergency mode)
- DNS resolution rarely changes (10-minute cache safe)
- Disk latency stable (30-second cache acceptable)

**Implementation:**
```python
DEFAULT_STATUS_CACHE_TTL_SECONDS = 15      # 3x fewer snapshot calls
LIGHT_STATUS_CACHE_TTL_SECONDS = 20
ULTRA_STATUS_CACHE_TTL_SECONDS = 30
```

### 4. Adaptive Ultra-Light Mode
**Decision:** Auto-enable ultra-light mode when sustained CPU pressure detected

**Rationale:**
- Dashboard shouldn't worsen VPN performance
- Disable expensive probes when system is under pressure
- Auto-scaling (no manual configuration needed)
- Hysteresis prevents rapid mode flipping

**Implementation:**
```python
_ADAPT_HIGH_PCT = 70.0    # Enable ultra-light when CPU > 70%
_ADAPT_LOW_PCT = 25.0     # Disable ultra-light when CPU < 25%
_ADAPT_HIGH_READS = 3     # Trigger on 3 consecutive high reads
_ADAPT_LOW_READS = 5      # Require 5 low reads to disable
```

### 5. Flask SSE Streaming for Real-Time Updates
**Decision:** Use Server-Sent Events (SSE) instead of polling for live dashboard

**Rationale:**
- Lower latency (server pushes to client)
- Lower bandwidth (only send when data changes)
- Heartbeat mechanism keeps connection alive
- Standard HTTP (no WebSocket upgrade needed)

**Implementation:**
- `/api/status/stream` endpoint yields SSE events
- Client autoreconnects on disconnect
- Heartbeat every 1s if no changes (prevents idle timeout)

### 6. JSON Serialization Caching
**Decision:** Cache JSON string representation of snapshots (not just dict)

**Rationale:**
- Avoid repeated `json.dumps()` for same snapshot
- SSE endpoint previously serialized every second
- Phase 3D2 optimization: 5x fewer serializations
- Minimal memory overhead (JSON string ~2KB)

---

## Performance Characteristics

### Snapshot Generation (with Phase 3 optimizations)

| Component | Time | Notes |
|-----------|------|-------|
| VPN status | <50ms | Run `ip` commands |
| Ports status (1 port) | 500-1500ms | Parallel TCP checks |
| Ports status (5 ports) | 1-2s | All ports in parallel |
| System metrics | 50-200ms | CPU, memory, disk |
| DNS resolution (cached) | <1ms | 10-minute cache hit |
| DNS resolution (uncached) | 50-200ms | Network lookup |
| Total snapshot (no cache) | 5-10s | All operations |
| Total snapshot (cached) | <1ms | Cache hit path |

**Snapshot Cache TTL:**
- Normal mode: 15s → ~4 regenerations/min
- Light mode: 20s → ~3 regenerations/min
- Ultra-light: 30s → ~2 regenerations/min

### API Response Times

| Endpoint | Response Time | Cache | Notes |
|----------|---------------|-------|-------|
| `/api/status` (JSON) | <100ms | 5s | Uses cached snapshot |
| `/api/status/stream` (SSE) | <50ms/event | Streaming | No cache (1s heartbeat) |
| `/api/healthz` | <50ms | 5s | Cached snapshot check |
| `/api/diagnose` | 5-10s | None | Realtime 5 parallel tests |
| `/api/uptime` | <500ms | None | DB query 24h data |
| `/api/metrics/export` | Streaming | None | O(1) memory, variable bandwidth |

### Database Performance

| Operation | Queries/min | Notes |
|-----------|------------|-------|
| Incident cache lookup | ~1 | Every ~5 seconds (cached) |
| Metrics insert | ~60 | 1 per port per minute |
| Incident insert | Variable | Only on threshold breach |

**Before Phase 3A2:** ~12 DB queries/min (incident lookup per port)  
**After Phase 3A2:** ~4 DB queries/min (incident cache 5-min TTL)

### Memory Usage

| Component | Typical | Peak | Notes |
|-----------|---------|------|-------|
| Flask app | ~50MB | ~100MB | Varies with query load |
| Metrics export (streaming) | ~5KB | ~10MB | O(1), not O(n) |
| Snapshots cache | <1MB | <5MB | 2 cached snapshots (admin/public) |
| Incident cache | <100KB | <500KB | 5-min incident window |
| DNS cache | <500KB | <2MB | 256 host limit |
| **Total** | **~60MB** | **~200MB** | Streaming prevents spikes |

---

## Technology Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Web Framework | Flask | Lightweight, simple routing, SSE support |
| Database | SQLite (WAL) | Embedded, concurrent access, zero config |
| Parallelization | `concurrent.futures` | Built-in, simple thread pool |
| Authentication | bcrypt + pyotp | Strong password hashing, 2FA support |
| Monitoring | systemd/supervisord | Native service integration |
| Config | JSON | Human-readable, version control friendly |
| Serialization | json | Standard library, fast |
| System queries | subprocess | Direct access to system info |
| HTTP Server | Werkzeug (Flask default) | Sufficient for monitoring dashboard |

---

## Deployment Models

### Model 1: Native Installation (Systemd)
- HomelinkWG service runs as unprivileged user (`homelinkwg`)
- Metrics database: `/var/lib/homelinkwg/homelinkwg-metrics.db`
- Config: `/etc/homelinkwg/config.json`
- Logs: `/var/log/homelinkwg/`
- Systemd manages service lifecycle

### Model 2: Docker Container (Supervisord)
- Dashboard runs as PID 1 in container
- Supervisor manages background metrics collector
- Metrics persist in volume mount
- Config via environment variables or volume mount
- Port 5555 exposed to host

**Both models support:**
- Multi-port port-forwarding monitoring
- Real-time diagnostics
- 24-hour metrics persistence
- Admin authentication with optional TOTP
- SSE streaming to multiple clients

---

## Security Considerations

### Authentication
- Admin password hashed with bcrypt (salted, iterated)
- Session tokens random, IP/User-Agent validated
- Login rate limiting: 5 attempts per 15 min per IP
- API rate limiting: 100 requests per 60s per session

### Session Management
- HTTP-only cookies (prevent XSS access)
- 60-minute timeout (configurable)
- Re-auth required for sensitive operations (`@require_admin`)
- Correlation IDs for audit trail

### Data Protection
- Passwords never logged
- Metrics database readable only by homelinkwg user
- Configuration file (analytics.conf) with 600 permissions
- All SQL queries use parameterized statements (no injection)

### Network Isolation
- SSE stream runs over same HTTPS as main dashboard
- No unauthenticated access to status endpoints (without redaction)
- Redacted mode hides remote host/port from unauthenticated users

---

## Monitoring & Observability

### Logging
- All operations logged via structured `flog()` function
- Levels: DEBUG, INFO, WARN, ERROR
- Correlation ID tracks request through system
- Format: timestamp, level, component, message, context dict

### Health Checks
- `/api/livez` - Liveness (always responds 200)
- `/api/healthz` - Readiness (200 if VPN+ports OK, 503 if degraded)
- Metrics collector health status in `/api/status` → `runtime`

### Diagnostics
- `/api/diagnose?port_id=port-NNNN` - Segmented latency analysis
- Breakdowns: local (client→socat), tunnel (socat→VPN), target (VPN→service)
- Identifies bottleneck: service, local path, VPN path, or target

---

## Future Enhancements

1. **Prometheus Metrics** - Export `/metrics` for Prometheus scraping
2. **Persistent Sessions** - Store sessions in database (for HA)
3. **Webhook Alerts** - Notify on threshold breach (email, Slack, etc.)
4. **Multi-admin** - Support multiple admin users with different permissions
5. **API Tokens** - Long-lived tokens for programmatic access
6. **Custom Probes** - User-defined health checks (scripts)
7. **Performance APM** - Detailed tracing of slow operations
