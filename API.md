# HomelinkWG REST API Documentation

## Table of Contents

- [Authentication](#authentication)
- [Status Endpoints](#status-endpoints)
- [Diagnostic Endpoints](#diagnostic-endpoints)
- [Configuration Endpoints](#configuration-endpoints)
- [Metrics & Analytics](#metrics--analytics)
- [Admin Endpoints](#admin-endpoints)
- [Server Health](#server-health)
- [Error Handling](#error-handling)

---

## Base URL

```
http://localhost:5555/api/
```

## Authentication

### Login

**Endpoint:** `POST /api/login`

**Request:**
```json
{
  "password": "admin_password",
  "totp": "123456"  // Optional, only if TOTP enabled
}
```

**Response (Success):**
```json
{
  "ok": true,
  "message": "Login successful",
  "session": "token_string"
}
```

**Response (Failure - 401):**
```json
{
  "error": "Invalid password or TOTP code",
  "remaining_attempts": 4
}
```

**Rate Limiting:**
- 5 login attempts per 15 minutes per IP
- After 5 failures, retry required after 15 minutes
- TOTP clock skew tolerance: ±1 time window (60 seconds total)

**Headers:**
- `Content-Type: application/json`
- Returns `Set-Cookie: session={token}; HttpOnly; Path=/`

---

## Status Endpoints

### Get Status (JSON)

**Endpoint:** `GET /api/status`

**Authentication:** Optional (redacted without admin)

**Cache:** 5 seconds (public cache)

**Response:**
```json
{
  "timestamp": "2026-04-29T15:30:45",
  "version": "5.0",
  "date": "2026-04-28",
  "vpn": {
    "status": "CONNECTED",
    "ip": "10.0.0.1",
    "interface": "wg0"
  },
  "ports": [
    {
      "local_port": 8080,
      "remote_host": "example.com",
      "remote_port": 443,
      "name": "HTTPS Service",
      "description": "Production web server",
      "port_active": true,
      "service_active": true,
      "target_reachable": true,
      "overall_status": "ACTIVE",
      "has_incident": false,
      "public_read_only": false,
      "stats_24h": {
        "uptime_24h_percent": 99.5,
        "avg_latency_ms": 45.2,
        "samples": 1440,
        "uptime_trend": "stable",
        "latency_trend": "improving"
      }
    }
  ],
  "system": {
    "cpu_percent": 12.5,
    "memory_percent": 34.2,
    "load_avg": [0.5, 0.4, 0.3]
  },
  "network": {
    "wg0": {
      "bytes_in": 1024000,
      "bytes_out": 512000,
      "packets_in": 5000,
      "packets_out": 3000,
      "errors_in": 0,
      "errors_out": 0
    }
  },
  "diagnostics": {
    "internet": "PASS",
    "wg_ip": "10.0.0.1",
    "routes": true,
    "target_reachable": true,
    "wg_handshake_recent": true
  },
  "diagnostics_summary": {
    "code": "healthy",
    "message": "No obvious issue detected."
  },
  "alerts": {
    "muted": false,
    "mute_until": null,
    "active_count": 0
  },
  "runtime": {
    "light_mode": false,
    "ultra_light": false,
    "ultra_light_adaptive": false,
    "refresh_ms": 5000,
    "analytics_refresh_ms": 30000,
    "public_read_only": false
  }
}
```

**Redacted Mode (without admin auth):**
- `remote_host` → `"hidden"`
- `remote_port` → `"hidden"`
- `vpn.ip` → `"N/A"`
- All stats still visible

---

### Stream Status (Server-Sent Events)

**Endpoint:** `GET /api/status/stream`

**Authentication:** Optional (redacted without admin)

**Response Type:** `text/event-stream` (SSE)

**Behavior:**
- Streams full status snapshot every time state changes
- Sends heartbeat every 1 second if no changes
- Client automatically reconnects on disconnect
- Stream lifetime: 10 minutes (client should reconnect)

**Example Stream:**
```
data: {"timestamp":"2026-04-29T15:30:45",...full status dict...}

: heartbeat

data: {"timestamp":"2026-04-29T15:30:46",...full status dict...}

: heartbeat
```

**Headers:**
- `Content-Type: text/event-stream`
- `Cache-Control: no-cache`
- `X-Accel-Buffering: no` (disable proxy buffering)

---

### Health Check

**Endpoint:** `GET /api/healthz`

**Authentication:** Not required

**Cache:** 5 seconds (public cache)

**Response (Healthy - 200):**
```json
{
  "ok": true,
  "timestamp": "2026-04-29T15:30:45"
}
```

**Response (Degraded - 503):**
```json
{
  "ok": false,
  "timestamp": "2026-04-29T15:30:45"
}
```

**Criteria for 503:**
- VPN status != "CONNECTED"
- OR any configured port status != "ACTIVE"

**Use Case:** Load balancer health checks, Kubernetes liveness probes

---

### Liveness Check

**Endpoint:** `GET /api/livez`

**Authentication:** Not required

**Cache:** None (always fresh)

**Response:** `200 OK` (empty body)

**Purpose:** Pure liveness check (process is running), independent of system health

---

## Diagnostic Endpoints

### Latency Breakdown

**Endpoint:** `GET /api/diagnose?port_id=port-8080`

**Required Params:**
- `port_id`: Port identifier (format: `port-{local_port}`)

**Optional Params:**
- `full`: "true" for extended diagnostics (default: false)

**Authentication:** Required (admin)

**Response Type:** `text/event-stream` (SSE)

**Latency Breakdown Segments:**

1. **Local Path** (Client → Socat)
   - Measures latency to local forwarded port
   - TCP connect time from 127.0.0.1

2. **Tunnel Path** (Socat → VPN)
   - Implied by WireGuard tunnel status
   - = Target latency - Local latency

3. **Target Path** (VPN → Service)
   - Measures latency through tunnel to target
   - Identifies bottleneck (service response time)

**Stream Events:**
```
data: {"step":"local_latency","status":"testing","message":"Measuring..."}
data: {"step":"local_latency","status":"ok","message":"avg=12.5ms","latency":12.5}
data: {"step":"wireguard","status":"ok","message":"Connected (IP: 10.0.0.1)"}
data: {"step":"target_latency","status":"testing","message":"Measuring..."}
data: {"step":"target_latency","status":"ok","message":"avg=45.2ms","latency":45.2}
data: {
  "step":"complete",
  "status":"done",
  "service_active": true,
  "target_reachable": true,
  "segments": {
    "local_ms": 12.5,
    "tunnel_ms": 32.7,
    "target_ms": 45.2
  },
  "bottleneck": "vpn_path"
}
```

**Duration:** 5-10 seconds total

**Bottleneck Identification:**
- `"service"` - Service not running
- `"target_unreachable"` - Target not responding
- `"local_path"` - High local latency (>15ms)
- `"vpn_path"` - High tunnel latency (largest segment)
- `"target_path"` - High target response time

---

### 24-Hour Uptime

**Endpoint:** `GET /api/uptime?port_id=port-8080`

**Required Params:**
- `port_id`: Port identifier

**Authentication:** Required (admin)

**Response:**
```json
{
  "port_id": "port-8080",
  "service_name": "HTTPS Service",
  "uptime_24h_percent": 99.5,
  "avg_latency_ms": 45.2,
  "min_latency_ms": 12.3,
  "max_latency_ms": 128.7,
  "samples": 1440,
  "uptime_trend": "stable",
  "latency_trend": "improving",
  "incidents_24h": [
    {
      "timestamp": "2026-04-28T08:15:00",
      "event_type": "PORT_DOWN",
      "severity": "high",
      "description": "Port not listening"
    }
  ]
}
```

**Uptime Trend:**
- `"improving"` - Uptime increased in last 12 hours
- `"degrading"` - Uptime decreased
- `"stable"` - No significant change

**Latency Trend:**
- `"improving"` - Average latency decreased
- `"degrading"` - Average latency increased
- `"stable"` - No significant change

---

## Configuration Endpoints

### Get Configuration

**Endpoint:** `GET /api/config`

**Authentication:** Required (admin)

**Response:**
```json
{
  "config": {
    "vpn": {
      "interface": "wg0",
      "config_file": "yourconfwg/wg0.conf"
    },
    "ports": [
      {
        "enabled": true,
        "local_port": 8080,
        "remote_host": "example.com",
        "remote_port": 443,
        "name": "HTTPS Service",
        "description": "Production web server"
      }
    ]
  }
}
```

---

### Update Configuration

**Endpoint:** `POST /api/config`

**Authentication:** Required (admin)

**Request:**
```json
{
  "config": {
    "vpn": {
      "interface": "wg0",
      "config_file": "yourconfwg/wg0.conf"
    },
    "ports": [...]
  }
}
```

**Response (Success):**
```json
{
  "ok": true,
  "message": "Configuration updated"
}
```

**Response (Validation Error - 400):**
```json
{
  "error": "config.ports must be an array"
}
```

**Validation Rules:**
- `config` must be a JSON object
- `config.ports` must be an array
- Each port must have: `local_port`, `remote_host`, `remote_port`

---

### Get Thresholds

**Endpoint:** `GET /api/config/thresholds`

**Authentication:** Required (admin)

**Response:**
```json
{
  "latency_threshold_ms": 50.0,
  "uptime_threshold_percent": 95.0
}
```

---

### Update Thresholds

**Endpoint:** `POST /api/config/thresholds`

**Authentication:** Required (admin)

**Request:**
```json
{
  "latency_threshold_ms": 100.0,
  "uptime_threshold_percent": 90.0
}
```

**Response:**
```json
{
  "ok": true,
  "thresholds": {
    "latency_threshold_ms": 100.0,
    "uptime_threshold_percent": 90.0
  }
}
```

---

## Metrics & Analytics

### Export Metrics

**Endpoint:** `GET /api/metrics/export`

**Optional Params:**
- `days`: Number of days to export (1-90, default: 7)
- `port_id`: Filter by port (optional, default: all)

**Authentication:** Required (admin)

**Response Type:** `text/csv`

**Headers:**
- `Content-Type: text/csv`
- `Content-Disposition: attachment; filename=homelinkwg-metrics-7d.csv`

**CSV Format:**
```csv
datetime_utc,timestamp_unix,port_id,service_name,service_active,port_listening,target_reachable,latency_ms
2026-04-28 12:00:00,1714328400,port-8080,HTTPS Service,1,1,1,45
2026-04-28 12:01:00,1714328460,port-8080,HTTPS Service,1,1,1,47
```

**Streaming:**
- CSV streamed directly (memory: O(1), not O(n_rows))
- Suitable for 90-day exports (100k+ rows)
- Each row sent as it's retrieved from database

---

## Admin Endpoints

### Service Restart

**Endpoint:** `POST /api/service/{service}/restart`

**Parameters:**
- `service`: Service name (e.g., `homelinkwg-socat-8080`)

**Authentication:** Required (admin)

**Request:** `{}` (empty body)

**Response (Success):**
```json
{
  "ok": true,
  "message": "Service restarted",
  "service": "homelinkwg-socat-8080"
}
```

**Response (Failure - 400):**
```json
{
  "error": "Service restart failed",
  "details": "systemctl: command not found"
}
```

---

### Alerts Mute

**Endpoint:** `POST /api/alerts/mute/{duration}`

**Parameters:**
- `duration`: Duration in minutes (0 to unmute immediately)

**Authentication:** Required (admin)

**Response:**
```json
{
  "ok": true,
  "muted": true,
  "mute_until": "2026-04-29T16:30:45",
  "message": "Alerts muted for 60 minutes"
}
```

**Special Values:**
- `duration=0` → Unmute immediately

---

### Diagnostics Bundle

**Endpoint:** `GET /api/diagnostics/bundle`

**Authentication:** Required (admin)

**Response:**
```json
{
  "timestamp": "2026-04-29T15:30:45",
  "version": "5.0",
  "system": {
    "hostname": "router",
    "os": "Linux 5.10.0",
    "python": "3.10.12"
  },
  "wireguard": {
    "interface": "wg0",
    "status": "CONNECTED",
    "ip": "10.0.0.1",
    "peers": 2,
    "last_handshake": "2 minutes ago"
  },
  "ports": [...],
  "services": {
    "homelinkwg-socat-8080": "running",
    "homelinkwg-socat-8443": "running"
  },
  "metrics_collector": {
    "cycles": 1440,
    "last_cycle_ts": 1714328400,
    "age_seconds": 5.2,
    "healthy": true,
    "last_error": null
  },
  "logs": [
    {"level": "INFO", "component": "probe", "message": "Port 8080 status: ACTIVE", "timestamp": 1714328395},
    ...last 100 log lines...
  ]
}
```

**Use Case:** Debugging issues, sending to support

---

## Server Health

### Version Information

**Endpoint:** `GET /api/version`

**Authentication:** Not required

**Response:**
```json
{
  "version": "5.0",
  "date": "2026-04-28",
  "api_version": "1.0"
}
```

---

### Release Notes

**Endpoint:** `GET /api/release-notes`

**Authentication:** Not required

**Response:**
```json
{
  "version": "5.0",
  "notes": "...",
  "released": "2026-04-28"
}
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning | Example |
|------|---------|---------|
| 200 | OK | Successful GET request |
| 400 | Bad Request | Invalid JSON, missing required field |
| 401 | Unauthorized | Invalid credentials, session expired |
| 403 | Forbidden | Insufficient permissions (non-admin endpoint) |
| 404 | Not Found | Unknown port_id, missing endpoint |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Error | Unexpected exception |
| 503 | Service Unavailable | Database error, analytics disabled |

### Error Response Format

**Example 401 (Unauthorized):**
```json
{
  "error": "Session expired or invalid",
  "code": "auth_expired",
  "timestamp": "2026-04-29T15:30:45"
}
```

**Example 429 (Rate Limited):**
```json
{
  "error": "Too many login attempts",
  "retry_after_seconds": 900,
  "remaining_attempts": 0
}
```

---

## Rate Limiting

### Login Attempts
- **Limit:** 5 per 15 minutes per IP
- **Header:** (No header returned, applies to all requests from IP)
- **Behavior:** Blocks login POST after 5 failures for 15 minutes

### API Requests
- **Limit:** 100 per 60 seconds per session
- **Header:** `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- **Behavior:** Returns 429 when exceeded

### Query String Parameters
- **Max ports per config:** 100 (if required)
- **Max export days:** 90 (for metrics)
- **Max samples per diagnose:** 10 (per test)

---

## Headers

### Request Headers (General)

```
Content-Type: application/json
Authorization: Bearer {session_token}  (Optional, use Cookie instead)
X-Requested-With: XMLHttpRequest      (Optional, CORS)
```

### Request Headers (SSE)

```
Accept: text/event-stream
Cache-Control: no-cache
```

### Response Headers (General)

```
Content-Type: application/json; charset=utf-8
Cache-Control: public, max-age=5      (varies by endpoint)
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Set-Cookie: session={token}; HttpOnly; Path=/; SameSite=Strict
```

### Response Headers (SSE)

```
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no
Connection: keep-alive
```

---

## Examples

### Example 1: Check System Health

```bash
# Get current status
curl -s http://localhost:5555/api/healthz | jq .

# Response
{
  "ok": true,
  "timestamp": "2026-04-29T15:30:45"
}
```

### Example 2: Monitor Real-Time Status

```bash
# Stream status updates (subscribe to changes)
curl -N http://localhost:5555/api/status/stream | while IFS= read -r line; do
  echo "$(date): $line"
done
```

### Example 3: Export Metrics for Analysis

```bash
# Export 7 days of metrics
curl -s http://localhost:5555/api/metrics/export?days=7 \
  -H "Cookie: session={session_token}" \
  -o metrics.csv

# View first 10 rows
head -10 metrics.csv
```

### Example 4: Diagnose Latency Issue

```bash
# Run latency breakdown for port 8080
curl -s http://localhost:5555/api/diagnose?port_id=port-8080 \
  -H "Cookie: session={session_token}" | grep -o 'data: .*'
```

---

## Deprecated Endpoints

None currently. API is stable in v5.0.

---

## API Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-04-28 | Initial API (v5.0 dashboard) |

---

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - System design and module architecture
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and debugging
- [DEVELOPMENT.md](DEVELOPMENT.md) - Contributing guidelines
