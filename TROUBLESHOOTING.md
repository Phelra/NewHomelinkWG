# HomelinkWG Troubleshooting Guide

## Quick Diagnostics

**Start here for most issues:**

```bash
# 1. Check if dashboard is running
curl -s http://localhost:5555/api/healthz | jq .

# 2. Check VPN status
curl -s http://localhost:5555/api/status | jq '.vpn'

# 3. Check all ports
curl -s http://localhost:5555/api/status | jq '.ports[] | {local_port, overall_status}'

# 4. Check logs
sudo journalctl -u homelinkwg-dashboard -n 50 -f

# 5. Check metrics database
sqlite3 homelinkwg-metrics.db "SELECT COUNT(*) as metric_count FROM metrics;"
```

---

## Common Issues & Solutions

### 1. VPN Tunnel Issues

#### Problem: "WireGuard tunnel shows DOWN"

**Diagnostic Steps:**

```bash
# Step 1: Check WireGuard interface exists
ip link show wg0

# Step 2: Check interface has IP
ip addr show wg0

# Step 3: Check WireGuard status
wg show

# Step 4: Check systemd service status (if managed)
sudo systemctl status wg-quick@wg0
```

**Common Causes:**

| Symptom | Cause | Solution |
|---------|-------|----------|
| Interface doesn't exist | Config not loaded | Load config: `sudo wg-quick up wg0` |
| No IP address | DHCP/Config issue | Check config file for Address setting |
| Handshake old (>2min) | Peer unreachable | Check firewall rules, peer endpoint |
| Multiple peers shown | Misconfiguration | Review peers in config |

**Dashboard Diagnostic:**
```bash
# Use /api/diagnose endpoint
curl -s 'http://localhost:5555/api/diagnose?port_id=port-8080' | grep wireguard
```

---

#### Problem: "Target unreachable through tunnel"

**Investigation:**

The `/api/diagnose` endpoint shows latency breakdown:
- **Local latency** (client→socat): Should be <20ms
- **Tunnel latency** (socat→VPN): Should be <50ms
- **Target latency** (VPN→service): Depends on service

**If tunnel latency is high:**

1. Check WireGuard handshake:
```bash
wg show
# Look for "latest handshake: X seconds ago"
# Should be recent (<2 minutes)
```

2. Check tunnel MTU:
```bash
ip link show wg0 | grep mtu
# WireGuard MTU is typically 1420 (1500 - 80 byte overhead)
```

3. Check AllowedIPs on peer:
```bash
wg show
# AllowedIPs should include target IP or subnet
```

**If target latency is high:**

- Check target service is running: `ssh user@target systemctl status service`
- Check target firewall allows incoming connections
- Check routing tables: `route -n` on target

---

#### Problem: "Intermittent connectivity"

**Symptoms:** Random timeouts, packet loss, high jitter

**Check System Pressure:**

```bash
# Check CPU usage
top -n 1 | head -3

# Check if ultra-light mode activated
curl -s http://localhost:5555/api/status | jq '.runtime.ultra_light'

# If ultra_light=true, system is under CPU pressure
# Reduce number of ports or disable expensive probes
```

**Check Network Stability:**

```bash
# Monitor jitter in diagnose output
curl -s 'http://localhost:5555/api/diagnose?port_id=port-8080' \
  | grep -o '"jitter_ms":[^,}]*'

# High jitter (>50ms) indicates network instability
```

**Solutions:**

- Reduce probe frequency in config
- Enable light mode: Set in config or auto-detected
- Check for packet loss: `ping -c 100 target.host | grep "% packet loss"`

---

### 2. Performance Issues

#### Problem: "Dashboard slow to load"

**Check Snapshot Generation Time:**

```bash
# View logs for snapshot timing
journalctl -u homelinkwg-dashboard | grep "snapshot"

# Typical time: 5-10s for full snapshot
# If >15s, probes may be hanging
```

**Check Current Mode:**

```bash
curl -s http://localhost:5555/api/status | jq '.runtime'
```

**Modes:**
- `light_mode=false, ultra_light=false` - Normal (fast)
- `light_mode=true` - Reduced TCP probes
- `ultra_light=true` - Minimal probes (emergency mode)

**Solutions:**

```bash
# Option 1: Force light mode
# Edit config.json, add: "light_mode": true

# Option 2: Reduce number of ports in config
# Remove non-critical ports from monitoring

# Option 3: Check for hanging probes
# Set timeout in logs, see if any probe >10s
```

---

#### Problem: "High CPU usage"

**Diagnose Source:**

```bash
# Check which process uses CPU
top -n 1 | grep python

# Check if metrics collector is running
curl -s http://localhost:5555/api/status | jq '.runtime | select(.ultra_light_adaptive==true)'
```

**Solutions:**

1. **Reduce ports:** Each port = ~1 TCP check + latency measurement
2. **Disable metrics collection:** Set `analytics_enabled=false` in config
3. **Increase cache TTL:** Edit dashboard.py `DEFAULT_STATUS_CACHE_TTL_SECONDS`
4. **Increase probe intervals:** Add delay between probe cycles

---

#### Problem: "Database growing large"

**Check Database Size:**

```bash
du -h homelinkwg-metrics.db
# Typical: 1MB per 1000 metric samples
# 90 days @ 1/min per port = 90 * 24 * 60 = 129,600 rows
# With 5 ports = 648,000 rows ≈ 50-100MB
```

**Clean Old Data:**

```bash
# Backup first
cp homelinkwg-metrics.db homelinkwg-metrics.db.backup

# Delete metrics older than 30 days
sqlite3 homelinkwg-metrics.db "DELETE FROM metrics WHERE timestamp < datetime('now', '-30 days');"

# Vacuum to reclaim space
sqlite3 homelinkwg-metrics.db "VACUUM;"

# Check new size
du -h homelinkwg-metrics.db
```

---

### 3. Authentication Issues

#### Problem: "Login fails repeatedly"

**Check Rate Limiting:**

```bash
# Login rate limit: 5 attempts per 15 minutes per IP
# Wait 15 minutes after 5 failures, or:
# 1. Try from different IP/client
# 2. Check admin password is correct
```

**Check Password Hash:**

```bash
# Verify password is set in analytics.conf
grep ADMIN_PASSWORD /etc/homelinkwg/analytics.conf

# If empty, set password:
# 1. Generate hash: python3 -c "import bcrypt; print(bcrypt.hashpw(b'newpass', bcrypt.gensalt()).decode())"
# 2. Add to analytics.conf: ADMIN_PASSWORD=<hash>
# 3. Restart dashboard
```

**Check Session is Valid:**

```bash
# Session timeout: 60 minutes
# After timeout, must re-login
# Check if session cookie is present:
curl -v http://localhost:5555/api/status 2>&1 | grep "Set-Cookie"
```

---

#### Problem: "TOTP codes rejected"

**Check System Time:**

```bash
# TOTP requires accurate system time (±30 seconds)
ntpstat
# Should show "synchronized to..."

# Sync time if needed
sudo ntpdate ntp.ubuntu.com
```

**Check TOTP Secret:**

```bash
# TOTP secret must be set in analytics.conf
grep TOTP_SECRET /etc/homelinkwg/analytics.conf

# Generate new TOTP secret if needed:
# python3 -c "import pyotp; print(pyotp.random_base32())"
```

**Troubleshoot Code Timing:**

```bash
# TOTP uses 30-second windows, allows ±1 window = 60s tolerance
# Try code from previous/next 30s window if current fails
# Generate codes: python3 -c "import pyotp; totp = pyotp.TOTP(secret); print(totp.now())"
```

---

### 4. Configuration Issues

#### Problem: "Config changes not taking effect"

**Causes:**

| Symptom | Cause | Solution |
|---------|-------|----------|
| New ports not monitored | Config not reloaded | Restart dashboard or reload manually |
| Old ports still showing | Config not reloaded | Restart dashboard |
| Mode not applying | Cache TTL not expired | Wait 5+ seconds for cache to expire |

**Reload Config:**

```bash
# Option 1: Restart service
sudo systemctl restart homelinkwg-dashboard

# Option 2: Reload via API (admin only)
# No direct API for this yet, must restart
```

---

#### Problem: "Port configuration invalid"

**Check Configuration:**

```bash
# Validate JSON syntax
python3 -m json.tool config.json

# Required fields per port:
# - local_port (integer)
# - remote_host (string)
# - remote_port (integer)
```

**Example Valid Config:**

```json
{
  "ports": [
    {
      "enabled": true,
      "local_port": 8080,
      "remote_host": "example.com",
      "remote_port": 443,
      "name": "Web Server"
    }
  ]
}
```

---

### 5. Monitoring & Alerting

#### Problem: "Alerts always muted"

**Check Mute Status:**

```bash
# Check if alerts are muted
curl -s http://localhost:5555/api/status | jq '.alerts'

# Output:
{
  "muted": true,
  "mute_until": "2026-04-30T12:00:00",
  "active_count": 2
}
```

**Unmute:**

```bash
# Unmute immediately (duration=0)
curl -X POST http://localhost:5555/api/alerts/mute/0 \
  -H "Cookie: session={token}"
```

---

#### Problem: "Missing metrics"

**Check Analytics Status:**

```bash
# Check if analytics are enabled
curl -s http://localhost:5555/api/status | jq '.runtime | {analytics_enabled}'

# If disabled:
# 1. Set analytics_enabled=true in config.json
# 2. Restart dashboard
```

**Check Collector Thread:**

```bash
# Check metrics collector health
curl -s http://localhost:5555/api/status | jq '.metrics_collector'

# Output:
{
  "cycles": 1440,
  "last_cycle_ts": 1714328400,
  "age_seconds": 5.2,
  "healthy": true,
  "last_error": null
}

# If healthy=false, check logs for errors
journalctl -u homelinkwg-dashboard | grep ERROR
```

**Check Database Permissions:**

```bash
# Database file should be writable by homelinkwg user
ls -la homelinkwg-metrics.db
# Should show: rw-rw---- homelinkwg:homelinkwg

# Fix permissions if needed:
sudo chown homelinkwg:homelinkwg homelinkwg-metrics.db
sudo chmod 660 homelinkwg-metrics.db
```

---

## Debugging Tools

### 1. Using /api/status Endpoint

```bash
# Full snapshot (JSON format)
curl -s http://localhost:5555/api/status | jq .

# Just VPN status
curl -s http://localhost:5555/api/status | jq '.vpn'

# Just ports
curl -s http://localhost:5555/api/status | jq '.ports | length'

# Last error in system logs
curl -s http://localhost:5555/api/status | jq '.diagnostics_summary'
```

### 2. Using /api/diagnose Endpoint

```bash
# Run diagnostics for specific port
curl -N http://localhost:5555/api/diagnose?port_id=port-8080 \
  | jq -R 'fromjson? | select(.step)' \
  | jq '{step, status, message, segments}'
```

### 3. Enabling Debug Logging

```bash
# Set environment variable
export HOMELINKWG_DEBUG=1
sudo systemctl set-environment HOMELINKWG_DEBUG=1

# Restart service
sudo systemctl restart homelinkwg-dashboard

# View verbose logs
journalctl -u homelinkwg-dashboard -n 100 | grep DEBUG
```

### 4. Checking System Logs

```bash
# Systemd logs (native systemd deployment)
journalctl -u homelinkwg-dashboard -f

# Docker logs (container deployment)
docker logs -f homelinkwg

# Application logs
tail -f /var/log/homelinkwg/dashboard.log
```

### 5. Database Access

```bash
# Connect to SQLite database
sqlite3 homelinkwg-metrics.db

# Useful queries:
# Count metrics
SELECT COUNT(*) FROM metrics;

# Check latest metric timestamp
SELECT MAX(timestamp) FROM metrics;

# See recent incidents
SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 10;

# Check port-specific uptime
SELECT port_id, COUNT(*) as total, 
       SUM(CASE WHEN target_reachable=1 THEN 1 ELSE 0 END) as up,
       ROUND(100.0 * SUM(CASE WHEN target_reachable=1 THEN 1 ELSE 0 END) / COUNT(*), 1) as uptime_pct
FROM metrics 
WHERE timestamp > datetime('now', '-1 day')
GROUP BY port_id;
```

---

## Network Diagnostics

### Check Network Connectivity

```bash
# From dashboard host to target through VPN
ping -c 5 10.0.0.2  # VPN IP of target

# Check route to target
route -n | grep UG  # Gateway

# Traceroute through tunnel
traceroute target.example.com | head -5
```

### Monitor Real-Time Traffic

```bash
# Watch WireGuard interface
watch -n 1 'wg show'

# Monitor bandwidth
vnstat -i wg0

# Check packet loss
ping -i 0.2 target.example.com | grep "% packet loss"
```

### Test Service on Target

```bash
# From target side
ssh user@target "systemctl status servicename"

# Check if port is listening
ssh user@target "ss -tuln | grep :443"

# Test service directly
ssh user@target "curl -v http://localhost:443"
```

---

## Performance Optimization

### Reduce Snapshot Generation Time

```bash
# Current time
journalctl -u homelinkwg-dashboard | grep "snapshot" | tail -1

# Bottlenecks:
# 1. Too many ports: Reduce to essential ports only
# 2. DNS timeouts: Check /etc/resolv.conf
# 3. System under pressure: Enable light mode
# 4. Long probes: Check for hanging TCP connections
```

### Reduce Database Load

```bash
# Current query load
sqlite3 homelinkwg-metrics.db "PRAGMA query_only=ON; SELECT COUNT(*) FROM metrics;"

# Optimize by:
# 1. Reducing probe frequency (cache TTL)
# 2. Disabling analytics for non-critical ports
# 3. Archiving old metrics (DELETE + VACUUM)
# 4. Using streaming export instead of in-memory loads
```

---

## When to Escalate

If none of the above steps resolve the issue:

1. **Collect diagnostic bundle:**
   ```bash
   curl -s http://localhost:5555/api/diagnostics/bundle | jq . > diag.json
   ```

2. **Check system logs:**
   ```bash
   journalctl -u homelinkwg-dashboard --all --no-pager > logs.txt
   ```

3. **Include in bug report:**
   - `diag.json` (system state)
   - `logs.txt` (recent errors)
   - `config.json` (redacted)
   - Steps to reproduce

---

## See Also

- [API.md](API.md) - API reference for diagnostics endpoints
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design for understanding internals
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development environment setup
