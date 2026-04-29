# HomelinkWG Development Guide

## Development Setup

### Prerequisites

- Python 3.10+
- Git
- Linux system (WSL2 on Windows)
- WireGuard installed (for testing)

### Installation

```bash
# Clone repository
git clone <repo-url>
cd woodenforestplatform_upgrade_v5.0

# Create Python environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development tools
pip install ruff pytest
```

### Configuration

```bash
# Create config.json
cat > config.json << 'EOF'
{
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
      "name": "Test Service"
    }
  ]
}
EOF

# Create analytics.conf
cat > analytics.conf << 'EOF'
ADMIN_PASSWORD=$2b$12$...bcrypt_hash...
TOTP_ENABLED=false
EOF

# Run locally
python3 dashboard.py
# Visit http://localhost:5555
```

---

## Running Tests

### Unit Tests

```bash
# Run all tests
pytest test_dashboard.py -v

# Run specific test
pytest test_dashboard.py::test_parse_kv_config -v

# Run with coverage
pytest test_dashboard.py --cov=homelinkwg --cov-report=html
```

### What's Tested

- `test_parse_kv_config()` - Configuration parsing
- `test_verify_password()` - Password verification (bcrypt)
- `test_load_config()` - Config caching and TTL
- `test_correlation_id()` - Request tracking
- More in `test_dashboard.py`

### Adding New Tests

```python
# In test_dashboard.py
def test_new_feature():
    """Test description."""
    # Arrange
    setup_data = {...}
    
    # Act
    result = function_under_test(setup_data)
    
    # Assert
    assert result == expected_value
```

---

## Code Quality

### Linting

```bash
# Check code style
ruff check homelinkwg/ dashboard.py

# Auto-fix common issues
ruff check --fix homelinkwg/ dashboard.py
```

### Type Hints

The codebase is 96% type-hinted. All new functions MUST include:
- Parameter type hints
- Return type hints
- Type hints in complex structures

Example:
```python
def calculate_uptime(port_id: str, days: int) -> float | None:
    """Calculate uptime percentage.
    
    Args:
        port_id: Port identifier (format: port-NNNN)
        days: Number of days to calculate (1-90)
    
    Returns:
        Uptime percentage (0-100) or None if insufficient data
    """
    ...
```

### Docstrings

All public functions MUST have docstrings:
```python
def get_port_status(port_id: str) -> dict[str, Any]:
    """Get current status of a port.
    
    Checks local port listening, service status, and target reachability
    in parallel using ThreadPoolExecutor for performance.
    
    Args:
        port_id: Port identifier (e.g., 'port-8080')
    
    Returns:
        Dict with keys: port_active, service_active, target_reachable
    
    Raises:
        ValueError: If port_id format invalid
    """
```

---

## Adding New Features

### Adding a New API Endpoint

1. **Define function in `homelinkwg/api.py`:**
   ```python
   @app.route("/api/mynew", methods=["GET"])
   @require_admin  # If admin-only
   def my_new_endpoint():
       """Describe what this endpoint does."""
       # Get data
       result = some_function()
       # Return JSON
       return jsonify({"data": result})
   ```

2. **Add to API.md documentation**

3. **Test locally:**
   ```bash
   curl http://localhost:5555/api/mynew
   ```

### Adding a New Probe

1. **Add function to `homelinkwg/probes.py`:**
   ```python
   def my_probe(host: str, port: int) -> bool | None:
       """Check something specific about host:port.
       
       Returns:
           True if check passes, False if fails, None if unknown
       """
       # Implementation
       return True
   ```

2. **Integration options:**
   - Add to `ports_status()` for regular monitoring
   - Add to `diagnostics()` for diagnostic endpoint
   - Call via API endpoint directly

3. **Performance considerations:**
   - Should complete in <1 second
   - Use ThreadPoolExecutor for concurrent work
   - Cache results if called frequently

### Adding a New Configuration Option

1. **Document in `homelinkwg/config.py`:**
   ```python
   MY_NEW_SETTING = os.getenv("HOMELINKWG_MY_SETTING", "default_value")
   ```

2. **Load in config file:**
   ```bash
   # In config.json
   {
     "my_setting": "value"
   }
   ```

3. **Access in code:**
   ```python
   cfg = load_config()
   value = cfg.get("my_setting", "default")
   ```

---

## Performance Guidelines

### Snapshot Generation Budget

- **Target:** <10 seconds total
- **VPN status:** <50ms
- **Port probes:** 1-3s (5 ports in parallel)
- **System metrics:** <200ms
- **Diagnostics:** <2s (if enabled)

### Cache Appropriately

- Snapshot: 5-30s (depends on mode)
- DNS: 600s (10 minutes)
- Config: 2s
- Disk latency: 30s

Use `cache_store` for expensive operations:
```python
cache_key = "my_expensive_operation"
cached = cache_store.get(cache_key)
if cached:
    return cached

result = expensive_operation()
cache_store.set(cache_key, result)
return result
```

### Monitor Before Optimizing

Use the `/api/status` endpoint to measure:
```bash
# Time snapshot generation
time curl http://localhost:5555/api/status | jq '.ports | length'

# Check CPU usage
curl http://localhost:5555/api/status | jq '.system.cpu_percent'

# Identify slow probes in logs
journalctl -u homelinkwg-dashboard | grep "WARN\|slow"
```

---

## Git Workflow

### Branch Naming

```bash
# Feature
git checkout -b feature/add-webhook-alerts

# Bug fix
git checkout -b fix/rate-limit-bypass

# Documentation
git checkout -b docs/update-api-guide

# Refactoring
git checkout -b refactor/simplify-snapshot-logic
```

### Commit Messages

```bash
# Format: {verb} {what} - {why}
git commit -m "Add webhook alerting - notify users on threshold breach"
git commit -m "Fix rate limit bypass - session verification was missing"
git commit -m "Refactor probe execution - parallelize TCP checks"
```

### Before Pushing

```bash
# 1. Run tests
pytest test_dashboard.py -v

# 2. Run linting
ruff check homelinkwg/ dashboard.py

# 3. Test manually
python3 dashboard.py
# Check http://localhost:5555

# 4. Push to branch
git push -u origin feature/yourfeature
```

### Pull Request Checklist

- [ ] All tests pass (`pytest test_dashboard.py`)
- [ ] Linting clean (`ruff check`)
- [ ] Manual testing done
- [ ] Documentation updated (API.md, ARCHITECTURE.md if needed)
- [ ] No secrets committed (no passwords, API keys)
- [ ] Commit messages follow format
- [ ] Branch updated with latest main

---

## Architecture Patterns

### Threading Safety

Use locks when accessing shared state:
```python
from threading import Lock

_my_cache_lock = Lock()
_my_cache = {}

def get_cached(key):
    with _my_cache_lock:
        if key in _my_cache:
            return _my_cache[key]
    # ... fetch and cache outside lock
```

### Error Handling

```python
try:
    result = risky_operation()
except SpecificException as e:
    flog("ERROR", "component", "Error message", {
        "error": str(e),
        "context": "details"
    })
    return None  # or raise
```

### Logging

```python
from homelinkwg.utils import flog

# Log structured events
flog("INFO", "probe", "Port checked", {
    "port_id": "port-8080",
    "reachable": True,
    "latency_ms": 45
})

# Log errors with context
flog("ERROR", "analytics", "Metrics store failed", {
    "port_id": "port-8080",
    "count": 1440
}, exc=exception)
```

---

## Common Development Tasks

### Debug a Failing Test

```bash
# Run single test with verbose output
pytest test_dashboard.py::test_name -vv

# Run with print statements visible
pytest test_dashboard.py -s

# Run with pdb on failure
pytest test_dashboard.py --pdb
```

### Profile Performance

```python
# Add timing decorator
from homelinkwg.utils import timed

with timed("component", "operation", warn_above_ms=1000):
    result = expensive_operation()
```

### Check Metrics

```bash
# Count rows in metrics table
sqlite3 homelinkwg-metrics.db "SELECT COUNT(*) FROM metrics;"

# Check database size
du -h homelinkwg-metrics.db

# Analyze query performance
sqlite3 homelinkwg-metrics.db "EXPLAIN QUERY PLAN SELECT * FROM metrics LIMIT 1;"
```

### Monitor Live Activity

```bash
# SSE stream (real-time updates)
curl -N http://localhost:5555/api/status/stream | head -20

# Tail logs
journalctl -u homelinkwg-dashboard -f

# Monitor with watch
watch -n 1 'curl -s http://localhost:5555/api/status | jq ".system"'
```

---

## Project Structure

```
homelinkwg/
├── __init__.py           # Package initialization
├── config.py             # Configuration loading (250 LOC)
├── utils.py              # Logging, timing utilities (350 LOC)
├── auth.py               # Authentication, sessions (280 LOC)
├── analytics.py          # Metrics, incidents, DB (450 LOC)
├── probes.py             # Health checks, diagnostics (1,600 LOC)
└── api.py                # Flask endpoints (stubs in Phase 2)

dashboard.py              # Flask app, orchestration (100 LOC)
test_dashboard.py         # Unit tests (200 LOC)

templates/
├── index.html            # Main dashboard (3,700 LOC HTML/JS)
static/
├── css/
│   ├── main.css
│   └── themes.css
├── js/
│   ├── main.js
│   └── tabs.js
└── img/
    └── favicon.svg
```

---

## Performance Targets

| Operation | Target | Current |
|-----------|--------|---------|
| Snapshot generation | <10s | 5-10s ✓ |
| API response time | <500ms | <500ms ✓ |
| SSE stream latency | <100ms | <50ms ✓ |
| DB queries/min | <10 | ~4 ✓ |
| Memory usage | <100MB | ~60MB ✓ |

---

## Release Process

1. **Version bump:**
   ```bash
   # Update dashboard.py
   __version__ = "X.Y"
   __date__ = "YYYY-MM-DD"
   ```

2. **Update docs:**
   - RELEASE_NOTES.md
   - API.md (if API changes)
   - ARCHITECTURE.md (if design changes)

3. **Tag release:**
   ```bash
   git tag -a vX.Y -m "Release version X.Y"
   git push origin vX.Y
   ```

4. **Build/deploy:**
   - Run full test suite
   - Build Docker image
   - Deploy to staging
   - Manual smoke test
   - Deploy to production

---

## Useful Resources

- [ARCHITECTURE.md](ARCHITECTURE.md) - System design and module interactions
- [API.md](API.md) - REST API reference
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and debugging
- [README.md](README.md) - Feature overview and setup

---

## Getting Help

1. **Check logs:** `journalctl -u homelinkwg-dashboard`
2. **Read TROUBLESHOOTING.md** for common issues
3. **Run tests:** `pytest test_dashboard.py -v`
4. **Check architecture:** Read ARCHITECTURE.md module dependency graph
5. **Grep codebase:** `grep -r "function_name" homelinkwg/`

---

## Code Standards

- **Python:** 3.10+ (f-strings, type hints, walrus operator)
- **Docstrings:** Required for all public functions
- **Type hints:** Required, aim for 95%+ coverage
- **Tests:** New code should have tests
- **Linting:** `ruff check` must pass
- **Format:** No manual formatting (ruff auto-format safe)

---

## Questions?

Refer to:
1. Code comments (inline documentation)
2. Module docstrings (at top of file)
3. Function docstrings (Args, Returns, Raises)
4. ARCHITECTURE.md (system design)
5. Grep for similar examples: `grep -r "pattern" homelinkwg/`
