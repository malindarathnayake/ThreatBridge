# Testing Harness: Graylog Dashboard Status (v1.4.1)

## Test Archetype: Infrastructure Tool

No automated test suite exists. Testing is manual via curl and browser.

## Unit 1: Backend Health Endpoint Tests

### Test: Graylog not configured (no GRAYLOG_URL)
```bash
# Ensure GRAYLOG_URL is not set
curl -s http://localhost:8000/ui/health/graylog | python -m json.tool
# Expected:
# {
#   "status": "not_configured",
#   "error": null,
#   "cached": false
# }
```

### Test: Graylog connected (with valid GRAYLOG_URL)
```bash
curl -s http://localhost:8000/ui/health/graylog | python -m json.tool
# Expected:
# {
#   "status": "connected",
#   "error": null,
#   "cached": false
# }
```

### Test: Cache works (second call within 60s)
```bash
# First call
curl -s http://localhost:8000/ui/health/graylog | python -m json.tool
# Second call immediately
curl -s http://localhost:8000/ui/health/graylog | python -m json.tool
# Expected: second call has "cached": true
```

### Test: Cache expires (call after 60s)
```bash
curl -s http://localhost:8000/ui/health/graylog | python -m json.tool
# Wait 61 seconds
sleep 61
curl -s http://localhost:8000/ui/health/graylog | python -m json.tool
# Expected: "cached": false (fresh check)
```

### Test: Graylog timeout
```bash
# Set GRAYLOG_TIMEOUT=1 and point to unreachable URL
curl -s http://localhost:8000/ui/health/graylog | python -m json.tool
# Expected:
# {
#   "status": "disconnected",
#   "error": "timeout",
#   "cached": false
# }
```

### Test: IPInfo configured
```bash
curl -s http://localhost:8000/ui/health/ipinfo | python -m json.tool
# Expected (with ipinfo_token set):
# { "configured": true }
# Expected (without ipinfo_token):
# { "configured": false }
```

## Unit 2-3: Frontend Integration Tests

### Test: All enrichment sources visible
1. Open browser to `http://localhost:8000`
2. Scroll below Feed Status section
3. Verify "Enrichment Sources" section is visible
4. Verify Graylog card shows with correct status indicator
5. Verify IPInfo card shows with correct status indicator

### Test: Graylog connected state
1. Start with valid `GRAYLOG_URL` and `GRAYLOG_TOKEN`
2. Load dashboard
3. Verify: Graylog card shows green dot + "Connected"

### Test: Graylog disconnected state
1. Set invalid `GRAYLOG_URL` (e.g., `https://invalid.example.com`)
2. Load dashboard
3. Verify: Graylog card shows red dot + "Disconnected" + error text

### Test: Graylog not configured state
1. Remove `GRAYLOG_URL` env var
2. Load dashboard
3. Verify: Graylog card shows grey dot + "Not Configured"

### Test: IPInfo configured state
1. Set `ipinfo_token` in feeds.yml or `IPINFO_TOKEN` env var
2. Load dashboard
3. Verify: IPInfo card shows green dot + "Configured"

### Test: IPInfo not configured state
1. Remove `ipinfo_token` from feeds.yml and `IPINFO_TOKEN` env var
2. Load dashboard
3. Verify: IPInfo card shows grey dot + "Not Configured"

### Test: Auto-refresh updates enrichment
1. Load dashboard
2. Wait 30 seconds
3. Verify: enrichment cards refresh (check browser console for `/ui/health/graylog` requests)
4. Verify: no more than 1 Graylog API call per 60 seconds (cache working)

### Test: Enrichment failure doesn't break dashboard
1. Load dashboard with Graylog misconfigured
2. Verify: Feed Status section still loads correctly
3. Verify: Quick Lookup still works
4. Verify: No JavaScript errors in browser console

## Regression Checks

- [ ] Existing `/check/ip` endpoint unchanged
- [ ] Existing `/check/domain` endpoint unchanged
- [ ] IPInfo enrichment in Quick Lookup still works
- [ ] Graylog enrichment in Quick Lookup still works
- [ ] Dashboard feed list still loads
- [ ] Feed refresh still works
- [ ] `/health` endpoint still responds
- [ ] `/metrics` endpoint still responds
