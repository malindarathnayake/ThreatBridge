# Spec: Graylog Dashboard Status (v1.4.1)

## Overview
Add an "Enrichment Sources" section to the ThreatBridge dashboard showing the health status of Graylog and IPInfo integrations. Graylog status is determined by pinging the Graylog API with a 60-second response cache to avoid excessive requests.

## Requirements

### Functional
1. New backend endpoint `GET /ui/health/graylog` pings the Graylog search API and returns connection status.
2. Response is cached for 60 seconds — repeated calls within the window return the cached result without hitting Graylog.
3. New "Enrichment Sources" section renders below the Feed Status section on the dashboard.
4. Graylog card shows: Connected (green), Disconnected (red), or Not Configured (grey).
5. IPInfo card shows: Configured (green) or Not Configured (grey).
6. Dashboard auto-refresh (every 30s) includes the Graylog health fetch.

### Non-Functional
1. Graylog health check reuses existing `GRAYLOG_TIMEOUT` for the ping request.
2. Health endpoint always returns HTTP 200 — status conveyed in JSON body.
3. No new Prometheus metrics — reuses existing `ti_graylog_enrichment_total` if needed.

## Data Models

### Response Model (add to `source/src/models.py`)

```python
class GraylogHealthResponse(BaseModel):
    status: str  # "connected", "disconnected", "not_configured"
    error: Optional[str] = None
    cached: bool = False
```

### Response States

| State | `status` | `error` | `cached` |
|-------|----------|---------|----------|
| Connected | `"connected"` | `null` | `true`/`false` |
| Disconnected | `"disconnected"` | error message | `true`/`false` |
| Not configured | `"not_configured"` | `null` | `false` |

## Backend Endpoint

### `GET /ui/health/graylog`

**Location:** `source/src/ti_api.py` (add before the static files mount at line 635)

**Logic:**
1. If `GRAYLOG_URL` is empty: return `GraylogHealthResponse(status="not_configured")`
2. Check cache: if cached result exists and is less than 60 seconds old, return it with `cached=True`
3. Ping Graylog: `GET {GRAYLOG_URL}/api/search/universal/relative` with `query=*`, `range=1`, `limit=1`, `filter=streams:{GRAYLOG_STREAM_ID}`
4. On success: cache `status="connected"`, return it
5. On timeout: cache `status="disconnected", error="timeout"`, return it
6. On 401/403: cache `status="disconnected", error="auth failed"`, return it
7. On any other error: cache `status="disconnected", error=str(e)`, return it

**Cache implementation:** Module-level dict with `result` and `timestamp` keys. No Redis, no external state.

```python
_graylog_health_cache = {"result": None, "timestamp": 0.0}
GRAYLOG_HEALTH_CACHE_TTL = 60  # seconds
```

## Frontend Changes

### `source/src/static/index.html`

**1. Add CSS styles** (after existing `.countdown` style, before `</style>` at line 243):

```css
.enrichment-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 16px;
    margin-top: 16px;
}

.enrichment-card {
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    padding: 16px;
    background: #fafafa;
    display: flex;
    align-items: center;
    gap: 12px;
}

.enrichment-card h4 {
    margin: 0;
    color: #2c3e50;
    font-size: 1em;
}

.enrichment-card .enrichment-status {
    font-size: 0.85em;
    color: #7f8c8d;
}
```

**2. Add HTML section** (after the Feed Status `</div>` at line 272, before the closing `</div>` at line 273):

```html
<div class="section">
    <h2>Enrichment Sources</h2>
    <div id="enrichment-container" class="enrichment-grid">
        <div class="loading">Loading enrichment status...</div>
    </div>
</div>
```

**3. Update `refreshAllData()`** (~line 308):
Add Graylog health fetch in parallel with existing calls. Fetch with `.catch(() => null)` so failures don't break the dashboard.

**4. Add `updateEnrichmentDisplay(graylogHealth)`** function:
Renders the enrichment cards:
- **Graylog card:** status indicator (green/red/grey) + "Graylog Firewall" label + status text ("Connected"/"Disconnected: {error}"/"Not Configured")
- **IPInfo card:** status indicator (green/grey) + "IPInfo Geolocation" label + status text ("Configured"/"Not Configured"). Derive from `healthStatus` or check `app_config.ipinfo_token` — simplest: add an `/ui/health/ipinfo` endpoint that returns `{configured: true/false}`, OR just check if the existing `/ui/enrich/ip` returns `configured: false`. For simplicity, use a static check: if the first enrichment attempt returned `configured: false`, show grey; otherwise show green. Actually the cleanest approach: piggyback on the existing `/ui/enrich/ip` pattern — the frontend already knows if IPInfo is configured from lookup results. For the dashboard, just check with a lightweight call.

**Simplest approach for IPInfo:** The `enrich_ip` endpoint already returns `{"configured": false}` when not set up. Make a quick call to `/ui/enrich/ip?ip=8.8.8.8` and check the response. But this wastes an IPInfo API call. Better: add a simple `/ui/health/ipinfo` endpoint that returns `{"configured": true/false}` by checking `app_config.ipinfo_token`.

## Config

No new environment variables. Uses existing:
- `GRAYLOG_URL`, `GRAYLOG_TOKEN`, `GRAYLOG_STREAM_ID`, `GRAYLOG_TIMEOUT`, `GRAYLOG_VERIFY_SSL`
- `app_config.ipinfo_token` (for IPInfo status)

## Logging

| Event | Level | Format |
|-------|-------|--------|
| Graylog health ping success | DEBUG | `Graylog health check: connected` |
| Graylog health ping failure | WARNING | `Graylog health check failed: {error}` |
| Cache hit | DEBUG | `Graylog health check: returning cached result` |

## Dependencies

No new dependencies.
