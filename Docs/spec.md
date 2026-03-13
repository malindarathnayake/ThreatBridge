# Spec: Graylog Firewall Enrichment

## Overview
Add a Graylog Search API integration to the ThreatBridge quick lookup, providing firewall activity context (denied/accepted traffic, policies, ports, NAT translations) alongside existing threat feed and IPInfo results.

## Requirements

### Functional
1. New backend endpoint `GET /ui/enrich/graylog?ip=X` queries Graylog's FortiGate Syslog stream for the given IP in both `srcip` and `dstip` fields over the last 24 hours.
2. Results are aggregated by action category (DENIED / ACCEPTED) with top-5 policies, top-5 destination ports, unique interfaces, and NAT translations (accepted only).
3. Frontend fires the Graylog enrichment request in parallel with threat feed and IPInfo lookups using the same `.catch(() => null)` pattern.
4. Firewall activity section displays inline below IPInfo in the lookup result.
5. Graylog failures never block or hide threat feed / IPInfo results.

### Non-Functional
1. Graylog query timeout: 10s (configurable via `GRAYLOG_TIMEOUT`).
2. All responses return HTTP 200 — failure state conveyed via `available: false` in JSON body.
3. Prometheus metrics track Graylog enrichment duration and request count.

## Data Models

### Pydantic Models (add to `source/src/models.py`)

```python
class PolicyCount(BaseModel):
    name: str
    count: int

class PortCount(BaseModel):
    port: int
    count: int

class NatTranslation(BaseModel):
    ip: str
    port: int
    count: int

class ActionSummary(BaseModel):
    count: int
    top_policies: List[PolicyCount]
    top_dst_ports: List[PortCount]
    interfaces: List[str]
    nat_translations: Optional[List[NatTranslation]] = None  # Only for ACCEPTED

class GraylogEnrichmentResponse(BaseModel):
    available: bool
    ip: str
    total_hits: Optional[int] = None
    time_range_hours: Optional[int] = None
    device: Optional[str] = None
    denied: Optional[ActionSummary] = None
    accepted: Optional[ActionSummary] = None
    error: Optional[str] = None
```

### Response States

| State | `available` | `total_hits` | `denied`/`accepted` | `error` |
|-------|-------------|--------------|----------------------|---------|
| Results found | `true` | `>0` | populated | `null` |
| Zero results | `true` | `0` | `null` | `null` |
| Unavailable | `false` | `null` | `null` | error message |

## Action Normalization

```python
ACTION_NORMALIZATION = {
    "deny": "DENIED",
    "drop": "DENIED",
    "reject": "DENIED",
    "close": "DENIED",
    "accept": "ACCEPTED",
    "allow": "ACCEPTED",
    "ip-conn": "ACCEPTED",
}
# Default for unknown actions: "DENIED"
```

## Backend Endpoint

### `GET /ui/enrich/graylog`

**Location:** `source/src/ti_api.py` (add after the existing `enrich_ip` endpoint at ~line 475)

**Query Parameters:**
- `ip` (str, required) — IP address to search for

**Logic:**
1. Validate IP using `psl_classifier.is_ip_address()`
2. Build Graylog search query: `srcip:{ip} OR dstip:{ip}`
3. Call `GET {GRAYLOG_URL}/api/search/universal/relative` with:
   - `query`: the search query
   - `range`: `86400` (24h in seconds)
   - `limit`: `150`
   - `sort`: `timestamp:desc`
   - `filter`: `streams:{GRAYLOG_STREAM_ID}`
   - Auth: basic auth with token as username, `"token"` as password
   - Headers: `Accept: application/json`, `X-Requested-By: ThreatBridge`
   - SSL verify: `GRAYLOG_VERIFY_SSL`
   - Timeout: `GRAYLOG_TIMEOUT` seconds
4. Parse messages, normalize actions, aggregate into `GraylogEnrichmentResponse`
5. On any error: return `GraylogEnrichmentResponse(available=False, ip=ip, error=str(e))`

**Aggregation Logic:**
1. Group messages by normalized action (DENIED / ACCEPTED)
2. For each group:
   - Count total
   - Count by `policyname` (fallback to `policyid`), take top 5
   - Count by `dstport`, take top 5
   - Collect unique `srcintf (srcintfrole)` values
   - For ACCEPTED only: count by `tranip:tranport` pairs, take top 5
3. Extract `device` from first message's `source` or `devname` field

## Frontend Changes

### `source/src/static/index.html`

**`performLookup()` (~line 608):**
Change `Promise.all` to include the Graylog fetch for IP lookups:

```javascript
const [result, ipInfo, graylogInfo] = await Promise.all([
    fetchApi(endpoint),
    isIP ? fetchApi(`/ui/enrich/ip?ip=${encodeURIComponent(query)}`).catch(() => null) : Promise.resolve(null),
    isIP ? fetchApi(`/ui/enrich/graylog?ip=${encodeURIComponent(query)}`).catch(() => null) : Promise.resolve(null)
]);
displayLookupResult(result, ipInfo, graylogInfo);
```

**`displayLookupResult(result, ipInfo, graylogInfo)` (~line 620):**
Add `graylogInfo` parameter. After the IPInfo section, append:

```
--- Firewall Activity (last 24h) ---

Total Hits: 82
Source: L31-400F-01

DENIED (78 hits)
  Top Policies:
    Magic_Transit_to_CORE_IN_Prod_2  (74)
    local-in-policy-0                (4)
  Top Dest Ports: 17234 (40), 7779 (22), 443 (16)
  Interfaces: x6 (wan), x5 (wan)

ACCEPTED (4 hits)
  Top Policies:
    VPN_Inbound_Allow               (4)
  Top Dest Ports: 443 (4)
  NAT Translations:
    192.168.94.22:12109  (3)
    192.168.94.45:8443   (1)
  Interfaces: x6 (wan)
```

If `graylogInfo` is `null` or `available === false`: show `"Graylog unavailable"`.
If `total_hits === 0`: show `"No firewall activity in last 24h"`.

## Config

### Environment Variables

| Variable | Default | Required |
|----------|---------|----------|
| `GRAYLOG_URL` | — | Yes (for Graylog enrichment) |
| `GRAYLOG_TOKEN` | — | Yes (for Graylog enrichment) |
| `GRAYLOG_STREAM_ID` | `686add4875a6c5ef0cd4bc44` | No |
| `GRAYLOG_TIMEOUT` | `10` | No |
| `GRAYLOG_VERIFY_SSL` | `false` | No |

**Load in `source/src/ti_api.py`** (not in config.py — follow IPInfo pattern of reading env vars directly in the endpoint):

```python
GRAYLOG_URL = os.getenv("GRAYLOG_URL", "")
GRAYLOG_TOKEN = os.getenv("GRAYLOG_TOKEN", "")
GRAYLOG_STREAM_ID = os.getenv("GRAYLOG_STREAM_ID", "686add4875a6c5ef0cd4bc44")
GRAYLOG_TIMEOUT = int(os.getenv("GRAYLOG_TIMEOUT", "10"))
GRAYLOG_VERIFY_SSL = os.getenv("GRAYLOG_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
```

### Files to Update

- `.env.example` — add commented `GRAYLOG_*` variables
- `docker-compose.yml` — add `GRAYLOG_URL`, `GRAYLOG_TOKEN` to environment passthrough
- `deploy/docker-compose.yml` — same

## Prometheus Metrics

Add to `source/src/metrics.py`:

```python
ti_graylog_enrichment_total = Counter(
    'ti_graylog_enrichment_total',
    'Graylog enrichment request count',
    ['result']  # result: available/unavailable/error
)

ti_graylog_enrichment_duration_seconds = Histogram(
    'ti_graylog_enrichment_duration_seconds',
    'Graylog enrichment latency',
    buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 7.5, 10.0, 15.0]
)
```

Add static methods to `MetricsCollector`:

```python
@staticmethod
def record_graylog_enrichment(result: str, duration: float):
    ti_graylog_enrichment_total.labels(result=result).inc()
    ti_graylog_enrichment_duration_seconds.observe(duration)
```

## Logging

| Event | Level | Format |
|-------|-------|--------|
| Graylog query success | INFO | `Graylog enrichment for {ip}: {total_hits} hits in {duration:.2f}s` |
| Graylog not configured | INFO | `Graylog enrichment skipped (not configured)` (once at startup) |
| Graylog timeout | WARNING | `Graylog enrichment timeout for {ip} after {timeout}s` |
| Graylog auth failure | WARNING | `Graylog enrichment auth failed for {ip}: HTTP {status}` |
| Graylog error | WARNING | `Graylog enrichment error for {ip}: {error}` |

## Dependencies

No new dependencies. `httpx` (already in requirements.txt) handles the Graylog API call.
