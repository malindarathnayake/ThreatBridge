# Handoff: Graylog Firewall Enrichment

## Implementation Order

This feature has 4 units. Each unit is independently testable. Implement in order.

---

## Unit 1: Pydantic Models + Action Normalization

**Files to modify:**
- `source/src/models.py`

**What to do:**
1. Add these models after `ErrorResponse` (after line 94):
   - `PolicyCount(BaseModel)` — `name: str`, `count: int`
   - `PortCount(BaseModel)` — `port: int`, `count: int`
   - `NatTranslation(BaseModel)` — `ip: str`, `port: int`, `count: int`
   - `ActionSummary(BaseModel)` — `count: int`, `top_policies: List[PolicyCount]`, `top_dst_ports: List[PortCount]`, `interfaces: List[str]`, `nat_translations: Optional[List[NatTranslation]] = None`
   - `GraylogEnrichmentResponse(BaseModel)` — `available: bool`, `ip: str`, `total_hits: Optional[int] = None`, `time_range_hours: Optional[int] = None`, `device: Optional[str] = None`, `denied: Optional[ActionSummary] = None`, `accepted: Optional[ActionSummary] = None`, `error: Optional[str] = None`

2. Add the action normalization constant (can go in models.py or at the top of the endpoint file — prefer models.py since it's a data mapping):
   ```python
   ACTION_NORMALIZATION = {
       "deny": "DENIED", "drop": "DENIED", "reject": "DENIED", "close": "DENIED",
       "accept": "ACCEPTED", "allow": "ACCEPTED", "ip-conn": "ACCEPTED",
   }
   ```

**Verify:** Models can be imported and instantiated with sample data from the design summary's response contract examples.

---

## Unit 2: Prometheus Metrics + Config

**Files to modify:**
- `source/src/metrics.py`
- `.env.example`
- `docker-compose.yml`
- `deploy/docker-compose.yml`

**What to do:**

### metrics.py
1. Add after `ti_redis_connection_status` (after line 80):
   ```python
   # Graylog enrichment metrics
   ti_graylog_enrichment_total = Counter(
       'ti_graylog_enrichment_total',
       'Graylog enrichment request count',
       ['result']  # available/unavailable/error
   )

   ti_graylog_enrichment_duration_seconds = Histogram(
       'ti_graylog_enrichment_duration_seconds',
       'Graylog enrichment latency',
       buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 7.5, 10.0, 15.0]
   )
   ```

2. Add to `MetricsCollector` class:
   ```python
   @staticmethod
   def record_graylog_enrichment(result: str, duration: float):
       ti_graylog_enrichment_total.labels(result=result).inc()
       ti_graylog_enrichment_duration_seconds.observe(duration)
   ```

### .env.example
Add at the end:
```
# Graylog Enrichment (optional - enables firewall activity in Quick Lookup)
# GRAYLOG_URL=https://graylog.example.com
# GRAYLOG_TOKEN=your_graylog_api_token
# GRAYLOG_STREAM_ID=686add4875a6c5ef0cd4bc44
# GRAYLOG_TIMEOUT=10
# GRAYLOG_VERIFY_SSL=false
```

### docker-compose.yml
Add to `threatbridge` service environment block (after the existing env vars around line 23):
```yaml
      - GRAYLOG_URL=${GRAYLOG_URL:-}
      - GRAYLOG_TOKEN=${GRAYLOG_TOKEN:-}
      - GRAYLOG_STREAM_ID=${GRAYLOG_STREAM_ID:-686add4875a6c5ef0cd4bc44}
      - GRAYLOG_TIMEOUT=${GRAYLOG_TIMEOUT:-10}
      - GRAYLOG_VERIFY_SSL=${GRAYLOG_VERIFY_SSL:-false}
```

### deploy/docker-compose.yml
Same env vars added to the `threatbridge` service environment block.

**Verify:** `/metrics` endpoint still works. New metric names appear (with zero values) in output.

---

## Unit 3: Backend Endpoint

**Files to modify:**
- `source/src/ti_api.py`

**What to do:**

1. Add env var reads near the top of the file (after existing imports/config, before the app routes):
   ```python
   GRAYLOG_URL = os.getenv("GRAYLOG_URL", "")
   GRAYLOG_TOKEN = os.getenv("GRAYLOG_TOKEN", "")
   GRAYLOG_STREAM_ID = os.getenv("GRAYLOG_STREAM_ID", "686add4875a6c5ef0cd4bc44")
   GRAYLOG_TIMEOUT = int(os.getenv("GRAYLOG_TIMEOUT", "10"))
   GRAYLOG_VERIFY_SSL = os.getenv("GRAYLOG_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
   ```

2. Add the aggregation helper function (private, before the endpoint):
   ```python
   def _aggregate_graylog_messages(messages: list, ip: str) -> GraylogEnrichmentResponse:
       """Aggregate raw Graylog messages into a structured response."""
   ```
   This function:
   - Iterates all messages, normalizes action via `ACTION_NORMALIZATION.get(action, "DENIED")`
   - Groups by normalized action
   - For each group: counts by policyname (fallback policyid), counts by dstport, collects unique interfaces as `"{srcintf} ({srcintfrole})"`, and for ACCEPTED collects `tranip:tranport` pairs
   - Takes top 5 for each list, sorted by count descending
   - Extracts device from first message's `source` or `devname`
   - Returns `GraylogEnrichmentResponse`

3. Add the endpoint after `enrich_ip` (~after line 475):
   ```python
   @app.get("/ui/enrich/graylog")
   async def enrich_graylog(ip: str, request: Request):
   ```
   Logic:
   - If `GRAYLOG_URL` is empty: return `GraylogEnrichmentResponse(available=False, ip=ip, error="not configured")`
   - Validate IP via `psl_classifier`
   - Record start time
   - Use `httpx.AsyncClient` with:
     - `auth=(GRAYLOG_TOKEN, "token")`
     - `timeout=GRAYLOG_TIMEOUT`
     - `verify=GRAYLOG_VERIFY_SSL`
     - Headers: `Accept: application/json`, `X-Requested-By: ThreatBridge`
   - GET `/api/search/universal/relative` with params: `query=f"srcip:{ip} OR dstip:{ip}"`, `range=86400`, `limit=150`, `sort=timestamp:desc`, `filter=f"streams:{GRAYLOG_STREAM_ID}"`
   - On success: extract messages, call `_aggregate_graylog_messages()`, record metric as "available"
   - On `httpx.TimeoutException`: log warning, record metric as "unavailable", return unavailable response
   - On any other exception: log warning, record metric as "error", return unavailable response

**Key implementation notes:**
- **Do NOT follow `enrich_ip`'s error handling pattern** — `enrich_ip` raises HTTPException and returns non-200 status codes. The Graylog endpoint must always return HTTP 200 with error state in the JSON body via `GraylogEnrichmentResponse(available=False, ip=ip, error="...")`. For invalid IPs, return `available=False, error="invalid IP"` instead of raising HTTPException(400).
- The Graylog API returns messages in `data["messages"][i]["message"]` structure

**Verify:**
- `curl localhost:8000/ui/enrich/graylog?ip=195.184.76.167` returns aggregated results
- With no `GRAYLOG_URL` set: returns `{"available": false, "error": "not configured"}`

---

## Unit 4: Frontend Integration

**Files to modify:**
- `source/src/static/index.html`

**What to do:**

1. **Update `performLookup()`** (~line 608):
   Change the `Promise.all` to add the Graylog fetch:
   ```javascript
   const [result, ipInfo, graylogInfo] = await Promise.all([
       fetchApi(endpoint),
       isIP ? fetchApi(`/ui/enrich/ip?ip=${encodeURIComponent(query)}`).catch(() => null) : Promise.resolve(null),
       isIP ? fetchApi(`/ui/enrich/graylog?ip=${encodeURIComponent(query)}`).catch(() => null) : Promise.resolve(null)
   ]);
   displayLookupResult(result, ipInfo, graylogInfo);
   ```

2. **Update `displayLookupResult(result, ipInfo, graylogInfo)`** (~line 620):
   Add `graylogInfo` parameter. After the IPInfo section (after the `--- IP Info ---` block), add:

   ```javascript
   // Graylog Firewall Activity
   if (graylogInfo && graylogInfo.available && graylogInfo.total_hits > 0) {
       message += '\n\n--- Firewall Activity (last 24h) ---\n';
       message += `Total Hits: ${graylogInfo.total_hits}\n`;
       if (graylogInfo.device) message += `Source: ${graylogInfo.device}\n`;

       // DENIED section
       if (graylogInfo.denied && graylogInfo.denied.count > 0) {
           message += `\nDENIED (${graylogInfo.denied.count} hits)\n`;
           if (graylogInfo.denied.top_policies.length > 0) {
               message += '  Top Policies:\n';
               graylogInfo.denied.top_policies.forEach(p => {
                   message += `    ${p.name}  (${p.count})\n`;
               });
           }
           if (graylogInfo.denied.top_dst_ports.length > 0) {
               message += '  Top Dest Ports: ' +
                   graylogInfo.denied.top_dst_ports.map(p => `${p.port} (${p.count})`).join(', ') + '\n';
           }
           if (graylogInfo.denied.interfaces.length > 0) {
               message += '  Interfaces: ' + graylogInfo.denied.interfaces.join(', ') + '\n';
           }
       }

       // ACCEPTED section
       if (graylogInfo.accepted && graylogInfo.accepted.count > 0) {
           message += `\nACCEPTED (${graylogInfo.accepted.count} hits)\n`;
           if (graylogInfo.accepted.top_policies.length > 0) {
               message += '  Top Policies:\n';
               graylogInfo.accepted.top_policies.forEach(p => {
                   message += `    ${p.name}  (${p.count})\n`;
               });
           }
           if (graylogInfo.accepted.top_dst_ports.length > 0) {
               message += '  Top Dest Ports: ' +
                   graylogInfo.accepted.top_dst_ports.map(p => `${p.port} (${p.count})`).join(', ') + '\n';
           }
           if (graylogInfo.accepted.nat_translations && graylogInfo.accepted.nat_translations.length > 0) {
               message += '  NAT Translations:\n';
               graylogInfo.accepted.nat_translations.forEach(t => {
                   message += `    ${t.ip}:${t.port}  (${t.count})\n`;
               });
           }
           if (graylogInfo.accepted.interfaces.length > 0) {
               message += '  Interfaces: ' + graylogInfo.accepted.interfaces.join(', ') + '\n';
           }
       }
   } else if (graylogInfo && graylogInfo.available && graylogInfo.total_hits === 0) {
       message += '\n\n--- Firewall Activity (last 24h) ---\n';
       message += 'No firewall activity in last 24h\n';
   } else if (graylogInfo === null || (graylogInfo && !graylogInfo.available)) {
       // Only show if Graylog is configured (don't show for "not configured" error)
       if (graylogInfo && graylogInfo.error !== 'not configured') {
           message += '\n\n--- Firewall Activity (last 24h) ---\n';
           message += 'Graylog unavailable\n';
       }
   }
   ```

**Verify:**
- Look up a known threat IP — see TI result + IPInfo + Firewall Activity
- Look up a clean IP — see TI result + IPInfo + "No firewall activity"
- Stop Graylog (or remove env var) — TI + IPInfo still display, Graylog section shows "unavailable" or is absent

---

## Files Changed Summary

| File | Unit | Change |
|------|------|--------|
| `source/src/models.py` | 1 | Add 6 Pydantic models + ACTION_NORMALIZATION |
| `source/src/metrics.py` | 2 | Add 2 Prometheus metrics + 1 MetricsCollector method |
| `.env.example` | 2 | Add GRAYLOG_* env var examples |
| `docker-compose.yml` | 2 | Add GRAYLOG_* env var passthrough |
| `deploy/docker-compose.yml` | 2 | Add GRAYLOG_* env var passthrough |
| `source/src/ti_api.py` | 3 | Add env var reads, aggregation function, `/ui/enrich/graylog` endpoint |
| `source/src/static/index.html` | 4 | Update performLookup + displayLookupResult for 3-way parallel |

## Critical Constraints
- Never return non-200 HTTP from the Graylog endpoint — error state is in JSON body
- Graylog auth: token goes as username, literal string `"token"` as password (basic auth)
- Top-N lists capped at 5, sorted descending by count
- The `policyname` field is not always present — fall back to `policyid` formatted as string
- `tranip`/`tranport` only exist on forwarded traffic — check before accessing
- SSL verify defaults to `false` (most Graylog installs use self-signed certs)
