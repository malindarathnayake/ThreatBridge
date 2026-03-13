# Handoff: Graylog Dashboard Status (v1.4.1)

## Implementation Order

This feature has 3 units. Each unit is independently testable. Implement in order.

---

## Unit 1: Backend Health Endpoints

**Files to modify:**
- `source/src/models.py`
- `source/src/ti_api.py`

**What to do:**

### models.py
1. Add after `GraylogEnrichmentResponse` (after the `ACTION_NORMALIZATION` constant, before `class FeedMetadata`):
   ```python
   class GraylogHealthResponse(BaseModel):
       """Graylog connection health status."""
       status: str = Field(..., description="Connection status: connected, disconnected, not_configured")
       error: Optional[str] = Field(None, description="Error message if disconnected")
       cached: bool = Field(False, description="Whether this is a cached response")
   ```

### ti_api.py
1. Add the `GraylogHealthResponse` import to the existing models import block (line 20-24).

2. Add cache state after the GRAYLOG config vars (after line 54):
   ```python
   # Graylog health cache (60-second TTL)
   _graylog_health_cache: Dict = {"result": None, "timestamp": 0.0}
   GRAYLOG_HEALTH_CACHE_TTL = 60
   ```

3. Add the health endpoint before the static files mount (before line 635):
   ```python
   @app.get("/ui/health/graylog")
   async def health_graylog():
       """Check Graylog connectivity with 60s response cache."""
       if not GRAYLOG_URL:
           return GraylogHealthResponse(status="not_configured")

       # Check cache
       now = time.time()
       if _graylog_health_cache["result"] and (now - _graylog_health_cache["timestamp"]) < GRAYLOG_HEALTH_CACHE_TTL:
           cached = _graylog_health_cache["result"].copy()
           cached["cached"] = True
           return cached

       # Ping Graylog
       try:
           async with httpx.AsyncClient(
               timeout=GRAYLOG_TIMEOUT,
               verify=GRAYLOG_VERIFY_SSL,
           ) as client:
               response = await client.get(
                   f"{GRAYLOG_URL.rstrip('/')}/api/search/universal/relative",
                   params={"query": "*", "range": 1, "limit": 1,
                           "filter": f"streams:{GRAYLOG_STREAM_ID}"},
                   auth=(GRAYLOG_TOKEN, "token"),
                   headers={"Accept": "application/json",
                            "X-Requested-By": "ThreatBridge"},
               )
               response.raise_for_status()

           result = {"status": "connected", "error": None, "cached": False}
           logger.debug("Graylog health check: connected")

       except httpx.TimeoutException:
           result = {"status": "disconnected", "error": "timeout", "cached": False}
           logger.warning("Graylog health check failed: timeout")

       except httpx.HTTPStatusError as e:
           error_msg = "auth failed" if e.response.status_code in (401, 403) else f"HTTP {e.response.status_code}"
           result = {"status": "disconnected", "error": error_msg, "cached": False}
           logger.warning(f"Graylog health check failed: {error_msg}")

       except Exception as e:
           result = {"status": "disconnected", "error": str(e), "cached": False}
           logger.warning(f"Graylog health check failed: {e}")

       _graylog_health_cache["result"] = result
       _graylog_health_cache["timestamp"] = time.time()
       return result
   ```

4. Add IPInfo health endpoint (next to the Graylog one):
   ```python
   @app.get("/ui/health/ipinfo")
   async def health_ipinfo():
       """Check if IPInfo enrichment is configured."""
       return {"configured": bool(app_config.ipinfo_token)}
   ```

**Verify:**
- `curl localhost:8000/ui/health/graylog` returns status
- `curl localhost:8000/ui/health/ipinfo` returns configured true/false
- Second call within 60s returns `cached: true`

---

## Unit 2: Frontend CSS + HTML

**Files to modify:**
- `source/src/static/index.html`

**What to do:**

1. **Add CSS** — after the `.countdown` style block (after line 242), before `</style>` (line 243):
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

   .enrichment-card .enrichment-error {
       font-size: 0.85em;
       color: #e74c3c;
   }
   ```

2. **Add HTML** — after the Feed Status section closing `</div>` (after line 272), before the container closing `</div>` (line 273):
   ```html
   <div class="section">
       <h2>Enrichment Sources</h2>
       <div id="enrichment-container" class="enrichment-grid">
           <div class="loading">Loading enrichment status...</div>
       </div>
   </div>
   ```

**Verify:** Page loads without errors, new section visible with loading text.

---

## Unit 3: Frontend JavaScript

**Files to modify:**
- `source/src/static/index.html`

**What to do:**

1. **Update `refreshAllData()`** (~line 308) — add enrichment health fetches in parallel:
   ```javascript
   async function refreshAllData() {
       try {
           // Fetch health status, feeds data, and enrichment health in parallel
           const [healthResult, feedsResponse, graylogHealth, ipinfoHealth] = await Promise.all([
               fetchApi('/health'),
               fetchApi('/feeds'),
               fetchApi('/ui/health/graylog').catch(() => null),
               fetchApi('/ui/health/ipinfo').catch(() => null)
           ]);

           healthStatus = healthResult;
           updateHealthIndicator();

           feedsData = feedsResponse.feeds || [];
           updateFeedsDisplay();

           updateEnrichmentDisplay(graylogHealth, ipinfoHealth);

           document.getElementById('last-updated').textContent =
               `Last updated: ${new Date().toLocaleTimeString()}`;

       } catch (error) {
           console.error('Failed to refresh dashboard:', error);
           document.getElementById('feeds-container').innerHTML =
               '<div style="color: #e74c3c;">Failed to load dashboard data. Check console for details.</div>';
       }
   }
   ```

2. **Add `updateEnrichmentDisplay()` function** (after `updateFeedsDisplay()`, ~after line 354):
   ```javascript
   function updateEnrichmentDisplay(graylogHealth, ipinfoHealth) {
       const container = document.getElementById('enrichment-container');
       let cards = '';

       // Graylog card
       if (graylogHealth) {
           let statusClass, statusText;
           if (graylogHealth.status === 'connected') {
               statusClass = 'status-healthy';
               statusText = 'Connected';
           } else if (graylogHealth.status === 'disconnected') {
               statusClass = 'status-unhealthy';
               statusText = 'Disconnected';
           } else {
               statusClass = 'status-unknown';
               statusText = 'Not Configured';
           }

           cards += `
               <div class="enrichment-card">
                   <span class="status-indicator ${statusClass}" title="${statusText}"></span>
                   <div>
                       <h4>Graylog Firewall</h4>
                       <div class="enrichment-status">${statusText}</div>
                       ${graylogHealth.error && graylogHealth.status === 'disconnected'
                           ? `<div class="enrichment-error">${escapeHtml(graylogHealth.error)}</div>`
                           : ''}
                   </div>
               </div>`;
       }

       // IPInfo card
       if (ipinfoHealth) {
           const configured = ipinfoHealth.configured;
           cards += `
               <div class="enrichment-card">
                   <span class="status-indicator ${configured ? 'status-healthy' : 'status-unknown'}"
                         title="${configured ? 'Configured' : 'Not Configured'}"></span>
                   <div>
                       <h4>IPInfo Geolocation</h4>
                       <div class="enrichment-status">${configured ? 'Configured' : 'Not Configured'}</div>
                   </div>
               </div>`;
       }

       container.innerHTML = cards || '<div>No enrichment sources available.</div>';
   }
   ```

**Verify:**
- Dashboard shows Enrichment Sources section with Graylog and IPInfo cards
- Graylog shows green/red/grey based on connection status
- IPInfo shows green/grey based on configuration
- Auto-refresh updates the cards every 30 seconds

---

## Files Changed Summary

| File | Unit | Change |
|------|------|--------|
| `source/src/models.py` | 1 | Add GraylogHealthResponse model |
| `source/src/ti_api.py` | 1 | Add cache state, `/ui/health/graylog` endpoint, `/ui/health/ipinfo` endpoint |
| `source/src/static/index.html` | 2, 3 | Add enrichment CSS, HTML section, JS for health fetch + rendering |

## Critical Constraints
- Always return HTTP 200 from health endpoints — status in JSON body
- Cache is in-memory only — resets on container restart (acceptable)
- Graylog ping uses `query=*&range=1&limit=1` — minimal load on Graylog
- Health check failures must not break the dashboard — use `.catch(() => null)` pattern
- IPInfo health check does NOT call the IPInfo API — just checks if token is configured
