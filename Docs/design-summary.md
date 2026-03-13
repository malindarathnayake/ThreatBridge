## Design Summary — Graylog Firewall Enrichment

### Problem
When investigating a threat IP via quick lookup, analysts have to separately check Graylog to see if that IP has hit the firewall. This adds manual steps and context-switching to a daily workflow.

### Approach
Add Graylog as a third parallel enrichment source in the existing IP lookup flow (alongside threat feeds + IPInfo). Query the FortiGate Syslog stream for the IP in both `srcip` and `dstip`, aggregate results by action (deny/accept), and display inline in the lookup result.

### Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Result format | Aggregated summary (not raw logs) | High-hit IPs would produce unreadable raw output |
| Deny vs Accept | Show both sections separately | Analyst needs to see what was blocked AND what got through |
| Search fields | Both srcip and dstip | IP could be inbound attacker or outbound C2 destination |
| Time window | 24h hardcoded | Matches analyst workflow, simplifies UI |
| Parallel execution | Yes, same pattern as IPInfo | Don't block threat feed results on Graylog latency |
| Scope | IP lookups only | Firewall logs are IP-based, not domain-based |
| Stream | FortiGate Syslog (`686add4875a6c5ef0cd4bc44`) | Only firewall stream needed |
| Auth | Graylog API token (token-as-username basic auth) | Confirmed working via discovery |
| Graceful degradation | Frontend uses `.catch(() => null)` for Graylog fetch | Same pattern as IPInfo — Graylog failure never blocks TI results |
| Query limit | Fetch up to 150 messages, aggregate client-side | Graylog default page size; avoids pagination complexity for v1 |

### Architecture

```
User enters IP -> Frontend fires 3 parallel requests:
  1. GET /check/ip?ip=X          -> Redis (threat feeds)
  2. GET /ui/enrich/ip?ip=X      -> IPInfo API
  3. GET /ui/enrich/graylog?ip=X -> Graylog Search API (NEW)
                                      |
                              FortiGate Syslog stream
                              query: srcip:X OR dstip:X
                              range: 24h
                                      |
                              Aggregate by action -> response
```

### Integration Points

| System | Protocol | Auth | Discovery Status |
|--------|----------|------|------------------|
| Graylog 7.0.1 | REST (`/api/search/universal/relative`) | API token (basic auth) | **Done** - field mapping confirmed |
| FortiGate stream | Via Graylog | N/A | **Done** - stream ID `686add4875a6c5ef0cd4bc44` |

### Field Mapping (FortiGate -> Response)

| Response field | Graylog field | Notes |
|---|---|---|
| Timestamp | `timestamp` | ISO format |
| Policy/Rule name | `policyname` | Falls back to `policyid` if absent |
| Action | `action` | Normalized (see Action Normalization table) |
| Source IP | `srcip` | |
| Source port | `srcport` | |
| Destination IP | `dstip` | |
| Destination port | `dstport` | |
| NAT IP | `tranip` | Only present on accepted/forwarded traffic |
| NAT port | `tranport` | Only present on accepted/forwarded traffic |
| Interface | `srcintf` / `srcintfrole` | e.g., `x6 (wan)` |
| Device | `source` / `devname` | e.g., `L31-400F-01` |
| Service | `service` | e.g., `tcp/7779` |
| Internet service | `srcinetsvc` | e.g., `ONYPHE-Scanner` |

### Action Normalization

FortiGate emits multiple action values. Normalize to two display categories:

| Raw FortiGate value | Display category |
|---------------------|-----------------|
| `deny` | DENIED |
| `drop` | DENIED |
| `reject` | DENIED |
| `close` | DENIED |
| `accept` | ACCEPTED |
| `allow` | ACCEPTED |
| `ip-conn` | ACCEPTED |
| (any other) | DENIED (default) |

### Response Contract

New Pydantic model for `GET /ui/enrich/graylog?ip=X`:

```json
{
  "available": true,
  "ip": "195.184.76.167",
  "total_hits": 82,
  "time_range_hours": 24,
  "device": "L31-400F-01",
  "denied": {
    "count": 78,
    "top_policies": [
      {"name": "Magic_Transit_to_CORE_IN_Prod_2", "count": 74},
      {"name": "local-in-policy-0", "count": 4}
    ],
    "top_dst_ports": [
      {"port": 17234, "count": 40},
      {"port": 7779, "count": 22},
      {"port": 443, "count": 16}
    ],
    "interfaces": ["x6 (wan)", "x5 (wan)"]
  },
  "accepted": {
    "count": 4,
    "top_policies": [
      {"name": "VPN_Inbound_Allow", "count": 4}
    ],
    "top_dst_ports": [
      {"port": 443, "count": 4}
    ],
    "nat_translations": [
      {"ip": "192.168.94.22", "port": 12109, "count": 3},
      {"ip": "192.168.94.45", "port": 8443, "count": 1}
    ],
    "interfaces": ["x6 (wan)"]
  }
}
```

**Unavailable response** (Graylog down/timeout/auth failure):
```json
{
  "available": false,
  "ip": "195.184.76.167",
  "error": "Graylog timeout"
}
```

**Zero results response:**
```json
{
  "available": true,
  "ip": "195.184.76.167",
  "total_hits": 0,
  "time_range_hours": 24,
  "device": null,
  "denied": null,
  "accepted": null
}
```

Top-N lists are capped at **5 entries** each, sorted by count descending.

### Config Surface

| Setting | Type | Source | Default |
|---------|------|--------|---------|
| `GRAYLOG_URL` | string | env var | **required** |
| `GRAYLOG_TOKEN` | string | env var | **required** |
| `GRAYLOG_STREAM_ID` | string | env var | `686add4875a6c5ef0cd4bc44` |
| `GRAYLOG_TIMEOUT` | int (seconds) | env var | `10` |
| `GRAYLOG_VERIFY_SSL` | bool | env var | `false` |

Config follows the same env-var-only pattern used by `IPINFO_TOKEN`. Add entries to `.env.example` and `docker-compose.yml` during implementation.

### Error Handling

| Scenario | Behavior |
|----------|----------|
| Graylog unreachable / timeout | Backend returns `{"available": false, "error": "..."}` with HTTP 200. Frontend shows "Graylog unavailable" |
| Graylog 401/403 | Same as above + log warning server-side |
| Zero results from Graylog | Backend returns `{"available": true, "total_hits": 0, ...}`. Frontend shows "No firewall activity in last 24h" |
| Graylog slow (>10s) | Timeout, treat as unavailable |
| Frontend fetch fails | `.catch(() => null)` — same pattern as IPInfo. TI + IPInfo results still display normally |

### Observability
- **Metrics:** Add `ti_graylog_enrichment_duration_seconds` histogram and `ti_graylog_enrichment_total` counter (matching existing Prometheus pattern in `metrics.py`)
- **Logging:** Log Graylog query time + result count at INFO level
- **Errors:** Log Graylog failures at WARNING level

### Testing Strategy
- **Archetype:** Infrastructure Tool
- **Mock boundaries:** Mock Graylog HTTP responses (use captured sample from discovery)
- **Critical path:** Aggregation logic (grouping by action, counting by policy/port), action normalization, response schema for all 3 states (available/unavailable/zero), parallel execution not blocking on Graylog failure

### Scope
**In scope:**
- New backend endpoint `GET /ui/enrich/graylog?ip=X`
- Pydantic response model for Graylog enrichment
- Graylog search + aggregation logic with action normalization
- Frontend: fire parallel request with `.catch(() => null)`, display aggregated firewall section in lookup result
- Config: env vars for Graylog URL, token, stream ID, timeout, SSL verify
- Update `.env.example` and `docker-compose.yml` with new env vars
- Prometheus metrics for Graylog enrichment

**Out of scope:**
- Domain lookups (IP only)
- Raw log display / drill-down
- Configurable time window (hardcoded 24h)
- Multiple streams / multiple firewalls
- Caching of Graylog results
- IPv6 compressed form detection in frontend (pre-existing limitation)

**Phase 2 candidates:**
- Configurable time window (1h / 6h / 24h / 7d dropdown)
- Click-through to Graylog search for full results
- Multiple stream support
- Domain-to-IP resolution for domain lookups
- Pagination for high-volume IPs (>150 events)

### Open Items

| Item | Status | Blocking |
|------|--------|----------|
| None | - | - |
