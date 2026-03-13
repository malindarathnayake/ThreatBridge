## Design Summary — Graylog Dashboard Status

### Problem
When Graylog is configured, there's no visibility into whether the connection is healthy without performing a lookup. Users need to see Graylog connectivity status on the dashboard alongside feed status.

### Approach
Add an "Enrichment Sources" section below the feeds grid on the dashboard. A new backend endpoint pings Graylog's API and caches the result for 60 seconds. The frontend renders a status card showing connected/disconnected/not configured.

### Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Health check method | Ping Graylog API | Real connectivity validation (URL + auth + stream access) |
| Cache duration | 60 seconds | Dashboard auto-refreshes every 30s — without caching, that's 2,880 pings/day |
| UI placement | Separate "Enrichment Sources" section below feeds grid | Graylog is an enrichment source, not a threat feed — mixing them is misleading |
| What to show | Connected (green), Disconnected (red), Not Configured (grey) | Matches the feed card status pattern |

### Architecture

```
Dashboard refresh (every 30s)
  ├── GET /health          → Redis status (existing)
  ├── GET /feeds           → Feed cards (existing)
  └── GET /ui/health/graylog → Graylog status (NEW, cached 60s)
        │
        ├── GRAYLOG_URL empty → { "status": "not_configured" }
        ├── Cached && fresh   → return cached result
        └── Stale/no cache    → ping Graylog API
              ├── success → { "status": "connected", "message_count": N }
              └── failure → { "status": "disconnected", "error": "..." }
```

### Integration Points

| System | Protocol | Auth | Discovery Status |
|--------|----------|------|------------------|
| Graylog API | REST (GET /api/search/universal/relative) | Basic auth (token:token) | Done (v1.4.0) |

### Config Surface

No new config. Uses existing `GRAYLOG_URL`, `GRAYLOG_TOKEN`, `GRAYLOG_STREAM_ID`, `GRAYLOG_TIMEOUT`, `GRAYLOG_VERIFY_SSL`.

### Error Handling

| Scenario | Behavior |
|----------|----------|
| GRAYLOG_URL not set | Return `status: not_configured`, frontend hides section or shows grey |
| Graylog timeout | Return `status: disconnected, error: "timeout"`, show red |
| Auth failure (401/403) | Return `status: disconnected, error: "auth failed"`, show red |
| Connection refused | Return `status: disconnected, error: "connection refused"`, show red |
| Graylog responds OK | Return `status: connected`, show green |

### Observability
- **Metrics:** Reuses existing `ti_graylog_enrichment_total` — no new metrics needed
- **Logging:** Log health check failures at WARNING, same as enrichment errors

### Testing Strategy
- **Archetype:** Infrastructure Tool (manual curl + browser tests)
- **Critical path:** Health endpoint returns correct status for each state; frontend renders correctly; 60s cache works

### Scope
**In scope:**
- New `GET /ui/health/graylog` endpoint with 60s response caching
- New "Enrichment Sources" section in dashboard HTML
- Graylog status card (connected/disconnected/not configured)
- IPInfo status card (configured/not configured) — since we're adding the section, include both enrichment sources

**Out of scope:**
- Graylog field mappings (1.5.0)
- Multiple stream support
- Historical connectivity tracking

### Open Items
None — all decisions made.
