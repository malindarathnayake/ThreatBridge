# Testing Harness: Graylog Firewall Enrichment

## Test Archetype: Infrastructure Tool

No automated test suite exists in this project. Testing is manual via curl and browser.

## Sample Data

### Captured from live Graylog discovery (2026-03-13)

**Single message (raw):**
```json
{
  "timestamp": "2026-03-13T13:08:13.000Z",
  "source": "L31-400F-01",
  "devname": "L31-400F-01",
  "srcip": "195.184.76.167",
  "srcport": "39811",
  "dstip": "69.18.192.37",
  "dstport": "17234",
  "action": "deny",
  "policyid": "0",
  "policytype": "local-in-policy",
  "srcintf": "x6",
  "srcintfrole": "wan",
  "dstintf": "root",
  "dstintfrole": "undefined",
  "srccountry": "United States",
  "dstcountry": "United States",
  "sessionid": "1237962454",
  "proto": "6",
  "service": "LBS_TCP_10000_22000",
  "trandisp": "noop",
  "srcinetsvc": "ONYPHE-Scanner"
}
```

**Message with NAT (accepted traffic):**
```json
{
  "timestamp": "2026-03-13T12:17:52.000Z",
  "source": "L31-400F-01",
  "srcip": "195.184.76.167",
  "srcport": "62181",
  "dstip": "167.206.57.118",
  "dstport": "7779",
  "action": "accept",
  "policyname": "Magic_Transit_to_CORE_IN_Prod_2",
  "policyid": "42",
  "srcintf": "x5",
  "srcintfrole": "wan",
  "tranip": "192.168.94.22",
  "tranport": "12109",
  "service": "tcp/7779"
}
```

**Message with policyname field:**
```json
{
  "timestamp": "2026-03-13T11:18:50.000Z",
  "source": "L31-400F-01",
  "srcip": "195.184.76.167",
  "srcport": "55432",
  "dstip": "167.206.57.118",
  "dstport": "443",
  "action": "accept",
  "policyname": "Magic_Transit_to_CORE_IN_Prod_2",
  "policyid": "42",
  "srcintf": "x5",
  "srcintfrole": "wan",
  "tranip": "192.168.94.22",
  "tranport": "12109"
}
```

## Unit 1: Model Tests

### Test: Models instantiate with sample data
```python
from src.models import GraylogEnrichmentResponse, ActionSummary, PolicyCount, PortCount, NatTranslation

# Available with results
resp = GraylogEnrichmentResponse(
    available=True, ip="195.184.76.167", total_hits=82, time_range_hours=24,
    device="L31-400F-01",
    denied=ActionSummary(
        count=78,
        top_policies=[PolicyCount(name="Magic_Transit_to_CORE_IN_Prod_2", count=74)],
        top_dst_ports=[PortCount(port=17234, count=40)],
        interfaces=["x6 (wan)"]
    ),
    accepted=ActionSummary(
        count=4,
        top_policies=[PolicyCount(name="VPN_Inbound_Allow", count=4)],
        top_dst_ports=[PortCount(port=443, count=4)],
        interfaces=["x5 (wan)"],
        nat_translations=[NatTranslation(ip="192.168.94.22", port=12109, count=3)]
    )
)
assert resp.available is True
assert resp.total_hits == 82
assert resp.denied.count == 78
assert resp.accepted.nat_translations[0].ip == "192.168.94.22"

# Unavailable
resp = GraylogEnrichmentResponse(available=False, ip="1.2.3.4", error="timeout")
assert resp.available is False
assert resp.denied is None

# Zero results
resp = GraylogEnrichmentResponse(available=True, ip="8.8.8.8", total_hits=0, time_range_hours=24)
assert resp.total_hits == 0
assert resp.denied is None
```

### Test: Action normalization
```python
from src.models import ACTION_NORMALIZATION

assert ACTION_NORMALIZATION["deny"] == "DENIED"
assert ACTION_NORMALIZATION["drop"] == "DENIED"
assert ACTION_NORMALIZATION["accept"] == "ACCEPTED"
assert ACTION_NORMALIZATION["allow"] == "ACCEPTED"
assert ACTION_NORMALIZATION.get("unknown_action", "DENIED") == "DENIED"
```

## Unit 2: Metrics Tests

### Test: Metrics endpoint includes new metrics
```bash
curl -s http://localhost:8000/metrics | grep -E "ti_graylog"
# Expected: ti_graylog_enrichment_total and ti_graylog_enrichment_duration_seconds lines
```

## Unit 3: Backend Endpoint Tests

### Test: Not configured (no GRAYLOG_URL)
```bash
# Ensure GRAYLOG_URL is not set
curl -s http://localhost:8000/ui/enrich/graylog?ip=195.184.76.167 | python -m json.tool
# Expected:
# {
#   "available": false,
#   "ip": "195.184.76.167",
#   "error": "not configured"
# }
```

### Test: Invalid IP
```bash
curl -s http://localhost:8000/ui/enrich/graylog?ip=not-an-ip | python -m json.tool
# Expected: HTTP 400 or available=false with error
```

### Test: Live query (with GRAYLOG_URL set)
```bash
curl -s http://localhost:8000/ui/enrich/graylog?ip=195.184.76.167 | python -m json.tool
# Expected: available=true, total_hits > 0, denied/accepted sections populated
# Verify:
# - top_policies has max 5 entries
# - top_dst_ports has max 5 entries
# - nat_translations only present in accepted section
# - interfaces formatted as "x6 (wan)"
# - device is populated
```

### Test: Clean IP (no firewall hits)
```bash
curl -s http://localhost:8000/ui/enrich/graylog?ip=8.8.8.8 | python -m json.tool
# Expected:
# {
#   "available": true,
#   "ip": "8.8.8.8",
#   "total_hits": 0,
#   "time_range_hours": 24,
#   "device": null,
#   "denied": null,
#   "accepted": null
# }
```

### Test: Graylog timeout
```bash
# Set GRAYLOG_TIMEOUT=1 and query a slow/unreachable Graylog
curl -s http://localhost:8000/ui/enrich/graylog?ip=1.2.3.4 | python -m json.tool
# Expected: available=false, error contains "timeout"
```

### Test: Metrics recorded
```bash
# After running a few lookups:
curl -s http://localhost:8000/metrics | grep ti_graylog
# Expected:
# ti_graylog_enrichment_total{result="available"} >= 1
# ti_graylog_enrichment_duration_seconds_count >= 1
```

## Unit 4: Frontend Integration Tests

### Test: Threat IP with firewall activity
1. Open browser to `http://localhost:8000`
2. Enter `195.184.76.167` in Quick Lookup
3. Verify result shows:
   - TI section (Found: YES, Risk: high, Feeds: malwareurl)
   - IP Info section (ASN, Org, Country)
   - Firewall Activity section with DENIED and/or ACCEPTED subsections
4. Verify formatting matches the expected output in the spec

### Test: Clean IP with no firewall activity
1. Enter `8.8.8.8` in Quick Lookup
2. Verify: TI section (Found: NO), IP Info, "No firewall activity in last 24h"

### Test: Graylog unavailable
1. Stop Graylog or set invalid `GRAYLOG_URL`
2. Enter any IP in Quick Lookup
3. Verify: TI + IPInfo display normally, Firewall section shows "Graylog unavailable"
4. No JavaScript errors in browser console

### Test: Graylog not configured
1. Remove `GRAYLOG_URL` env var entirely
2. Enter any IP in Quick Lookup
3. Verify: TI + IPInfo display normally, no Firewall section visible at all

### Test: Domain lookup (no Graylog)
1. Enter `example.com` in Quick Lookup
2. Verify: Domain TI results display, no Firewall section (domains don't trigger Graylog)

## Regression Checks

- [ ] Existing `/check/ip` endpoint unchanged (test with curl)
- [ ] Existing `/check/domain` endpoint unchanged
- [ ] IPInfo enrichment still works
- [ ] Dashboard feed list still loads
- [ ] Feed refresh still works
- [ ] `/health` endpoint still responds
- [ ] `/metrics` endpoint still responds (with new metrics added)

## Known Limitations
- IPv6 compressed forms (e.g., `::1`, `fe80::1`) may not trigger IP detection in frontend (pre-existing)
- Graylog results capped at 150 messages — high-volume IPs may have incomplete aggregation
- No caching — every lookup queries Graylog fresh
