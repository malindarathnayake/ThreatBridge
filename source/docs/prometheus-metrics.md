# ThreatBridge Prometheus Metrics

This document describes the Prometheus metrics exposed by ThreatBridge at the `/metrics` endpoint.

## Overview

ThreatBridge exposes metrics in Prometheus text format for monitoring feed health, API performance, and system status.

```bash
# Fetch metrics
curl http://localhost:8000/metrics
```

---

## Feed Metrics

Metrics related to threat intelligence feed loading and status.

### `ti_feed_entries_total`

| Property | Value |
|----------|-------|
| Type | Gauge |
| Labels | `feed`, `type` |
| Description | Current entry count per feed |

**Labels:**
- `feed` - Feed name (e.g., `malwareurl`, `emerging_threats`)
- `type` - Entry type: `ip` or `domain`

**Example:**
```promql
# Total IPs across all feeds
sum(ti_feed_entries_total{type="ip"})

# Entries per feed
ti_feed_entries_total{feed="malwareurl"}
```

---

### `ti_feed_entries_walkable_total`

| Property | Value |
|----------|-------|
| Type | Gauge |
| Labels | `feed` |
| Description | Count of walkable domains (registrable domains for parent matching) |

**Example:**
```promql
ti_feed_entries_walkable_total{feed="malwareurl"}
```

---

### `ti_feed_last_load_timestamp`

| Property | Value |
|----------|-------|
| Type | Gauge |
| Labels | `feed` |
| Description | Unix timestamp of last successful feed load |

**Example:**
```promql
# Time since last load (seconds)
time() - ti_feed_last_load_timestamp{feed="malwareurl"}

# Alert if feed not loaded in 2 hours
time() - ti_feed_last_load_timestamp > 7200
```

---

### `ti_feed_last_load_duration_seconds`

| Property | Value |
|----------|-------|
| Type | Gauge |
| Labels | `feed` |
| Description | Duration of the last feed load operation (seconds) |

**Example:**
```promql
# Slowest feed load
max(ti_feed_last_load_duration_seconds)
```

---

### `ti_feed_entries_added`

| Property | Value |
|----------|-------|
| Type | Gauge |
| Labels | `feed` |
| Description | Number of entries added in the last load (delta tracking) |

**Example:**
```promql
ti_feed_entries_added{feed="malwareurl"}
```

---

### `ti_feed_entries_removed`

| Property | Value |
|----------|-------|
| Type | Gauge |
| Labels | `feed` |
| Description | Number of entries removed in the last load (delta tracking) |

**Example:**
```promql
ti_feed_entries_removed{feed="malwareurl"}
```

---

### `ti_feed_load_errors_total`

| Property | Value |
|----------|-------|
| Type | Counter |
| Labels | `feed` |
| Description | Cumulative count of feed load failures |

**Example:**
```promql
# Error rate over last hour
increase(ti_feed_load_errors_total[1h])

# Alert on errors
rate(ti_feed_load_errors_total[5m]) > 0
```

---

## Lookup Metrics

Metrics related to IP and domain lookup API requests.

### `ti_lookup_requests_total`

| Property | Value |
|----------|-------|
| Type | Counter |
| Labels | `endpoint`, `type`, `result` |
| Description | Total lookup request count |

**Labels:**
- `endpoint` - API endpoint: `check_ip` or `check_domain`
- `type` - Query type: `ip` or `domain`
- `result` - Lookup result: `found`, `not_found`, `error`, `invalid`

**Example:**
```promql
# Request rate
rate(ti_lookup_requests_total[5m])

# Hit rate (found vs total)
sum(rate(ti_lookup_requests_total{result="found"}[5m])) 
/ 
sum(rate(ti_lookup_requests_total{result=~"found|not_found"}[5m]))

# Error rate
sum(rate(ti_lookup_requests_total{result="error"}[5m]))
```

---

### `ti_lookup_duration_seconds`

| Property | Value |
|----------|-------|
| Type | Histogram |
| Labels | `endpoint`, `type` |
| Description | Lookup request latency distribution |

**Buckets:** 1ms, 5ms, 10ms, 25ms, 50ms, 75ms, 100ms, 250ms, 500ms, 750ms, 1s, 2.5s, 5s, 7.5s, 10s

**Example:**
```promql
# p50 latency
histogram_quantile(0.5, rate(ti_lookup_duration_seconds_bucket[5m]))

# p95 latency
histogram_quantile(0.95, rate(ti_lookup_duration_seconds_bucket[5m]))

# p99 latency
histogram_quantile(0.99, rate(ti_lookup_duration_seconds_bucket[5m]))

# Average latency
rate(ti_lookup_duration_seconds_sum[5m]) / rate(ti_lookup_duration_seconds_count[5m])
```

---

### `ti_lookup_client_requests_total`

| Property | Value |
|----------|-------|
| Type | Counter |
| Labels | `client_ip`, `endpoint` |
| Description | Request count per client IP address |

**Example:**
```promql
# Top clients by request count
topk(10, sum by (client_ip) (ti_lookup_client_requests_total))

# Requests from specific client
ti_lookup_client_requests_total{client_ip="192.168.1.100"}
```

> **Note:** This metric has high cardinality. Consider using recording rules or dropping in production if you have many unique clients.

---

## Refresh Metrics

Metrics related to manual feed refresh requests.

### `ti_refresh_requests_total`

| Property | Value |
|----------|-------|
| Type | Counter |
| Labels | `feed`, `result` |
| Description | Manual refresh request count |

**Labels:**
- `feed` - Feed name
- `result` - Request result: `accepted` or `rate_limited`

**Example:**
```promql
# Refresh attempts
rate(ti_refresh_requests_total[1h])

# Rate limited requests
ti_refresh_requests_total{result="rate_limited"}
```

---

## System Metrics

Metrics related to system health.

### `ti_redis_connection_status`

| Property | Value |
|----------|-------|
| Type | Gauge |
| Labels | none |
| Description | Redis connection status |

**Values:**
- `1` = Connected
- `0` = Disconnected

**Example:**
```promql
# Alert on Redis disconnect
ti_redis_connection_status == 0
```

---

## Grafana Dashboard Examples

### Feed Health Panel

```promql
# Feed entry counts (table)
ti_feed_entries_total

# Feed staleness (single stat with threshold)
time() - ti_feed_last_load_timestamp
```

### API Performance Panel

```promql
# Request rate (graph)
sum(rate(ti_lookup_requests_total[1m])) by (endpoint)

# Latency heatmap
sum(rate(ti_lookup_duration_seconds_bucket[1m])) by (le)

# Hit rate (gauge)
sum(rate(ti_lookup_requests_total{result="found"}[5m])) 
/ 
sum(rate(ti_lookup_requests_total{result=~"found|not_found"}[5m])) * 100
```

### Error Panel

```promql
# Feed errors (graph)
sum(increase(ti_feed_load_errors_total[1h])) by (feed)

# Lookup errors (graph)
sum(rate(ti_lookup_requests_total{result="error"}[5m])) by (endpoint)
```

---

## Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: threatbridge
    rules:
      - alert: ThreatBridgeRedisDown
        expr: ti_redis_connection_status == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "ThreatBridge Redis connection lost"

      - alert: ThreatBridgeFeedStale
        expr: time() - ti_feed_last_load_timestamp > 7200
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Feed {{ $labels.feed }} not updated in 2+ hours"

      - alert: ThreatBridgeFeedLoadErrors
        expr: increase(ti_feed_load_errors_total[1h]) > 3
        labels:
          severity: warning
        annotations:
          summary: "Feed {{ $labels.feed }} has load errors"

      - alert: ThreatBridgeHighLatency
        expr: histogram_quantile(0.95, rate(ti_lookup_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "ThreatBridge p95 latency > 100ms"
```

---

## Scrape Configuration

Example Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: 'threatbridge'
    static_configs:
      - targets: ['threatbridge:8000']
    metrics_path: /metrics
    scrape_interval: 15s
```

For Docker Compose deployments, ensure Prometheus is on the same network as ThreatBridge.

