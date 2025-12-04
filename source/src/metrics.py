"""ThreatBridge - Prometheus metrics."""

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST


# Feed-related metrics
ti_feed_entries_total = Gauge(
    'ti_feed_entries_total',
    'Current entry count per feed',
    ['feed', 'type']  # type: ip/domain
)

ti_feed_entries_walkable_total = Gauge(
    'ti_feed_entries_walkable_total',
    'Walkable domains per feed',
    ['feed']
)

ti_feed_last_load_timestamp = Gauge(
    'ti_feed_last_load_timestamp',
    'Unix timestamp of last successful load',
    ['feed']
)

ti_feed_last_load_duration_seconds = Gauge(
    'ti_feed_last_load_duration_seconds',
    'Duration of last load',
    ['feed']
)

ti_feed_entries_added = Gauge(
    'ti_feed_entries_added',
    'Entries added in last load',
    ['feed']
)

ti_feed_entries_removed = Gauge(
    'ti_feed_entries_removed',
    'Entries removed in last load',
    ['feed']
)

ti_feed_load_errors_total = Counter(
    'ti_feed_load_errors_total',
    'Cumulative load failures',
    ['feed']
)

# Lookup request metrics
ti_lookup_requests_total = Counter(
    'ti_lookup_requests_total',
    'Lookup request count',
    ['endpoint', 'type', 'result']  # endpoint: check_ip/check_domain, type: ip/domain, result: found/not_found
)

ti_lookup_duration_seconds = Histogram(
    'ti_lookup_duration_seconds',
    'Lookup latency',
    ['endpoint', 'type'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0]
)

ti_lookup_client_requests_total = Counter(
    'ti_lookup_client_requests_total',
    'Requests per client IP',
    ['client_ip', 'endpoint']
)

# Refresh request metrics
ti_refresh_requests_total = Counter(
    'ti_refresh_requests_total',
    'Manual refresh attempts',
    ['feed', 'result']  # result: accepted/rate_limited
)

# Redis connection status
ti_redis_connection_status = Gauge(
    'ti_redis_connection_status',
    'Redis connection status (1=connected, 0=disconnected)'
)


class MetricsCollector:
    """Helper class for updating metrics."""
    
    @staticmethod
    def update_feed_entries(feed_name: str, ip_count: int, domain_count: int, walkable_count: int):
        """Update feed entry count metrics."""
        ti_feed_entries_total.labels(feed=feed_name, type='ip').set(ip_count)
        ti_feed_entries_total.labels(feed=feed_name, type='domain').set(domain_count)
        ti_feed_entries_walkable_total.labels(feed=feed_name).set(walkable_count)
    
    @staticmethod
    def update_feed_load_stats(feed_name: str, load_timestamp: float, duration: float, 
                             entries_added: int, entries_removed: int):
        """Update feed load statistics."""
        ti_feed_last_load_timestamp.labels(feed=feed_name).set(load_timestamp)
        ti_feed_last_load_duration_seconds.labels(feed=feed_name).set(duration)
        ti_feed_entries_added.labels(feed=feed_name).set(entries_added)
        ti_feed_entries_removed.labels(feed=feed_name).set(entries_removed)
    
    @staticmethod
    def increment_feed_load_error(feed_name: str):
        """Increment feed load error counter."""
        ti_feed_load_errors_total.labels(feed=feed_name).inc()
    
    @staticmethod
    def record_lookup_request(endpoint: str, lookup_type: str, result: str, duration: float, client_ip: str):
        """Record a lookup request with timing."""
        ti_lookup_requests_total.labels(endpoint=endpoint, type=lookup_type, result=result).inc()
        ti_lookup_duration_seconds.labels(endpoint=endpoint, type=lookup_type).observe(duration)
        ti_lookup_client_requests_total.labels(client_ip=client_ip, endpoint=endpoint).inc()
    
    @staticmethod
    def record_refresh_request(feed_name: str, result: str):
        """Record a refresh request."""
        ti_refresh_requests_total.labels(feed=feed_name, result=result).inc()
    
    @staticmethod
    def set_redis_connection_status(connected: bool):
        """Set Redis connection status."""
        ti_redis_connection_status.set(1 if connected else 0)
    
    @staticmethod
    def clear_feed_metrics(feed_name: str):
        """Clear all metrics for a feed (useful when feed is disabled)."""
        ti_feed_entries_total.labels(feed=feed_name, type='ip').set(0)
        ti_feed_entries_total.labels(feed=feed_name, type='domain').set(0)
        ti_feed_entries_walkable_total.labels(feed=feed_name).set(0)
        ti_feed_last_load_timestamp.labels(feed=feed_name).set(0)
        ti_feed_last_load_duration_seconds.labels(feed=feed_name).set(0)
        ti_feed_entries_added.labels(feed=feed_name).set(0)
        ti_feed_entries_removed.labels(feed=feed_name).set(0)
    
    @staticmethod
    def initialize_feed_metrics(feed_name: str):
        """Initialize metrics for a new feed with zero values."""
        ti_feed_entries_total.labels(feed=feed_name, type='ip').set(0)
        ti_feed_entries_total.labels(feed=feed_name, type='domain').set(0)
        ti_feed_entries_walkable_total.labels(feed=feed_name).set(0)
        ti_feed_last_load_timestamp.labels(feed=feed_name).set(0)
        ti_feed_last_load_duration_seconds.labels(feed=feed_name).set(0)
        ti_feed_entries_added.labels(feed=feed_name).set(0)
        ti_feed_entries_removed.labels(feed=feed_name).set(0)


# Global metrics collector instance
metrics_collector = MetricsCollector()


def get_metrics_content() -> str:
    """Get Prometheus metrics in text format."""
    return generate_latest().decode('utf-8')


def get_metrics_content_type() -> str:
    """Get the content type for Prometheus metrics."""
    return CONTENT_TYPE_LATEST
