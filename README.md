# ThreatBridge

A lightweight threat intelligence API that aggregates free IP/domain reputation feeds into a fast, queryable REST API for SIEM log enrichment.


## Why This Project?

> *"I much prefer other people solving my problems for me"* — Linus Torvalds
>
> I couldn't find a simple project that bridges free TI feeds to a lookup API for Graylog, so I built one. Contributions welcome!


| Solution | Problem |
|----------|---------|
| **MISP / OpenCTI** | Overkill for simple lookups - requires MySQL, ElasticSearch, 8GB+ RAM, complex setup. Designed for TI sharing communities, not fast SIEM enrichment. |
| **Commercial APIs** (GreyNoise, Recorded Future, AbuseIPDB) | Expensive ($5K-50K/year) or severely rate-limited free tiers (100-1000 queries/day). |
| **Free TI Feeds** (Emerging Threats, CINS Army, Abuse.ch) | High-quality data but just text files - no API, not queryable. |

**ThreatBridge fills that gap:**

```
FREE/PAID TEXT FEEDS          THREATBRIDGE           COMMERCIAL APIs
─────────────────        ────────────           ───────────────
• Just files             • Aggregates feeds     • GreyNoise
• No API                 • Redis-backed         • Recorded Future  
• Manual parsing         • Simple REST API      • $5K-50K/year
• Not queryable          • SIEM-ready           • Rate limited
                         • FREE
```

**Primary use case:** Graylog log enrichment via HTTP lookup tables.

**Also works with:** Any tool that can make HTTP requests - Splunk, Elastic SIEM, Logstash, Wazuh, SOAR platforms, custom scripts, etc.

## Features

- **Fast Lookups**: Redis-based storage for millisecond IP/domain lookups
- **PSL-Aware Matching**: Subdomain matching using Public Suffix List logic
- **CIDR Support**: Automatic expansion of CIDR notation (e.g., `192.168.0.0/24`)
- **Feed Management**: Automatic downloading, parsing, and delta tracking
- **Management UI**: Web-based dashboard for feed status and quick lookups
- **Prometheus Metrics**: Comprehensive metrics for monitoring
- **Rate Limiting**: Built-in rate limiting for manual feed refreshes
- **Docker Ready**: Fully containerized with Docker Compose

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────┐
│   External      │    │  Docker Stack    │    │ Consumers   │
│   Sources       │    │                  │    │             │
├─────────────────┤    ├──────────────────┤    ├─────────────┤
│ MalwareURL      │───→│ ThreatBridge     │←───│ Graylog     │
│ Proofpoint      │    │ - API endpoints  │    │ Prometheus  │
│ Public Suffix   │    │ - Background     │    │ Browser UI  │
│ List            │    │   scheduler      │    │             │
└─────────────────┘    │ - Management UI  │    └─────────────┘
                       │                  │
                       │ Redis            │
                       │ - Feed storage   │
                       │ - Metadata       │
                       │ - Rate limiting  │
                       └──────────────────┘
```

## Quick Deploy (No Build Required) 🚀

**TL;DR:** Download 2 files and run `docker-compose up -d`

```bash
# 1. Download the deployment files
curl -O https://raw.githubusercontent.com/malindarathnayake/ThreatBridge/main/deploy/docker-compose.yml
curl -O https://raw.githubusercontent.com/malindarathnayake/ThreatBridge/main/deploy/feeds.sample.yml

# 2. Copy and customize feed configuration
cp feeds.sample.yml feeds.yml
# Edit feeds.yml - enable/disable feeds as needed

# 3. Optional: Create .env for custom settings (most users can skip this)
# curl -O https://raw.githubusercontent.com/malindarathnayake/ThreatBridge/main/deploy/.env.example
# cp .env.example .env  # Edit if you need custom feed URLs

# 4. Start services (pulls pre-built images from GitHub Container Registry)
docker-compose up -d

# 5. Verify it's working
curl http://localhost:8000/health
curl "http://localhost:8000/check/ip?ip=1.2.3.4"
```

**What you get:**
- Pre-built Docker images (no compilation needed)
- Automatic feed loading and refresh every hour
- Management UI at http://localhost:8000
- Two free threat feeds enabled by default (Emerging Threats, CINS Army)

---

## Development Setup (Build from Source)

If you want to modify the code or build from source:

### 1. Clone and Setup

```bash
git clone https://github.com/malindarathnayake/ThreatBridge.git
cd ThreatBridge

# Copy and customize feed configuration
cp source/config/feeds.sample.yml source/config/feeds.yml
# Edit source/config/feeds.yml - enable/disable feeds, add your own URLs
```

### 2. Configure Environment

Create `.env` file with your feed URLs (for feeds using `from env var:` syntax):

```bash
# Required: MalwareURL feed URL
MALWAREURL_FEED_URL=https://www.malwareurl.com/your-feed-url

# Optional: Proofpoint feed URL (disabled by default)
PROOFPOINT_FEED_URL=https://your-proofpoint-url

# Optional: Logging level
LOG_LEVEL=INFO

# Optional: API port
API_PORT=8000
```

### 3. Start Services

```bash
# Build and start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f threatbridge
```

### 4. Verify Installation

```bash
# Health check
curl http://localhost:8000/health

# Access management UI
open http://localhost:8000

# Test lookup
curl "http://localhost:8000/check/ip?ip=1.2.3.4"
curl "http://localhost:8000/check/domain?domain=example.com"
```

## API Endpoints

### Health Check
```http
GET /health
```

### IP Lookup
```http
GET /check/ip?ip=1.2.3.4
```

**Response:**
```json
{
  "found": true,
  "query": "1.2.3.4",
  "type": "ip", 
  "feeds": ["malwareurl"],
  "risk": "high"
}
```

### Domain Lookup
```http
GET /check/domain?domain=foo.kortin.click
```

**Response:**
```json
{
  "found": true,
  "query": "foo.kortin.click",
  "type": "domain",
  "match_type": "parent",
  "matched_value": "kortin.click",
  "feeds": ["malwareurl"],
  "risk": "high"
}
```

### Feed Management
```http
GET /feeds                    # List all feeds
GET /feeds/{name}            # Get feed details
POST /feeds/{name}/refresh   # Manual refresh (rate limited)
```

### Metrics
```http
GET /metrics                 # Prometheus metrics
```

## Configuration

### feeds.yml

Copy `config/feeds.sample.yml` to `config/feeds.yml` and customize:

```yaml
feeds:
  - name: my_feed
    description: "My threat feed"  
    url: "from env var: MY_FEED_URL"  # Or direct URL
    risk: high                        # high | medium | low
    enabled: true
    refresh_minutes: 300              # Optional: per-feed refresh interval (overrides global)

settings:
  reload_interval_minutes: 60    # Default refresh interval for all feeds
  download_timeout_seconds: 300  # HTTP timeout for downloads
  max_entry_length: 253          # Max DNS name length
  min_cidr_prefix: 20            # Min CIDR to expand (/20=4096 IPs max)
```

> **Per-Feed Refresh Intervals:** Each feed can have its own `refresh_minutes` setting to override the global `reload_interval_minutes`. This is useful for feeds that don't update frequently - set a longer interval (e.g., `300` for 5 hours) to reduce unnecessary downloads.

> **CIDR Expansion**: Feeds with CIDR notation (e.g., `1.2.3.0/24`) are automatically expanded. The `min_cidr_prefix` setting limits expansion to prevent memory issues (default `/20` = max 4096 IPs per CIDR).

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | redis | Redis hostname |
| `REDIS_PORT` | 6379 | Redis port |
| `REDIS_DB` | 0 | Redis database |
| `API_PORT` | 8000 | API server port |
| `LOG_LEVEL` | INFO | Logging level |
| `FEEDS_CONFIG` | /config/feeds.yml | Feed configuration path |
| `MALWAREURL_FEED_URL` | - | MalwareURL feed URL (required) |
| `PROOFPOINT_FEED_URL` | - | Proofpoint feed URL (optional) |
| `LOADER_CHECK_INTERVAL` | 3600 | How often (seconds) the loader checks for feeds due for refresh |

> **Changing the API Port:** To expose the API on a different host port (e.g., 9000), set `API_PORT=9000` in your `.env` file or pass it when starting Docker Compose:
> ```bash
> API_PORT=9000 docker-compose up -d
> ```
> The API will then be accessible at `http://localhost:9000`. The container internally still listens on port 8000.

## Domain Matching Logic

The API implements PSL-aware domain matching:

1. **Exact Match**: Check if domain exists directly in feeds
2. **Parent Walk**: If no exact match and domain is subdomain:
   - Extract registrable domain (eTLD+1) using Public Suffix List
   - Check if registrable domain is in "walkable" domains
   - Return parent match if found

**Examples:**
- `kortin.click` → walkable (registrable domain)
- `foo.kortin.click` → matches via parent `kortin.click`
- `github.io` → walkable (special case registrable domain)
- `user.github.io` → matches via parent `github.io`

## Monitoring

### Prometheus Metrics

Key metrics exposed at `/metrics`:

- `ti_feed_entries_total` - Entry counts per feed
- `ti_feed_last_load_timestamp` - Last successful load time
- `ti_lookup_requests_total` - Lookup request counters
- `ti_lookup_duration_seconds` - Lookup latency histograms
- `ti_redis_connection_status` - Redis connectivity

### Health Monitoring

```bash
# Check API health
curl http://localhost:8000/health

# Check container health
docker-compose ps

# Check Redis
docker-compose exec redis redis-cli ping
```

### Logs

```bash
# API logs
docker-compose logs -f threatbridge

# Redis logs  
docker-compose logs -f redis

# All logs
docker-compose logs -f
```

## Feed Management

### Automatic Loading

Feeds are loaded automatically:
- On startup
- Every 60 minutes (configurable)
- Via manual refresh API

### Manual Refresh

```bash
# Via API (rate limited: once per 15 minutes)
curl -X POST http://localhost:8000/feeds/malwareurl/refresh

# Via management UI
# Visit http://localhost:8000 and click "Refresh Feed"
```

### Adding New Feeds

1. Copy sample config if you haven't already:
```bash
cp config/feeds.sample.yml config/feeds.yml
```

2. Edit `config/feeds.yml` - add your feed:
```yaml
feeds:
  - name: new_feed
    description: "New threat feed"
    url: "from env var: NEW_FEED_URL"   # Or direct URL
    risk: medium
    enabled: true
```

3. If using `from env var:` syntax, add to `.env`:
```bash
NEW_FEED_URL=https://your-feed-url
```

4. Restart services:
```bash
docker-compose restart threatbridge
```

> **Note:** The sample file includes free feeds from Emerging Threats and CINS Army. See `config/feeds.sample.yml` for more examples.

## Graylog Integration

See `docs/graylog-setup.md` for detailed Graylog configuration.

**Quick Setup:**

1. Create HTTP JSON lookup tables:
   - TI IP Lookup: `http://threatbridge:8000/check/ip?ip=${key}`
   - TI Domain Lookup: `http://threatbridge:8000/check/domain?domain=${key}`

2. Add pipeline rules:
```groovy
rule "ti_enrich_srcip"
when
  has_field("srcip")
then
  let ti = lookup("ti_ip_lookup", to_string($message.srcip));
  if (ti != null && ti.found == true) {
    set_field("ti_hit", true);
    set_field("ti_risk", ti.risk);
    set_field("ti_feeds", to_string(ti.feeds));
  }
end
```

## Development

### Local Development

```bash
# Build docker-compose from root
docker-compose build threatbridge

# run compose file allows you to see the logs of the running containers for debugging
docker-compose up 

#Oneliner to build and run
docker compose up -d --build threatbridge

# Check logs 
docker compose logs threatbridge

```

### Testing

```bash
# Test individual components
python -m pytest tests/

# Test API endpoints
curl http://localhost:8000/health
curl "http://localhost:8000/check/ip?ip=8.8.8.8"
```

### Code Structure

```
source/
├── src/                    # Application source code
│   ├── __init__.py
│   ├── config.py          # Configuration management
│   ├── models.py          # Pydantic data models
│   ├── redis_client.py    # Redis connection and operations
│   ├── psl_classifier.py  # Domain classification logic
│   ├── metrics.py         # Prometheus metrics
│   ├── loader.py          # Feed download and parsing
│   ├── ti_api.py          # FastAPI application
│   └── static/
│       └── index.html     # Management UI
├── config/                 # Configuration files
│   ├── feeds.sample.yml   # Sample feed configuration
│   └── feeds.yml          # Actual feed configuration (created by user)
└── docs/                   # Documentation
    └── graylog-setup.md   # Graylog integration guide
deploy/                     # User deployment files (pre-built images)
├── docker-compose.yml     # Production deployment
├── feeds.sample.yml       # Feed configuration template
└── .env.example           # Environment variables template
```

## Troubleshooting

### Common Issues

**1. Redis Connection Failed**
```bash
# Check Redis status
docker-compose ps redis

# Check Redis logs
docker-compose logs redis

# Test Redis connectivity
docker-compose exec redis redis-cli ping
```

**2. Feed Download Errors**
```bash
# Check API logs
docker-compose logs threatbridge | grep -i error

# Test feed URL manually
curl -I $MALWAREURL_FEED_URL

# Check feed metadata
curl http://localhost:8000/feeds/malwareurl
```

**3. High Memory Usage**
```bash
# Check Redis memory usage
docker-compose exec redis redis-cli info memory

# Monitor feed sizes
curl http://localhost:8000/feeds
```

**4. Slow Lookups**
```bash
# Check Redis latency
docker-compose exec redis redis-cli --latency

# Monitor metrics
curl http://localhost:8000/metrics | grep ti_lookup_duration
```

**5. Redis Memory Overcommit Warning**

If you see this warning in Redis logs:
```
WARNING Memory overcommit must be enabled!
```

This is a Linux kernel setting. To fix it on the Docker host:
```bash
# Temporary (until reboot)
sudo sysctl vm.overcommit_memory=1

# Permanent (add to sysctl.conf)
echo 'vm.overcommit_memory = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

> **Note:** This warning doesn't prevent Redis from working, but enabling overcommit prevents potential background save failures under low memory conditions.

### Performance Tuning

**Redis Configuration:**
- Increase `maxmemory` for large feeds
- Enable RDB snapshots for persistence
- Consider Redis clustering for scale

**API Configuration:**
- Adjust `reload_interval_minutes` for feed freshness vs. load
- Tune `download_timeout_seconds` for slow feeds
- Scale API containers horizontally

## Security Considerations

- Redis is bound to localhost only by default
- No authentication required (internal network assumed)
- Feed URLs are sensitive - use environment variables
- Consider reverse proxy with HTTPS for external access
- Monitor for feed URL changes/hijacking

## Changelog

### v1.1.0 (2025-12-04)

**New Features:**
- **Per-feed refresh intervals**: Each feed can now have its own `refresh_minutes` setting to override the global `reload_interval_minutes`. Useful for feeds that don't update frequently.
- **Large feed warnings**: UI shows warning for feeds with > 1M entries and asks for confirmation before refresh.
- **Background refresh progress**: UI shows elapsed time during refresh and polls for completion.
- **Configurable loader interval**: `LOADER_CHECK_INTERVAL` environment variable to control how often the loader checks for feeds due for refresh.

**Improvements:**
- **Redis client resilience**: Handles `BusyLoadingError` gracefully - waits for Redis to finish loading RDB instead of crashing.
- **Increased Redis timeouts**: `socket_timeout` increased to 60s, `socket_connect_timeout` to 30s for large datasets.
- **Batched Redis writes**: Large SADD operations now write in batches of 5000 to avoid timeouts.
- **API port documentation**: Added clear instructions for changing the API listening port.

**Bug Fixes:**
- Removed obsolete `version` attribute from docker-compose files (Docker Compose v2+ warning).
- Fixed refresh endpoint returning wrong HTTP status codes (now properly returns 202 Accepted and 429 Too Many Requests).

**Documentation:**
- Added troubleshooting for Redis memory overcommit warning (`vm.overcommit_memory`).
- Added `LOADER_CHECK_INTERVAL` to environment variables table.
- Documented `refresh_minutes` per-feed configuration option.

### v1.0.0 (Initial Release)

- Core threat intelligence API with IP and domain lookups
- Redis-backed storage with PSL-aware domain matching
- CIDR expansion support
- Management UI dashboard
- Prometheus metrics endpoint
- Automatic feed refresh scheduling
- Rate-limited manual refresh API

## License

MIT License - Free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! This project was born from a need - if you find it useful and want to improve it:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

Ideas for contributions:
- Additional feed parsers (JSON, CSV, STIX)
- New free feed sources
- Integration guides for other SIEMs
- Performance improvements

## Support

For issues and questions:
1. Check this README and troubleshooting section
2. Review logs: `docker-compose logs -f`
3. Check `/health` endpoint and metrics
4. Open GitHub issue with logs and configuration
