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

<details>
<summary><strong>feeds.yml</strong> - Feed configuration options</summary>

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

**Per-Feed Refresh:** Each feed can have its own `refresh_minutes` to override the global setting.

**CIDR Expansion:** Feeds with CIDR notation are automatically expanded. `min_cidr_prefix` limits expansion (default `/20` = max 4096 IPs).

</details>

<details>
<summary><strong>Environment Variables</strong> - All configuration options</summary>

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

**Changing the API Port:**
```bash
API_PORT=9000 docker-compose up -d
```

</details>

## Domain Matching Logic

<details>
<summary><strong>PSL-Aware Matching</strong> - How domain lookups work</summary>

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

</details>

## Monitoring

<details>
<summary><strong>Prometheus Metrics</strong> - Available at /metrics</summary>

- `ti_feed_entries_total` - Entry counts per feed
- `ti_feed_last_load_timestamp` - Last successful load time
- `ti_lookup_requests_total` - Lookup request counters
- `ti_lookup_duration_seconds` - Lookup latency histograms
- `ti_redis_connection_status` - Redis connectivity

📊 **[Full Metrics Reference](source/docs/prometheus-metrics.md)** - Complete metrics documentation with Grafana examples and alerting rules.

</details>

<details>
<summary><strong>Health & Logs</strong> - Monitoring commands</summary>

```bash
# Check API health
curl http://localhost:8000/health

# Check container health
docker-compose ps

# Check Redis
docker-compose exec redis redis-cli ping

# View logs
docker-compose logs -f threatbridge
docker-compose logs -f redis
```

</details>

## Feed Management

Feeds are loaded automatically on startup, every 60 minutes (configurable), and via manual refresh API.

<details>
<summary><strong>Manual Refresh</strong></summary>

```bash
# Via API (rate limited: once per 15 minutes)
curl -X POST http://localhost:8000/feeds/malwareurl/refresh

# Via management UI at http://localhost:8000
```

</details>

<details>
<summary><strong>Adding New Feeds</strong></summary>

1. Edit `config/feeds.yml`:
```yaml
feeds:
  - name: new_feed
    description: "New threat feed"
    url: "from env var: NEW_FEED_URL"   # Or direct URL
    risk: medium
    enabled: true
```

2. If using `from env var:`, add to `.env`:
```bash
NEW_FEED_URL=https://your-feed-url
```

3. Restart: `docker-compose restart threatbridge`

</details>

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

<details>
<summary><strong>Local Development</strong></summary>

```bash
# Build and run
docker compose up -d --build threatbridge

# Check logs 
docker compose logs threatbridge

# Test endpoints
curl http://localhost:8000/health
curl "http://localhost:8000/check/ip?ip=8.8.8.8"
```

</details>

<details>
<summary><strong>Code Structure</strong></summary>

```
source/
├── src/                    # Application source code
│   ├── config.py          # Configuration management
│   ├── models.py          # Pydantic data models
│   ├── redis_client.py    # Redis connection and operations
│   ├── psl_classifier.py  # Domain classification logic
│   ├── metrics.py         # Prometheus metrics
│   ├── loader.py          # Feed download and parsing
│   ├── ti_api.py          # FastAPI application (gunicorn + uvicorn workers)
│   └── static/index.html  # Management UI
├── config/                 # Feed configuration files
└── docs/                   # Documentation
deploy/                     # Production deployment files
```

</details>

## Troubleshooting

<details>
<summary><strong>Common Issues</strong></summary>

**Redis Connection Failed**
```bash
docker-compose ps redis
docker-compose logs redis
docker-compose exec redis redis-cli ping
```

**Feed Download Errors**
```bash
docker-compose logs threatbridge | grep -i error
curl http://localhost:8000/feeds/malwareurl
```

**High Memory / Slow Lookups**
```bash
docker-compose exec redis redis-cli info memory
docker-compose exec redis redis-cli --latency
curl http://localhost:8000/metrics | grep ti_lookup_duration
```

**Redis Memory Overcommit Warning** - Fix on Docker host:
```bash
sudo sysctl vm.overcommit_memory=1
```

</details>

<details>
<summary><strong>Performance Tuning</strong></summary>

**Redis:** Increase `maxmemory` for large feeds, enable RDB snapshots.

**API:** Adjust `reload_interval_minutes`, tune `download_timeout_seconds`, scale containers horizontally. The API runs with 4 gunicorn workers by default for improved throughput.

</details>

## Security Considerations

- Redis is bound to localhost only by default
- No authentication required (internal network assumed)
- Feed URLs are sensitive - use environment variables
- Consider reverse proxy with HTTPS for external access
- Monitor for feed URL changes/hijacking

## Changelog

<details>
<summary><strong>v1.2.0 (2025-12-04)</strong> - Click to expand</summary>

- **Gunicorn with 4 workers** for improved API throughput and concurrency

</details>

<details>
<summary><strong>v1.1.0 (2025-12-04)</strong> - Click to expand</summary>

- Per-feed refresh intervals (`refresh_minutes` config option)
- Large feed warnings in UI (> 1M entries)
- Background refresh progress tracking
- Redis client resilience improvements
- Batched Redis writes for large feeds
- Fixed HTTP status codes on refresh endpoint

</details>

<details>
<summary><strong>v1.0.0 (Initial Release)</strong> - Click to expand</summary>

- Core threat intelligence API with IP/domain lookups
- Redis-backed storage with PSL-aware domain matching
- Management UI dashboard
- Prometheus metrics endpoint
- Automatic feed refresh scheduling

</details>

📋 **[Full Changelog](CHANGELOG.md)** - Complete release history with all details.

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
