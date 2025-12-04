# Changelog

All notable changes to ThreatBridge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2025-12-04

### Added
- **SKIP_STARTUP_LOAD option**: New environment variable to skip feed loading on API startup when a dedicated loader container handles feeds. Prevents race conditions with multiple gunicorn workers.

### Changed
- **Gunicorn timeout increased**: Raised worker timeout from 30s to 120s to prevent worker kills during slow feed processing.
- **Gunicorn preload mode**: Added `--preload` flag to load app once before forking workers, reducing memory usage and preventing startup race conditions.
- **Healthcheck start period**: Increased from 40s to 60s to accommodate slower startups.

### Fixed
- **Worker timeout on startup**: Fixed issue where gunicorn workers were killed (SIGKILL) during initial feed load due to 30s timeout being exceeded by large feed processing (~27s for proofpoint_block_ips).
- **Race condition on startup**: Fixed multiple workers racing to load the same feeds simultaneously when using gunicorn with multiple workers.

## [1.2.0] - 2025-12-04

### Added
- **IPInfo enrichment for Quick Lookup**: Web UI now shows ASN, organization, country, and continent data for IP lookups via [IPInfo Lite API](https://ipinfo.io/developers/lite). Configure via `ipinfo_token` in `feeds.yml` or `IPINFO_TOKEN` env var. Does not affect Graylog API lookups.

### Changed
- **Gunicorn with 4 workers**: Switched from single-process uvicorn to gunicorn with 4 uvicorn workers for improved API throughput and concurrency.

## [1.1.0] - 2025-12-04

### Added
- **Per-feed refresh intervals**: Each feed can now have its own `refresh_minutes` setting to override the global `reload_interval_minutes`. Useful for feeds that don't update frequently.
- **Large feed warnings**: UI shows warning for feeds with > 1M entries and asks for confirmation before refresh.
- **Background refresh progress**: UI shows elapsed time during refresh and polls for completion.
- **Configurable loader interval**: `LOADER_CHECK_INTERVAL` environment variable to control how often the loader checks for feeds due for refresh.

### Changed
- **Redis client resilience**: Handles `BusyLoadingError` gracefully - waits for Redis to finish loading RDB instead of crashing.
- **Increased Redis timeouts**: `socket_timeout` increased to 60s, `socket_connect_timeout` to 30s for large datasets.
- **Batched Redis writes**: Large SADD operations now write in batches of 5000 to avoid timeouts.

### Fixed
- Removed obsolete `version` attribute from docker-compose files (Docker Compose v2+ warning).
- Fixed refresh endpoint returning wrong HTTP status codes (now properly returns 202 Accepted and 429 Too Many Requests).

### Documentation
- Added troubleshooting for Redis memory overcommit warning (`vm.overcommit_memory`).
- Added `LOADER_CHECK_INTERVAL` to environment variables table.
- Documented `refresh_minutes` per-feed configuration option.
- Added clear instructions for changing the API listening port.

## [1.0.0] - 2025-12-01

### Added
- Core threat intelligence API with IP and domain lookups
- Redis-backed storage with PSL-aware domain matching
- CIDR expansion support with configurable prefix limits
- Management UI dashboard
- Prometheus metrics endpoint (`/metrics`)
- Automatic feed refresh scheduling
- Rate-limited manual refresh API
- Docker Compose deployment (API + Redis)
- Pre-built Docker images on GitHub Container Registry
- Support for multiple feed sources:
  - Emerging Threats (Proofpoint)
  - CINS Army
  - Custom feeds via configuration

### Security
- Redis bound to localhost only by default
- Feed URLs support environment variable references for sensitive keys

