# Architecture Overview

## Purpose

ThreatBridge aggregates multiple text-based threat intelligence feeds into a Redis-backed store and exposes a FastAPI HTTP API (plus a small UI) for low-latency IP/domain reputation lookups, feed status, and Prometheus metrics.

## Main Components

- **Configuration (`source/src/config.py`, `source/config/feeds.yml`)** – Pydantic models for feeds/settings; loads YAML plus env vars into a global `app_config`. Feed names become Redis key prefixes; URLs can reference env vars via `url: "from env var: NAME"`.
- **Redis Client (`source/src/redis_client.py`)** – Manages Redis connection (pool, readiness wait, retries) and provides helpers for set/hash operations, feed-level sets, global union sets, metadata, and refresh rate limits.
- **PSL Classifier (`source/src/psl_classifier.py`)** – Validates and classifies entries as IP / CIDR / domain using regex + `ipaddress` + `tldextract`; determines “walkable” registrable domains and handles CIDR expansion with size limits.
- **Feed Loader (`source/src/loader.py`)** – Asynchronous pipeline that downloads feeds via `httpx`, parses and classifies lines, stages entries in Redis, computes deltas, atomically swaps live sets, updates metadata, and updates Prometheus metrics.
- **API & Scheduler (`source/src/ti_api.py`)** – FastAPI app with health, lookup, feed management, enrichment, metrics, and UI endpoints; sets up logging, starts/stops an `apscheduler` job for periodic `load_all_feeds()`, and performs initial feed load (unless disabled by env).
- **Models (`source/src/models.py`)** – Pydantic models for API responses (health, lookups, feeds list/detail, refresh/rate-limit/error responses) and internal metadata/load stats structures.
- **Metrics (`source/src/metrics.py`, `source/docs/prometheus-metrics.md`)** – Prometheus metrics definitions (Gauges, Counters, Histograms) and a `metrics_collector` helper plus `/metrics` response helpers.
- **Static UI (`source/src/static`)** – Management/lookup UI served at `/` and `/static`.
- **Deployment (`docker-compose.yml`, `deploy/docker-compose.yml`)** – Docker Compose stacks for API+Redis and, in `deploy/`, an additional loader container that calls `src.loader.load_all_feeds()` in a loop.

## Data Flow

### Threat feed ingestion

- On import, `AppConfig` reads `feeds.yml` (via `FEEDS_CONFIG`) and env vars into `Config` / `SettingsConfig`; `RedisClient` connects and waits until Redis is ready.
- On API startup:
  - Redis connectivity is checked; metrics are initialized per configured feed.
  - `start_scheduler()` creates an `AsyncIOScheduler` job running `scheduled_feed_load()` every `reload_interval_minutes`.
  - Unless `SKIP_STARTUP_LOAD` is set, `scheduled_feed_load()` immediately calls `loader.load_all_feeds()`.
- `FeedLoader.load_all_feeds()`:
  - Iterates over enabled feeds, optionally skipping those not due based on `refresh_minutes` or global `reload_interval_minutes`.
  - For each feed, `load_feed()`:
    - `download_feed()` streams lines via `httpx.AsyncClient.stream("GET", url)`, computing a SHA-256 hash and capturing response headers.
    - `parse_and_classify_entries()` normalizes lines, filters comments/invalid entries, expands CIDRs (respecting `min_cidr_prefix`), and classifies into IPs, domains, and walkable domains using `psl_classifier`.
    - `stage_entries_to_redis()` writes `:new` sets for that feed’s IPs/domains/walkable domains.
    - `calculate_delta()` compares new sets to existing feed sets; `redis_client.swap_staging_to_live()` replaces live keys with staged ones.
    - A `LoadStats` object is built and `update_feed_metadata()` stores a metadata hash; `update_metrics()` updates Prometheus gauges/counters.
  - After loading at least one feed, `rebuild_global_sets()` recomputes union sets across all enabled feeds.

### Lookup and management

- `GET /check/ip`:
  - Normalizes and validates the IP via `psl_classifier`; on invalid input returns `400`.
  - Checks membership in the global `ti:all:ips` set; if found, inspects per-feed IP sets to build the feed list and derive the highest risk level from `FeedConfig.risk`.
  - Records result and latency via Prometheus metrics.
- `GET /check/domain`:
  - Normalizes and validates the domain.
  - Checks exact membership in `ti:all:domains`. If not found, derives a registrable parent via `psl_classifier.get_parent_domain_for_lookup()` and checks it in the global `ti:all:domains:walkable` set.
  - Matching feeds are resolved from per-feed domain or walkable-domain sets; the highest risk is derived as above. Metrics are recorded as for IP lookups.
- `GET /feeds` and `GET /feeds/{feed_name}`:
  - Combine static feed config with metadata hashes from Redis (`ti:feed:{name}:meta`) into `FeedInfo` / `FeedDetail` responses, including parsed timestamps and last load deltas.
- `POST /feeds/{feed_name}/refresh`:
  - Validates feed existence.
  - Enforces a TTL-based rate limit using `ti:ratelimit:refresh:{feed}` (default 900s). On limit, returns `429` with a rate-limited response payload.
  - If allowed, sets a new TTL, schedules an async `refresh_feed_task()` which calls `load_single_feed()`, and returns `202`.
- `GET /metrics` returns Prometheus text via `prometheus_client`.
- `GET /ui/enrich/ip` optionally enriches IPs via the IPInfo Lite API if an `ipinfo_token` is configured.
- `/` and `/static` serve the management UI; custom exception handlers standardize `404` and `500` responses.

## External Integrations

- **Threat Feeds (HTTP)** – Arbitrary text feeds defined in `feeds.yml` or env; fetched asynchronously via `httpx`.
- **Redis** – Single instance used for:
  - Per-feed sets: `ti:feed:{feed}:ips`, `ti:feed:{feed}:domains`, `ti:feed:{feed}:domains:walkable` (plus `:new` staging variants).
  - Global sets: `ti:all:ips`, `ti:all:domains`, `ti:all:domains:walkable`.
  - Metadata: `ti:feed:{feed}:meta` (hash), registry set `ti:feeds`, refresh-rate keys `ti:ratelimit:refresh:{feed}`.
- **Prometheus** – Scrapes `/metrics` for feed, lookup, refresh, and Redis status metrics (`ti_feed_*`, `ti_lookup_*`, `ti_refresh_requests_total`, `ti_redis_connection_status`).
- **IPInfo** – Optional external HTTP calls from `/ui/enrich/ip` to `https://api.ipinfo.io/lite/{ip}` with token.
- **Consumers (e.g., Graylog)** – Use HTTP to call `/check/ip`, `/check/domain`, `/feeds*`, `/metrics`, or the UI; no auth is implemented in the code.

## Cross-cutting Concerns

- **Logging** – Configured in `ti_api.py` via `logging.basicConfig`, using `LOG_LEVEL`. Core modules log downloads, CIDR expansion choices, Redis readiness, scheduler/loader activity, lookups, and enrichment errors.
- **Metrics** – Centralized in `metrics.py` and `metrics_collector`; loader updates per-feed entry counts, deltas, durations, and error counters; lookup endpoints record requests with status and latency; refresh endpoint logs accepted vs rate-limited; health checks update Redis connectivity.
- **Configuration** – YAML (`feeds.yml`) plus environment variables. Pydantic models use `extra='forbid'` and field constraints for strictness (unique feed names, positive intervals, allowed risk values). `AppConfig.reload_config()` allows config reload from disk.
- **Security** – Redis is bound to localhost in the Compose files; refresh endpoint is rate-limited via Redis TTLs; IP/domain inputs are validated. There is no authentication/authorization or TLS termination logic in the codebase.
- **Error Handling** – Endpoints raise `HTTPException` for client errors; unexpected exceptions are caught, logged, and mapped to `500` responses; global handlers for 404 and 500 return standardized JSON.

## Notes / Risks

- `feeds.sample.yml` documents optional fields like `format`, `auth_type`, `auth_env`, and `parser` that are not present in `FeedConfig` (and `extra='forbid'` will reject them), so using these keys will currently break config validation.
- If both the API scheduler and the standalone loader container are active (without `SKIP_STARTUP_LOAD=true` on the API), concurrent feed-loading activity may occur against the same Redis keys.
- `ti_lookup_client_requests_total` is keyed by `client_ip`, which creates high-cardinality metrics; this may be problematic at high scale and should be considered in monitoring setups.
- Global singletons (`app_config`, `redis_client`, `psl_classifier`, `metrics_collector`, `feed_loader`) are constructed at import time; missing config files or Redis availability issues will fail the application early rather than degrade gracefully.

