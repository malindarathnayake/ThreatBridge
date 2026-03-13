## Gunicorn Timeout Investigation

### Issue
Graylog data adapter `fts-threatbridge-api` reporting HTTP lookup failures:
```
Data adapter <fts-threatbridge-api>: HTTP request error from URL
<http://192.168.92.126:8010/check/ip?ip=172.58.57.133>: Read timed out
```
Alert triggered 2026-03-07. Started after switching from bare Uvicorn to Gunicorn.

### Current Config
`Dockerfile.api` line 51:
```
CMD ["gunicorn", "src.ti_api:app", "-w", "1", "-k", "uvicorn.workers.UvicornWorker",
     "-b", "0.0.0.0:8000", "--timeout", "120", "--preload"]
```
- 1 worker
- `--preload` enabled
- 120s Gunicorn timeout
- Graylog HTTP adapter default read timeout: 10s

### Root Cause (Confirmed via Claude x Codex deliberation)

The root cause is **not** `--preload` or the single worker alone. It is a chain of three issues:

**1. Synchronous Redis blocking the async event loop**
The loader uses synchronous `redis-py` (not `redis.asyncio`) for all Redis operations. These blocking calls run directly on the Uvicorn worker's asyncio event loop:
- `loader.py:100-104` — sync SADD after each batch during feed processing
- `loader.py:578-581` — sync Redis during delta/swap/rebuild
- `redis_client.py:90-110` — `time.sleep()` in retry logic (blocking sleep on the event loop)
- `redis_client.py:238-259` — `swap_staging_to_live()` with large SET operations

When a feed reload runs, these sync Redis calls block the event loop for the duration of each call. During that time, incoming `/check/ip` requests from Graylog queue up and exceed Graylog's 10s read timeout.

**2. Scheduler runs in the API container even with `SKIP_STARTUP_LOAD=true`**
`ti_api.py:565` — `start_scheduler()` is called **before** the `SKIP_STARTUP_LOAD` check at line 568. `SKIP_STARTUP_LOAD` only skips the initial startup load, but the `AsyncIOScheduler` still starts and triggers `scheduled_feed_load()` at the configured `reload_interval_minutes`. This means the API container reloads feeds periodically even when a dedicated loader container exists.

**3. No distributed lock on feed reloads**
In the deploy compose, both the API container's scheduler and the `threatbridge-loader` container can trigger feed reloads concurrently. Both write to the same Redis staging/live keys (`redis_client.py:238`, `redis_client.py:259`) without any locking, risking data corruption and compounding the event loop blocking.

**Bonus: Non-atomic swap produces false negatives**
`swap_staging_to_live()` at `redis_client.py:238-257` claims to be atomic (docstring says "Atomically swap") but is not. It `DELETE`s live keys first, then `RENAME`s staging keys one by one. Between the delete and the rename completion, lookups against live keys return no data (false negatives). Not wrapped in `MULTI/EXEC`.

### Why Bare Uvicorn Didn't Show This
With bare Uvicorn, the same sync Redis blocking existed, but the timing was different — startup was faster without Gunicorn's fork overhead, and the single-process model avoided the scheduler duplication issue. The timeouts were likely intermittent before but not frequent enough to trigger Graylog alerts. Gunicorn's process management added enough overhead to push the blocking window past Graylog's 10s timeout threshold.

### Fix Plan

#### Priority 1: Stop reloads in API container (resolves Graylog timeout)
Add `DISABLE_SCHEDULER` env var to `ti_api.py`. When set, `start_scheduler()` is skipped entirely — API becomes lookup-only.

```python
# In startup_event():
disable_scheduler = os.environ.get("DISABLE_SCHEDULER", "").lower() in ("1", "true", "yes")
if not disable_scheduler:
    start_scheduler()
```

Set `DISABLE_SCHEDULER=true` in `deploy/docker-compose.yml` where the loader container handles reloads. This immediately eliminates the event loop blocking during reloads.

#### Priority 2: Add distributed lock on feed reload
Prevent concurrent reloads from multiple containers. Use a Redis-based lock (`SET NX EX`) around the reload path in `loader.py`. This protects against the API scheduler (if enabled) and loader container racing.

#### Priority 3: Make swap_staging_to_live atomic
Wrap the delete + rename sequence in a Redis `MULTI/EXEC` transaction, or use versioned key names with a final atomic pointer switch:
```
ti:feed:malwareurl:ips:v2  (new data)
ti:active:malwareurl:ips -> RENAME to point to v2
DELETE v1
```

#### Priority 4: Migrate to async Redis (architectural)
Replace `redis-py` with `redis.asyncio` in `redis_client.py` and `loader.py`. Replace `time.sleep()` with `asyncio.sleep()` in retry logic. This is the full fix but requires touching most of the data path.

### Rejected / Low-Value Fixes

| Fix | Why rejected |
|-----|-------------|
| Bump workers to 2-4 | Each worker runs its own `startup_event` → own scheduler → concurrent reloads without locking. Unsafe until scheduler is isolated. |
| Add `--keep-alive 15` | Controls idle persistent-connection timeout, not in-flight request timeout. Does not address Graylog "Read timed out". |
| Increase Graylog adapter read timeout | Band-aid only. Masks the real issue. Acceptable as temporary mitigation alongside Priority 1. |
| Move reload to background asyncio task | Reloads already run in an async scheduler task (`ti_api.py:496`). The problem is sync Redis calls inside that task blocking the event loop — another async wrapper doesn't help. |

### Temporary Mitigation
While Priority 1 is implemented, increase Graylog adapter read timeout:
- System > Lookup Tables > Data Adapters > `fts-threatbridge-api`
- Change HTTP Read timeout from `10000` to `20000` ms

### Status
Parked — pick up after Graylog enrichment feature is complete.

### References
- Gunicorn settings docs: https://docs.gunicorn.org/en/stable/settings.html
- CHANGELOG.md: Previous fix for worker timeout on startup (v1.2.0) and race condition with multiple workers
- Deliberation: Claude x Codex joint review, 2026-03-13
