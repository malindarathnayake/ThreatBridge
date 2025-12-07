"""Feed loader for downloading, parsing, and loading threat intelligence feeds."""

import asyncio
import hashlib
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

import httpx

from .config import app_config, FeedConfig
from .metrics import metrics_collector
from .models import FeedMetadata, LoadStats
from .psl_classifier import psl_classifier
from .redis_client import redis_client

logger = logging.getLogger(__name__)


class FeedLoadResult:
    """Result of a feed load operation."""
    
    def __init__(self, success: bool, error_message: Optional[str] = None, stats: Optional[LoadStats] = None):
        self.success = success
        self.error_message = error_message
        self.stats = stats


class FeedLoader:
    """Downloads, parses, and loads threat intelligence feeds into Redis."""
    
    def __init__(self):
        self.timeout = app_config.config.settings.download_timeout_seconds
        self.max_entry_length = app_config.config.settings.max_entry_length
        self.batch_size = app_config.config.settings.batch_size
        # Min prefix for CIDR expansion (default /20 = max 4096 IPs per CIDR)
        self.min_cidr_prefix = getattr(app_config.config.settings, 'min_cidr_prefix', 20)
    
    def _clear_staging_keys(self, feed_name: str) -> None:
        """Clear staging keys for a feed."""
        staging_keys = [
            f"ti:feed:{feed_name}:ips:new",
            f"ti:feed:{feed_name}:domains:new",
            f"ti:feed:{feed_name}:domains:walkable:new"
        ]
        redis_client.delete(*staging_keys)
    
    async def _process_and_flush_batch(self, feed_name: str, batch: List[str]) -> None:
        """
        Process a batch of lines and flush to Redis staging.
        
        Args:
            feed_name: Name of the feed
            batch: List of raw lines to process
        """
        if not batch:
            return
        
        # Use asyncio.to_thread for CPU-bound classification
        def classify_batch(lines: List[str]) -> Tuple[List[str], List[str], List[str]]:
            ips, domains, walkable = [], [], []
            
            for line in lines:
                # Skip comments and empty lines
                if not line.strip() or line.strip().startswith('#'):
                    continue
                
                # Normalize entry
                entry = psl_classifier.normalize_entry(line)
                
                # Check for CIDR notation first
                if psl_classifier.is_cidr_notation(entry):
                    expanded_ips = psl_classifier.expand_cidr(entry, self.min_cidr_prefix)
                    if expanded_ips:
                        ips.extend(expanded_ips)
                    continue
                
                # Validate entry
                if not psl_classifier.is_valid_entry(entry, self.max_entry_length):
                    continue
                
                # Classify entry
                entry_type, is_walkable = psl_classifier.classify_entry(entry)
                
                if entry_type == "ip":
                    ips.append(entry)
                elif entry_type == "domain":
                    domains.append(entry)
                    if is_walkable:
                        walkable.append(entry)
            
            return ips, domains, walkable
        
        # Process classification in a thread to avoid blocking the event loop
        ips, domains, walkable = await asyncio.to_thread(classify_batch, batch)
        
        # Append to staging sets (not replace)
        if ips:
            redis_client.add_feed_ips(feed_name, ips, staging=True)
        if domains:
            redis_client.add_feed_domains(feed_name, domains, staging=True)
        if walkable:
            redis_client.add_feed_walkable_domains(feed_name, walkable, staging=True)
    
    async def stream_and_process_feed(self, feed_config: FeedConfig) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Stream and process feed with batching to avoid memory issues.
        
        Args:
            feed_config: Feed configuration
        
        Returns:
            Tuple of (success, error_message, feed_data)
            feed_data contains: headers, file_hash, entry_counts
        """
        try:
            url = feed_config.get_resolved_url()
            feed_name = feed_config.name
            logger.info(f"Streaming feed '{feed_name}' from {url}")
            
            # Clear staging keys upfront
            self._clear_staging_keys(feed_name)
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream('GET', url) as response:
                    response.raise_for_status()
                    
                    hasher = hashlib.sha256()
                    batch = []
                    line_count = 0
                    
                    async for line in response.aiter_lines():
                        hasher.update((line + '\n').encode('utf-8'))
                        line_count += 1
                        
                        batch.append(line)
                        
                        if len(batch) >= self.batch_size:
                            await self._process_and_flush_batch(feed_name, batch)
                            batch = []
                            
                            # Progress logging every 100k lines
                            if line_count % 100000 == 0:
                                logger.info(f"Feed '{feed_name}': processed {line_count:,} lines...")
                    
                    # Flush remaining batch
                    if batch:
                        await self._process_and_flush_batch(feed_name, batch)
                    
                    # Get final counts from Redis staging keys
                    ips_count = redis_client.scard(f"ti:feed:{feed_name}:ips:new")
                    domains_count = redis_client.scard(f"ti:feed:{feed_name}:domains:new")
                    walkable_count = redis_client.scard(f"ti:feed:{feed_name}:domains:walkable:new")
                    
                    feed_data = {
                        'headers': dict(response.headers),
                        'file_hash': hasher.hexdigest(),
                        'entry_count_ips': ips_count,
                        'entry_count_domains': domains_count,
                        'entry_count_walkable': walkable_count,
                        'total_lines': line_count
                    }
                    
                    logger.info(f"Streamed {line_count:,} lines from feed '{feed_name}': "
                              f"{ips_count} IPs, {domains_count} domains ({walkable_count} walkable), "
                              f"hash: {feed_data['file_hash'][:16]}...")
                    
                    return True, None, feed_data
                    
        except httpx.TimeoutException as e:
            error_msg = f"Download timeout after {self.timeout}s: {e}"
            logger.error(f"Feed '{feed_config.name}' stream failed: {error_msg}")
            return False, error_msg, None
            
        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP error {e.response.status_code}: {e.response.reason_phrase}"
            logger.error(f"Feed '{feed_config.name}' stream failed: {error_msg}")
            return False, error_msg, None
            
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            logger.error(f"Feed '{feed_config.name}' stream failed: {error_msg}")
            return False, error_msg, None

    async def download_feed(self, feed_config: FeedConfig) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Download feed from URL with streaming.
        
        Args:
            feed_config: Feed configuration
        
        Returns:
            Tuple of (success, error_message, feed_data)
            feed_data contains: content, headers, file_hash
        """
        try:
            url = feed_config.get_resolved_url()
            logger.info(f"Downloading feed '{feed_config.name}' from {url}")
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream('GET', url) as response:
                    response.raise_for_status()
                    
                    # Collect content and calculate hash
                    content_lines = []
                    hasher = hashlib.sha256()
                    
                    async for line in response.aiter_lines():
                        line_bytes = (line + '\n').encode('utf-8')
                        hasher.update(line_bytes)
                        content_lines.append(line)
                    
                    feed_data = {
                        'content': content_lines,
                        'headers': dict(response.headers),
                        'file_hash': hasher.hexdigest()
                    }
                    
                    logger.info(f"Downloaded {len(content_lines)} lines from feed '{feed_config.name}', "
                              f"hash: {feed_data['file_hash'][:16]}...")
                    
                    return True, None, feed_data
                    
        except httpx.TimeoutException as e:
            error_msg = f"Download timeout after {self.timeout}s: {e}"
            logger.error(f"Feed '{feed_config.name}' download failed: {error_msg}")
            return False, error_msg, None
            
        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP error {e.response.status_code}: {e.response.reason_phrase}"
            logger.error(f"Feed '{feed_config.name}' download failed: {error_msg}")
            return False, error_msg, None
            
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            logger.error(f"Feed '{feed_config.name}' download failed: {error_msg}")
            return False, error_msg, None
    
    def parse_and_classify_entries(self, content_lines: List[str], feed_name: str) -> Tuple[List[str], List[str], List[str]]:
        """
        Parse feed content and classify entries.
        
        Args:
            content_lines: Raw lines from feed
            feed_name: Name of the feed for logging
        
        Returns:
            Tuple of (ips, domains, walkable_domains)
        """
        ips = []
        domains = []
        walkable_domains = []
        
        processed_count = 0
        skipped_count = 0
        invalid_count = 0
        cidr_count = 0
        cidr_expanded_count = 0
        cidr_skipped_large = 0
        
        for line in content_lines:
            # Basic filtering
            if not line.strip() or line.strip().startswith('#'):
                skipped_count += 1
                continue
            
            # Normalize entry
            entry = psl_classifier.normalize_entry(line)
            
            # Check for CIDR notation first
            if psl_classifier.is_cidr_notation(entry):
                cidr_count += 1
                expanded_ips = psl_classifier.expand_cidr(entry, self.min_cidr_prefix)
                if expanded_ips:
                    ips.extend(expanded_ips)
                    cidr_expanded_count += len(expanded_ips)
                    processed_count += 1
                else:
                    # CIDR was too large to expand
                    cidr_skipped_large += 1
                continue
            
            # Validate entry
            if not psl_classifier.is_valid_entry(entry, self.max_entry_length):
                invalid_count += 1
                continue
            
            # Classify entry
            entry_type, is_walkable = psl_classifier.classify_entry(entry)
            
            if entry_type == "ip":
                ips.append(entry)
            elif entry_type == "domain":
                domains.append(entry)
                if is_walkable:
                    walkable_domains.append(entry)
            
            processed_count += 1
        
        # Build log message
        log_parts = [f"Feed '{feed_name}' parsed: {processed_count} valid entries"]
        log_parts.append(f"{len(ips)} IPs")
        if cidr_count > 0:
            log_parts.append(f"({cidr_count} CIDRs → {cidr_expanded_count} expanded)")
        if cidr_skipped_large > 0:
            log_parts.append(f"({cidr_skipped_large} large CIDRs skipped)")
        log_parts.append(f"{len(domains)} domains ({len(walkable_domains)} walkable)")
        log_parts.append(f"{skipped_count} skipped, {invalid_count} invalid")
        
        logger.info(", ".join(log_parts))
        
        return ips, domains, walkable_domains
    
    def calculate_delta(self, feed_name: str, new_ips: Set[str], new_domains: Set[str], 
                       new_walkable: Set[str]) -> Tuple[int, int, int]:
        """
        Calculate delta between new and existing entries.
        
        Args:
            feed_name: Feed name
            new_ips: New IP set
            new_domains: New domain set
            new_walkable: New walkable domain set
        
        Returns:
            Tuple of (entries_added, entries_removed, entries_unchanged)
        """
        # Get current entries
        current_ips = redis_client.get_feed_ips(feed_name)
        current_domains = redis_client.get_feed_domains(feed_name)
        current_walkable = redis_client.get_feed_walkable_domains(feed_name)
        
        # Combine all entries for delta calculation
        current_all = current_ips | current_domains
        new_all = new_ips | new_domains
        
        # Calculate deltas
        entries_added = len(new_all - current_all)
        entries_removed = len(current_all - new_all)
        entries_unchanged = len(new_all & current_all)
        
        logger.debug(f"Feed '{feed_name}' delta: +{entries_added}, -{entries_removed}, ={entries_unchanged}")
        
        return entries_added, entries_removed, entries_unchanged
    
    async def calculate_delta_redis_native(self, feed_name: str) -> Tuple[int, int, int]:
        """
        Calculate delta using Redis-native operations to avoid loading large sets into memory.
        
        Args:
            feed_name: Feed name
        
        Returns:
            Tuple of (entries_added, entries_removed, entries_unchanged)
        """
        try:
            # Use temporary keys for calculations
            temp_new_all = f"ti:feed:{feed_name}:temp:new_all"
            temp_old_all = f"ti:feed:{feed_name}:temp:old_all"
            temp_added = f"ti:feed:{feed_name}:temp:added"
            temp_removed = f"ti:feed:{feed_name}:temp:removed"
            temp_unchanged = f"ti:feed:{feed_name}:temp:unchanged"
            
            # Create unified new set (staging IPs + domains)
            new_ips_key = f"ti:feed:{feed_name}:ips:new"
            new_domains_key = f"ti:feed:{feed_name}:domains:new"
            if redis_client.exists(new_ips_key) and redis_client.exists(new_domains_key):
                redis_client.sunionstore(temp_new_all, new_ips_key, new_domains_key)
            elif redis_client.exists(new_ips_key):
                redis_client.sunionstore(temp_new_all, new_ips_key)
            elif redis_client.exists(new_domains_key):
                redis_client.sunionstore(temp_new_all, new_domains_key)
            else:
                # No new data
                return 0, 0, 0
            
            # Create unified old set (current IPs + domains)
            old_ips_key = f"ti:feed:{feed_name}:ips"
            old_domains_key = f"ti:feed:{feed_name}:domains"
            if redis_client.exists(old_ips_key) and redis_client.exists(old_domains_key):
                redis_client.sunionstore(temp_old_all, old_ips_key, old_domains_key)
            elif redis_client.exists(old_ips_key):
                redis_client.sunionstore(temp_old_all, old_ips_key)
            elif redis_client.exists(old_domains_key):
                redis_client.sunionstore(temp_old_all, old_domains_key)
            
            # Calculate deltas using Redis set operations
            # Added = new - old
            if redis_client.exists(temp_old_all):
                redis_client._execute_with_retry(redis_client._redis.sdiffstore, temp_added, temp_new_all, temp_old_all)
                entries_added = redis_client.scard(temp_added)
                
                # Removed = old - new  
                redis_client._execute_with_retry(redis_client._redis.sdiffstore, temp_removed, temp_old_all, temp_new_all)
                entries_removed = redis_client.scard(temp_removed)
                
                # Unchanged = new ∩ old
                redis_client._execute_with_retry(redis_client._redis.sinterstore, temp_unchanged, temp_new_all, temp_old_all)
                entries_unchanged = redis_client.scard(temp_unchanged)
            else:
                # No old data, everything is added
                entries_added = redis_client.scard(temp_new_all)
                entries_removed = 0
                entries_unchanged = 0
            
            # Clean up temporary keys
            temp_keys = [temp_new_all, temp_old_all, temp_added, temp_removed, temp_unchanged]
            redis_client.delete(*temp_keys)
            
            logger.debug(f"Feed '{feed_name}' Redis-native delta: +{entries_added}, -{entries_removed}, ={entries_unchanged}")
            
            return entries_added, entries_removed, entries_unchanged
            
        except Exception as e:
            logger.error(f"Error calculating Redis-native delta for feed '{feed_name}': {e}")
            # Fallback to simple counts without delta calculation
            new_ips_count = redis_client.scard(f"ti:feed:{feed_name}:ips:new")
            new_domains_count = redis_client.scard(f"ti:feed:{feed_name}:domains:new")
            total_new = new_ips_count + new_domains_count
            return total_new, 0, 0  # Assume all entries are new on error
    
    def stage_entries_to_redis(self, feed_name: str, ips: List[str], domains: List[str],
                             walkable_domains: List[str]) -> bool:
        """
        Stage entries to Redis with :new suffix.
        
        Args:
            feed_name: Feed name
            ips: List of IP addresses
            domains: List of domains
            walkable_domains: List of walkable domains
        
        Returns:
            True if staging successful, False otherwise
        """
        try:
            # Clear any existing staging keys first
            staging_keys = [
                f"ti:feed:{feed_name}:ips:new",
                f"ti:feed:{feed_name}:domains:new",
                f"ti:feed:{feed_name}:domains:walkable:new"
            ]
            redis_client.delete(*staging_keys)
            
            # Stage new entries
            if ips:
                redis_client.add_feed_ips(feed_name, ips, staging=True)
            if domains:
                redis_client.add_feed_domains(feed_name, domains, staging=True)
            if walkable_domains:
                redis_client.add_feed_walkable_domains(feed_name, walkable_domains, staging=True)
            
            logger.debug(f"Feed '{feed_name}' staged: {len(ips)} IPs, {len(domains)} domains, "
                        f"{len(walkable_domains)} walkable")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to stage entries for feed '{feed_name}': {e}")
            return False
    
    def update_feed_metadata(self, feed_config: FeedConfig, stats: LoadStats, 
                           error_message: Optional[str] = None) -> None:
        """
        Update feed metadata in Redis.
        
        Args:
            feed_config: Feed configuration
            stats: Load statistics
            error_message: Error message if load failed
        """
        now = datetime.utcnow()
        
        # Get existing metadata or create new
        existing_meta = redis_client.get_feed_metadata(feed_config.name)
        
        if existing_meta:
            metadata = FeedMetadata.from_redis_dict(existing_meta)
        else:
            metadata = FeedMetadata(
                description=feed_config.description,
                risk=feed_config.risk,
                enabled=feed_config.enabled
            )
        
        # Update with new stats
        metadata.description = feed_config.description
        metadata.risk = feed_config.risk
        metadata.enabled = feed_config.enabled
        metadata.last_loaded = now.isoformat()
        metadata.file_hash = f"sha256:{stats.file_hash}"
        metadata.entry_count_ips = stats.entry_count_ips
        metadata.entry_count_domains = stats.entry_count_domains
        metadata.entries_added = stats.entries_added
        metadata.entries_removed = stats.entries_removed
        metadata.load_duration_seconds = stats.load_duration_seconds
        
        if stats.last_modified:
            metadata.last_modified = stats.last_modified
        if stats.etag:
            metadata.etag = stats.etag
        
        # Handle errors
        if error_message:
            metadata.last_error = error_message
            metadata.last_error_time = now.isoformat()
        else:
            metadata.last_error = None
            metadata.last_error_time = None
        
        # Save to Redis
        redis_client.set_feed_metadata(feed_config.name, metadata.to_redis_dict())
        
        # Register feed
        redis_client.register_feed(feed_config.name)
    
    def update_metrics(self, feed_name: str, stats: LoadStats, success: bool) -> None:
        """
        Update Prometheus metrics.
        
        Args:
            feed_name: Feed name
            stats: Load statistics
            success: Whether load was successful
        """
        if success:
            # Update entry counts
            walkable_count = redis_client.scard(f"ti:feed:{feed_name}:domains:walkable")
            metrics_collector.update_feed_entries(
                feed_name, stats.entry_count_ips, stats.entry_count_domains, walkable_count
            )
            
            # Update load stats
            load_timestamp = time.time()
            metrics_collector.update_feed_load_stats(
                feed_name, load_timestamp, stats.load_duration_seconds,
                stats.entries_added, stats.entries_removed
            )
        else:
            # Increment error counter
            metrics_collector.increment_feed_load_error(feed_name)
    
    async def load_feed(self, feed_config: FeedConfig) -> FeedLoadResult:
        """
        Load a single feed with streaming and batch processing.
        
        Args:
            feed_config: Feed configuration
        
        Returns:
            FeedLoadResult with success status and statistics
        """
        start_time = time.time()
        feed_name = feed_config.name
        
        logger.info(f"Starting streaming load for feed '{feed_name}'")
        
        try:
            # Stream and process feed with batching
            success, error_msg, feed_data = await self.stream_and_process_feed(feed_config)
            if not success:
                # Update metadata with error
                dummy_stats = LoadStats(
                    entries_added=0,
                    entries_removed=0,
                    entries_unchanged=0,
                    entry_count_ips=0,
                    entry_count_domains=0,
                    load_duration_seconds=time.time() - start_time,
                    file_hash=""
                )
                self.update_feed_metadata(feed_config, dummy_stats, error_msg)
                self.update_metrics(feed_name, dummy_stats, False)
                return FeedLoadResult(False, error_msg)
            
            # Calculate delta using Redis-native operations (memory efficient)
            entries_added, entries_removed, entries_unchanged = await self.calculate_delta_redis_native(feed_name)
            
            # Atomic swap from staging to live
            redis_client.swap_staging_to_live(feed_name)
            
            # Create load statistics
            stats = LoadStats(
                entries_added=entries_added,
                entries_removed=entries_removed,
                entries_unchanged=entries_unchanged,
                entry_count_ips=feed_data['entry_count_ips'],
                entry_count_domains=feed_data['entry_count_domains'],
                load_duration_seconds=time.time() - start_time,
                file_hash=feed_data['file_hash'],
                last_modified=feed_data['headers'].get('last-modified'),
                etag=feed_data['headers'].get('etag')
            )
            
            # Update metadata and metrics
            self.update_feed_metadata(feed_config, stats)
            self.update_metrics(feed_name, stats, True)
            
            logger.info(f"Successfully streamed feed '{feed_name}': "
                       f"{feed_data['entry_count_ips']} IPs, "
                       f"{feed_data['entry_count_domains']} domains "
                       f"({feed_data['entry_count_walkable']} walkable), "
                       f"+{entries_added}/-{entries_removed} delta, "
                       f"{stats.load_duration_seconds:.1f}s")
            
            return FeedLoadResult(True, None, stats)
            
        except Exception as e:
            error_msg = f"Unexpected error during streaming feed load: {e}"
            logger.error(f"Feed '{feed_name}' load failed: {error_msg}")
            
            dummy_stats = LoadStats(
                entries_added=0,
                entries_removed=0,
                entries_unchanged=0,
                entry_count_ips=0,
                entry_count_domains=0,
                load_duration_seconds=time.time() - start_time,
                file_hash=""
            )
            self.update_feed_metadata(feed_config, dummy_stats, error_msg)
            self.update_metrics(feed_name, dummy_stats, False)
            
            return FeedLoadResult(False, error_msg)
    
    def is_feed_due_for_refresh(self, feed_config: FeedConfig) -> bool:
        """
        Check if a feed is due for refresh based on its interval.
        
        Args:
            feed_config: Feed configuration
        
        Returns:
            True if feed should be refreshed, False otherwise
        """
        # Get effective interval (per-feed or global default)
        interval_minutes = feed_config.refresh_minutes or app_config.config.settings.reload_interval_minutes
        
        # Get last loaded time from metadata
        metadata = redis_client.get_feed_metadata(feed_config.name)
        if not metadata:
            # Never loaded, so it's due
            logger.debug(f"Feed '{feed_config.name}' has no metadata, marking as due for refresh")
            return True
        
        last_loaded_str = metadata.get('last_loaded')
        if not last_loaded_str:
            logger.debug(f"Feed '{feed_config.name}' has no last_loaded timestamp, marking as due for refresh")
            return True
        
        try:
            last_loaded = datetime.fromisoformat(last_loaded_str)
            next_due = last_loaded + timedelta(minutes=interval_minutes)
            now = datetime.utcnow()
            
            if now >= next_due:
                logger.debug(f"Feed '{feed_config.name}' is due for refresh (last: {last_loaded_str}, interval: {interval_minutes}m)")
                return True
            else:
                remaining = (next_due - now).total_seconds() / 60
                logger.debug(f"Feed '{feed_config.name}' not due for refresh ({remaining:.1f}m remaining)")
                return False
                
        except (ValueError, TypeError) as e:
            logger.warning(f"Could not parse last_loaded for feed '{feed_config.name}': {e}, marking as due")
            return True

    async def load_all_feeds(self, rebuild_global_sets: bool = True, force: bool = False) -> Dict[str, FeedLoadResult]:
        """
        Load all enabled feeds that are due for refresh.
        
        Args:
            rebuild_global_sets: Whether to rebuild global union sets after loading
            force: If True, bypass interval check and load all feeds
        
        Returns:
            Dictionary of feed_name -> FeedLoadResult
        """
        results = {}
        enabled_feeds = app_config.enabled_feeds
        feeds_loaded = 0
        feeds_skipped = 0
        
        logger.info(f"Checking {len(enabled_feeds)} enabled feeds for refresh (force={force})")
        
        for feed_config in enabled_feeds:
            # Check if feed is due for refresh (unless force=True)
            if not force and not self.is_feed_due_for_refresh(feed_config):
                feeds_skipped += 1
                continue
            
            result = await self.load_feed(feed_config)
            results[feed_config.name] = result
            feeds_loaded += 1
        
        logger.info(f"Feed refresh complete: {feeds_loaded} loaded, {feeds_skipped} skipped (not due)")
        
        if rebuild_global_sets and feeds_loaded > 0:
            self.rebuild_global_sets()
        
        # Update Redis connection status metric
        metrics_collector.set_redis_connection_status(redis_client.is_connected())
        
        return results
    
    def rebuild_global_sets(self) -> None:
        """Rebuild global union sets from all feed sets."""
        enabled_feed_names = [feed.name for feed in app_config.enabled_feeds]
        logger.info(f"Rebuilding global sets from {len(enabled_feed_names)} feeds")
        
        start_time = time.time()
        redis_client.rebuild_global_sets(enabled_feed_names)
        duration = time.time() - start_time
        
        # Get counts for logging
        total_ips = redis_client.scard("ti:all:ips")
        total_domains = redis_client.scard("ti:all:domains")
        total_walkable = redis_client.scard("ti:all:domains:walkable")
        
        logger.info(f"Global sets rebuilt in {duration:.1f}s: "
                   f"{total_ips} IPs, {total_domains} domains, {total_walkable} walkable")


# Global loader instance
feed_loader = FeedLoader()


# Standalone functions for external use
async def load_single_feed(feed_name: str) -> FeedLoadResult:
    """Load a single feed by name."""
    feed_config = app_config.get_feed_by_name(feed_name)
    if not feed_config:
        return FeedLoadResult(False, f"Feed '{feed_name}' not found in configuration")
    
    if not feed_config.enabled:
        return FeedLoadResult(False, f"Feed '{feed_name}' is disabled")
    
    result = await feed_loader.load_feed(feed_config)
    
    # Rebuild global sets after single feed load
    feed_loader.rebuild_global_sets()
    
    return result


async def load_all_feeds() -> Dict[str, FeedLoadResult]:
    """Load all enabled feeds."""
    return await feed_loader.load_all_feeds()


def rebuild_global_sets() -> None:
    """Rebuild global union sets."""
    feed_loader.rebuild_global_sets()
