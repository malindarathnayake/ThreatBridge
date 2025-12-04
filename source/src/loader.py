"""Feed loader for downloading, parsing, and loading threat intelligence feeds."""

import hashlib
import logging
import time
from datetime import datetime
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
        # Min prefix for CIDR expansion (default /20 = max 4096 IPs per CIDR)
        self.min_cidr_prefix = getattr(app_config.config.settings, 'min_cidr_prefix', 20)
    
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
        Load a single feed completely.
        
        Args:
            feed_config: Feed configuration
        
        Returns:
            FeedLoadResult with success status and statistics
        """
        start_time = time.time()
        feed_name = feed_config.name
        
        logger.info(f"Starting load for feed '{feed_name}'")
        
        try:
            # Download feed
            success, error_msg, feed_data = await self.download_feed(feed_config)
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
            
            # Parse and classify entries
            ips, domains, walkable_domains = self.parse_and_classify_entries(
                feed_data['content'], feed_name
            )
            
            # Stage to Redis
            if not self.stage_entries_to_redis(feed_name, ips, domains, walkable_domains):
                error_msg = "Failed to stage entries to Redis"
                dummy_stats = LoadStats(
                    entries_added=0,
                    entries_removed=0,
                    entries_unchanged=0,
                    entry_count_ips=len(ips),
                    entry_count_domains=len(domains),
                    load_duration_seconds=time.time() - start_time,
                    file_hash=feed_data['file_hash']
                )
                self.update_feed_metadata(feed_config, dummy_stats, error_msg)
                self.update_metrics(feed_name, dummy_stats, False)
                return FeedLoadResult(False, error_msg)
            
            # Calculate delta
            entries_added, entries_removed, entries_unchanged = self.calculate_delta(
                feed_name, set(ips), set(domains), set(walkable_domains)
            )
            
            # Atomic swap from staging to live
            redis_client.swap_staging_to_live(feed_name)
            
            # Create load statistics
            stats = LoadStats(
                entries_added=entries_added,
                entries_removed=entries_removed,
                entries_unchanged=entries_unchanged,
                entry_count_ips=len(ips),
                entry_count_domains=len(domains),
                load_duration_seconds=time.time() - start_time,
                file_hash=feed_data['file_hash'],
                last_modified=feed_data['headers'].get('last-modified'),
                etag=feed_data['headers'].get('etag')
            )
            
            # Update metadata and metrics
            self.update_feed_metadata(feed_config, stats)
            self.update_metrics(feed_name, stats, True)
            
            logger.info(f"Successfully loaded feed '{feed_name}': "
                       f"{len(ips)} IPs, {len(domains)} domains ({len(walkable_domains)} walkable), "
                       f"+{entries_added}/-{entries_removed} delta, "
                       f"{stats.load_duration_seconds:.1f}s")
            
            return FeedLoadResult(True, None, stats)
            
        except Exception as e:
            error_msg = f"Unexpected error during feed load: {e}"
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
    
    async def load_all_feeds(self, rebuild_global_sets: bool = True) -> Dict[str, FeedLoadResult]:
        """
        Load all enabled feeds.
        
        Args:
            rebuild_global_sets: Whether to rebuild global union sets after loading
        
        Returns:
            Dictionary of feed_name -> FeedLoadResult
        """
        results = {}
        enabled_feeds = app_config.enabled_feeds
        
        logger.info(f"Loading {len(enabled_feeds)} enabled feeds")
        
        for feed_config in enabled_feeds:
            result = await self.load_feed(feed_config)
            results[feed_config.name] = result
        
        if rebuild_global_sets:
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
