"""ThreatBridge - Redis client with connection management."""

import logging
import time
from typing import Dict, List, Optional, Set, Union

import redis
from redis.connection import ConnectionPool
from redis.exceptions import ConnectionError, RedisError

from .config import app_config

logger = logging.getLogger(__name__)


class RedisClient:
    """Redis client with retry logic and helper methods for TI operations."""
    
    def __init__(self):
        self._pool: Optional[ConnectionPool] = None
        self._redis: Optional[redis.Redis] = None
        self._connect()
    
    def _connect(self) -> None:
        """Establish Redis connection with connection pool."""
        try:
            self._pool = ConnectionPool(
                host=app_config.redis_host,
                port=app_config.redis_port,
                db=app_config.redis_db,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30,
                max_connections=20
            )
            self._redis = redis.Redis(connection_pool=self._pool)
            
            # Test connection
            self._redis.ping()
            logger.info(f"Connected to Redis at {app_config.redis_host}:{app_config.redis_port}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def is_connected(self) -> bool:
        """Check if Redis connection is healthy."""
        try:
            if self._redis is None:
                return False
            self._redis.ping()
            return True
        except Exception:
            return False
    
    def ping(self) -> bool:
        """Ping Redis server."""
        try:
            if self._redis is None:
                return False
            self._redis.ping()
            return True
        except Exception as e:
            logger.warning(f"Redis ping failed: {e}")
            return False
    
    def _execute_with_retry(self, operation, *args, **kwargs):
        """Execute Redis operation with retry logic."""
        max_retries = 3
        retry_delay = 1.0
        
        for attempt in range(max_retries):
            try:
                if self._redis is None:
                    self._connect()
                return operation(*args, **kwargs)
                
            except ConnectionError as e:
                logger.warning(f"Redis connection error (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                    try:
                        self._connect()
                    except Exception:
                        pass
                else:
                    raise
            except RedisError as e:
                logger.error(f"Redis operation error: {e}")
                raise
    
    # SET operations
    def sadd(self, key: str, *values) -> int:
        """Add members to a set."""
        return self._execute_with_retry(self._redis.sadd, key, *values)
    
    def sismember(self, key: str, value: str) -> bool:
        """Check if value is member of set."""
        return self._execute_with_retry(self._redis.sismember, key, value)
    
    def smembers(self, key: str) -> Set[str]:
        """Get all members of a set."""
        return self._execute_with_retry(self._redis.smembers, key)
    
    def scard(self, key: str) -> int:
        """Get cardinality (size) of set."""
        return self._execute_with_retry(self._redis.scard, key)
    
    def sunionstore(self, dest: str, *keys: str) -> int:
        """Store union of sets in destination key."""
        return self._execute_with_retry(self._redis.sunionstore, dest, *keys)
    
    def delete_set(self, key: str) -> int:
        """Delete a set."""
        return self._execute_with_retry(self._redis.delete, key)
    
    # HASH operations
    def hset(self, key: str, mapping: Dict[str, Union[str, int, float]]) -> int:
        """Set hash fields."""
        return self._execute_with_retry(self._redis.hset, key, mapping=mapping)
    
    def hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field value."""
        return self._execute_with_retry(self._redis.hget, key, field)
    
    def hgetall(self, key: str) -> Dict[str, str]:
        """Get all hash fields and values."""
        return self._execute_with_retry(self._redis.hgetall, key)
    
    def hdel(self, key: str, *fields: str) -> int:
        """Delete hash fields."""
        return self._execute_with_retry(self._redis.hdel, key, *fields)
    
    def hexists(self, key: str, field: str) -> bool:
        """Check if hash field exists."""
        return self._execute_with_retry(self._redis.hexists, key, field)
    
    # Key operations
    def rename(self, src: str, dest: str) -> bool:
        """Atomically rename key."""
        return self._execute_with_retry(self._redis.rename, src, dest)
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self._execute_with_retry(self._redis.exists, key) > 0
    
    def delete(self, *keys: str) -> int:
        """Delete keys."""
        return self._execute_with_retry(self._redis.delete, *keys)
    
    def set_with_ttl(self, key: str, value: str, ttl_seconds: int) -> bool:
        """Set string value with TTL."""
        return self._execute_with_retry(self._redis.setex, key, ttl_seconds, value)
    
    def get(self, key: str) -> Optional[str]:
        """Get string value."""
        return self._execute_with_retry(self._redis.get, key)
    
    def ttl(self, key: str) -> int:
        """Get TTL of key."""
        return self._execute_with_retry(self._redis.ttl, key)
    
    # TI-specific helper methods
    def get_feed_ips(self, feed_name: str) -> Set[str]:
        """Get all IPs for a feed."""
        key = f"ti:feed:{feed_name}:ips"
        return self.smembers(key)
    
    def get_feed_domains(self, feed_name: str) -> Set[str]:
        """Get all domains for a feed."""
        key = f"ti:feed:{feed_name}:domains"
        return self.smembers(key)
    
    def get_feed_walkable_domains(self, feed_name: str) -> Set[str]:
        """Get walkable domains for a feed."""
        key = f"ti:feed:{feed_name}:domains:walkable"
        return self.smembers(key)
    
    def add_feed_ips(self, feed_name: str, ips: List[str], staging: bool = False) -> int:
        """Add IPs to feed set."""
        suffix = ":new" if staging else ""
        key = f"ti:feed:{feed_name}:ips{suffix}"
        if ips:
            return self.sadd(key, *ips)
        return 0
    
    def add_feed_domains(self, feed_name: str, domains: List[str], staging: bool = False) -> int:
        """Add domains to feed set."""
        suffix = ":new" if staging else ""
        key = f"ti:feed:{feed_name}:domains{suffix}"
        if domains:
            return self.sadd(key, *domains)
        return 0
    
    def add_feed_walkable_domains(self, feed_name: str, domains: List[str], staging: bool = False) -> int:
        """Add walkable domains to feed set."""
        suffix = ":new" if staging else ""
        key = f"ti:feed:{feed_name}:domains:walkable{suffix}"
        if domains:
            return self.sadd(key, *domains)
        return 0
    
    def swap_staging_to_live(self, feed_name: str) -> None:
        """Atomically swap staging keys to live keys."""
        staging_keys = [
            f"ti:feed:{feed_name}:ips:new",
            f"ti:feed:{feed_name}:domains:new", 
            f"ti:feed:{feed_name}:domains:walkable:new"
        ]
        live_keys = [
            f"ti:feed:{feed_name}:ips",
            f"ti:feed:{feed_name}:domains",
            f"ti:feed:{feed_name}:domains:walkable"
        ]
        
        # Delete old live keys first
        self.delete(*live_keys)
        
        # Rename staging to live
        for staging_key, live_key in zip(staging_keys, live_keys):
            if self.exists(staging_key):
                self.rename(staging_key, live_key)
    
    def rebuild_global_sets(self, feed_names: List[str]) -> None:
        """Rebuild global union sets from all feed sets."""
        if not feed_names:
            return
        
        # Rebuild global IP set
        ip_keys = [f"ti:feed:{name}:ips" for name in feed_names]
        existing_ip_keys = [key for key in ip_keys if self.exists(key)]
        if existing_ip_keys:
            self.sunionstore("ti:all:ips", *existing_ip_keys)
        else:
            self.delete("ti:all:ips")
        
        # Rebuild global domain set
        domain_keys = [f"ti:feed:{name}:domains" for name in feed_names]
        existing_domain_keys = [key for key in domain_keys if self.exists(key)]
        if existing_domain_keys:
            self.sunionstore("ti:all:domains", *existing_domain_keys)
        else:
            self.delete("ti:all:domains")
        
        # Rebuild global walkable domain set
        walkable_keys = [f"ti:feed:{name}:domains:walkable" for name in feed_names]
        existing_walkable_keys = [key for key in walkable_keys if self.exists(key)]
        if existing_walkable_keys:
            self.sunionstore("ti:all:domains:walkable", *existing_walkable_keys)
        else:
            self.delete("ti:all:domains:walkable")
    
    def check_ip_membership(self, ip: str) -> bool:
        """Check if IP exists in global IP set."""
        return self.sismember("ti:all:ips", ip)
    
    def check_domain_membership(self, domain: str) -> bool:
        """Check if domain exists in global domain set."""
        return self.sismember("ti:all:domains", domain)
    
    def check_walkable_domain_membership(self, domain: str) -> bool:
        """Check if domain exists in global walkable domain set."""
        return self.sismember("ti:all:domains:walkable", domain)
    
    def find_matching_feeds_for_ip(self, ip: str, feed_names: List[str]) -> List[str]:
        """Find which feeds contain the given IP."""
        matching_feeds = []
        for feed_name in feed_names:
            key = f"ti:feed:{feed_name}:ips"
            if self.sismember(key, ip):
                matching_feeds.append(feed_name)
        return matching_feeds
    
    def find_matching_feeds_for_domain(self, domain: str, feed_names: List[str]) -> List[str]:
        """Find which feeds contain the given domain (exact match)."""
        matching_feeds = []
        for feed_name in feed_names:
            key = f"ti:feed:{feed_name}:domains"
            if self.sismember(key, domain):
                matching_feeds.append(feed_name)
        return matching_feeds
    
    def find_matching_feeds_for_walkable_domain(self, domain: str, feed_names: List[str]) -> List[str]:
        """Find which feeds contain the given walkable domain."""
        matching_feeds = []
        for feed_name in feed_names:
            key = f"ti:feed:{feed_name}:domains:walkable"
            if self.sismember(key, domain):
                matching_feeds.append(feed_name)
        return matching_feeds
    
    def get_feed_metadata(self, feed_name: str) -> Dict[str, str]:
        """Get feed metadata hash."""
        key = f"ti:feed:{feed_name}:meta"
        return self.hgetall(key)
    
    def set_feed_metadata(self, feed_name: str, metadata: Dict[str, Union[str, int, float]]) -> int:
        """Set feed metadata hash."""
        key = f"ti:feed:{feed_name}:meta"
        return self.hset(key, metadata)
    
    def register_feed(self, feed_name: str) -> int:
        """Add feed to registry set."""
        return self.sadd("ti:feeds", feed_name)
    
    def get_registered_feeds(self) -> Set[str]:
        """Get all registered feed names."""
        return self.smembers("ti:feeds")
    
    def set_refresh_rate_limit(self, feed_name: str, ttl_seconds: int = 900) -> bool:
        """Set rate limit for feed refresh (default 15 minutes)."""
        key = f"ti:ratelimit:refresh:{feed_name}"
        timestamp = str(int(time.time()))
        return self.set_with_ttl(key, timestamp, ttl_seconds)
    
    def check_refresh_rate_limit(self, feed_name: str) -> Optional[int]:
        """Check refresh rate limit TTL remaining (None if not rate limited)."""
        key = f"ti:ratelimit:refresh:{feed_name}"
        ttl = self.ttl(key)
        return ttl if ttl > 0 else None


# Global Redis client instance
redis_client = RedisClient()
