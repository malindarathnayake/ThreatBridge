"""ThreatBridge - FastAPI application for threat intelligence lookups."""

import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .config import app_config
from .loader import load_all_feeds, load_single_feed
from .metrics import get_metrics_content, get_metrics_content_type, metrics_collector
from .models import (
    CheckResult, DomainCheckResult, ErrorResponse, FeedDetail, FeedInfo, 
    FeedsListResponse, HealthResponse, LoadHistoryEntry, RateLimitedResponse, RefreshResponse
)
from .psl_classifier import psl_classifier
from .redis_client import redis_client

# Configure logging
logging.basicConfig(
    level=getattr(logging, app_config.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="ThreatBridge",
    description="Lightweight Threat Intelligence Lookup API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Global scheduler instance
scheduler: Optional[AsyncIOScheduler] = None


def get_client_ip(request: Request) -> str:
    """Get client IP address from request."""
    # Check X-Forwarded-For header first (for reverse proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    # Check X-Real-IP header (nginx)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fall back to direct client IP
    if hasattr(request, 'client') and request.client:
        return request.client.host
    
    return "unknown"


def get_highest_risk_level(feed_names: List[str]) -> Optional[str]:
    """Get the highest risk level from a list of feed names."""
    if not feed_names:
        return None
    
    risk_priority = {"high": 3, "medium": 2, "low": 1}
    highest_risk = None
    highest_priority = 0
    
    for feed_name in feed_names:
        feed_config = app_config.get_feed_by_name(feed_name)
        if feed_config:
            priority = risk_priority.get(feed_config.risk, 0)
            if priority > highest_priority:
                highest_priority = priority
                highest_risk = feed_config.risk
    
    return highest_risk


def parse_feed_metadata_for_response(feed_name: str, metadata: Dict[str, str]) -> FeedDetail:
    """Parse Redis metadata into FeedDetail response model."""
    # Parse timestamps
    last_loaded = None
    last_error_time = None
    
    if metadata.get('last_loaded'):
        try:
            last_loaded = datetime.fromisoformat(metadata['last_loaded'].replace('Z', '+00:00'))
        except ValueError:
            pass
    
    if metadata.get('last_error_time'):
        try:
            last_error_time = datetime.fromisoformat(metadata['last_error_time'].replace('Z', '+00:00'))
        except ValueError:
            pass
    
    # Parse numeric fields
    entry_count_ips = int(metadata.get('entry_count_ips', '0') or '0')
    entry_count_domains = int(metadata.get('entry_count_domains', '0') or '0')
    entries_added = int(metadata.get('entries_added', '0') or '0')
    entries_removed = int(metadata.get('entries_removed', '0') or '0')
    
    load_duration_seconds = None
    if metadata.get('load_duration_seconds'):
        try:
            load_duration_seconds = float(metadata['load_duration_seconds'])
        except ValueError:
            pass
    
    # Create load history (for now, just show last load)
    load_history = []
    if last_loaded and load_duration_seconds is not None:
        load_history.append(LoadHistoryEntry(
            timestamp=last_loaded,
            entries_added=entries_added,
            entries_removed=entries_removed,
            duration_seconds=load_duration_seconds
        ))
    
    return FeedDetail(
        name=feed_name,
        description=metadata.get('description', ''),
        risk=metadata.get('risk', 'medium'),
        enabled=metadata.get('enabled', '').lower() in ('true', '1', 'yes'),
        last_loaded=last_loaded,
        last_modified=metadata.get('last_modified') or None,
        etag=metadata.get('etag') or None,
        file_hash=metadata.get('file_hash') or None,
        entry_count_ips=entry_count_ips,
        entry_count_domains=entry_count_domains,
        entries_added=entries_added,
        entries_removed=entries_removed,
        load_duration_seconds=load_duration_seconds,
        last_error=metadata.get('last_error') or None,
        last_error_time=last_error_time,
        load_history=load_history
    )


# API Endpoints

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    redis_connected = redis_client.ping()
    metrics_collector.set_redis_connection_status(redis_connected)
    
    return HealthResponse(
        status="healthy" if redis_connected else "unhealthy",
        redis_connected=redis_connected,
        timestamp=datetime.utcnow()
    )


@app.get("/check/ip", response_model=CheckResult)
async def check_ip(ip: str, request: Request):
    """Check if IP exists in threat intelligence feeds."""
    start_time = time.time()
    client_ip = get_client_ip(request)
    
    try:
        # Validate IP format
        normalized_ip = psl_classifier.normalize_entry(ip)
        if not psl_classifier.is_ip_address(normalized_ip):
            duration = time.time() - start_time
            metrics_collector.record_lookup_request("check_ip", "ip", "invalid", duration, client_ip)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address format: {ip}"
            )
        
        # Check membership
        found = redis_client.check_ip_membership(normalized_ip)
        
        # Find matching feeds
        matching_feeds = []
        risk = None
        
        if found:
            enabled_feed_names = [feed.name for feed in app_config.enabled_feeds]
            matching_feeds = redis_client.find_matching_feeds_for_ip(normalized_ip, enabled_feed_names)
            risk = get_highest_risk_level(matching_feeds)
        
        duration = time.time() - start_time
        result = "found" if found else "not_found"
        metrics_collector.record_lookup_request("check_ip", "ip", result, duration, client_ip)
        
        return CheckResult(
            found=found,
            query=ip,  # Return original query
            type="ip",
            feeds=matching_feeds,
            risk=risk
        )
        
    except HTTPException:
        raise
    except Exception as e:
        duration = time.time() - start_time
        metrics_collector.record_lookup_request("check_ip", "ip", "error", duration, client_ip)
        logger.error(f"Error in IP lookup for '{ip}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during IP lookup"
        )


@app.get("/check/domain", response_model=DomainCheckResult)
async def check_domain(domain: str, request: Request):
    """Check if domain exists in threat intelligence feeds with parent walking."""
    start_time = time.time()
    client_ip = get_client_ip(request)
    
    try:
        # Validate domain format
        normalized_domain = psl_classifier.normalize_entry(domain)
        if not psl_classifier.is_valid_domain(normalized_domain):
            duration = time.time() - start_time
            metrics_collector.record_lookup_request("check_domain", "domain", "invalid", duration, client_ip)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid domain format: {domain}"
            )
        
        # Check exact match first
        found = redis_client.check_domain_membership(normalized_domain)
        match_type = None
        matched_value = None
        matching_feeds = []
        risk = None
        
        if found:
            match_type = "exact"
            matched_value = normalized_domain
            enabled_feed_names = [feed.name for feed in app_config.enabled_feeds]
            matching_feeds = redis_client.find_matching_feeds_for_domain(normalized_domain, enabled_feed_names)
        else:
            # Try parent domain walk
            parent_domain = psl_classifier.get_parent_domain_for_lookup(normalized_domain)
            if parent_domain:
                parent_found = redis_client.check_walkable_domain_membership(parent_domain)
                if parent_found:
                    found = True
                    match_type = "parent"
                    matched_value = parent_domain
                    enabled_feed_names = [feed.name for feed in app_config.enabled_feeds]
                    matching_feeds = redis_client.find_matching_feeds_for_walkable_domain(parent_domain, enabled_feed_names)
        
        if found:
            risk = get_highest_risk_level(matching_feeds)
        
        duration = time.time() - start_time
        result = "found" if found else "not_found"
        metrics_collector.record_lookup_request("check_domain", "domain", result, duration, client_ip)
        
        return DomainCheckResult(
            found=found,
            query=domain,  # Return original query
            type="domain",
            feeds=matching_feeds,
            risk=risk,
            match_type=match_type,
            matched_value=matched_value
        )
        
    except HTTPException:
        raise
    except Exception as e:
        duration = time.time() - start_time
        metrics_collector.record_lookup_request("check_domain", "domain", "error", duration, client_ip)
        logger.error(f"Error in domain lookup for '{domain}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during domain lookup"
        )


@app.get("/feeds", response_model=FeedsListResponse)
async def list_feeds():
    """List all configured feeds with metadata."""
    feeds_info = []
    
    for feed_config in app_config.config.feeds:
        metadata = redis_client.get_feed_metadata(feed_config.name)
        
        if metadata:
            # Parse metadata
            last_loaded = None
            if metadata.get('last_loaded'):
                try:
                    last_loaded = datetime.fromisoformat(metadata['last_loaded'].replace('Z', '+00:00'))
                except ValueError:
                    pass
            
            entry_count_ips = int(metadata.get('entry_count_ips', '0') or '0')
            entry_count_domains = int(metadata.get('entry_count_domains', '0') or '0')
            entries_added = int(metadata.get('entries_added', '0') or '0')
            entries_removed = int(metadata.get('entries_removed', '0') or '0')
            
            feeds_info.append(FeedInfo(
                name=feed_config.name,
                description=feed_config.description,
                risk=feed_config.risk,
                enabled=feed_config.enabled,
                entry_count_ips=entry_count_ips,
                entry_count_domains=entry_count_domains,
                last_loaded=last_loaded,
                entries_added=entries_added,
                entries_removed=entries_removed,
                file_hash=metadata.get('file_hash')
            ))
        else:
            # Feed not loaded yet
            feeds_info.append(FeedInfo(
                name=feed_config.name,
                description=feed_config.description,
                risk=feed_config.risk,
                enabled=feed_config.enabled
            ))
    
    return FeedsListResponse(feeds=feeds_info)


@app.get("/feeds/{feed_name}", response_model=FeedDetail)
async def get_feed_detail(feed_name: str):
    """Get detailed information about a specific feed."""
    # Check if feed exists in configuration
    feed_config = app_config.get_feed_by_name(feed_name)
    if not feed_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed '{feed_name}' not found"
        )
    
    # Get metadata from Redis
    metadata = redis_client.get_feed_metadata(feed_name)
    
    if not metadata:
        # Feed exists in config but not loaded yet
        return FeedDetail(
            name=feed_name,
            description=feed_config.description,
            risk=feed_config.risk,
            enabled=feed_config.enabled
        )
    
    return parse_feed_metadata_for_response(feed_name, metadata)


@app.post("/feeds/{feed_name}/refresh")
async def refresh_feed(feed_name: str, request: Request):
    """Trigger manual refresh of a specific feed."""
    client_ip = get_client_ip(request)
    
    # Check if feed exists
    feed_config = app_config.get_feed_by_name(feed_name)
    if not feed_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed '{feed_name}' not found"
        )
    
    # Check rate limit
    rate_limit_ttl = redis_client.check_refresh_rate_limit(feed_name)
    if rate_limit_ttl:
        metrics_collector.record_refresh_request(feed_name, "rate_limited")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "rate_limited",
                "message": "Refresh allowed once per 15 minutes",
                "retry_after_seconds": rate_limit_ttl
            }
        )
    
    # Set rate limit
    redis_client.set_refresh_rate_limit(feed_name, 900)  # 15 minutes
    
    # Trigger async refresh
    asyncio.create_task(refresh_feed_task(feed_name))
    
    metrics_collector.record_refresh_request(feed_name, "accepted")
    
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "accepted",
            "message": f"Refresh started for feed: {feed_name}"
        }
    )


async def refresh_feed_task(feed_name: str):
    """Background task to refresh a single feed."""
    try:
        logger.info(f"Manual refresh triggered for feed '{feed_name}'")
        result = await load_single_feed(feed_name)
        
        if result.success:
            logger.info(f"Manual refresh completed successfully for feed '{feed_name}'")
        else:
            logger.error(f"Manual refresh failed for feed '{feed_name}': {result.error_message}")
            
    except Exception as e:
        logger.error(f"Error during manual refresh of feed '{feed_name}': {e}")


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=get_metrics_content(),
        media_type=get_metrics_content_type()
    )


# Static files and UI
app.mount("/static", StaticFiles(directory="src/static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def management_ui():
    """Serve management UI."""
    try:
        with open("src/static/index.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Management UI not found</h1><p>The static UI files are not available.</p>",
            status_code=404
        )


# Background scheduler functions
async def scheduled_feed_load():
    """Scheduled task to load all feeds."""
    try:
        logger.info("Starting scheduled feed load")
        results = await load_all_feeds()
        
        success_count = sum(1 for result in results.values() if result.success)
        total_count = len(results)
        
        logger.info(f"Scheduled feed load completed: {success_count}/{total_count} feeds successful")
        
    except Exception as e:
        logger.error(f"Error during scheduled feed load: {e}")


def start_scheduler():
    """Start the background scheduler."""
    global scheduler
    
    if scheduler is not None:
        logger.warning("Scheduler already started")
        return
    
    scheduler = AsyncIOScheduler()
    
    # Schedule feed loading
    reload_interval = app_config.config.settings.reload_interval_minutes
    logger.info(f"Scheduling feed loads every {reload_interval} minutes")
    
    scheduler.add_job(
        scheduled_feed_load,
        trigger=IntervalTrigger(minutes=reload_interval),
        id="feed_load",
        name="Load all feeds",
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Background scheduler started")


def stop_scheduler():
    """Stop the background scheduler."""
    global scheduler
    
    if scheduler is not None:
        scheduler.shutdown()
        scheduler = None
        logger.info("Background scheduler stopped")


# Application lifecycle events
@app.on_event("startup")
async def startup_event():
    """Application startup tasks."""
    logger.info("Starting ThreatBridge")
    
    # Test Redis connection
    if not redis_client.ping():
        logger.error("Failed to connect to Redis at startup")
        raise RuntimeError("Redis connection failed")
    
    logger.info("Redis connection established")
    
    # Initialize metrics for all configured feeds
    for feed_config in app_config.config.feeds:
        metrics_collector.initialize_feed_metrics(feed_config.name)
    
    # Start background scheduler
    start_scheduler()
    
    # Load feeds on startup (optional - could be disabled for faster startup)
    logger.info("Loading feeds on startup...")
    try:
        await scheduled_feed_load()
    except Exception as e:
        logger.error(f"Failed to load feeds on startup: {e}")
        # Continue anyway - feeds will be loaded by scheduler
    
    logger.info("ThreatBridge startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks."""
    logger.info("Shutting down ThreatBridge")
    
    # Stop scheduler
    stop_scheduler()
    
    logger.info("ThreatBridge shutdown complete")


# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Handle 404 errors."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"error": "not_found", "message": "The requested resource was not found"}
    )


@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "internal_server_error", "message": "An internal server error occurred"}
    )
