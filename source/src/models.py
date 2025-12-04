"""ThreatBridge - Pydantic models for requests and responses."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Health status")
    redis_connected: bool = Field(..., description="Redis connection status")
    timestamp: datetime = Field(..., description="Current timestamp")


class CheckResult(BaseModel):
    """Base result for IP/domain lookup."""
    found: bool = Field(..., description="Whether entry was found in feeds")
    query: str = Field(..., description="Original query value")
    type: str = Field(..., description="Query type: ip or domain")
    feeds: List[str] = Field(default_factory=list, description="List of feeds containing the entry")
    risk: Optional[str] = Field(None, description="Highest risk level: high, medium, low")


class DomainCheckResult(CheckResult):
    """Domain lookup result with parent matching info."""
    match_type: Optional[str] = Field(None, description="Match type: exact or parent")
    matched_value: Optional[str] = Field(None, description="The actual matched value (for parent matches)")


class LoadHistoryEntry(BaseModel):
    """Single load history entry."""
    timestamp: datetime = Field(..., description="Load timestamp")
    entries_added: int = Field(..., description="Entries added in this load")
    entries_removed: int = Field(..., description="Entries removed in this load")
    duration_seconds: float = Field(..., description="Load duration in seconds")


class FeedInfo(BaseModel):
    """Feed information for feeds list endpoint."""
    name: str = Field(..., description="Feed name")
    description: str = Field(..., description="Feed description")
    risk: str = Field(..., description="Risk level")
    enabled: bool = Field(..., description="Whether feed is enabled")
    entry_count_ips: int = Field(default=0, description="Number of IP entries")
    entry_count_domains: int = Field(default=0, description="Number of domain entries")
    last_loaded: Optional[datetime] = Field(None, description="Last successful load timestamp")
    entries_added: int = Field(default=0, description="Entries added in last load")
    entries_removed: int = Field(default=0, description="Entries removed in last load")
    file_hash: Optional[str] = Field(None, description="SHA256 hash of feed file")


class FeedDetail(BaseModel):
    """Detailed feed information for single feed endpoint."""
    name: str = Field(..., description="Feed name")
    description: str = Field(..., description="Feed description")
    risk: str = Field(..., description="Risk level")
    enabled: bool = Field(..., description="Whether feed is enabled")
    last_loaded: Optional[datetime] = Field(None, description="Last successful load timestamp")
    last_modified: Optional[str] = Field(None, description="HTTP Last-Modified header from feed")
    etag: Optional[str] = Field(None, description="HTTP ETag header from feed")
    file_hash: Optional[str] = Field(None, description="SHA256 hash of feed file")
    entry_count_ips: int = Field(default=0, description="Number of IP entries")
    entry_count_domains: int = Field(default=0, description="Number of domain entries")
    entries_added: int = Field(default=0, description="Entries added in last load")
    entries_removed: int = Field(default=0, description="Entries removed in last load")
    load_duration_seconds: Optional[float] = Field(None, description="Last load duration")
    last_error: Optional[str] = Field(None, description="Last error message")
    last_error_time: Optional[datetime] = Field(None, description="Last error timestamp")
    load_history: List[LoadHistoryEntry] = Field(default_factory=list, description="Recent load history")


class FeedsListResponse(BaseModel):
    """Response for feeds list endpoint."""
    feeds: List[FeedInfo] = Field(..., description="List of configured feeds")


class RefreshResponse(BaseModel):
    """Response for feed refresh endpoint."""
    status: str = Field(..., description="Response status")
    message: str = Field(..., description="Human readable message")


class RateLimitedResponse(BaseModel):
    """Response for rate limited requests."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    retry_after_seconds: int = Field(..., description="Seconds until retry allowed")


class ErrorResponse(BaseModel):
    """Generic error response."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")


class FeedMetadata(BaseModel):
    """Feed metadata stored in Redis."""
    description: str = Field(..., description="Feed description")
    risk: str = Field(..., description="Risk level")
    enabled: bool = Field(..., description="Whether feed is enabled")
    last_loaded: Optional[str] = Field(None, description="ISO timestamp of last load")
    last_modified: Optional[str] = Field(None, description="HTTP Last-Modified header")
    etag: Optional[str] = Field(None, description="HTTP ETag header")
    file_hash: Optional[str] = Field(None, description="SHA256 hash of feed file")
    entry_count_ips: int = Field(default=0, description="Number of IP entries")
    entry_count_domains: int = Field(default=0, description="Number of domain entries")
    entries_added: int = Field(default=0, description="Entries added in last load")
    entries_removed: int = Field(default=0, description="Entries removed in last load")
    load_duration_seconds: Optional[float] = Field(None, description="Load duration")
    last_error: Optional[str] = Field(None, description="Last error message")
    last_error_time: Optional[str] = Field(None, description="ISO timestamp of last error")

    def to_redis_dict(self) -> dict:
        """Convert to dictionary for Redis hash storage."""
        data = self.model_dump()
        # Convert None values to empty strings for Redis
        return {k: str(v) if v is not None else "" for k, v in data.items()}

    @classmethod
    def from_redis_dict(cls, data: dict) -> "FeedMetadata":
        """Create instance from Redis hash data."""
        # Convert empty strings back to None
        processed_data = {}
        for k, v in data.items():
            if v == "":
                processed_data[k] = None
            elif k in ["enabled"]:
                processed_data[k] = v.lower() in ("true", "1", "yes")
            elif k in ["entry_count_ips", "entry_count_domains", "entries_added", "entries_removed"]:
                processed_data[k] = int(v) if v else 0
            elif k == "load_duration_seconds":
                processed_data[k] = float(v) if v else None
            else:
                processed_data[k] = v
        
        return cls(**processed_data)


class LoadStats(BaseModel):
    """Statistics for a single feed load operation."""
    entries_added: int = Field(default=0, description="Entries added")
    entries_removed: int = Field(default=0, description="Entries removed")
    entries_unchanged: int = Field(default=0, description="Entries unchanged")
    entry_count_ips: int = Field(default=0, description="Total IP entries")
    entry_count_domains: int = Field(default=0, description="Total domain entries")
    load_duration_seconds: float = Field(..., description="Load duration")
    file_hash: str = Field(..., description="SHA256 hash of downloaded file")
    last_modified: Optional[str] = Field(None, description="HTTP Last-Modified header")
    etag: Optional[str] = Field(None, description="HTTP ETag header")
