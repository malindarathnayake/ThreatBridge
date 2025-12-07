"""ThreatBridge - Configuration management."""

import os
import re
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, validator


class FeedConfig(BaseModel):
    """Configuration for a single threat intelligence feed."""
    
    model_config = ConfigDict(extra='forbid')
    
    name: str = Field(..., description="Feed name (used as Redis key prefix)")
    description: str = Field(..., description="Human readable description")
    url: str = Field(..., description="Feed URL (may contain env var references)")
    risk: str = Field(..., pattern="^(high|medium|low)$", description="Risk level")
    enabled: bool = Field(default=True, description="Whether feed is active")
    refresh_minutes: Optional[int] = Field(default=None, gt=0, description="Per-feed refresh interval (overrides global)")
    
    def get_resolved_url(self) -> str:
        """Resolve environment variable references in URL."""
        # Pattern: "from env var: VARIABLE_NAME"
        env_pattern = r"from env var:\s*([A-Z_]+)"
        match = re.search(env_pattern, self.url)
        
        if match:
            env_var = match.group(1)
            env_value = os.getenv(env_var)
            if not env_value:
                raise ValueError(f"Environment variable {env_var} not set for feed {self.name}")
            return env_value
        
        return self.url


class SettingsConfig(BaseModel):
    """Global settings configuration."""
    
    model_config = ConfigDict(extra='forbid')
    
    reload_interval_minutes: int = Field(default=60, gt=0, description="Feed reload interval")
    download_timeout_seconds: int = Field(default=300, gt=0, description="HTTP download timeout")
    max_entry_length: int = Field(default=253, gt=0, description="Maximum entry length (DNS limit)")
    min_cidr_prefix: int = Field(default=20, ge=8, le=32, description="Min CIDR prefix to expand (/20=4096 IPs max)")
    batch_size: int = Field(default=10000, gt=0, description="Lines to process in each batch for streaming feeds")
    ipinfo_token: Optional[str] = Field(default=None, description="IPInfo API token for web UI enrichment")


class Config(BaseModel):
    """Complete configuration structure."""
    
    model_config = ConfigDict(extra='forbid')
    
    feeds: List[FeedConfig] = Field(..., min_length=1, description="List of feed configurations")
    settings: SettingsConfig = Field(default_factory=SettingsConfig, description="Global settings")
    
    @validator('feeds')
    def validate_unique_names(cls, feeds):
        """Ensure feed names are unique."""
        names = [feed.name for feed in feeds]
        if len(names) != len(set(names)):
            raise ValueError("Feed names must be unique")
        return feeds


class AppConfig:
    """Application configuration loader."""
    
    def __init__(self):
        # Load environment variables
        self.redis_host = os.getenv("REDIS_HOST", "redis")
        self.redis_port = int(os.getenv("REDIS_PORT", "6379"))
        self.redis_db = int(os.getenv("REDIS_DB", "0"))
        
        self.api_port = int(os.getenv("API_PORT", "8000"))
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        
        self.feeds_config_path = os.getenv("FEEDS_CONFIG", "/config/feeds.yml")
        
        # Load feeds configuration
        self._config: Optional[Config] = None
        self.load_feeds_config()
        
        # IPInfo API for web UI enrichment (env var overrides yaml setting)
        self.ipinfo_token = os.getenv("IPINFO_TOKEN") or self.config.settings.ipinfo_token or ""
    
    def load_feeds_config(self) -> None:
        """Load and validate feeds configuration from YAML."""
        config_path = Path(self.feeds_config_path)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Feeds configuration not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            self._config = Config(**config_data)
            
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in feeds config: {e}")
        except Exception as e:
            raise ValueError(f"Invalid feeds configuration: {e}")
    
    @property
    def config(self) -> Config:
        """Get the current configuration."""
        if self._config is None:
            raise RuntimeError("Configuration not loaded")
        return self._config
    
    @property
    def enabled_feeds(self) -> List[FeedConfig]:
        """Get only enabled feeds."""
        return [feed for feed in self.config.feeds if feed.enabled]
    
    def get_feed_by_name(self, name: str) -> Optional[FeedConfig]:
        """Get feed configuration by name."""
        for feed in self.config.feeds:
            if feed.name == name:
                return feed
        return None
    
    def reload_config(self) -> None:
        """Reload configuration from disk."""
        self.load_feeds_config()


# Global configuration instance
app_config = AppConfig()
