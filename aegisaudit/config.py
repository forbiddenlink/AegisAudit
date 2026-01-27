from typing import List, Optional, Dict, Any
from pathlib import Path
import yaml
from pydantic import BaseModel, HttpUrl, Field
from aegisaudit.policy import DEFAULT_POLICY

class ScopeConfig(BaseModel):
    allow: List[str] = Field(default_factory=list)

class TargetsConfig(BaseModel):
    urls: List[str] = Field(default_factory=list)
    urls_file: Optional[Path] = None
    sitemap: Optional[HttpUrl] = None

class LimitsConfig(BaseModel):
    rate_per_sec: float = 2.0
    timeout_sec: float = 10.0
    max_html_bytes: int = 200_000

class AegisConfig(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    targets: TargetsConfig = Field(default_factory=TargetsConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    policy: Dict[str, Any] = Field(default_factory=lambda: DEFAULT_POLICY)

def load_config(config_path: Optional[Path] = None) -> AegisConfig:
    """Load configuration from a YAML file or return defaults."""
    if not config_path or not config_path.exists():
        return AegisConfig()

    with open(config_path, "r") as f:
        data = yaml.safe_load(f) or {}

    return AegisConfig(**data)
