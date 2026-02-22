"""
Configuration loader for secimport.

Reads a YAML config file declaring data sources, outputs, and
enrichment settings. Supports ``${ENV_VAR}`` substitution in
credential values.

Example config::

    sources:
      - name: qualys_prod
        connector: qualys
        base_url: https://qualysapi.qualys.com
        auth_type: basic
        credentials:
          username: ${QUALYS_USER}
          password: ${QUALYS_PASS}

      - name: crowdstrike_edr
        connector: crowdstrike_falcon
        base_url: https://api.crowdstrike.com
        auth_type: oauth2
        credentials:
          client_id: ${CS_ID}
          client_secret: ${CS_SECRET}

    outputs:
      - type: json
        path: ./output/enriched.json

      - type: csv
        path: ./output/assets.csv

    enrichment:
      deduplicate: true
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_ENV_PATTERN = re.compile(r"\$\{(\w+)}")


def _substitute_env(value: Any) -> Any:
    """Recursively substitute ``${VAR}`` with environment variable values."""
    if isinstance(value, str):
        def _replacer(m: re.Match) -> str:
            env_val = os.environ.get(m.group(1), "")
            return env_val
        return _ENV_PATTERN.sub(_replacer, value)
    if isinstance(value, dict):
        return {k: _substitute_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_env(v) for v in value]
    return value


class SourceConfig(BaseModel):
    """Configuration for a single data source."""

    name: str = Field(..., description="Unique name for this source instance")
    connector: str = Field(..., description="Connector name (e.g. 'qualys', 'crowdstrike_falcon')")
    base_url: str = Field(..., description="Base URL for the API")
    auth_type: str = Field("api_key", description="Auth type: basic, api_key, oauth2, token")
    credentials: Dict[str, str] = Field(default_factory=dict)
    verify_ssl: bool = True
    timeout: int = 30
    max_retries: int = 3
    options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Connector-specific options",
    )


class OutputConfig(BaseModel):
    """Configuration for a single output sink."""

    type: str = Field(..., description="Output type: json, csv, webhook, stdout")
    path: Optional[str] = Field(None, description="File path for file-based outputs")
    url: Optional[str] = Field(None, description="URL for webhook output")
    options: Dict[str, Any] = Field(default_factory=dict)


class EnrichmentConfig(BaseModel):
    """Configuration for the enrichment engine."""

    deduplicate: bool = Field(True, description="Run deduplication after ingestion")
    gap_sources: List[List[str]] = Field(
        default_factory=list,
        description="Pairs of sources to compare for gap analysis",
    )


class SecimportConfig(BaseModel):
    """
    Top-level configuration model.

    Loaded from a YAML file via ``load_config()``.
    """

    sources: List[SourceConfig] = Field(default_factory=list)
    outputs: List[OutputConfig] = Field(default_factory=list)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)


def load_config(path: str | Path) -> SecimportConfig:
    """
    Load and validate a secimport YAML config file.

    Environment variables in ``${VAR}`` format are substituted
    in credential values before validation.

    Args:
        path: Path to the YAML config file.

    Returns:
        A validated ``SecimportConfig`` instance.

    Raises:
        FileNotFoundError: If the config file doesn't exist.
        ImportError: If PyYAML is not installed.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ImportError(
            "PyYAML is required for config loading. Install with: pip install pyyaml"
        ) from exc

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = yaml.safe_load(path.read_text())
    if raw is None:
        raw = {}

    substituted = _substitute_env(raw)
    return SecimportConfig.model_validate(substituted)
