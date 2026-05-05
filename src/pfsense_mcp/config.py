"""Configuration loading for the read-only pfSense MCP server."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
from urllib.parse import urlparse


REDACTED_VALUE = "[REDACTED]"


class ConfigError(ValueError):
    """Raised when local pfSense MCP configuration is missing or unsafe."""


@dataclass(frozen=True)
class PfSenseConfig:
    """Runtime configuration for authenticated pfSense WebGUI access."""

    base_url: str
    username: str
    password: str = field(repr=False)
    read_only: bool = True
    verify_tls: bool = True
    timeout_seconds: float = 15.0
    max_response_bytes: int = 2_000_000

    def __repr__(self) -> str:
        return (
            "PfSenseConfig("
            f"base_url={self.base_url!r}, "
            f"username={self.username!r}, "
            f"password={REDACTED_VALUE!r}, "
            f"read_only={self.read_only!r}, "
            f"verify_tls={self.verify_tls!r}, "
            f"timeout_seconds={self.timeout_seconds!r}, "
            f"max_response_bytes={self.max_response_bytes!r})"
        )


def load_config(
    env_path: str | Path | None = None, *, require_read_only: bool = True, require_https: bool = True
) -> PfSenseConfig:
    """Load pfSense MCP settings from a dotenv-style local file."""
    resolved_env_path = Path(env_path or os.environ.get("PFSENSE_MCP_ENV_PATH", ".env"))
    values = _read_env_file(resolved_env_path)
    missing_keys = [
        key
        for key in ("PFSENSE_BASE_URL", "PFSENSE_USERNAME", "PFSENSE_PASSWORD")
        if not values.get(key)
    ]
    if missing_keys:
        raise ConfigError(f"Missing required configuration values: {', '.join(missing_keys)}")

    read_only = _parse_bool(values.get("PFSENSE_MCP_READ_ONLY", "true"), "PFSENSE_MCP_READ_ONLY")
    if require_read_only and not read_only:
        raise ConfigError("PFSENSE_MCP_READ_ONLY must be true for the read-only MCP server")

    base_url = _validate_base_url(values["PFSENSE_BASE_URL"], require_https=require_https)
    verify_tls = _parse_bool(values.get("PFSENSE_VERIFY_TLS", "true"), "PFSENSE_VERIFY_TLS")
    timeout_seconds = _parse_positive_float(
        values.get("PFSENSE_TIMEOUT_SECONDS", "15.0"), "PFSENSE_TIMEOUT_SECONDS"
    )
    max_response_bytes = _parse_positive_int(
        values.get("PFSENSE_MAX_RESPONSE_BYTES", "2000000"), "PFSENSE_MAX_RESPONSE_BYTES"
    )

    return PfSenseConfig(
        base_url=base_url,
        username=values["PFSENSE_USERNAME"],
        password=values["PFSENSE_PASSWORD"],
        read_only=read_only,
        verify_tls=verify_tls,
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
    )


def _validate_base_url(base_url: str, *, require_https: bool) -> str:
    normalized = base_url.strip().rstrip("/")
    parsed = urlparse(normalized)
    if not parsed.scheme or not parsed.hostname:
        raise ConfigError("PFSENSE_BASE_URL must be a valid URL with scheme and host")
    try:
        parsed.port
    except ValueError as exc:
        raise ConfigError("PFSENSE_BASE_URL must include a valid port when one is specified") from exc
    if "@" in parsed.netloc or parsed.username or parsed.password:
        raise ConfigError("PFSENSE_BASE_URL must be an origin URL without user info")
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        raise ConfigError("PFSENSE_BASE_URL must be an origin URL without path, query, or fragment")
    if require_https and parsed.scheme != "https":
        raise ConfigError("PFSENSE_BASE_URL must use HTTPS unless explicitly allowed")
    return normalized


def _read_env_file(env_path: Path) -> dict[str, str]:
    if not env_path.exists():
        raise ConfigError(f"Configuration file not found: {env_path}")

    values: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = _strip_optional_quotes(value.strip())
    return values


def _strip_optional_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_bool(value: str, key: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{key} must be a boolean value")


def _parse_positive_float(value: str, key: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a positive finite number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise ConfigError(f"{key} must be a positive finite number")
    return parsed


def _parse_positive_int(value: str, key: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a positive integer") from exc
    if parsed <= 0:
        raise ConfigError(f"{key} must be a positive integer")
    return parsed
