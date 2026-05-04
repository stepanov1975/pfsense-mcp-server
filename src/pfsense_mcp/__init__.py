"""Read-only pfSense MCP server package."""

__all__ = ["ConfigError", "PfSenseConfig", "load_config"]

from pfsense_mcp.config import ConfigError, PfSenseConfig, load_config
