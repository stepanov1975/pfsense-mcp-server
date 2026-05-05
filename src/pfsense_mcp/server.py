"""Read-only MCP server entrypoint for pfSense WebGUI inspection tools."""

from __future__ import annotations

from dataclasses import asdict
from typing import Callable, Protocol
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from pfsense_mcp.config import PfSenseConfig, load_config
from pfsense_mcp.webgui import PfSenseWebGuiClient


class PfSenseClient(Protocol):
    """Read-only pfSense client behavior required by MCP tool handlers."""

    authenticated: bool

    def login(self) -> None:
        """Authenticate the client session."""

    def get_arp_table(self) -> list[object]:
        """Return read-only ARP entries."""

    def get_dhcp_leases(self) -> list[object]:
        """Return read-only DHCP leases."""


ConfigLoader = Callable[[], PfSenseConfig]
ClientFactory = Callable[[PfSenseConfig], PfSenseClient]


class PfSenseToolHandlers:
    """Read-only pfSense MCP tool handler collection."""

    def __init__(
        self,
        *,
        config_loader: ConfigLoader | None = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self._config_loader = config_loader or load_config
        self._client_factory = client_factory or PfSenseWebGuiClient

    def check_webgui_login(self) -> dict[str, object]:
        """Return safe pfSense WebGUI login status metadata without secret values."""
        config: PfSenseConfig | None = None
        try:
            config = self._config_loader()
            client = self._client_factory(config)
            client.login()
            return {
                "reachable": True,
                "authenticated": client.authenticated,
                "base_url_host": _base_url_host(config),
                "read_only": config.read_only,
            }
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return {
                "reachable": False,
                "authenticated": False,
                "base_url_host": _base_url_host(config),
                "read_only": config.read_only if config else None,
                "error_type": exc.__class__.__name__,
            }

    def get_arp_table(self) -> list[dict[str, object]] | dict[str, object]:
        """Return JSON-serializable read-only ARP table entries."""
        try:
            config = self._config_loader()
            client = self._client_factory(config)
            return [_entry_dict(entry) for entry in client.get_arp_table()]
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _safe_error(exc)

    def get_dhcp_leases(self) -> list[dict[str, object]] | dict[str, object]:
        """Return JSON-serializable read-only DHCP lease entries."""
        try:
            config = self._config_loader()
            client = self._client_factory(config)
            return [_entry_dict(lease) for lease in client.get_dhcp_leases()]
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _safe_error(exc)


def create_mcp_server(*, handlers: PfSenseToolHandlers | None = None) -> FastMCP:
    """Create the stdio-capable FastMCP server with read-only pfSense tools."""
    tool_handlers = handlers or PfSenseToolHandlers()
    server = FastMCP(
        "pfsense-mcp-server",
        instructions="Read-only pfSense WebGUI inspection tools. No mutation tools are exposed.",
    )

    @server.tool(name="pfsense_check_webgui_login")
    def pfsense_check_webgui_login() -> dict[str, object]:
        """Check pfSense WebGUI reachability/authentication without returning secrets."""
        return tool_handlers.check_webgui_login()

    @server.tool(name="pfsense_get_arp_table")
    def pfsense_get_arp_table() -> list[dict[str, object]] | dict[str, object]:
        """Return the read-only pfSense ARP table."""
        return tool_handlers.get_arp_table()

    @server.tool(name="pfsense_get_dhcp_leases")
    def pfsense_get_dhcp_leases() -> list[dict[str, object]] | dict[str, object]:
        """Return read-only pfSense DHCP leases."""
        return tool_handlers.get_dhcp_leases()

    return server


def main() -> None:
    """Run the pfSense MCP server over stdio."""
    create_mcp_server().run(transport="stdio")


def _base_url_host(config: PfSenseConfig | None) -> str | None:
    if config is None:
        return None
    return urlparse(config.base_url).hostname


def _safe_error(exc: Exception) -> dict[str, object]:
    return {"error_type": exc.__class__.__name__}


def _entry_dict(entry: object) -> dict[str, object]:
    return asdict(entry)


if __name__ == "__main__":
    main()
