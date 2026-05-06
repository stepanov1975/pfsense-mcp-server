"""Read-only MCP server entrypoint for pfSense WebGUI inspection tools."""

from __future__ import annotations

from dataclasses import asdict
from typing import Callable, Protocol
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from pfsense_mcp.config import PfSenseConfig, load_config
from pfsense_mcp.webgui import PfSenseWebGuiClient


READ_ONLY_ANNOTATIONS = ToolAnnotations(readOnlyHint=True, destructiveHint=False)


class PfSenseClient(Protocol):
    """Read-only pfSense client behavior required by MCP tool handlers."""

    authenticated: bool

    def login(self) -> None:
        """Authenticate the client session."""

    def get_arp_table(self) -> list[object]:
        """Return read-only ARP entries."""

    def get_dhcp_leases(self) -> list[object]:
        """Return read-only DHCP leases."""

    def get_firewall_states(self, *, ip_address: str | None = None, limit: int = 200) -> list[object]:
        """Return read-only firewall state entries."""

    def get_firewall_logs(  # pylint: disable=too-many-arguments
        self,
        *,
        ip_address: str | None = None,
        action: str | None = None,
        interface: str | None = None,
        protocol: str | None = None,
        limit: int = 200,
    ) -> list[object]:
        """Return read-only firewall log entries."""

    def get_firewall_aliases(self) -> list[object]:
        """Return read-only firewall aliases."""

    def get_firewall_rules(self, *, interface: str | None = None) -> list[object]:
        """Return read-only firewall rules."""

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

    def get_firewall_states(
        self, *, ip_address: str | None = None, limit: int = 200
    ) -> list[dict[str, object]] | dict[str, object]:
        """Return JSON-serializable read-only firewall state entries."""
        try:
            config = self._config_loader()
            client = self._client_factory(config)
            return [
                _entry_dict(state)
                for state in client.get_firewall_states(ip_address=ip_address, limit=limit)
            ]
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _safe_error(exc)

    def get_firewall_logs(  # pylint: disable=too-many-arguments
        self,
        *,
        ip_address: str | None = None,
        action: str | None = None,
        interface: str | None = None,
        protocol: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, object]] | dict[str, object]:
        """Return JSON-serializable read-only firewall log entries."""
        try:
            config = self._config_loader()
            client = self._client_factory(config)
            return [
                _entry_dict(log)
                for log in client.get_firewall_logs(
                    ip_address=ip_address,
                    action=action,
                    interface=interface,
                    protocol=protocol,
                    limit=limit,
                )
            ]
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _safe_error(exc)

    def get_firewall_aliases(self) -> list[dict[str, object]] | dict[str, object]:
        """Return JSON-serializable read-only firewall aliases."""
        try:
            config = self._config_loader()
            client = self._client_factory(config)
            return [_entry_dict(alias) for alias in client.get_firewall_aliases()]
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _safe_error(exc)

    def get_firewall_rules(
        self, *, interface: str | None = None
    ) -> list[dict[str, object]] | dict[str, object]:
        """Return JSON-serializable read-only firewall rules."""
        try:
            config = self._config_loader()
            client = self._client_factory(config)
            return [_entry_dict(rule) for rule in client.get_firewall_rules(interface=interface)]
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _safe_error(exc)


def create_mcp_server(*, handlers: PfSenseToolHandlers | None = None) -> FastMCP:
    """Create the stdio-capable FastMCP server with read-only pfSense tools."""
    tool_handlers = handlers or PfSenseToolHandlers()
    server = FastMCP(
        "pfsense-mcp-server",
        instructions=(
            "Read-only pfSense WebGUI inspection tools. No mutation tools are exposed. "
            "Firewall state inspection uses the diagnostics page and strips state-kill actions."
        ),
    )

    @server.tool(name="pfsense_check_webgui_login", annotations=READ_ONLY_ANNOTATIONS)
    def pfsense_check_webgui_login() -> dict[str, object]:
        """Check pfSense WebGUI reachability/authentication without returning secrets."""
        return tool_handlers.check_webgui_login()

    @server.tool(name="pfsense_get_arp_table", annotations=READ_ONLY_ANNOTATIONS)
    def pfsense_get_arp_table() -> list[dict[str, object]] | dict[str, object]:
        """Return the read-only pfSense ARP table."""
        return tool_handlers.get_arp_table()

    @server.tool(name="pfsense_get_dhcp_leases", annotations=READ_ONLY_ANNOTATIONS)
    def pfsense_get_dhcp_leases() -> list[dict[str, object]] | dict[str, object]:
        """Return read-only pfSense DHCP leases."""
        return tool_handlers.get_dhcp_leases()

    @server.tool(name="pfsense_get_firewall_states", annotations=READ_ONLY_ANNOTATIONS)
    def pfsense_get_firewall_states(
        ip_address: str | None = None, limit: int = 200
    ) -> list[dict[str, object]] | dict[str, object]:
        """Return read-only active firewall states, optionally exact-filtered by IP address."""
        return tool_handlers.get_firewall_states(ip_address=ip_address, limit=limit)

    @server.tool(name="pfsense_get_firewall_logs", annotations=READ_ONLY_ANNOTATIONS)
    def pfsense_get_firewall_logs(
        ip_address: str | None = None,
        action: str | None = None,
        interface: str | None = None,
        protocol: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, object]] | dict[str, object]:
        """Return read-only firewall log entries, optionally filtered by exact IP/action/interface/protocol."""
        return tool_handlers.get_firewall_logs(
            ip_address=ip_address,
            action=action,
            interface=interface,
            protocol=protocol,
            limit=limit,
        )

    @server.tool(name="pfsense_get_firewall_aliases", annotations=READ_ONLY_ANNOTATIONS)
    def pfsense_get_firewall_aliases() -> list[dict[str, object]] | dict[str, object]:
        """Return read-only pfSense firewall aliases."""
        return tool_handlers.get_firewall_aliases()

    @server.tool(name="pfsense_get_firewall_rules", annotations=READ_ONLY_ANNOTATIONS)
    def pfsense_get_firewall_rules(
        interface: str | None = None,
    ) -> list[dict[str, object]] | dict[str, object]:
        """Return read-only pfSense firewall rules, optionally for one interface tab."""
        return tool_handlers.get_firewall_rules(interface=interface)

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
