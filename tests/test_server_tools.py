"""Tests for read-only pfSense MCP server tool handlers."""

import asyncio

from support import LOGIN_FORM_VALUE, sample_config
from pfsense_mcp.arp import ArpEntry
from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.dhcp import DhcpLease
from pfsense_mcp.server import PfSenseToolHandlers, create_mcp_server


class FakePfSenseClient:
    """Fake WebGUI client for MCP handler tests."""

    def __init__(self, config: PfSenseConfig) -> None:
        self.config = config
        self.authenticated = False
        self.login_calls = 0

    def login(self) -> None:
        self.login_calls += 1
        self.authenticated = True

    def get_arp_table(self) -> list[ArpEntry]:
        return [
            ArpEntry(
                ip_address="192.0.2.10",
                mac_address="aa:bb:cc:dd:ee:ff",
                hostname="fixture-host",
                interface="lan",
                expires="permanent",
                entry_type="ethernet",
                permanent=True,
            )
        ]

    def get_dhcp_leases(self) -> list[DhcpLease]:
        return [
            DhcpLease(
                ip_address="192.0.2.20",
                mac_address="00:11:22:33:44:55",
                hostname="lease-host",
                starts="2026/05/05 10:00:00",
                ends="2026/05/05 12:00:00",
                online=True,
                lease_type="active",
                description="fixture lease",
            )
        ]


class FailingPfSenseClient(FakePfSenseClient):
    """Fake client that raises a secret-bearing error to verify redaction boundaries."""

    def login(self) -> None:
        raise RuntimeError(f"login failed with {self.config.password}")


class FailingArpPfSenseClient(FakePfSenseClient):
    """Fake client that raises a secret-bearing ARP retrieval error."""

    def get_arp_table(self) -> list[ArpEntry]:
        raise RuntimeError(f"ARP failed with {self.config.password}")


class FailingDhcpPfSenseClient(FakePfSenseClient):
    """Fake client that raises a secret-bearing DHCP retrieval error."""

    def get_dhcp_leases(self) -> list[DhcpLease]:
        raise RuntimeError(f"DHCP failed with {self.config.password}")


def _handlers(client_type: type[FakePfSenseClient] = FakePfSenseClient) -> PfSenseToolHandlers:
    return PfSenseToolHandlers(
        config_loader=sample_config,
        client_factory=client_type,
    )


def test_check_webgui_login_returns_status_metadata_without_secrets() -> None:
    result = _handlers().check_webgui_login()

    assert result == {
        "reachable": True,
        "authenticated": True,
        "base_url_host": "192.0.2.1",
        "read_only": True,
    }
    assert LOGIN_FORM_VALUE not in repr(result)


def test_check_webgui_login_redacts_exception_messages() -> None:
    result = _handlers(FailingPfSenseClient).check_webgui_login()

    assert result == {
        "reachable": False,
        "authenticated": False,
        "base_url_host": "192.0.2.1",
        "read_only": True,
        "error_type": "RuntimeError",
    }
    assert LOGIN_FORM_VALUE not in repr(result)


def test_get_arp_table_returns_json_serializable_entries() -> None:
    result = _handlers().get_arp_table()

    assert result == [
        {
            "ip_address": "192.0.2.10",
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "hostname": "fixture-host",
            "interface": "lan",
            "expires": "permanent",
            "entry_type": "ethernet",
            "permanent": True,
        }
    ]


def test_get_arp_table_redacts_retrieval_errors() -> None:
    result = _handlers(FailingArpPfSenseClient).get_arp_table()

    assert result == {"error_type": "RuntimeError"}
    assert LOGIN_FORM_VALUE not in repr(result)


def test_get_dhcp_leases_returns_json_serializable_leases() -> None:
    result = _handlers().get_dhcp_leases()

    assert result == [
        {
            "ip_address": "192.0.2.20",
            "mac_address": "00:11:22:33:44:55",
            "hostname": "lease-host",
            "starts": "2026/05/05 10:00:00",
            "ends": "2026/05/05 12:00:00",
            "online": True,
            "lease_type": "active",
            "description": "fixture lease",
        }
    ]


def test_get_dhcp_leases_redacts_retrieval_errors() -> None:
    result = _handlers(FailingDhcpPfSenseClient).get_dhcp_leases()

    assert result == {"error_type": "RuntimeError"}
    assert LOGIN_FORM_VALUE not in repr(result)


def test_create_mcp_server_registers_read_only_tools() -> None:
    server = create_mcp_server(handlers=_handlers())

    tools = asyncio.run(server.list_tools())

    assert [tool.name for tool in tools] == [
        "pfsense_check_webgui_login",
        "pfsense_get_arp_table",
        "pfsense_get_dhcp_leases",
    ]
