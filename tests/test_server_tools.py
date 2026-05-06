"""Tests for read-only pfSense MCP server tool handlers."""

import asyncio

from support import LOGIN_FORM_VALUE, sample_config
from pfsense_mcp.arp import ArpEntry
from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.dhcp import DhcpLease
from pfsense_mcp.firewall_inspection import FirewallAliasEntry, FirewallLogEntry, FirewallRuleEntry
from pfsense_mcp.firewall_states import FirewallStateEntry
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

    def get_firewall_states(self, ip_address: str | None = None, limit: int = 200) -> list[FirewallStateEntry]:
        assert ip_address is None
        assert limit == 200
        return [
            FirewallStateEntry(
                interface="LAN",
                protocol="tcp",
                source="192.0.2.10:35898",
                destination="198.51.100.20:443",
                state="ESTABLISHED:ESTABLISHED",
                packets="4.224K / 4.343K",
                bytes="372 KiB / 537 KiB",
                original_source=None,
                original_destination=None,
                ip_addresses=("192.0.2.10", "198.51.100.20"),
            )
        ]

    def get_firewall_logs(  # pylint: disable=too-many-arguments
        self,
        *,
        ip_address: str | None = None,
        action: str | None = None,
        interface: str | None = None,
        protocol: str | None = None,
        limit: int = 200,
    ) -> list[FirewallLogEntry]:
        assert ip_address is None
        assert action is None
        assert interface is None
        assert protocol is None
        assert limit == 200
        return [
            FirewallLogEntry(
                action="block",
                time="May 6 17:08:57",
                interface="WAN",
                rule="Default deny",
                source="198.51.100.25:55523",
                destination="192.0.2.10:443",
                protocol="TCP:S",
                source_ip="198.51.100.25",
                source_port="55523",
                destination_ip="192.0.2.10",
                destination_port="443",
                ip_addresses=("198.51.100.25", "192.0.2.10"),
            )
        ]

    def get_firewall_aliases(self) -> list[FirewallAliasEntry]:
        return [
            FirewallAliasEntry(
                name="trusted_hosts",
                alias_type="Host(s)",
                values=("192.0.2.10",),
                description="Trusted hosts",
            )
        ]

    def get_firewall_rules(self, interface: str | None = None) -> list[FirewallRuleEntry]:
        assert interface is None
        return [
            FirewallRuleEntry(
                index=0,
                interface=None,
                enabled=True,
                states="0/184 B",
                protocol="IPv4 UDP",
                source="trusted_hosts",
                source_port="*",
                destination="WAN address",
                destination_port="52000",
                gateway="*",
                queue="none",
                schedule=None,
                description="Allow VPN",
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

class FailingFirewallStatesPfSenseClient(FakePfSenseClient):
    """Fake client that raises a secret-bearing firewall-state retrieval error."""

    def get_firewall_states(self, ip_address: str | None = None, limit: int = 200) -> list[FirewallStateEntry]:
        raise RuntimeError(f"state failed with {self.config.password} {ip_address} {limit}")


class FailingFirewallLogsPfSenseClient(FakePfSenseClient):
    """Fake client that raises a secret-bearing firewall-log retrieval error."""

    def get_firewall_logs(  # pylint: disable=too-many-arguments
        self,
        *,
        ip_address: str | None = None,
        action: str | None = None,
        interface: str | None = None,
        protocol: str | None = None,
        limit: int = 200,
    ) -> list[FirewallLogEntry]:
        raise RuntimeError(
            f"logs failed with {self.config.password} {ip_address} {action} {interface} {protocol} {limit}"
        )


class FailingFirewallAliasesPfSenseClient(FakePfSenseClient):
    """Fake client that raises a secret-bearing firewall-alias retrieval error."""

    def get_firewall_aliases(self) -> list[FirewallAliasEntry]:
        raise RuntimeError(f"aliases failed with {self.config.password}")


class FailingFirewallRulesPfSenseClient(FakePfSenseClient):
    """Fake client that raises a secret-bearing firewall-rule retrieval error."""

    def get_firewall_rules(self, interface: str | None = None) -> list[FirewallRuleEntry]:
        raise RuntimeError(f"rules failed with {self.config.password} {interface}")


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


def test_get_firewall_states_returns_json_serializable_entries() -> None:
    result = _handlers().get_firewall_states()

    assert result == [
        {
            "interface": "LAN",
            "protocol": "tcp",
            "source": "192.0.2.10:35898",
            "destination": "198.51.100.20:443",
            "state": "ESTABLISHED:ESTABLISHED",
            "packets": "4.224K / 4.343K",
            "bytes": "372 KiB / 537 KiB",
            "original_source": None,
            "original_destination": None,
            "ip_addresses": ("192.0.2.10", "198.51.100.20"),
        }
    ]


def test_get_firewall_states_forwards_exact_ip_filter_and_limit() -> None:
    class CapturingFirewallStatesClient(FakePfSenseClient):
        """Fake client that records firewall-state filter arguments."""

        captured: dict[str, object] = {}

        def get_firewall_states(
            self, ip_address: str | None = None, limit: int = 200
        ) -> list[FirewallStateEntry]:
            self.captured["ip_address"] = ip_address
            self.captured["limit"] = limit
            return []

    result = _handlers(CapturingFirewallStatesClient).get_firewall_states(
        ip_address="192.0.2.10", limit=25
    )

    assert result == []
    assert CapturingFirewallStatesClient.captured == {"ip_address": "192.0.2.10", "limit": 25}


def test_get_firewall_states_redacts_retrieval_errors() -> None:
    result = _handlers(FailingFirewallStatesPfSenseClient).get_firewall_states(ip_address="192.0.2.10")

    assert result == {"error_type": "RuntimeError"}
    assert LOGIN_FORM_VALUE not in repr(result)


def test_get_firewall_logs_returns_json_serializable_entries() -> None:
    result = _handlers().get_firewall_logs()

    assert result == [
        {
            "action": "block",
            "time": "May 6 17:08:57",
            "interface": "WAN",
            "rule": "Default deny",
            "source": "198.51.100.25:55523",
            "destination": "192.0.2.10:443",
            "protocol": "TCP:S",
            "source_ip": "198.51.100.25",
            "source_port": "55523",
            "destination_ip": "192.0.2.10",
            "destination_port": "443",
            "ip_addresses": ("198.51.100.25", "192.0.2.10"),
        }
    ]


def test_get_firewall_logs_forwards_filters_and_limit() -> None:
    class CapturingFirewallLogsClient(FakePfSenseClient):
        """Fake client that records firewall-log filter arguments."""

        captured: dict[str, object] = {}

        def get_firewall_logs(  # pylint: disable=too-many-arguments
            self,
            *,
            ip_address: str | None = None,
            action: str | None = None,
            interface: str | None = None,
            protocol: str | None = None,
            limit: int = 200,
        ) -> list[FirewallLogEntry]:
            self.captured["ip_address"] = ip_address
            self.captured["action"] = action
            self.captured["interface"] = interface
            self.captured["protocol"] = protocol
            self.captured["limit"] = limit
            return []

    result = _handlers(CapturingFirewallLogsClient).get_firewall_logs(
        ip_address="192.0.2.10", action="block", interface="wan", protocol="tcp", limit=25
    )

    assert result == []
    assert CapturingFirewallLogsClient.captured == {
        "ip_address": "192.0.2.10",
        "action": "block",
        "interface": "wan",
        "protocol": "tcp",
        "limit": 25,
    }


def test_get_firewall_logs_redacts_retrieval_errors() -> None:
    result = _handlers(FailingFirewallLogsPfSenseClient).get_firewall_logs(ip_address="192.0.2.10")

    assert result == {"error_type": "RuntimeError"}
    assert LOGIN_FORM_VALUE not in repr(result)


def test_get_firewall_aliases_returns_json_serializable_entries() -> None:
    result = _handlers().get_firewall_aliases()

    assert result == [
        {
            "name": "trusted_hosts",
            "alias_type": "Host(s)",
            "values": ("192.0.2.10",),
            "description": "Trusted hosts",
        }
    ]


def test_get_firewall_aliases_redacts_retrieval_errors() -> None:
    result = _handlers(FailingFirewallAliasesPfSenseClient).get_firewall_aliases()

    assert result == {"error_type": "RuntimeError"}
    assert LOGIN_FORM_VALUE not in repr(result)


def test_get_firewall_rules_returns_json_serializable_entries() -> None:
    result = _handlers().get_firewall_rules()

    assert result == [
        {
            "index": 0,
            "interface": None,
            "enabled": True,
            "states": "0/184 B",
            "protocol": "IPv4 UDP",
            "source": "trusted_hosts",
            "source_port": "*",
            "destination": "WAN address",
            "destination_port": "52000",
            "gateway": "*",
            "queue": "none",
            "schedule": None,
            "description": "Allow VPN",
        }
    ]


def test_get_firewall_rules_forwards_interface() -> None:
    class CapturingFirewallRulesClient(FakePfSenseClient):
        """Fake client that records firewall-rule interface arguments."""

        captured: dict[str, object] = {}

        def get_firewall_rules(self, interface: str | None = None) -> list[FirewallRuleEntry]:
            self.captured["interface"] = interface
            return []

    result = _handlers(CapturingFirewallRulesClient).get_firewall_rules(interface="wan")

    assert result == []
    assert CapturingFirewallRulesClient.captured == {"interface": "wan"}


def test_get_firewall_rules_redacts_retrieval_errors() -> None:
    result = _handlers(FailingFirewallRulesPfSenseClient).get_firewall_rules(interface="wan")

    assert result == {"error_type": "RuntimeError"}
    assert LOGIN_FORM_VALUE not in repr(result)


def test_create_mcp_server_registers_read_only_tools() -> None:
    server = create_mcp_server(handlers=_handlers())

    tools = asyncio.run(server.list_tools())

    assert [tool.name for tool in tools] == [
        "pfsense_check_webgui_login",
        "pfsense_get_arp_table",
        "pfsense_get_dhcp_leases",
        "pfsense_get_firewall_states",
        "pfsense_get_firewall_logs",
        "pfsense_get_firewall_aliases",
        "pfsense_get_firewall_rules",
    ]
    assert all(tool.annotations.readOnlyHint is True for tool in tools)
    assert all(tool.annotations.destructiveHint is False for tool in tools)
