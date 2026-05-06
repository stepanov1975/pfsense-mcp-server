"""Tests for read-only passive troubleshooting helpers."""  # pylint: disable=duplicate-code

import pytest

from pfsense_mcp.arp import ArpEntry
from pfsense_mcp.dhcp import DhcpLease
from pfsense_mcp.firewall_inspection import FirewallAliasEntry, FirewallLogEntry, FirewallRuleEntry
from pfsense_mcp.firewall_states import FirewallStateEntry
from pfsense_mcp.troubleshooting import build_health_report, diagnose_host, normalize_troubleshoot_ip


def _arp(ip_address: str = "192.0.2.10") -> ArpEntry:
    return ArpEntry(
        ip_address=ip_address,
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="fixture-host",
        interface="lan",
        expires="permanent",
        entry_type="ethernet",
        permanent=True,
    )


def _lease(ip_address: str = "192.0.2.10") -> DhcpLease:
    return DhcpLease(
        ip_address=ip_address,
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="fixture-host",
        starts="2026/05/05 10:00:00",
        ends="2026/05/05 12:00:00",
        online=True,
        lease_type="active",
        description="fixture lease",
    )


def _state(ip_address: str = "192.0.2.10") -> FirewallStateEntry:
    return FirewallStateEntry(
        interface="LAN",
        protocol="tcp",
        source=f"{ip_address}:35898",
        destination="198.51.100.20:443",
        state="ESTABLISHED:ESTABLISHED",
        packets="4 / 4",
        bytes="372 KiB / 537 KiB",
        original_source=None,
        original_destination=None,
        ip_addresses=(ip_address, "198.51.100.20"),
    )


def _log(
    *,
    action: str = "block",
    source_ip: str = "198.51.100.25",
    source_port: str = "55523",
    destination_ip: str = "192.0.2.10",
    destination_port: str = "443",
) -> FirewallLogEntry:
    return FirewallLogEntry(
        action=action,
        time="May 6 17:08:57",
        interface="WAN",
        rule="Default deny",
        source=f"{source_ip}:{source_port}",
        destination=f"{destination_ip}:{destination_port}",
        protocol="TCP:S",
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        ip_addresses=(source_ip, destination_ip),
    )


def _alias() -> FirewallAliasEntry:
    return FirewallAliasEntry(
        name="trusted_hosts",
        alias_type="Host(s)",
        values=("192.0.2.10", "fixture-host"),
        description="Trusted hosts",
    )


def _rule(
    enabled: bool | None = True,
    *,
    destination: str = "trusted_hosts",
    protocol: str = "IPv4 TCP",
    source_port: str = "*",
    destination_port: str = "443",
) -> FirewallRuleEntry:
    return FirewallRuleEntry(
        index=0,
        interface="wan",
        enabled=enabled,
        states="0/184 B",
        protocol=protocol,
        source="any",
        source_port=source_port,
        destination=destination,
        destination_port=destination_port,
        gateway="*",
        queue="none",
        schedule=None,
        description="Allow HTTPS to fixture host",
    )


def test_normalize_troubleshoot_ip_rejects_invalid_values() -> None:
    with pytest.raises(ValueError, match="single valid IPv4"):
        normalize_troubleshoot_ip("not-an-ip")


def test_normalize_troubleshoot_ip_rejects_ipv6_until_passive_ipv6_evidence_exists() -> None:
    with pytest.raises(ValueError, match="single valid IPv4"):
        normalize_troubleshoot_ip("2001:db8::10")


def test_diagnose_host_combines_passive_arp_dhcp_state_log_alias_and_rule_evidence() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[_log(), _log(action="pass", destination_port="80")],
        firewall_aliases=[_alias()],
        firewall_rules=[_rule()],
        destination_port="443",
        protocol="tcp",
    )

    assert result["ip_address"] == "192.0.2.10"
    assert result["status"] == "blocked"
    assert result["checks"]["arp"]["present"] is True
    assert result["checks"]["dhcp"]["lease_found"] is True
    assert result["checks"]["firewall_states"]["active_state_count"] == 1
    assert result["checks"]["firewall_logs"]["blocked_count"] == 1
    assert result["checks"]["aliases"]["matching_aliases"] == ["trusted_hosts"]
    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 1
    assert "Recent block/reject firewall log entries match this host" in result["issues"]


def test_diagnose_host_uses_exact_ip_matches_and_reports_missing_passive_evidence() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp("192.0.2.100")],
        dhcp_leases=[_lease("192.0.2.100")],
        firewall_states=[_state("192.0.2.100")],
        firewall_logs=[_log(destination_ip="192.0.2.100")],
        firewall_aliases=[_alias()],
        firewall_rules=[_rule(destination="192.0.2.100")],
    )

    assert result["status"] == "warning"
    assert result["checks"]["arp"]["present"] is False
    assert result["checks"]["dhcp"]["lease_found"] is False
    assert result["checks"]["firewall_states"]["active_state_count"] == 0
    assert result["checks"]["firewall_logs"]["blocked_count"] == 0
    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 0
    assert "No exact ARP entry was found" in result["issues"]
    assert "No active firewall states were found" in result["issues"]


def test_diagnose_host_matches_firewall_rule_targets_by_exact_tokens() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[],
        firewall_aliases=[
            FirewallAliasEntry(
                name="web",
                alias_type="Host(s)",
                values=("192.0.2.10",),
                description="fixture alias",
            )
        ],
        firewall_rules=[_rule(destination="webservers"), _rule(destination="web")],
        destination_port="443",
        protocol="tcp",
    )

    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 1
    assert result["checks"]["firewall_rules"]["candidate_rules"][0]["destination"] == "web"


def test_diagnose_host_destination_port_filters_use_destination_not_source_port() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[_log(source_port="443", destination_port="80")],
        firewall_aliases=[_alias()],
        firewall_rules=[_rule(source_port="443", destination_port="80")],
        destination_port="443",
        protocol="tcp",
    )

    assert result["checks"]["firewall_logs"]["matching_count"] == 0
    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 0


def test_diagnose_host_treats_rule_any_destination_port_as_wildcard() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[],
        firewall_aliases=[_alias()],
        firewall_rules=[_rule(destination_port="*")],
        destination_port="443",
        protocol="tcp",
    )

    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 1


def test_diagnose_host_treats_rule_any_protocol_as_wildcard() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[],
        firewall_aliases=[_alias()],
        firewall_rules=[_rule(protocol="IPv4 *")],
        destination_port="443",
        protocol="tcp",
    )

    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 1


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_diagnose_host_matches_combined_tcp_udp_rule_protocol(protocol: str) -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[],
        firewall_aliases=[_alias()],
        firewall_rules=[_rule(protocol="IPv4 TCP/UDP")],
        destination_port="443",
        protocol=protocol,
    )

    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 1


def test_diagnose_host_matches_destination_port_alias_values() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[],
        firewall_aliases=[
            _alias(),
            FirewallAliasEntry(
                name="web_ports",
                alias_type="Port(s)",
                values=("80", "443"),
                description="fixture port alias",
            ),
        ],
        firewall_rules=[_rule(destination_port="web_ports")],
        destination_port="443",
        protocol="tcp",
    )

    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 1


def test_diagnose_host_matches_destination_port_ranges() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[],
        firewall_aliases=[_alias()],
        firewall_rules=[_rule(destination_port="440-445")],
        destination_port="443",
        protocol="tcp",
    )

    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 1


def test_diagnose_host_matches_alias_network_values() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[],
        firewall_aliases=[
            FirewallAliasEntry(
                name="trusted_net",
                alias_type="Network(s)",
                values=("192.0.2.0/24",),
                description="fixture network alias",
            )
        ],
        firewall_rules=[_rule(destination="trusted_net")],
        destination_port="443",
        protocol="tcp",
    )

    assert result["checks"]["aliases"]["matching_aliases"] == ["trusted_net"]
    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 1


def test_diagnose_host_treats_rule_any_targets_as_wildcards() -> None:
    result = diagnose_host(
        "192.0.2.10",
        arp_entries=[_arp()],
        dhcp_leases=[_lease()],
        firewall_states=[_state()],
        firewall_logs=[],
        firewall_aliases=[],
        firewall_rules=[_rule(destination="any"), _rule(destination="*")],
        destination_port="443",
        protocol="tcp",
    )

    assert result["checks"]["firewall_rules"]["candidate_rule_count"] == 2


def test_build_health_report_summarizes_counts_and_findings_without_active_probes() -> None:
    report = build_health_report(
        arp_entries=[_arp()],
        dhcp_leases=[_lease(), _lease("192.0.2.11")],
        firewall_states=[_state()],
        firewall_logs=[_log(), _log(action="pass", destination_port="80")],
        firewall_aliases=[_alias()],
        firewall_rules=[_rule(), _rule(enabled=False)],
    )

    assert report["status"] == "warning"
    assert report["summary"] == {
        "arp_entries": 1,
        "dhcp_leases": 2,
        "online_dhcp_leases": 2,
        "active_firewall_states": 1,
        "recent_firewall_logs": 2,
        "blocked_or_rejected_logs": 1,
        "firewall_aliases": 1,
        "firewall_rules": 2,
        "disabled_firewall_rules": 1,
    }
    assert "Recent block/reject firewall log entries are present" in report["findings"]
    assert "Disabled firewall rules are present" in report["findings"]
    assert "ping" in report["not_performed_active_checks"]
