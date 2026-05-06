"""Tests for read-only pfSense firewall logs, aliases, and rules inspection parsing."""

import pytest

from pfsense_mcp.firewall_inspection import (
    FirewallAliasParseError,
    FirewallLogParseError,
    FirewallRuleParseError,
    normalize_firewall_log_filter_ip,
    parse_firewall_aliases,
    parse_firewall_logs,
    parse_firewall_rules,
)


FIREWALL_LOG_HTML = """
<table>
  <tr><th>Action</th><th>Time</th><th>Interface</th><th>Rule</th><th>Source</th><th>Destination</th><th>Protocol</th></tr>
  <tr>
    <td><i title="block"></i></td><td>May 6 17:08:57</td><td>WAN</td><td>Default deny rule IPv4</td>
    <td>198.51.100.25:55523</td><td>192.0.2.10:443</td><td>TCP:S</td>
  </tr>
  <tr>
    <td><i title="pass"></i></td><td>May 6 17:08:58</td><td>LAN</td><td>Allow DNS</td>
    <td>[2001:db8::10]:5353</td><td>[2001:db8::20]:5353</td><td>UDP</td>
  </tr>
</table>
"""


FIREWALL_ALIASES_HTML = """
<table>
  <tr><th>Name</th><th>Type</th><th>Values</th><th>Description</th><th>Actions</th></tr>
  <tr>
    <td>cloudflare_ips</td><td>URL Table (IPs)</td><td>https://www.cloudflare.com/ips-v4</td>
    <td>Cloudflare allowlist</td><td><a title="Delete alias" href="firewall_aliases_edit.php?id=0">delete</a></td>
  </tr>
  <tr>
    <td>trusted_hosts</td><td>Host(s)</td><td>192.0.2.10 198.51.100.20</td>
    <td>Trusted hosts</td><td><a title="Edit alias" href="firewall_aliases_edit.php?id=1">edit</a></td>
  </tr>
</table>
"""


FIREWALL_RULES_HTML = """
<table>
  <tr>
    <th></th><th></th><th>States</th><th>Protocol</th><th>Source</th><th>Port</th><th>Destination</th>
    <th>Port</th><th>Gateway</th><th>Queue</th><th>Schedule</th><th>Description</th><th>Actions</th>
  </tr>
  <tr>
    <td></td><td></td><td>0/5 KiB</td><td>*</td><td>RFC 1918 networks</td><td>*</td><td>*</td>
    <td>*</td><td>*</td><td>*</td><td></td><td>Block private networks</td><td><a title="Settings" href="firewall_rules_edit.php?id=0">settings</a></td>
  </tr>
  <tr>
    <td></td><td><i title="click to toggle enabled/disabled status"></i></td><td>4/184 B</td><td>IPv4 UDP</td><td>trusted_hosts</td><td>*</td><td>WAN address</td>
    <td>52000</td><td>*</td><td>none</td><td></td><td>Allow VPN</td>
    <td><a title="Edit" href="firewall_rules_edit.php?id=1">edit</a><a title="Disable" href="firewall_rules.php?act=toggle">disable</a><a title="Delete this rule" href="firewall_rules.php?act=del">delete</a></td>
  </tr>
  <tr>
    <td></td><td><i title="click to toggle enabled/disabled status"></i></td><td>0/0 B</td><td>IPv4 TCP</td><td>*</td><td>*</td><td>LAN address</td>
    <td>22</td><td>*</td><td>none</td><td></td><td>Disabled SSH</td>
    <td><a title="Edit" href="firewall_rules_edit.php?id=2">edit</a><a title="Enable" href="firewall_rules.php?act=toggle">enable</a></td>
  </tr>
</table>
"""


def test_parse_firewall_logs_returns_read_only_entries_with_endpoint_metadata() -> None:
    logs = parse_firewall_logs(FIREWALL_LOG_HTML)

    assert logs[0].action == "block"
    assert logs[0].time == "May 6 17:08:57"
    assert logs[0].interface == "WAN"
    assert logs[0].rule == "Default deny rule IPv4"
    assert logs[0].source == "198.51.100.25:55523"
    assert logs[0].source_ip == "198.51.100.25"
    assert logs[0].source_port == "55523"
    assert logs[0].destination_ip == "192.0.2.10"
    assert logs[0].destination_port == "443"
    assert logs[1].source_ip == "2001:db8::10"
    assert logs[1].destination_ip == "2001:db8::20"
    assert "href" not in repr(logs)


def test_parse_firewall_logs_filters_by_exact_ip_action_interface_protocol_and_limit() -> None:
    logs = parse_firewall_logs(
        FIREWALL_LOG_HTML,
        ip_address="192.0.2.10",
        action="block",
        interface="wan",
        protocol="tcp",
        limit=999,
    )

    assert len(logs) == 1
    assert logs[0].destination_ip == "192.0.2.10"
    assert logs[0].protocol == "TCP:S"


def test_parse_firewall_logs_protocol_filter_matches_protocol_prefix_case_insensitively() -> None:
    logs = parse_firewall_logs(FIREWALL_LOG_HTML, protocol="udp")

    assert len(logs) == 1
    assert logs[0].source_ip == "2001:db8::10"


def test_firewall_log_filter_rejects_invalid_ip_before_network_use() -> None:
    with pytest.raises(FirewallLogParseError):
        normalize_firewall_log_filter_ip("192.0.2.10; rm -rf /")


def test_parse_firewall_logs_missing_table_raises() -> None:
    with pytest.raises(FirewallLogParseError):
        parse_firewall_logs("<table><tr><th>Unrelated</th></tr></table>")


def test_parse_firewall_aliases_returns_values_without_action_links() -> None:
    aliases = parse_firewall_aliases(FIREWALL_ALIASES_HTML)

    assert aliases[0].name == "cloudflare_ips"
    assert aliases[0].alias_type == "URL Table (IPs)"
    assert aliases[0].values == ("https://www.cloudflare.com/ips-v4",)
    assert aliases[0].description == "Cloudflare allowlist"
    assert aliases[1].values == ("192.0.2.10", "198.51.100.20")
    assert "firewall_aliases_edit" not in repr(aliases)
    assert "Delete alias" not in repr(aliases)


def test_parse_firewall_aliases_missing_table_raises() -> None:
    with pytest.raises(FirewallAliasParseError):
        parse_firewall_aliases("<table><tr><th>Name</th><th>Something Else</th></tr></table>")


def test_parse_firewall_aliases_handles_type_column_at_index_zero() -> None:
    aliases = parse_firewall_aliases(
        """
        <table>
          <tr><th>Type</th><th>Name</th><th>Values</th><th>Description</th></tr>
          <tr><td>Host(s)</td><td>trusted_hosts</td><td>192.0.2.10</td><td>Trusted hosts</td></tr>
        </table>
        """
    )

    assert len(aliases) == 1
    assert aliases[0].name == "trusted_hosts"
    assert aliases[0].alias_type == "Host(s)"


def test_parse_firewall_rules_returns_ordered_rules_without_mutating_actions() -> None:
    rules = parse_firewall_rules(FIREWALL_RULES_HTML, interface="wan")

    assert rules[0].index == 0
    assert rules[0].interface == "wan"
    assert rules[0].states == "0/5 KiB"
    assert rules[0].protocol == "*"
    assert rules[0].source == "RFC 1918 networks"
    assert rules[0].source_port == "*"
    assert rules[0].destination == "*"
    assert rules[0].destination_port == "*"
    assert rules[0].description == "Block private networks"
    assert rules[0].enabled is None
    assert rules[1].enabled is True
    assert rules[2].enabled is False
    assert "Delete this rule" not in repr(rules)
    assert "firewall_rules.php?act" not in repr(rules)


def test_parse_firewall_rules_missing_table_raises() -> None:
    with pytest.raises(FirewallRuleParseError):
        parse_firewall_rules("<table><tr><th>Protocol</th><th>Only</th></tr></table>")


def test_parse_firewall_rules_skips_separator_rows() -> None:
    rules = parse_firewall_rules(
        """
        <table>
          <tr><th>States</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Actions</th></tr>
          <tr><td colspan="5">WAN rules</td></tr>
          <tr><td>1/2 KiB</td><td>IPv4 TCP</td><td>trusted_hosts</td><td>WAN address</td><td></td></tr>
        </table>
        """
    )

    assert len(rules) == 1
    assert rules[0].protocol == "IPv4 TCP"
    assert rules[0].source == "trusted_hosts"


def test_parse_firewall_rules_infers_enabled_from_descriptive_action_titles() -> None:
    rules = parse_firewall_rules(
        """
        <table>
          <tr><th>States</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Actions</th></tr>
          <tr>
            <td>1/2 KiB</td><td>IPv4 TCP</td><td>trusted_hosts</td><td>WAN address</td>
            <td><a title="Disable this rule" href="firewall_rules.php?act=toggle">disable</a></td>
          </tr>
          <tr>
            <td>0/0 B</td><td>IPv4 TCP</td><td>*</td><td>LAN address</td>
            <td><a title="Enable this rule" href="firewall_rules.php?act=toggle">enable</a></td>
          </tr>
        </table>
        """
    )

    assert rules[0].enabled is True
    assert rules[1].enabled is False
