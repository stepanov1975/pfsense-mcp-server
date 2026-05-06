"""Tests for read-only pfSense firewall state table parsing."""

import pytest

from pfsense_mcp.firewall_states import (
    FirewallStateParseError,
    parse_firewall_states,
)


STATE_TABLE_HTML = """
<table>
  <tr>
    <th>Interface</th>
    <th>Protocol</th>
    <th>Source (Original Source) -&gt; Destination (Original Destination)</th>
    <th>State</th>
    <th>Packets</th>
    <th>Bytes</th>
    <th></th>
  </tr>
  <tr>
    <td>LAN</td>
    <td>tcp</td>
    <td>192.0.2.10:35898 -&gt; 198.51.100.20:443</td>
    <td>ESTABLISHED:ESTABLISHED</td>
    <td>4.224K / 4.343K</td>
    <td>372 KiB / 537 KiB</td>
    <td><a href="diag_dump_states.php?killstate=1" title="Remove all state entries">kill</a></td>
  </tr>
  <tr>
    <td>WAN</td>
    <td>udp</td>
    <td>203.0.113.5:51820 (192.0.2.10:51820) -&gt; 203.0.113.10:40000</td>
    <td>MULTIPLE:SINGLE</td>
    <td>10 / 12</td>
    <td>1 KiB / 2 KiB</td>
    <td><a href="diag_dump_states.php?killstate=2" title="Remove all state entries">kill</a></td>
  </tr>
</table>
"""


def test_parse_firewall_states_returns_read_only_entries_without_action_links() -> None:
    states = parse_firewall_states(STATE_TABLE_HTML)

    assert states[0].interface == "LAN"
    assert states[0].protocol == "tcp"
    assert states[0].source == "192.0.2.10:35898"
    assert states[0].destination == "198.51.100.20:443"
    assert states[0].state == "ESTABLISHED:ESTABLISHED"
    assert states[0].packets == "4.224K / 4.343K"
    assert states[0].bytes == "372 KiB / 537 KiB"
    assert states[0].ip_addresses == ("192.0.2.10", "198.51.100.20")
    assert "killstate" not in repr(states)


def test_parse_firewall_states_keeps_original_nat_addresses_for_exact_matching() -> None:
    states = parse_firewall_states(STATE_TABLE_HTML)

    assert states[1].source == "203.0.113.5:51820"
    assert states[1].original_source == "192.0.2.10:51820"
    assert states[1].destination == "203.0.113.10:40000"
    assert states[1].ip_addresses == ("203.0.113.5", "192.0.2.10", "203.0.113.10")


def test_parse_firewall_states_exact_ip_filter_does_not_substring_match() -> None:
    html = STATE_TABLE_HTML + """
    <table>
      <tr>
        <th>Interface</th><th>Protocol</th>
        <th>Source (Original Source) -&gt; Destination (Original Destination)</th>
        <th>State</th><th>Packets</th><th>Bytes</th><th></th>
      </tr>
      <tr>
        <td>LAN</td><td>tcp</td><td>192.0.2.100:123 -&gt; 198.51.100.30:443</td>
        <td>ESTABLISHED:ESTABLISHED</td><td>1 / 1</td><td>1 KiB / 1 KiB</td><td></td>
      </tr>
    </table>
    """

    states = parse_firewall_states(html, ip_address="192.0.2.10")

    assert len(states) == 2
    assert all("192.0.2.100" not in state.ip_addresses for state in states)


def test_parse_firewall_states_rejects_invalid_ip_filter() -> None:
    with pytest.raises(FirewallStateParseError):
        parse_firewall_states(STATE_TABLE_HTML, ip_address="192.0.2.10; rm -rf /")


def test_parse_firewall_states_rejects_ipv6_filter_until_ipv6_state_extraction_exists() -> None:
    with pytest.raises(FirewallStateParseError, match="IPv4"):
        parse_firewall_states(STATE_TABLE_HTML, ip_address="2001:db8::1")


def test_parse_firewall_states_caps_and_floors_limit() -> None:
    row = """
      <tr>
        <td>LAN</td><td>tcp</td><td>192.0.2.10:123 -&gt; 198.51.100.20:443</td>
        <td>ESTABLISHED:ESTABLISHED</td><td>1 / 1</td><td>1 KiB / 1 KiB</td><td></td>
      </tr>
    """
    html = """
    <table>
      <tr><th>Interface</th><th>Protocol</th><th>Source -&gt; Destination</th><th>State</th><th>Packets</th><th>Bytes</th><th></th></tr>
    """ + row * 250 + "</table>"

    assert len(parse_firewall_states(html, limit=0)) == 1
    assert len(parse_firewall_states(html, limit=999)) == 200


def test_parse_firewall_states_missing_table_raises() -> None:
    with pytest.raises(FirewallStateParseError):
        parse_firewall_states("<table><tr><th>Unrelated</th></tr></table>")
