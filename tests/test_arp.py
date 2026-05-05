"""Tests for read-only pfSense ARP table parsing."""

import pytest

from support import FakeStatusPageTransport, sample_config, status_table_html
from pfsense_mcp.arp import ArpEntry, ArpTableParseError, parse_arp_table
from pfsense_mcp.webgui import PfSenseWebGuiClient


def arp_html() -> str:
    return status_table_html(
        ["IP address", "MAC address", "Hostname", "Interface", "Expires", "Type"],
        [
            [
                '<a href="diag_ping.php?host=192.0.2.10">192.0.2.10</a>',
                "00:11:22:33:44:55",
                "printer&amp;office",
                "LAN",
                "1180",
                "ethernet",
            ],
            ["192.0.2.1", "aa:bb:cc:dd:ee:ff", "&nbsp;", "WAN", "permanent", "ethernet"],
        ],
    )


def test_parse_arp_table_returns_empty_list_for_valid_empty_table() -> None:
    html = """
    <table>
      <thead><tr><th>IP address</th><th>MAC address</th><th>Interface</th></tr></thead>
      <tbody></tbody>
    </table>
    """

    assert parse_arp_table(html) == []


def test_parse_arp_table_raises_when_no_arp_table_is_present() -> None:
    with pytest.raises(ArpTableParseError, match="ARP table"):
        parse_arp_table("<table><tr><th>Unrelated</th></tr><tr><td>ignore me</td></tr></table>")


def test_parse_arp_table_extracts_pfsense_rows() -> None:
    assert parse_arp_table(arp_html()) == [
        ArpEntry(
            ip_address="192.0.2.10",
            mac_address="00:11:22:33:44:55",
            hostname="printer&office",
            interface="LAN",
            expires="1180",
            entry_type="ethernet",
            permanent=False,
        ),
        ArpEntry(
            ip_address="192.0.2.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname=None,
            interface="WAN",
            expires="permanent",
            entry_type="ethernet",
            permanent=True,
        ),
    ]


def test_client_get_arp_table_fetches_status_arp_page() -> None:
    transport = FakeStatusPageTransport(arp_html())
    client = PfSenseWebGuiClient(sample_config(), transport=transport)

    entries = client.get_arp_table()

    assert entries[0].ip_address == "192.0.2.10"
    assert transport.get_urls == [
        "https://192.0.2.1:8843/",
        "https://192.0.2.1:8843/status_arp.php",
    ]
