"""Tests for read-only pfSense ARP table parsing."""

import pytest

from support import dashboard_page, sample_config
from pfsense_mcp.arp import ArpEntry, ArpTableParseError, parse_arp_table
from pfsense_mcp.webgui import PfSenseWebGuiClient


class FakePageClientTransport:
    """Deterministic transport for testing ARP page retrieval."""

    def __init__(self) -> None:
        self.get_urls: list[str] = []
        self.posted_forms: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str) -> str:
        self.get_urls.append(url)
        if url.endswith("/"):
            return '<input name="__csrf_magic" value="sid:csrf-token,1700000000">'
        return arp_html()

    def post_form(self, url: str, data: dict[str, str]) -> str:
        self.posted_forms.append((url, data))
        return dashboard_page()


def arp_html() -> str:
    return """
    <html>
      <body>
        <table><thead><tr><th>Unrelated</th></tr></thead><tbody><tr><td>ignore me</td></tr></tbody></table>
        <table class="table table-striped">
          <thead>
            <tr>
              <th>IP address</th>
              <th>MAC address</th>
              <th>Hostname</th>
              <th>Interface</th>
              <th>Expires</th>
              <th>Type</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><a href="diag_ping.php?host=192.0.2.10">192.0.2.10</a></td>
              <td>00:11:22:33:44:55</td>
              <td>printer&amp;office</td>
              <td>LAN</td>
              <td>1180</td>
              <td>ethernet</td>
            </tr>
            <tr>
              <td>192.0.2.1</td>
              <td>aa:bb:cc:dd:ee:ff</td>
              <td>&nbsp;</td>
              <td>WAN</td>
              <td>permanent</td>
              <td>ethernet</td>
            </tr>
          </tbody>
        </table>
      </body>
    </html>
    """


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
    transport = FakePageClientTransport()
    client = PfSenseWebGuiClient(sample_config(), transport=transport)

    entries = client.get_arp_table()

    assert entries[0].ip_address == "192.0.2.10"
    assert transport.get_urls == [
        "https://192.0.2.1:8843/",
        "https://192.0.2.1:8843/status_arp.php",
    ]
