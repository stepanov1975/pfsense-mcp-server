"""Tests for read-only pfSense DHCP lease parsing."""

import pytest

from support import FakeStatusPageTransport, sample_config, status_table_html
from pfsense_mcp.dhcp import DhcpLease, DhcpLeaseParseError, parse_dhcp_leases
from pfsense_mcp.webgui import PfSenseWebGuiClient


def dhcp_leases_html() -> str:
    return status_table_html(
        ["IP address", "MAC address", "Hostname", "Starts", "Ends", "Online", "Lease type", "Description"],
        [
            [
                '<a href="diag_ping.php?host=192.0.2.50">192.0.2.50</a>',
                "00:11:22:33:44:55",
                "sensor&amp;kitchen",
                "2026/05/05 09:00:00",
                "2026/05/05 11:00:00",
                "online",
                "active",
                "Kitchen temperature sensor",
            ],
            ["192.0.2.51", "aa:bb:cc:dd:ee:ff", "&nbsp;", "n/a", "never", "offline", "static", "&nbsp;"],
        ],
    )


def test_parse_dhcp_leases_returns_empty_list_for_valid_empty_table() -> None:
    html = """
    <table>
      <thead><tr><th>IP address</th><th>MAC address</th><th>Hostname</th></tr></thead>
      <tbody></tbody>
    </table>
    """

    assert parse_dhcp_leases(html) == []


def test_parse_dhcp_leases_raises_when_no_lease_table_is_present() -> None:
    with pytest.raises(DhcpLeaseParseError, match="DHCP lease"):
        parse_dhcp_leases("<table><tr><th>Unrelated</th></tr><tr><td>ignore me</td></tr></table>")


def test_parse_dhcp_leases_extracts_real_pfsense_table_shape() -> None:
    html = status_table_html(
        ["", "IP Address", "MAC Address", "Hostname", "Description", "Start", "End", "Actions"],
        [
            [
                '<i class="fa-regular fa-circle-check act" title="active"></i><i class="online" title="online"></i>',
                "192.0.2.60",
                "00:11:22:33:44:55 (Example Devices)",
                '<i class="fa-solid fa-globe" title="Registered with the DNS Resolver"></i>camera-garage.example.test',
                "Garage camera",
                "2026/05/05 09:00:00",
                "2026/05/05 11:00:00",
                '<a title="Add static mapping"></a>',
            ],
            [
                '<i class="fa-solid fa-user act" title="static"></i><i class="online" title="offline"></i>',
                "192.0.2.61",
                "aa:bb:cc:dd:ee:ff",
                "&nbsp;",
                "Static mapping",
                "n/a",
                "n/a",
                '<a title="Edit static mapping"></a>',
            ],
        ],
    )

    assert parse_dhcp_leases(html) == [
        DhcpLease(
            ip_address="192.0.2.60",
            mac_address="00:11:22:33:44:55",
            hostname="camera-garage.example.test",
            starts="2026/05/05 09:00:00",
            ends="2026/05/05 11:00:00",
            online=True,
            lease_type="active",
            description="Garage camera",
        ),
        DhcpLease(
            ip_address="192.0.2.61",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname=None,
            starts="n/a",
            ends="n/a",
            online=False,
            lease_type="static",
            description="Static mapping",
        ),
    ]


def test_parse_dhcp_leases_extracts_pfsense_rows() -> None:
    assert parse_dhcp_leases(dhcp_leases_html()) == [
        DhcpLease(
            ip_address="192.0.2.50",
            mac_address="00:11:22:33:44:55",
            hostname="sensor&kitchen",
            starts="2026/05/05 09:00:00",
            ends="2026/05/05 11:00:00",
            online=True,
            lease_type="active",
            description="Kitchen temperature sensor",
        ),
        DhcpLease(
            ip_address="192.0.2.51",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname=None,
            starts="n/a",
            ends="never",
            online=False,
            lease_type="static",
            description=None,
        ),
    ]


def test_client_get_dhcp_leases_fetches_status_dhcp_leases_page() -> None:
    transport = FakeStatusPageTransport(dhcp_leases_html())
    client = PfSenseWebGuiClient(sample_config(), transport=transport)

    leases = client.get_dhcp_leases()

    assert leases[0].ip_address == "192.0.2.50"
    assert transport.get_urls == [
        "https://192.0.2.1:8843/",
        "https://192.0.2.1:8843/status_dhcp_leases.php",
    ]
