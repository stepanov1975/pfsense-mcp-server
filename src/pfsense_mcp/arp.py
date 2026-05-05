"""Read-only ARP table parsing for pfSense WebGUI pages."""

from __future__ import annotations

from dataclasses import dataclass

from pfsense_mcp.table import find_header_index, header_indexes, parse_html_tables, value_at


@dataclass(frozen=True)
class ArpEntry:
    """Single row from pfSense Diagnostics > ARP Table."""

    ip_address: str
    mac_address: str
    hostname: str | None
    interface: str | None
    expires: str | None
    entry_type: str | None
    permanent: bool


class ArpTableParseError(ValueError):
    """Raised when a pfSense ARP table cannot be found in WebGUI HTML."""

def parse_arp_table(html: str) -> list[ArpEntry]:
    """Parse pfSense's ``diag_arp.php`` HTML into structured ARP entries."""
    for table in parse_html_tables(html):
        entries = _entries_from_table(table)
        if entries is not None:
            return entries
    raise ArpTableParseError("Could not find a pfSense ARP table in WebGUI HTML")


def _entries_from_table(table: list[list[str]]) -> list[ArpEntry] | None:
    header_index = find_header_index(table, {"ip_address", "mac_address"})
    if header_index is None:
        return None
    indexes = header_indexes(table[header_index])
    return [entry for row in table[header_index + 1 :] if (entry := _entry_from_row(row, indexes))]


def _entry_from_row(row: list[str], indexes: dict[str, int]) -> ArpEntry | None:
    ip_address = value_at(row, indexes["ip_address"])
    mac_address = value_at(row, indexes["mac_address"])
    if not ip_address or not mac_address:
        return None
    expires = value_at(row, indexes.get("expires"))
    return ArpEntry(
        ip_address=ip_address,
        mac_address=mac_address,
        hostname=value_at(row, indexes.get("hostname")),
        interface=value_at(row, indexes.get("interface")),
        expires=expires,
        entry_type=value_at(row, indexes.get("entry_type")),
        permanent=bool(expires and expires.lower() == "permanent"),
    )
