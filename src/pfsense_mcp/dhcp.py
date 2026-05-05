"""Read-only DHCP lease parsing for pfSense WebGUI pages."""

from __future__ import annotations

from dataclasses import dataclass
import re

from pfsense_mcp.table import (
    HtmlCell,
    find_header_index,
    header_indexes,
    parse_html_table_cells,
    value_at,
)


@dataclass(frozen=True)
class DhcpLease:  # pylint: disable=too-many-instance-attributes
    """Single row from pfSense Status > DHCP Leases."""

    ip_address: str
    mac_address: str
    hostname: str | None
    starts: str | None
    ends: str | None
    online: bool | None
    lease_type: str | None
    description: str | None


class DhcpLeaseParseError(ValueError):
    """Raised when a pfSense DHCP lease table cannot be found in WebGUI HTML."""


def parse_dhcp_leases(html: str) -> list[DhcpLease]:
    """Parse pfSense's ``status_dhcp_leases.php`` HTML into structured leases."""
    for table in parse_html_table_cells(html):
        leases = _leases_from_table(table)
        if leases is not None:
            return leases
    raise DhcpLeaseParseError("Could not find a pfSense DHCP lease table in WebGUI HTML")


def _leases_from_table(table: list[list[HtmlCell]]) -> list[DhcpLease] | None:
    text_table = [[cell.text for cell in row] for row in table]
    header_index = find_header_index(text_table, {"ip_address", "mac_address"})
    if header_index is None:
        return None
    indexes = header_indexes(text_table[header_index])
    return [
        lease
        for row in table[header_index + 1 :]
        if (lease := _lease_from_row(row, indexes))
    ]


def _lease_from_row(row: list[HtmlCell], indexes: dict[str, int]) -> DhcpLease | None:
    text_row = [cell.text for cell in row]
    ip_address = value_at(text_row, indexes["ip_address"])
    mac_address = _mac_address(value_at(text_row, indexes["mac_address"]))
    if not ip_address or not mac_address:
        return None
    status_text = _status_text(row, indexes)
    return DhcpLease(
        ip_address=ip_address,
        mac_address=mac_address,
        hostname=_hostname(value_at(text_row, indexes.get("hostname"))),
        starts=_first_value(text_row, indexes, "starts", "start"),
        ends=_first_value(text_row, indexes, "ends", "end"),
        online=_online_value(_first_value(text_row, indexes, "online") or status_text),
        lease_type=(
            _first_value(text_row, indexes, "lease_type", "entry_type")
            or _lease_type_from_status(status_text)
        ),
        description=value_at(text_row, indexes.get("description")),
    )


def _first_value(row: list[str], indexes: dict[str, int], *keys: str) -> str | None:
    for key in keys:
        if value := value_at(row, indexes.get(key)):
            return value
    return None


def _status_text(row: list[HtmlCell], indexes: dict[str, int]) -> str | None:
    status_cell_index = indexes.get("")
    if status_cell_index is None or status_cell_index >= len(row):
        return None
    values = [*row[status_cell_index].titles, row[status_cell_index].text]
    return " ".join(value for value in values if value) or None


def _mac_address(value: str | None) -> str | None:
    if value is None:
        return None
    match = re.search(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value, flags=re.IGNORECASE)
    return match.group(0).lower() if match else value


def _hostname(value: str | None) -> str | None:
    if value is None:
        return None
    dns_resolver_marker = "Registered with the DNS Resolver"
    cleaned = value.replace(dns_resolver_marker, "").strip()
    return cleaned or None


def _online_value(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.lower()
    if any(marker in normalized for marker in ("online", "yes", "true")):
        return True
    if any(marker in normalized for marker in ("offline", "no", "false")):
        return False
    return None


def _lease_type_from_status(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.lower()
    for lease_type in ("active", "expired", "static"):
        if lease_type in normalized:
            return lease_type
    return None
