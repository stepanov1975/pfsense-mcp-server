"""Read-only parsing for pfSense WebGUI firewall state tables."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from pfsense_mcp.table import find_header_index, header_indexes, parse_html_tables, value_at


_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_MAX_FIREWALL_STATES = 200


class FirewallStateParseError(ValueError):
    """Raised when a pfSense firewall state table cannot be parsed safely."""


@dataclass(frozen=True)
class FirewallStateEntry:  # pylint: disable=too-many-instance-attributes
    """One read-only pfSense firewall state table entry."""

    interface: str
    protocol: str
    source: str
    destination: str
    state: str | None
    packets: str | None
    bytes: str | None
    original_source: str | None
    original_destination: str | None
    ip_addresses: tuple[str, ...]


def parse_firewall_states(
    html: str, *, ip_address: str | None = None, limit: int = _MAX_FIREWALL_STATES
) -> list[FirewallStateEntry]:
    """Parse read-only firewall state entries from pfSense ``diag_dump_states.php`` HTML.

    The pfSense page includes action links that can kill states; this parser ignores
    the action column entirely and returns only inert state metadata.
    """
    normalized_ip = normalize_firewall_state_ip_filter(ip_address)
    safe_limit = _normalize_limit(limit)
    states: list[FirewallStateEntry] = []

    for table in parse_html_tables(html):
        header_index = find_header_index(table, {"interface", "protocol", "state"})
        if header_index is None:
            continue
        header = table[header_index]
        indexes = header_indexes(header)
        flow_index = _flow_column_index(indexes)
        if flow_index is None:
            continue

        for row in table[header_index + 1 :]:
            entry = _parse_state_row(row, indexes, flow_index)
            if entry is None:
                continue
            if normalized_ip and normalized_ip not in entry.ip_addresses:
                continue
            states.append(entry)
            if len(states) >= safe_limit:
                return states

    if not states and not _has_state_table(html):
        raise FirewallStateParseError("Could not find pfSense firewall state table")
    return states


def _parse_state_row(
    row: list[str], indexes: dict[str, int], flow_index: int
) -> FirewallStateEntry | None:
    interface = value_at(row, indexes.get("interface"))
    protocol = value_at(row, indexes.get("protocol"))
    flow = value_at(row, flow_index)
    if not interface or not protocol or not flow or "->" not in flow:
        return None

    source_part, destination_part = (part.strip() for part in flow.split("->", 1))
    source, original_source = _split_original_endpoint(source_part)
    destination, original_destination = _split_original_endpoint(destination_part)
    ips = _extract_ips(source, original_source, destination, original_destination)

    return FirewallStateEntry(
        interface=interface,
        protocol=protocol,
        source=source,
        destination=destination,
        state=value_at(row, indexes.get("state")),
        packets=value_at(row, indexes.get("packets")),
        bytes=value_at(row, indexes.get("bytes")),
        original_source=original_source,
        original_destination=original_destination,
        ip_addresses=ips,
    )


def _flow_column_index(indexes: dict[str, int]) -> int | None:
    for header in (
        "source_original_source_destination_original_destination",
        "source_destination",
        "source",
    ):
        if header in indexes:
            return indexes[header]
    return None


def _split_original_endpoint(value: str) -> tuple[str, str | None]:
    match = re.fullmatch(r"(?P<current>.*?)\s*\((?P<original>.*?)\)\s*", value)
    if not match:
        return value.strip(), None
    return match.group("current").strip(), match.group("original").strip() or None


def _extract_ips(*values: str | None) -> tuple[str, ...]:
    ips: list[str] = []
    for value in values:
        if not value:
            continue
        for match in _IP_RE.findall(value):
            try:
                normalized = str(ipaddress.ip_address(match))
            except ValueError:
                continue
            if normalized not in ips:
                ips.append(normalized)
    return tuple(ips)


def normalize_firewall_state_ip_filter(ip_address: str | None) -> str | None:
    """Return a canonical IPv4 filter or ``None`` for an omitted/blank filter.

    pfSense's current WebGUI state table parser extracts IPv4 endpoints only, so
    IPv6 filters are rejected explicitly instead of silently returning no matches.
    """
    if ip_address is None or not ip_address.strip():
        return None
    try:
        parsed = ipaddress.ip_address(ip_address.strip())
    except ValueError as exc:
        raise FirewallStateParseError("Firewall state IP filter must be a single valid IPv4 address") from exc
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise FirewallStateParseError("Firewall state IP filter must be a single valid IPv4 address")
    return str(parsed)


def _normalize_limit(limit: int) -> int:
    if limit < 1:
        return 1
    return min(limit, _MAX_FIREWALL_STATES)


def _has_state_table(html: str) -> bool:
    for table in parse_html_tables(html):
        if find_header_index(table, {"interface", "protocol", "state"}) is not None:
            return True
    return False
