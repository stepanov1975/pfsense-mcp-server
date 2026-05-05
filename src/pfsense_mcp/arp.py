"""Read-only ARP table parsing for pfSense WebGUI pages."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import re


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


class _TableParser(HTMLParser):
    """Collect text cells from HTML tables while preserving table boundaries."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._table_depth = 0
        self._current_table: list[list[str]] | None = None
        self._current_row: list[str] | None = None
        self._current_cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        normalized_tag = tag.lower()
        if normalized_tag == "table":
            if self._table_depth == 0:
                self._current_table = []
            self._table_depth += 1
            return
        if self._table_depth == 0:
            return
        if normalized_tag == "tr":
            self._current_row = []
        elif normalized_tag in {"td", "th"}:
            self._current_cell = []

    def handle_data(self, data: str) -> None:
        if self._current_cell is not None:
            self._current_cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.lower()
        if normalized_tag in {"td", "th"} and self._current_cell is not None:
            if self._current_row is not None:
                self._current_row.append(_clean_cell("".join(self._current_cell)))
            self._current_cell = None
        elif normalized_tag == "tr" and self._current_row is not None:
            if self._current_table is not None and any(self._current_row):
                self._current_table.append(self._current_row)
            self._current_row = None
        elif normalized_tag == "table" and self._table_depth > 0:
            self._table_depth -= 1
            if self._table_depth == 0 and self._current_table is not None:
                self.tables.append(self._current_table)
                self._current_table = None


def parse_arp_table(html: str) -> list[ArpEntry]:
    """Parse pfSense's ``status_arp.php`` HTML into structured ARP entries."""
    parser = _TableParser()
    parser.feed(html)
    for table in parser.tables:
        entries = _entries_from_table(table)
        if entries is not None:
            return entries
    raise ArpTableParseError("Could not find a pfSense ARP table in WebGUI HTML")


def _entries_from_table(table: list[list[str]]) -> list[ArpEntry] | None:
    header_index = _find_header_index(table)
    if header_index is None:
        return None
    header = [_normalize_header(value) for value in table[header_index]]
    indexes = {name: header.index(name) for name in header}
    return [entry for row in table[header_index + 1 :] if (entry := _entry_from_row(row, indexes))]


def _find_header_index(table: list[list[str]]) -> int | None:
    for index, row in enumerate(table):
        headers = {_normalize_header(value) for value in row}
        if {"ip_address", "mac_address"}.issubset(headers):
            return index
    return None


def _entry_from_row(row: list[str], indexes: dict[str, int]) -> ArpEntry | None:
    ip_address = _value_at(row, indexes["ip_address"])
    mac_address = _value_at(row, indexes["mac_address"])
    if not ip_address or not mac_address:
        return None
    expires = _value_at(row, indexes.get("expires"))
    return ArpEntry(
        ip_address=ip_address,
        mac_address=mac_address,
        hostname=_value_at(row, indexes.get("hostname")),
        interface=_value_at(row, indexes.get("interface")),
        expires=expires,
        entry_type=_value_at(row, indexes.get("entry_type")),
        permanent=bool(expires and expires.lower() == "permanent"),
    )


def _value_at(row: list[str], index: int | None) -> str | None:
    if index is None or index >= len(row):
        return None
    value = row[index].strip()
    return value or None


def _clean_cell(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()


def _normalize_header(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    aliases = {
        "ip": "ip_address",
        "ip_addr": "ip_address",
        "mac": "mac_address",
        "type": "entry_type",
    }
    return aliases.get(normalized, normalized)
