"""Small HTML table parsing helpers for pfSense WebGUI status pages."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import re


@dataclass(frozen=True)
class HtmlCell:
    """Text and selected metadata extracted from a WebGUI table cell."""

    text: str
    titles: tuple[str, ...]


class _TableParser(HTMLParser):
    """Collect text cells from HTML tables while preserving table boundaries."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[HtmlCell]]] = []
        self._table_depth = 0
        self._current_table: list[list[HtmlCell]] | None = None
        self._current_row: list[HtmlCell] | None = None
        self._current_cell: list[str] | None = None
        self._current_cell_titles: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
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
            self._current_cell_titles = []
        elif self._current_cell is not None:
            attributes = {key.lower(): value for key, value in attrs if value is not None}
            if title := attributes.get("title"):
                self._current_cell_titles.append(clean_cell(title))

    def handle_data(self, data: str) -> None:
        if self._current_cell is not None:
            self._current_cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.lower()
        if normalized_tag in {"td", "th"} and self._current_cell is not None:
            if self._current_row is not None:
                self._current_row.append(
                    HtmlCell(
                        text=clean_cell("".join(self._current_cell)),
                        titles=tuple(title for title in self._current_cell_titles if title),
                    )
                )
            self._current_cell = None
            self._current_cell_titles = []
        elif normalized_tag == "tr" and self._current_row is not None:
            if self._current_table is not None and any(cell.text or cell.titles for cell in self._current_row):
                self._current_table.append(self._current_row)
            self._current_row = None
        elif normalized_tag == "table" and self._table_depth > 0:
            self._table_depth -= 1
            if self._table_depth == 0 and self._current_table is not None:
                self.tables.append(self._current_table)
                self._current_table = None


def parse_html_table_cells(html: str) -> list[list[list[HtmlCell]]]:
    """Return all HTML tables as rows of cells with cleaned text and title metadata."""
    parser = _TableParser()
    parser.feed(html)
    return parser.tables


def parse_html_tables(html: str) -> list[list[list[str]]]:
    """Return all HTML tables as rows of cleaned text cells."""
    return [[[cell.text for cell in row] for row in table] for table in parse_html_table_cells(html)]


def find_header_index(table: list[list[str]], required_headers: set[str]) -> int | None:
    """Return the first row index containing all normalized required headers."""
    for index, row in enumerate(table):
        headers = {normalize_header(value) for value in row}
        if required_headers.issubset(headers):
            return index
    return None


def header_indexes(header: list[str]) -> dict[str, int]:
    """Return normalized header names mapped to their first cell index."""
    indexes: dict[str, int] = {}
    for index, value in enumerate(header):
        indexes.setdefault(normalize_header(value), index)
    return indexes


def value_at(row: list[str], index: int | None) -> str | None:
    """Return a stripped cell value by index, or None for absent/empty cells."""
    if index is None or index >= len(row):
        return None
    value = row[index].strip()
    return value or None


def clean_cell(value: str) -> str:
    """Normalize WebGUI table cell whitespace."""
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()


def normalize_header(value: str) -> str:
    """Normalize common pfSense WebGUI table headers to stable snake_case keys."""
    normalized = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    aliases = {
        "ip": "ip_address",
        "ip_addr": "ip_address",
        "mac": "mac_address",
        "type": "entry_type",
    }
    return aliases.get(normalized, normalized)
