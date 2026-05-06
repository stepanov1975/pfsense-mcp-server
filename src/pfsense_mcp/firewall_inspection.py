"""Read-only parsing for pfSense firewall logs, aliases, and rule tables."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from pfsense_mcp.table import HtmlCell, find_header_index, header_indexes, parse_html_table_cells, value_at

_MAX_FIREWALL_LOGS = 200
_ENDPOINT_RE = re.compile(
    r"^(?:\[(?P<bracket_ip>[^\]]+)\]|(?P<plain_ip>[^:]+|(?:\d{1,3}\.){3}\d{1,3}))(?::(?P<port>\d+))?$"
)
_VALID_LOG_ACTIONS = {"pass", "block", "reject"}


class FirewallLogParseError(ValueError):
    """Raised when a pfSense firewall log table cannot be parsed safely."""


class FirewallAliasParseError(ValueError):
    """Raised when a pfSense firewall alias table cannot be parsed safely."""


class FirewallRuleParseError(ValueError):
    """Raised when a pfSense firewall rule table cannot be parsed safely."""


@dataclass(frozen=True)
class _FirewallLogFilters:
    """Normalized firewall log filter values used by parser internals."""

    ip_address: str | None
    action: str | None
    interface: str | None
    protocol: str | None
    limit: int


@dataclass(frozen=True)
class FirewallLogEntry:  # pylint: disable=too-many-instance-attributes
    """One inert pfSense firewall log table entry."""

    action: str | None
    time: str
    interface: str
    rule: str
    source: str
    destination: str
    protocol: str
    source_ip: str | None
    source_port: str | None
    destination_ip: str | None
    destination_port: str | None
    ip_addresses: tuple[str, ...]


@dataclass(frozen=True)
class FirewallAliasEntry:
    """One inert pfSense firewall alias table entry."""

    name: str
    alias_type: str
    values: tuple[str, ...]
    description: str | None


@dataclass(frozen=True)
class FirewallRuleEntry:  # pylint: disable=too-many-instance-attributes
    """One inert pfSense firewall rule table entry."""

    index: int
    interface: str | None
    enabled: bool | None
    states: str | None
    protocol: str | None
    source: str | None
    source_port: str | None
    destination: str | None
    destination_port: str | None
    gateway: str | None
    queue: str | None
    schedule: str | None
    description: str | None


def parse_firewall_logs(  # pylint: disable=too-many-arguments
    html: str,
    *,
    ip_address: str | None = None,
    action: str | None = None,
    interface: str | None = None,
    protocol: str | None = None,
    limit: int = _MAX_FIREWALL_LOGS,
) -> list[FirewallLogEntry]:
    """Parse read-only firewall log entries from ``status_logs_filter.php`` HTML."""
    filters = _normalize_firewall_log_filters(ip_address, action, interface, protocol, limit)
    logs: list[FirewallLogEntry] = []
    found_table = False

    for table in parse_html_table_cells(html):
        text_table = _text_table(table)
        header_index = find_header_index(text_table, {"action", "time", "interface", "source", "destination"})
        if header_index is None:
            continue
        found_table = True
        indexes = header_indexes(text_table[header_index])
        for row in table[header_index + 1 :]:
            entry = _parse_log_row(row, indexes)
            if entry is None:
                continue
            if filters.ip_address and filters.ip_address not in entry.ip_addresses:
                continue
            if filters.action and entry.action != filters.action:
                continue
            if filters.interface and entry.interface.lower() != filters.interface:
                continue
            if filters.protocol and not entry.protocol.lower().startswith(filters.protocol):
                continue
            logs.append(entry)
            if len(logs) >= filters.limit:
                return logs

    if not found_table:
        raise FirewallLogParseError("Could not find pfSense firewall log table")
    return logs


def parse_firewall_aliases(html: str) -> list[FirewallAliasEntry]:
    """Parse read-only firewall aliases from ``firewall_aliases.php`` HTML."""
    aliases: list[FirewallAliasEntry] = []
    found_table = False

    for table in parse_html_table_cells(html):
        text_table = _text_table(table)
        header_index = find_header_index(text_table, {"name", "values", "description"})
        if header_index is None:
            continue
        indexes = header_indexes(text_table[header_index])
        if "entry_type" not in indexes and "type" not in indexes:
            continue
        found_table = True
        for row in text_table[header_index + 1 :]:
            name = value_at(row, indexes.get("name"))
            alias_type = value_at(row, indexes.get("entry_type") or indexes.get("type"))
            if not name or not alias_type:
                continue
            aliases.append(
                FirewallAliasEntry(
                    name=name,
                    alias_type=alias_type,
                    values=_split_alias_values(value_at(row, indexes.get("values"))),
                    description=value_at(row, indexes.get("description")),
                )
            )

    if not found_table:
        raise FirewallAliasParseError("Could not find pfSense firewall alias table")
    return aliases


def parse_firewall_rules(html: str, *, interface: str | None = None) -> list[FirewallRuleEntry]:
    """Parse read-only firewall rules from ``firewall_rules.php`` HTML.

    The WebGUI rule table exposes mutating action links in its final column. This
    parser uses action-cell titles only to infer enabled state and never returns
    those links or action labels.
    """
    rules: list[FirewallRuleEntry] = []
    found_table = False
    normalized_interface = normalize_firewall_rule_interface(interface)

    for table in parse_html_table_cells(html):
        text_table = _text_table(table)
        header_index = find_header_index(text_table, {"states", "protocol", "source", "destination"})
        if header_index is None:
            continue
        found_table = True
        indexes = header_indexes(text_table[header_index])
        source_index = indexes.get("source")
        destination_index = indexes.get("destination")
        for row in table[header_index + 1 :]:
            text_row = [cell.text for cell in row]
            if not any(text_row):
                continue
            rules.append(
                FirewallRuleEntry(
                    index=len(rules),
                    interface=normalized_interface,
                    enabled=_infer_rule_enabled(row),
                    states=value_at(text_row, indexes.get("states")),
                    protocol=value_at(text_row, indexes.get("protocol")),
                    source=value_at(text_row, source_index),
                    source_port=value_at(text_row, _port_after(text_table[header_index], source_index)),
                    destination=value_at(text_row, destination_index),
                    destination_port=value_at(text_row, _port_after(text_table[header_index], destination_index)),
                    gateway=value_at(text_row, indexes.get("gateway")),
                    queue=value_at(text_row, indexes.get("queue")),
                    schedule=value_at(text_row, indexes.get("schedule")),
                    description=value_at(text_row, indexes.get("description")),
                )
            )

    if not found_table:
        raise FirewallRuleParseError("Could not find pfSense firewall rule table")
    return rules


def normalize_firewall_log_filter_ip(ip_address: str | None) -> str | None:
    """Return a canonical single IP log filter, or ``None`` for omitted filters."""
    if ip_address is None or not ip_address.strip():
        return None
    try:
        return str(ipaddress.ip_address(ip_address.strip()))
    except ValueError as exc:
        raise FirewallLogParseError("Firewall log IP filter must be a single valid IP address") from exc


def normalize_firewall_rule_interface(interface: str | None) -> str | None:
    """Return a safe pfSense interface token for WebGUI rule tab selection."""
    if interface is None or not interface.strip():
        return None
    normalized = interface.strip().lower()
    if not re.fullmatch(r"[a-z0-9_\-.]+", normalized):
        raise FirewallRuleParseError("Firewall rule interface must be a simple interface token")
    return normalized


def _normalize_firewall_log_filters(
    ip_address: str | None,
    action: str | None,
    interface: str | None,
    protocol: str | None,
    limit: int,
) -> _FirewallLogFilters:
    return _FirewallLogFilters(
        ip_address=normalize_firewall_log_filter_ip(ip_address),
        action=normalize_firewall_log_action_filter(action),
        interface=interface.strip().lower() if interface else None,
        protocol=protocol.strip().lower() if protocol else None,
        limit=_normalize_limit(limit, _MAX_FIREWALL_LOGS),
    )


def _parse_log_row(row: list[HtmlCell], indexes: dict[str, int]) -> FirewallLogEntry | None:
    text_row = [cell.text for cell in row]
    time = value_at(text_row, indexes.get("time"))
    interface = value_at(text_row, indexes.get("interface"))
    rule = value_at(text_row, indexes.get("rule"))
    source = value_at(text_row, indexes.get("source"))
    destination = value_at(text_row, indexes.get("destination"))
    protocol = value_at(text_row, indexes.get("protocol"))
    if not time or not interface or not source or not destination or not protocol:
        return None
    source_ip, source_port = _split_endpoint(source)
    destination_ip, destination_port = _split_endpoint(destination)
    return FirewallLogEntry(
        action=_infer_log_action(row[indexes["action"]] if "action" in indexes and indexes["action"] < len(row) else None, rule),
        time=time,
        interface=interface,
        rule=rule or "",
        source=source,
        destination=destination,
        protocol=protocol,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        ip_addresses=tuple(ip for ip in (source_ip, destination_ip) if ip),
    )


def _infer_log_action(action_cell: HtmlCell | None, rule: str | None) -> str | None:
    candidates: list[str] = []
    if action_cell:
        candidates.extend(action_cell.titles)
        candidates.append(action_cell.text)
    if rule:
        candidates.append(rule)
    for candidate in candidates:
        normalized = candidate.lower()
        if "reject" in normalized:
            return "reject"
        if "block" in normalized or "deny" in normalized:
            return "block"
        if "pass" in normalized or "allow" in normalized:
            return "pass"
    return None


def _split_endpoint(value: str) -> tuple[str | None, str | None]:
    cleaned = value.strip()
    match = _ENDPOINT_RE.match(cleaned)
    if match:
        ip_text = match.group("bracket_ip") or match.group("plain_ip")
        try:
            return str(ipaddress.ip_address(ip_text)), match.group("port")
        except ValueError:
            return None, match.group("port")
    try:
        return str(ipaddress.ip_address(cleaned)), None
    except ValueError:
        return None, None


def normalize_firewall_log_action_filter(action: str | None) -> str | None:
    """Return a canonical firewall log action filter, or ``None`` for omitted filters."""
    if action is None or not action.strip():
        return None
    normalized = action.strip().lower()
    if normalized not in _VALID_LOG_ACTIONS:
        raise FirewallLogParseError("Firewall log action filter must be pass, block, or reject")
    return normalized


def _split_alias_values(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part for part in value.split() if part)


def _infer_rule_enabled(row: list[HtmlCell]) -> bool | None:
    if not row:
        return None
    action_titles = tuple(title.lower() for title in row[-1].titles)
    if any(title == "disable" for title in action_titles):
        return True
    if any(title == "enable" for title in action_titles):
        return False
    return None


def _port_after(header: list[str], start_index: int | None) -> int | None:
    if start_index is None:
        return None
    for index in range(start_index + 1, len(header)):
        if header[index].strip().lower() == "port":
            return index
        if header[index].strip().lower() in {"source", "destination", "gateway", "queue", "schedule", "description"}:
            return None
    return None


def _normalize_limit(limit: int, maximum: int) -> int:
    if limit < 1:
        return 1
    return min(limit, maximum)


def _text_table(table: list[list[HtmlCell]]) -> list[list[str]]:
    return [[cell.text for cell in row] for row in table]
