"""Passive read-only troubleshooting helpers for pfSense WebGUI data."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import ipaddress
import re
from typing import Iterable

_ACTIVE_CHECKS_NOT_PERFORMED = (
    "ping",
    "traceroute",
    "dns_lookup",
    "vpn_tunnel_status",
    "high_availability_failover",
)
_BLOCKING_ACTIONS = {"block", "reject"}


def normalize_troubleshoot_ip(ip_address: str) -> str:
    """Return a canonical single IP address for troubleshooting filters."""
    try:
        parsed_ip = ipaddress.ip_address(ip_address.strip())
    except ValueError as exc:
        raise ValueError("Troubleshooting target must be a single valid IPv4 address") from exc
    if parsed_ip.version != 4:
        raise ValueError("Troubleshooting target must be a single valid IPv4 address")
    return str(parsed_ip)


def diagnose_host(  # pylint: disable=too-many-arguments,too-many-locals
    ip_address: str,
    *,
    arp_entries: Iterable[object],
    dhcp_leases: Iterable[object],
    firewall_states: Iterable[object],
    firewall_logs: Iterable[object],
    firewall_aliases: Iterable[object],
    firewall_rules: Iterable[object],
    destination_port: str | None = None,
    protocol: str | None = None,
) -> dict[str, object]:
    """Build a passive host troubleshooting report from already-collected WebGUI data."""
    normalized_ip = normalize_troubleshoot_ip(ip_address)
    normalized_port = _normalize_optional_text(destination_port)
    normalized_protocol = _normalize_optional_text(protocol)

    arp_match = _first_exact_ip_attr(arp_entries, "ip_address", normalized_ip)
    dhcp_match = _first_exact_ip_attr(dhcp_leases, "ip_address", normalized_ip)
    state_matches = [state for state in firewall_states if normalized_ip in _tuple_attr(state, "ip_addresses")]
    log_matches = [
        log
        for log in firewall_logs
        if normalized_ip in _tuple_attr(log, "ip_addresses")
        and _log_matches_port(log, normalized_port)
        and _log_matches_protocol(log, normalized_protocol)
    ]
    blocked_logs = [log for log in log_matches if _string_attr(log, "action").lower() in _BLOCKING_ACTIONS]
    alias_list = list(firewall_aliases)
    matching_alias_names = _matching_alias_names(alias_list, normalized_ip)
    matching_port_alias_names = _matching_port_alias_names(alias_list, normalized_port)
    candidate_rules = [
        rule
        for rule in firewall_rules
        if _rule_matches(
            rule,
            normalized_ip,
            matching_alias_names,
            matching_port_alias_names,
            normalized_port,
            normalized_protocol,
        )
    ]

    issues = _host_issues(arp_match, state_matches, blocked_logs)
    status = _host_status(issues, blocked_logs)
    return {
        "ip_address": normalized_ip,
        "status": status,
        "summary": _host_summary(normalized_ip, status, issues),
        "issues": issues,
        "checks": {
            "arp": {"present": arp_match is not None, "entry": _object_dict_or_none(arp_match)},
            "dhcp": {"lease_found": dhcp_match is not None, "lease": _object_dict_or_none(dhcp_match)},
            "firewall_states": {
                "active_state_count": len(state_matches),
                "states": [_object_dict(state) for state in state_matches],
            },
            "firewall_logs": {
                "matching_count": len(log_matches),
                "blocked_count": len(blocked_logs),
                "entries": [_object_dict(log) for log in log_matches],
            },
            "aliases": {"matching_aliases": matching_alias_names},
            "firewall_rules": {
                "candidate_rule_count": len(candidate_rules),
                "candidate_rules": [_object_dict(rule) for rule in candidate_rules],
            },
        },
        "not_performed_active_checks": list(_ACTIVE_CHECKS_NOT_PERFORMED),
    }


def build_health_report(  # pylint: disable=too-many-arguments
    *,
    arp_entries: Iterable[object],
    dhcp_leases: Iterable[object],
    firewall_states: Iterable[object],
    firewall_logs: Iterable[object],
    firewall_aliases: Iterable[object],
    firewall_rules: Iterable[object],
) -> dict[str, object]:
    """Build a passive health report from read-only WebGUI data collections."""
    arp_list = list(arp_entries)
    dhcp_list = list(dhcp_leases)
    state_list = list(firewall_states)
    log_list = list(firewall_logs)
    alias_list = list(firewall_aliases)
    rule_list = list(firewall_rules)

    blocked_count = sum(1 for log in log_list if _string_attr(log, "action").lower() in _BLOCKING_ACTIONS)
    disabled_rules = sum(1 for rule in rule_list if getattr(rule, "enabled", None) is False)
    findings = _health_findings(blocked_count, disabled_rules)
    return {
        "status": "warning" if findings else "healthy",
        "summary": {
            "arp_entries": len(arp_list),
            "dhcp_leases": len(dhcp_list),
            "online_dhcp_leases": sum(1 for lease in dhcp_list if getattr(lease, "online", None) is True),
            "active_firewall_states": len(state_list),
            "recent_firewall_logs": len(log_list),
            "blocked_or_rejected_logs": blocked_count,
            "firewall_aliases": len(alias_list),
            "firewall_rules": len(rule_list),
            "disabled_firewall_rules": disabled_rules,
        },
        "findings": findings,
        "not_performed_active_checks": list(_ACTIVE_CHECKS_NOT_PERFORMED),
    }


def _host_issues(arp_match: object | None, state_matches: list[object], blocked_logs: list[object]) -> list[str]:
    issues: list[str] = []
    if arp_match is None:
        issues.append("No exact ARP entry was found")
    if not state_matches:
        issues.append("No active firewall states were found")
    if blocked_logs:
        issues.append("Recent block/reject firewall log entries match this host")
    return issues


def _host_status(issues: list[str], blocked_logs: list[object]) -> str:
    if blocked_logs:
        return "blocked"
    if issues:
        return "warning"
    return "healthy"


def _host_summary(ip_address: str, status: str, issues: list[str]) -> str:
    if not issues:
        return f"Passive WebGUI evidence for {ip_address} looks healthy"
    return f"Passive WebGUI evidence for {ip_address} is {status}: " + "; ".join(issues)


def _health_findings(blocked_count: int, disabled_rules: int) -> list[str]:
    findings: list[str] = []
    if blocked_count:
        findings.append("Recent block/reject firewall log entries are present")
    if disabled_rules:
        findings.append("Disabled firewall rules are present")
    return findings


def _first_exact_ip_attr(entries: Iterable[object], attr_name: str, ip_address: str) -> object | None:
    for entry in entries:
        if getattr(entry, attr_name, None) == ip_address:
            return entry
    return None


def _matching_alias_names(aliases: Iterable[object], ip_address: str) -> list[str]:
    names: list[str] = []
    parsed_ip = ipaddress.ip_address(ip_address)
    for alias in aliases:
        if any(_address_token_matches_host(str(value), parsed_ip) for value in _tuple_attr(alias, "values")):
            name = _string_attr(alias, "name")
            if name:
                names.append(name)
    return names


def _matching_port_alias_names(aliases: Iterable[object], destination_port: str | None) -> list[str]:
    if destination_port is None:
        return []
    names: list[str] = []
    for alias in aliases:
        if any(_port_value_matches(destination_port, str(value)) for value in _tuple_attr(alias, "values")):
            name = _string_attr(alias, "name")
            if name:
                names.append(name.lower())
    return names


def _rule_matches(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    rule: object,
    ip_address: str,
    alias_names: list[str],
    port_alias_names: list[str],
    destination_port: str | None,
    protocol: str | None,
) -> bool:
    if not _rule_matches_port(rule, port_alias_names, destination_port):
        return False
    if not _rule_matches_protocol(rule, protocol):
        return False
    rule_targets = (_string_attr(rule, "source"), _string_attr(rule, "destination"))
    target_matches = [_rule_target_matches_host(target, ip_address, alias_names) for target in rule_targets]
    if any(target_matches):
        return True
    return all(_rule_target_is_wildcard(target) for target in rule_targets if target)


def _rule_matches_port(rule: object, port_alias_names: list[str], destination_port: str | None) -> bool:
    if not destination_port:
        return True
    rule_destination_port = _string_attr(rule, "destination_port").lower()
    return (
        rule_destination_port in {destination_port, "*", "any", *port_alias_names}
        or _port_value_matches(destination_port, rule_destination_port)
    )


def _rule_matches_protocol(rule: object, protocol: str | None) -> bool:
    if not protocol:
        return True
    rule_protocol_tokens = _protocol_tokens(_string_attr(rule, "protocol"))
    return any(token.lower() in {protocol, "*", "any"} for token in rule_protocol_tokens)


def _log_matches_port(log: object, destination_port: str | None) -> bool:
    if not destination_port:
        return True
    return destination_port == _string_attr(log, "destination_port").lower()


def _rule_target_matches_host(target: str, ip_address: str, alias_names: list[str]) -> bool:
    alias_name_set = {alias_name.lower() for alias_name in alias_names}
    parsed_ip = ipaddress.ip_address(ip_address)
    for token in _rule_target_tokens(target):
        normalized_token = token.lower()
        if normalized_token in alias_name_set:
            return True
        if _address_token_matches_host(token, parsed_ip):
            return True
    return False


def _rule_target_is_wildcard(target: str) -> bool:
    tokens = _rule_target_tokens(target)
    return bool(tokens) and all(token.lower() in {"*", "any"} for token in tokens)


def _rule_target_tokens(target: str) -> list[str]:
    return re.findall(r"\*|[A-Za-z0-9_.:/-]+", target)


def _protocol_tokens(protocol: str) -> list[str]:
    return re.findall(r"\*|[A-Za-z0-9]+", protocol)


def _address_token_matches_host(token: str, ip_address: ipaddress._BaseAddress) -> bool:
    try:
        return ip_address in ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False


def _port_value_matches(destination_port: str, rule_port_value: str) -> bool:
    normalized_value = rule_port_value.strip().lower()
    if normalized_value in {destination_port, "*", "any"}:
        return True
    match = re.fullmatch(r"(\d+)\s*[-:]\s*(\d+)", normalized_value)
    if not match:
        return False
    requested_port = int(destination_port) if destination_port.isdigit() else -1
    start_port, end_port = int(match.group(1)), int(match.group(2))
    return start_port <= requested_port <= end_port


def _log_matches_protocol(log: object, protocol: str | None) -> bool:
    if not protocol:
        return True
    return _string_attr(log, "protocol").lower().startswith(protocol)


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return value.strip().lower()


def _tuple_attr(entry: object, attr_name: str) -> tuple[object, ...]:
    value = getattr(entry, attr_name, ())
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    return ()


def _string_attr(entry: object, attr_name: str) -> str:
    value = getattr(entry, attr_name, None)
    return value if isinstance(value, str) else ""


def _object_dict_or_none(entry: object | None) -> dict[str, object] | None:
    if entry is None:
        return None
    return _object_dict(entry)


def _object_dict(entry: object) -> dict[str, object]:
    if is_dataclass(entry):
        return asdict(entry)
    if isinstance(entry, dict):
        return dict(entry)
    return dict(vars(entry))
