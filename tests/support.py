"""Shared test fixtures for pfSense MCP tests."""

from pfsense_mcp.config import PfSenseConfig

LOGIN_FORM_VALUE = "-".join(("fixture", "login", "value"))


def sample_config() -> PfSenseConfig:
    return PfSenseConfig(
        base_url="https://192.0.2.1:8843",
        username="readonly-user",
        password=LOGIN_FORM_VALUE,
        read_only=True,
    )


def login_page() -> str:
    return '<form><input name="__csrf_magic" value="sid:csrf-token,1700000000"></form>'


def dashboard_page() -> str:
    return '<html><title>pfSense - Dashboard</title><a href="/index.php?logout">Logout</a></html>'
