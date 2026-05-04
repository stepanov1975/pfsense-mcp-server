"""Tests for the pfSense WebGUI session client."""

import pytest

from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.webgui import PfSenseWebGuiClient, WebGuiAuthError


class FakeWebGuiTransport:
    """Deterministic transport for testing WebGUI request orchestration."""

    def __init__(self, *, login_html: str, login_response: str, page_response: str = "") -> None:
        self.login_page = login_html
        self.login_response = login_response
        self.page_response = page_response
        self.get_urls: list[str] = []
        self.posted_forms: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str) -> str:
        self.get_urls.append(url)
        if len(self.get_urls) == 1:
            return self.login_page
        return self.page_response

    def post_form(self, url: str, data: dict[str, str]) -> str:
        self.posted_forms.append((url, data))
        return self.login_response


def config() -> PfSenseConfig:
    return PfSenseConfig(
        base_url="https://192.0.2.1:8843",
        username="readonly-user",
        password="fixture-credential-value",
        read_only=True,
    )


def login_page() -> str:
    return '<form><input name="__csrf_magic" value="sid:csrf-token,1700000000"></form>'


def dashboard_page() -> str:
    return '<html><title>pfSense - Dashboard</title><a href="/index.php?logout">Logout</a></html>'


def test_login_gets_csrf_token_then_posts_pfsense_login_form() -> None:
    transport = FakeWebGuiTransport(login_html=login_page(), login_response=dashboard_page())
    client = PfSenseWebGuiClient(config(), transport=transport)

    client.login()

    assert client.authenticated is True
    assert transport.get_urls == ["https://192.0.2.1:8843/"]
    assert transport.posted_forms == [
        (
            "https://192.0.2.1:8843/",
            {
                "__csrf_magic": "sid:csrf-token,1700000000",
                "usernamefld": "readonly-user",
                "passwordfld": "fixture-credential-value",
                "login": "Sign In",
            },
        )
    ]


def test_login_raises_and_remains_unauthenticated_when_dashboard_markers_are_absent() -> None:
    transport = FakeWebGuiTransport(
        login_html=login_page(),
        login_response="<form><input name='usernamefld'><input name='passwordfld'></form>",
    )
    client = PfSenseWebGuiClient(config(), transport=transport)

    with pytest.raises(WebGuiAuthError, match="login did not reach"):
        client.login()

    assert client.authenticated is False


def test_get_page_logs_in_once_then_fetches_requested_webgui_path() -> None:
    transport = FakeWebGuiTransport(
        login_html=login_page(),
        login_response=dashboard_page(),
        page_response="<html>arp table</html>",
    )
    client = PfSenseWebGuiClient(config(), transport=transport)

    assert client.get_page("/status_arp.php") == "<html>arp table</html>"
    assert client.get_page("status_arp.php") == "<html>arp table</html>"

    assert transport.get_urls == [
        "https://192.0.2.1:8843/",
        "https://192.0.2.1:8843/status_arp.php",
        "https://192.0.2.1:8843/status_arp.php",
    ]
    assert len(transport.posted_forms) == 1


def test_get_page_rejects_absolute_or_parent_paths() -> None:
    transport = FakeWebGuiTransport(login_html=login_page(), login_response=dashboard_page())
    client = PfSenseWebGuiClient(config(), transport=transport)

    with pytest.raises(ValueError, match="relative WebGUI path"):
        client.get_page("https://evil.invalid/status_arp.php")

    with pytest.raises(ValueError, match="parent directory"):
        client.get_page("../etc/passwd")


def test_get_page_rejects_unsafe_path_before_login_network_calls() -> None:
    transport = FakeWebGuiTransport(login_html=login_page(), login_response=dashboard_page())
    client = PfSenseWebGuiClient(config(), transport=transport)

    with pytest.raises(ValueError, match="parent directory"):
        client.get_page("%2e%2e/status_arp.php")

    assert not transport.get_urls
    assert not transport.posted_forms
