"""Tests for the pfSense WebGUI session client."""

from email.message import EmailMessage
from urllib.request import Request

import pytest

from support import LOGIN_FORM_VALUE, dashboard_page, login_page, sample_config
from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.webgui import (
    PfSenseWebGuiClient,
    SameOriginHttpsRedirectHandler,
    UrlLibWebGuiTransport,
    WebGuiAuthError,
    WebGuiTransportError,
)


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


def test_login_gets_csrf_token_then_posts_pfsense_login_form() -> None:
    transport = FakeWebGuiTransport(login_html=login_page(), login_response=dashboard_page())
    client = PfSenseWebGuiClient(sample_config(), transport=transport)

    client.login()

    assert client.authenticated is True
    assert transport.get_urls == ["https://192.0.2.1:8843/"]
    assert transport.posted_forms == [
        (
            "https://192.0.2.1:8843/",
            {
                "__csrf_magic": "sid:csrf-token,1700000000",
                "usernamefld": "readonly-user",
                "passwordfld": LOGIN_FORM_VALUE,
                "login": "Sign In",
            },
        )
    ]


def test_login_raises_and_remains_unauthenticated_when_dashboard_markers_are_absent() -> None:
    transport = FakeWebGuiTransport(
        login_html=login_page(),
        login_response="<form><input name='usernamefld'><input name='passwordfld'></form>",
    )
    client = PfSenseWebGuiClient(sample_config(), transport=transport)

    with pytest.raises(WebGuiAuthError, match="login did not reach"):
        client.login()

    assert client.authenticated is False


def test_get_page_logs_in_once_then_fetches_requested_webgui_path() -> None:
    transport = FakeWebGuiTransport(
        login_html=login_page(),
        login_response=dashboard_page(),
        page_response="<html>arp table</html>",
    )
    client = PfSenseWebGuiClient(sample_config(), transport=transport)

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
    client = PfSenseWebGuiClient(sample_config(), transport=transport)

    with pytest.raises(ValueError, match="relative WebGUI path"):
        client.get_page("https://evil.invalid/status_arp.php")

    with pytest.raises(ValueError, match="parent directory"):
        client.get_page("../etc/passwd")


def test_get_page_rejects_unsafe_path_before_login_network_calls() -> None:
    transport = FakeWebGuiTransport(login_html=login_page(), login_response=dashboard_page())
    client = PfSenseWebGuiClient(sample_config(), transport=transport)

    with pytest.raises(ValueError, match="parent directory"):
        client.get_page("%2e%2e/status_arp.php")

    assert not transport.get_urls
    assert not transport.posted_forms


class FakeUrlLibResponse:
    """Context-manager response double for UrlLibWebGuiTransport tests."""

    def __init__(self, *, body: bytes, final_url: str, charset: str | None = "utf-8") -> None:
        self._body = body
        self._final_url = final_url
        self.headers = EmailMessage()
        if charset:
            self.headers.set_type("text/html")
            self.headers.set_param("charset", charset)

    def __enter__(self) -> "FakeUrlLibResponse":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self._body
        return self._body[:size]

    def geturl(self) -> str:
        return self._final_url


class FakeUrlLibOpener:
    """Fake urllib opener returning one deterministic response."""

    def __init__(self, response: FakeUrlLibResponse) -> None:
        self.response = response
        self.requests: list[Request] = []

    def open(self, request: Request, *, timeout: float) -> FakeUrlLibResponse:
        self.requests.append(request)
        assert timeout == 15.0
        return self.response


def test_same_origin_redirect_handler_rejects_cleartext_or_cross_origin_redirects() -> None:
    handler = SameOriginHttpsRedirectHandler()
    request = Request("https://192.0.2.1:8843/")

    with pytest.raises(WebGuiTransportError, match="Unsafe WebGUI redirect"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://192.0.2.1:8843/")

    with pytest.raises(WebGuiTransportError, match="Unsafe WebGUI redirect"):
        handler.redirect_request(request, None, 302, "Found", {}, "https://198.51.100.1/")

    redirected = handler.redirect_request(request, None, 302, "Found", {}, "/index.php")

    assert redirected is not None
    assert redirected.full_url == "https://192.0.2.1:8843/index.php"


def test_urllib_transport_rejects_unsafe_final_response_url() -> None:
    transport = UrlLibWebGuiTransport()
    transport.__dict__["_opener"] = FakeUrlLibOpener(
        FakeUrlLibResponse(body=b"<html></html>", final_url="http://192.0.2.1:8843/")
    )

    with pytest.raises(WebGuiTransportError, match="Unsafe WebGUI response URL"):
        transport.get("https://192.0.2.1:8843/")


def test_urllib_transport_rejects_cleartext_request_url_before_network_call() -> None:
    opener = FakeUrlLibOpener(
        FakeUrlLibResponse(body=b"<html></html>", final_url="http://192.0.2.1:8843/")
    )
    transport = UrlLibWebGuiTransport()
    transport.__dict__["_opener"] = opener

    with pytest.raises(WebGuiTransportError, match="Unsafe WebGUI request URL"):
        transport.get("http://192.0.2.1:8843/")

    assert not opener.requests


def test_urllib_transport_rejects_oversized_responses_before_decoding() -> None:
    transport = UrlLibWebGuiTransport(max_response_bytes=4)
    transport.__dict__["_opener"] = FakeUrlLibOpener(
        FakeUrlLibResponse(body=b"abcde", final_url="https://192.0.2.1:8843/")
    )

    with pytest.raises(WebGuiTransportError, match="response exceeded"):
        transport.get("https://192.0.2.1:8843/")


def test_client_default_transport_uses_config_safety_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_settings: dict[str, object] = {}

    class CapturingTransport:
        """Transport double that captures constructor safety settings."""

        def __init__(self, *, verify_tls: bool, timeout: float, max_response_bytes: int) -> None:
            captured_settings["verify_tls"] = verify_tls
            captured_settings["timeout"] = timeout
            captured_settings["max_response_bytes"] = max_response_bytes

        def get(self, url: str) -> str:
            raise AssertionError(f"unexpected GET {url}")

        def post_form(self, url: str, data: dict[str, str]) -> str:
            raise AssertionError(f"unexpected POST {url} {data}")

    monkeypatch.setattr("pfsense_mcp.webgui.UrlLibWebGuiTransport", CapturingTransport)
    config = PfSenseConfig(
        base_url="https://192.0.2.1:8843",
        username="readonly-user",
        password=LOGIN_FORM_VALUE,
        verify_tls=False,
        timeout_seconds=4.5,
        max_response_bytes=8192,
    )

    PfSenseWebGuiClient(config)

    assert captured_settings == {
        "verify_tls": False,
        "timeout": 4.5,
        "max_response_bytes": 8192,
    }
