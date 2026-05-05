"""pfSense WebGUI authentication and session helpers."""

from __future__ import annotations

from html.parser import HTMLParser
from http.cookiejar import CookieJar
import ssl
from typing import Protocol
from urllib.parse import ParseResult, unquote, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, HTTPSHandler, Request, build_opener

from pfsense_mcp.arp import ArpEntry, parse_arp_table
from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.dhcp import DhcpLease, parse_dhcp_leases


class WebGuiAuthError(ValueError):
    """Raised when pfSense WebGUI authentication HTML cannot be parsed safely."""


class WebGuiTransportError(RuntimeError):
    """Raised when WebGUI transport behavior would violate safety constraints."""


DEFAULT_MAX_RESPONSE_BYTES = 2_000_000


class SameOriginHttpsRedirectHandler(HTTPRedirectHandler):
    """Redirect handler that permits only same-origin HTTPS WebGUI redirects."""

    def redirect_request(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, req: Request, fp: object, code: int, msg: str, headers: object, newurl: str
    ) -> Request | None:
        redirected_url = urljoin(req.full_url, newurl)
        _ensure_same_origin_https(req.full_url, redirected_url, "Unsafe WebGUI redirect blocked")
        return super().redirect_request(req, fp, code, msg, headers, redirected_url)


class WebGuiTransport(Protocol):
    """Minimal transport interface used by the WebGUI session client."""

    def get(self, url: str) -> str:
        """Return the decoded HTML body for a WebGUI GET request."""

    def post_form(self, url: str, data: dict[str, str]) -> str:
        """Return the decoded HTML body for a form-encoded WebGUI POST request."""


class UrlLibWebGuiTransport:
    """Cookie-preserving urllib transport for pfSense WebGUI requests."""

    def __init__(
        self,
        *,
        verify_tls: bool = True,
        timeout: float = 15.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        if verify_tls:
            context = ssl.create_default_context()
        else:
            # Explicit opt-in for local pfSense self-signed certificate testing.
            context = ssl._create_unverified_context()  # nosec B323
        self._opener = build_opener(
            HTTPCookieProcessor(CookieJar()),
            HTTPSHandler(context=context),
            SameOriginHttpsRedirectHandler(),
        )
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes

    def get(self, url: str) -> str:
        """Return the decoded HTML body for a WebGUI GET request."""
        return self._open(Request(url, method="GET"))

    def post_form(self, url: str, data: dict[str, str]) -> str:
        """Return the decoded HTML body for a form-encoded WebGUI POST request."""
        encoded = urlencode(data).encode("utf-8")
        request = Request(
            url,
            data=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        return self._open(request)

    def _open(self, request: Request) -> str:
        _ensure_https_url(request.full_url, "Unsafe WebGUI request URL")
        with self._opener.open(request, timeout=self._timeout) as response:
            _ensure_same_origin_https(request.full_url, response.geturl(), "Unsafe WebGUI response URL")
            charset = response.headers.get_content_charset() or "utf-8"
            body = response.read(self._max_response_bytes + 1)
            if len(body) > self._max_response_bytes:
                raise WebGuiTransportError("WebGUI response exceeded configured size limit")
            return body.decode(charset, errors="replace")


class _CsrfInputParser(HTMLParser):
    """Extract the pfSense __csrf_magic hidden input value from login HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.csrf_magic: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        attributes = {key.lower(): value for key, value in attrs if value is not None}
        if attributes.get("name") == "__csrf_magic":
            self.csrf_magic = attributes.get("value")


def extract_csrf_magic(html: str) -> str:
    """Extract pfSense's WebGUI CSRF token from a login page."""
    parser = _CsrfInputParser()
    parser.feed(html)
    if not parser.csrf_magic:
        raise WebGuiAuthError("Could not find pfSense WebGUI CSRF token __csrf_magic")
    return parser.csrf_magic


def build_login_payload(*, csrf_magic: str, username: str, password: str) -> dict[str, str]:
    """Build the form payload expected by the pfSense WebGUI login page."""
    return {
        "__csrf_magic": csrf_magic,
        "usernamefld": username,
        "passwordfld": password,
        "login": "Sign In",
    }


def login_succeeded(html: str) -> bool:
    """Return True when a pfSense WebGUI response looks authenticated."""
    normalized = html.lower()
    failure_markers = (
        "usernamefld",
        "passwordfld",
        "username or password incorrect",
        "invalid username or password",
    )
    if any(marker in normalized for marker in failure_markers):
        return False

    success_markers = (
        "index.php?logout",
        "logout",
        "dashboard",
    )
    return all(marker in normalized for marker in success_markers)


class PfSenseWebGuiClient:
    """Authenticated read-only pfSense WebGUI client."""

    def __init__(self, config: PfSenseConfig, *, transport: WebGuiTransport | None = None) -> None:
        self._config = config
        self._transport = transport or UrlLibWebGuiTransport(
            verify_tls=config.verify_tls,
            timeout=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
        )
        self._authenticated = False

    @property
    def authenticated(self) -> bool:
        """Return whether the current session has completed WebGUI login."""
        return self._authenticated

    def login(self) -> None:
        """Authenticate to pfSense WebGUI using the configured read-only account."""
        login_url = self._build_url("/")
        login_page = self._transport.get(login_url)
        csrf_magic = extract_csrf_magic(login_page)
        payload = build_login_payload(
            csrf_magic=csrf_magic,
            username=self._config.username,
            password=self._config.password,
        )
        response = self._transport.post_form(login_url, payload)
        if not login_succeeded(response):
            self._authenticated = False
            raise WebGuiAuthError("pfSense WebGUI login did not reach authenticated dashboard")
        self._authenticated = True

    def get_page(self, path: str) -> str:
        """Return an authenticated WebGUI page by relative path."""
        page_url = self._build_url(path)
        if not self._authenticated:
            self.login()
        return self._transport.get(page_url)

    def get_arp_table(self) -> list[ArpEntry]:
        """Return parsed ARP entries from the read-only WebGUI ARP table page."""
        return parse_arp_table(self.get_page("/diag_arp.php"))

    def get_dhcp_leases(self) -> list[DhcpLease]:
        """Return parsed DHCP leases from the read-only WebGUI DHCP leases page."""
        return parse_dhcp_leases(self.get_page("/status_dhcp_leases.php"))

    def _build_url(self, path: str) -> str:
        safe_path = _normalize_relative_webgui_path(path)
        return f"{self._config.base_url}{safe_path}"


def _ensure_same_origin_https(original_url: str, candidate_url: str, message: str) -> None:
    _ensure_https_url(original_url, message)
    _ensure_https_url(candidate_url, message)
    original = urlparse(original_url)
    candidate = urlparse(candidate_url)
    if _origin_tuple(candidate) != _origin_tuple(original):
        raise WebGuiTransportError(message)


def _ensure_https_url(url: str, message: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise WebGuiTransportError(message)
    _origin_tuple(parsed)


def _origin_tuple(parsed: ParseResult) -> tuple[str, str, int | None]:
    try:
        port = parsed.port
    except ValueError as exc:
        raise WebGuiTransportError("Invalid WebGUI URL port") from exc
    default_port = 443 if parsed.scheme == "https" else None
    return (parsed.scheme.lower(), (parsed.hostname or "").lower(), port or default_port)


def _normalize_relative_webgui_path(path: str) -> str:
    parsed = urlparse(path)
    if parsed.scheme or parsed.netloc:
        raise ValueError("Expected a relative WebGUI path, not an absolute URL")

    decoded_path = unquote(parsed.path)
    if any(part == ".." for part in decoded_path.split("/")):
        raise ValueError("WebGUI path must not contain parent directory segments")

    normalized_path = parsed.path if parsed.path.startswith("/") else f"/{parsed.path}"
    if parsed.query:
        return f"{normalized_path}?{parsed.query}"
    return normalized_path
