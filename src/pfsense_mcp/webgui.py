"""pfSense WebGUI authentication parsing helpers."""

from __future__ import annotations

from html.parser import HTMLParser


class WebGuiAuthError(ValueError):
    """Raised when pfSense WebGUI authentication HTML cannot be parsed safely."""


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
