"""Tests for pfSense WebGUI authentication helpers."""

import pytest

from pfsense_mcp.webgui import (
    WebGuiAuthError,
    build_login_payload,
    extract_csrf_magic,
    login_succeeded,
)


def test_extract_csrf_magic_reads_token_from_login_form() -> None:
    html = """
    <html>
      <body>
        <form method="post">
          <input type="hidden" name="__csrf_magic" value="sid:abc123,1700000000" />
        </form>
      </body>
    </html>
    """

    assert extract_csrf_magic(html) == "sid:abc123,1700000000"


def test_extract_csrf_magic_handles_attribute_order_and_html_entities() -> None:
    html = '<input value="sid:abc&amp;def" id="csrf" name="__csrf_magic" type="hidden">'

    assert extract_csrf_magic(html) == "sid:abc&def"


def test_extract_csrf_magic_raises_when_login_page_has_no_token() -> None:
    with pytest.raises(WebGuiAuthError, match="CSRF"):
        extract_csrf_magic("<html><form><input name='usernamefld'></form></html>")


def test_build_login_payload_uses_pfsense_webgui_field_names() -> None:
    field_value = "pw"
    payload = build_login_payload(
        csrf_magic="sid:abc123,1700000000",
        username="readonly-user",
        password=field_value,
    )

    assert payload == {
        "__csrf_magic": "sid:abc123,1700000000",
        "usernamefld": "readonly-user",
        "passwordfld": field_value,
        "login": "Sign In",
    }


def test_login_succeeded_requires_authenticated_markers_without_login_form() -> None:
    html = """
    <html>
      <title>pfSense - Dashboard</title>
      <body><a href="/index.php?logout">Logout</a></body>
    </html>
    """

    assert login_succeeded(html) is True


def test_login_succeeded_rejects_failed_or_still_on_login_form() -> None:
    assert login_succeeded("<form><input name='usernamefld'></form>") is False
    assert login_succeeded("Username or Password incorrect") is False
