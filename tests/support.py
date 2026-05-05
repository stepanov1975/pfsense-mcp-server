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


class FakeStatusPageTransport:
    """Deterministic transport for testing authenticated WebGUI status pages."""

    def __init__(self, page_html: str) -> None:
        self.page_html = page_html
        self.get_urls: list[str] = []
        self.posted_forms: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str) -> str:
        self.get_urls.append(url)
        if url.endswith("/"):
            return login_page()
        return self.page_html

    def post_form(self, url: str, data: dict[str, str]) -> str:
        self.posted_forms.append((url, data))
        return dashboard_page()


def status_table_html(headers: list[str], rows: list[list[str]]) -> str:
    """Build a compact status page with one unrelated table and one data table."""
    header_html = "".join(f"<th>{header}</th>" for header in headers)
    row_html = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"""
    <html><body>
      <table><tr><th>Unrelated</th></tr><tr><td>ignore me</td></tr></table>
      <table class="table table-striped"><thead><tr>{header_html}</tr></thead><tbody>{row_html}</tbody></table>
    </body></html>
    """
