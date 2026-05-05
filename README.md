# pfSense MCP Server

Read-only pfSense MCP server work-in-progress for safely exposing selected pfSense status data to an MCP client.

The current codebase provides the read-only configuration, authenticated WebGUI session client, and parsers needed for the first MCP resources/tools. It intentionally favors conservative behavior over broad access: no pfSense mutation APIs are implemented.

## Status

Implemented so far:

- Safe local configuration loading from a dotenv-style `.env` file.
- HTTPS-only pfSense base URL validation by default.
- Read-only mode enforcement via `PFSENSE_MCP_READ_ONLY=true`.
- Password redaction in configuration representations.
- Authenticated pfSense WebGUI login helpers using pfSense's `__csrf_magic` token.
- Cookie-preserving WebGUI client transport using Python stdlib `urllib`.
- Relative-path validation for WebGUI page fetches.
- Read-only ARP table retrieval and parsing from `/diag_arp.php`.
- Read-only DHCP lease retrieval and parsing from `/status_dhcp_leases.php`.
- MCP stdio server entrypoint with read-only login-check, ARP, and DHCP tools.
- Deterministic pytest coverage for configuration, auth helpers, WebGUI client behavior, ARP parsing, DHCP parsing, and MCP tool handler registration.

Not implemented yet:

- pfSense REST API integration.
- Interface/VLAN, route/gateway, alias, firewall rule, and NDP read-only tools.
- Any mutating pfSense action. Mutations are intentionally out of scope unless explicitly approved later.

## Safety model

This repository is designed for a cautious homelab security workflow.

- Read-only is the default and expected operating mode.
- Local secrets belong only in `.env`, which is gitignored.
- Do not commit real pfSense credentials, API keys, cookies, CSRF tokens, or exported configs containing secrets.
- WebGUI requests are limited to relative paths and reject absolute URLs and parent-directory traversal.
- TLS verification is enabled by default. Disable it only deliberately for local/self-signed homelab testing.
- MCP stdout should remain clean JSON-RPC when the MCP server entrypoint is added; diagnostics should go to stderr.

## Requirements

- Python 3.11+
- `mcp` Python SDK for the stdio MCP server
- `pytest` for tests
- `pylint` for linting

## Configuration

Create a local `.env` file in the repository root:

```env
PFSENSE_BASE_URL=https://192.168.1.1:8843
PFSENSE_USERNAME=<read-only-pfsense-username>
PFSENSE_PASSWORD=<read-only-pfsense-password>
PFSENSE_MCP_READ_ONLY=true
# Optional safety/runtime knobs. Defaults shown.
PFSENSE_VERIFY_TLS=true
PFSENSE_TIMEOUT_SECONDS=15.0
PFSENSE_MAX_RESPONSE_BYTES=2000000
```

Recommended file permissions:

```bash
chmod 600 .env
```

Notes:

- `PFSENSE_BASE_URL` must be an HTTPS origin URL only: scheme, host, and optional port; no username, password, path, query, or fragment.
- HTTPS is required by default.
- `PFSENSE_MCP_READ_ONLY` defaults to `true` when omitted, but keeping it explicit is clearer.
- `PFSENSE_VERIFY_TLS=false` is available for local self-signed certificates, but only use it after accepting the MITM risk.
- `PFSENSE_MCP_ENV_PATH` can point the installed console script at a gitignored env file when the process is launched from another working directory.
- Use a dedicated pfSense read-only account.

## Development setup

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip pytest pylint
python3 -m pip install -e .
```

Because the package uses a `src/` layout, either run tools with the configured project settings or set `PYTHONPATH=src` for direct Python snippets.

## MCP server

Run the MCP server over stdio:

```bash
cd /home/alex/repos/pfsense-mcp-server
python3 -m pfsense_mcp.server
```

If the project is installed in a virtual environment, the console script is also available:

```bash
pfsense-mcp-server
```

Current read-only MCP tools:

- `pfsense_check_webgui_login` — returns reachability/authentication metadata only: `reachable`, `authenticated`, `base_url_host`, `read_only`, and `error_type` on failure. It never returns exception messages, passwords, cookies, or CSRF tokens.
- `pfsense_get_arp_table` — returns parsed ARP table entries from `/diag_arp.php`; failures return safe `error_type` metadata only.
- `pfsense_get_dhcp_leases` — returns parsed DHCP lease entries from `/status_dhcp_leases.php`; failures return safe `error_type` metadata only.

Example Hermes MCP configuration snippet, for review only until explicitly applied:

```yaml
mcp_servers:
  pfsense:
    command: "python3"
    args: ["-m", "pfsense_mcp.server"]
    env:
      PFSENSE_MCP_ENV_PATH: "/home/alex/repos/pfsense-mcp-server/.env"
    timeout: 120
    connect_timeout: 60
```

## Usage examples

Load local configuration:

```python
from pfsense_mcp import load_config

config = load_config(".env")
print(config)  # password is redacted
```

Parse an exported or fixture ARP table HTML page:

```python
from pfsense_mcp import parse_arp_table

entries = parse_arp_table(html)
for entry in entries:
    print(entry.ip_address, entry.mac_address, entry.interface)
```

Parse an exported or fixture DHCP leases HTML page:

```python
from pfsense_mcp import parse_dhcp_leases

leases = parse_dhcp_leases(html)
for lease in leases:
    print(lease.ip_address, lease.mac_address, lease.hostname, lease.online)
```

Fetch read-only WebGUI data through the authenticated client:

```python
from pfsense_mcp import PfSenseWebGuiClient, load_config

config = load_config(".env")
client = PfSenseWebGuiClient(config)

arp_entries = client.get_arp_table()
dhcp_leases = client.get_dhcp_leases()
```

For self-signed local pfSense certificates, prefer the `.env` setting below only when you understand the MITM risk:

```env
PFSENSE_VERIFY_TLS=false
```

For one-off Python snippets, you can still pass an explicit transport:

```python
from pfsense_mcp.webgui import PfSenseWebGuiClient, UrlLibWebGuiTransport
from pfsense_mcp import load_config

config = load_config(".env")
transport = UrlLibWebGuiTransport(verify_tls=False)
client = PfSenseWebGuiClient(config, transport=transport)
```

## Validation

Run the full test suite:

```bash
python3 -m pytest -q
```

Run pylint:

```bash
PYTHONPATH=src python3 -m pylint src tests
```

Check for whitespace errors before committing:

```bash
git diff --check
```

## Development workflow

For implementation work, use a strict read-first/TDD workflow:

1. Add focused tests before production behavior.
2. Run the focused test and confirm it fails for the expected reason.
3. Implement the minimal read-only code path.
4. Run focused tests, then the full test suite.
5. Run pylint and `git diff --check`.
6. Review the diff for credentials, unsafe shell execution, `eval`/`exec`, pickle usage, and unsafe SQL string formatting.
7. Commit only after validation is clean.

## Roadmap

Likely next read-only steps:

- Add interface and VLAN attribution.
- Add route and gateway status views.
- Add aliases and firewall rules as read-only inspection data.
- Add focused lookup/crosscheck tools for MAC/IP evidence correlation.
- Add NDP/IPv6 neighbor parsing.
- Revisit pfSense REST API support if the REST package/path is enabled in the target environment.

## Repository

GitHub: `git@github.com:stepanov1975/pfsense-mcp-server.git`
