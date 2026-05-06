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
- Read-only firewall state retrieval and parsing from `/diag_dump_states.php`, with optional exact-IP filtering and state-kill action links stripped from results.
- Read-only firewall log retrieval and parsing from `/status_logs_filter.php`, with optional exact-IP/action/interface/protocol filtering and bounded results.
- Read-only firewall alias retrieval and parsing from `/firewall_aliases.php`, with mutating action links omitted from results.
- Read-only firewall rule retrieval and parsing from `/firewall_rules.php`, optionally for one interface tab, with mutating action links omitted from results.
- MCP stdio server entrypoint with read-only login-check, ARP, DHCP, firewall-state, firewall-log, firewall-alias, and firewall-rule tools annotated as non-destructive.
- Deterministic pytest coverage for configuration, auth helpers, WebGUI client behavior, ARP parsing, DHCP parsing, firewall-state parsing, firewall inspection parsing, and MCP tool handler registration.

Not implemented yet:

- pfSense REST API integration.
- Interface/VLAN, route/gateway, and NDP read-only tools.
- Any mutating pfSense action. Mutations are intentionally out of scope unless explicitly approved later.

## Safety model

This repository is designed for a cautious homelab security workflow.

- Read-only is the default and expected operating mode.
- Local secrets belong only in `.env`, which is gitignored.
- Do not commit real pfSense credentials, API keys, cookies, CSRF tokens, or exported configs containing secrets.
- WebGUI requests are limited to relative paths and reject absolute URLs and parent-directory traversal.
- Firewall state inspection is read-only: parser output omits WebGUI state-kill action links, validates optional IP filters as single IP addresses, and caps returned states.
- Firewall log/rule/alias inspection is read-only: parser output omits WebGUI action URLs and labels that would enable mutation, validates optional filters before WebGUI fetches where applicable, and caps returned log entries.
- MCP tools are annotated with `readOnlyHint=True` and `destructiveHint=False` for compatible clients.
- TLS verification is enabled by default. Disable it only deliberately for local/self-signed homelab testing.
- MCP stdout should remain clean JSON-RPC when the MCP server entrypoint is added; diagnostics should go to stderr.

## Requirements

- Python 3.11+
- `mcp` Python SDK for the stdio MCP server
- `pytest` for tests
- `pylint` for linting
- `bandit` for Python static security scanning
- `detect-secrets` for repository secret scanning
- `pip-audit` for Python dependency vulnerability auditing
- `pre-commit` for local commit-time guardrails

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
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
pre-commit install
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
- `pfsense_get_firewall_states` — returns parsed active firewall states from `/diag_dump_states.php`, optionally exact-filtered by `ip_address` and capped by `limit` (max 200); action links for killing states are never returned.
- `pfsense_get_firewall_logs` — returns parsed firewall log entries from `/status_logs_filter.php`, optionally filtered by exact `ip_address`, `action` (`pass`, `block`, `reject`), `interface`, and protocol prefix; returned entries are capped by `limit` (max 200).
- `pfsense_get_firewall_aliases` — returns parsed firewall aliases from `/firewall_aliases.php`; action links for editing/copying/deleting aliases are never returned.
- `pfsense_get_firewall_rules` — returns parsed firewall rules from `/firewall_rules.php`, optionally for one safe interface token; action links for editing/toggling/deleting rules are never returned.

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
matching_states = client.get_firewall_states(ip_address="192.168.1.202", limit=25)
blocked_logs = client.get_firewall_logs(action="block", limit=25)
aliases = client.get_firewall_aliases()
wan_rules = client.get_firewall_rules(interface="wan")
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

Run the full local verification gate:

```bash
make verify
```

Or run checks individually:

```bash
python3 -m pytest -q
PYTHONPATH=src python3 -m pylint src tests
python3 -m bandit --configfile pyproject.toml --recursive src
python3 -m pip_audit . --strict
python3 -m detect_secrets scan --baseline .secrets.baseline --force-use-all-plugins
git diff --check
```

Run all configured pre-commit hooks manually:

```bash
pre-commit run --all-files
```

The GitHub Actions CI workflow runs tests, pylint, Bandit, pip-audit, and the detect-secrets baseline on pushes and pull requests.

## Development workflow

For implementation work, use a strict read-first/TDD workflow:

1. Add focused tests before production behavior.
2. Run the focused test and confirm it fails for the expected reason.
3. Implement the minimal read-only code path.
4. Run focused tests, then the full test suite.
5. Run `make verify`, `pre-commit run --all-files`, and `git diff --check`.
6. Review the diff for credentials, unsafe shell execution, `eval`/`exec`, pickle usage, unsafe SQL string formatting, and unintended pfSense mutation paths.
7. Commit only after validation is clean.

## Roadmap

Likely next read-only steps:

- Add interface and VLAN attribution.
- Add route and gateway status views.
- Add focused lookup/crosscheck tools for MAC/IP evidence correlation.
- Add NDP/IPv6 neighbor parsing.
- Revisit pfSense REST API support if the REST package/path is enabled in the target environment.

## Acknowledgments

This project was informed by reviewing [`gensecaihq/pfsense-mcp-server`](https://github.com/gensecaihq/pfsense-mcp-server) as a reference implementation for pfSense MCP concepts.

## Repository

GitHub: `git@github.com:stepanov1975/pfsense-mcp-server.git`
