# Security Policy

## Supported status

This project is early-stage and intended for a controlled homelab environment. Treat all MCP tools as security-sensitive because they can expose firewall state.

## Reporting vulnerabilities

Report suspected vulnerabilities privately to the repository owner. Do not open public issues that contain exploit details, pfSense URLs, cookies, CSRF tokens, API keys, credentials, packet captures, or exported pfSense configuration secrets.

## Secret handling

- Never commit real pfSense credentials, API keys, cookies, CSRF tokens, private keys, VPN material, or exported configs containing secrets.
- Keep local credentials only in `.env`; this file is gitignored and should be mode `0600`.
- Use `.env.example` for documentation and placeholders only.
- Run the repository validation commands before commit, including the detect-secrets baseline check.

## Security posture

- The server is read-only by default.
- Mutating pfSense tools are out of scope unless explicitly approved and reviewed.
- WebGUI access should use a dedicated read-only pfSense account.
- TLS verification is enabled by default; disabling it is only for deliberate local self-signed certificate testing.
