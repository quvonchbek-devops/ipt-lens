# Security Policy

IPT-Lens runs as root and changes the host firewall, so security reports are
taken seriously.

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
[Report a vulnerability](https://github.com/quvonchbek-devops/ipt-lens/security/advisories/new).

Please include:

- the version (`ipt-lens --version`) and how it was started (flags, token or not)
- what an attacker needs (network position, token, a victim visiting a page)
- steps to reproduce, and what happens

You can expect an acknowledgement within 7 days. Once a fix is ready, a release
is published and the advisory is disclosed with credit, unless you prefer
otherwise.

## Security model

What IPT-Lens is designed to resist:

- **Untrusted rule input.** Rules are checked against allowlists of options,
  modules and targets and passed to `iptables` as arguments, never through a shell.
- **Requests from other web pages.** POST requests must be `application/json`,
  cross-site and foreign-origin requests are refused, and the `Host` header is
  checked against an allowlist to stop DNS rebinding.
- **Locking yourself out.** Every change is rolled back unless confirmed, and the
  rollback survives a crash or restart.

What it relies on you for:

- **Network exposure.** Keep it on loopback or a VPN address. A token is required
  on non-loopback addresses, but the panel should never face the internet.
- **TLS.** IPT-Lens serves plain HTTP. Over a VPN or SSH tunnel the transport is
  already encrypted; anything else needs a TLS-terminating reverse proxy (then set
  `--allowed-hosts`).
- **The token.** Anyone with the token can change the firewall. Use a long random
  value and keep `/etc/ipt-lens/env` at mode 0600.
- **Host access.** Anyone who can write to the state directory or the binary
  already controls the host.
