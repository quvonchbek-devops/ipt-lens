# Roadmap

This is a direction, not a promise. Open an issue to discuss any item before
working on it.

## v0.1 — first public release (done)

Crash-safe rollback, cross-site and DNS-rebinding protection, honest simulator
results, optional persistence, English UI, tests, CI, release builds, systemd
unit and community docs. See [CHANGELOG.md](../CHANGELOG.md).

## v0.2 — reach and correctness

- **IPv6 in the Advanced view:** a family switch for the rules table and the
  simulator (the simple view already applies its policy to IPv6).
- **Simulator coverage:** `OUTPUT` for locally generated traffic, plus the
  `mangle` and `raw` tables in kernel order.
- **Localization:** the UI string table moves to a locale file; Uzbek as the
  first translation after English.
- **Safer rollback (done):** rules are restored next to their old neighbors,
  and every undo is checked against the live ruleset before it runs.
- **Protect Docker's jump rules (done):** `FORWARD -j DOCKER-USER`, the newer
  `DOCKER-*` chains and Docker's bridge rules are locked.
- **Audit log:** an append-only record of every apply, confirm and rollback.
- **Faster simple-view apply (done):** each managed chain is built with one
  `iptables-restore --noflush` call.

## Later

- Native nftables backend (read and simulate first, then changes).
- Multi-step changes from the UI (batch several rules under one confirmation).
- Read-only mode and a second, view-only token.
- Managing several servers from one panel.

## Not planned

- Exposing the panel to the public internet without a VPN or tunnel.
- A general-purpose firewall manager with its own rule language. IPT-Lens stays a
  lens on iptables as it is.
