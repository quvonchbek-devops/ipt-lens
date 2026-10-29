# Roadmap

This is a direction, not a promise. Open an issue to discuss any item before
working on it.

## v0.1 — first public release (done)

Crash-safe rollback, cross-site and DNS-rebinding protection, honest simulator
results, optional persistence, English UI, tests, CI, release builds, systemd
unit and community docs. See [CHANGELOG.md](../CHANGELOG.md).

## v0.2 — reach and correctness

- **IPv6:** `ip6tables` support with a family switch in the UI.
- **Simulator coverage:** `OUTPUT` for locally generated traffic, plus the
  `mangle` and `raw` tables in kernel order.
- **Localization:** the UI string table moves to a locale file; Uzbek as the
  first translation after English.
- **Safer rollback:** re-insert and restore rules by matching neighbors instead
  of by bare position, so concurrent changes by other tools cannot shift it, and
  check the live ruleset before replaying an undo after a crash.
- **Protect Docker's jump rules:** treat `FORWARD -j DOCKER-USER` and similar
  jumps that Docker manages as locked.
- **Audit log:** an append-only record of every apply, confirm and rollback.

## Later

- Native nftables backend (read and simulate first, then changes).
- Multi-step changes from the UI (batch several rules under one confirmation).
- Read-only mode and a second, view-only token.
- Managing several servers from one panel.

## Not planned

- Exposing the panel to the public internet without a VPN or tunnel.
- A general-purpose firewall manager with its own rule language. IPT-Lens stays a
  lens on iptables as it is.
