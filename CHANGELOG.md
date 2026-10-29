# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-29

First public release.

### Added

- **Simple view**, now the default: a list of ports (host listeners and Docker
  published ports) with three choices each, *Everyone*, *VPN only* or
  *Nobody*, plus a setting for every other port. Quick tasks: lock the server
  behind the VPN, open a port, close a container port. Changes are reviewed in
  plain sentences, with the iptables commands folded away, and go through the
  usual confirm-or-rollback flow. The previous UI is the *Advanced* view.
- `GET /api/v1/access`, `POST /api/v1/access/preview`, `POST /api/v1/access/apply`.
- Light theme. The UI follows the system setting; a button in the top bar
  switches between system, light and dark, remembered per browser. Colors are
  semantic tokens with both themes checked against WCAG AA.
- Colors encode exposure in the simple view: amber for *Everyone*, blue for
  *VPN only*, neutral with a lock for *Nobody*, plus an icon per level. Red is
  kept for errors and destructive actions, green for success. Unapplied edits
  are violet. The review separates warnings from informational notes.
- The simple view filters IPv6 too, through `ip6tables` when present, in the
  same confirm-or-rollback step as IPv4. ICMPv6 and the DHCPv6 client stay
  allowed. `--persist-file6` saves the IPv6 ruleset; backups include it.
- `--persist-file`: on confirm, save the full ruleset (for example to
  `/etc/iptables/rules.v4`) so confirmed changes survive a reboot.
- `--keep-backups` (default 20): old `iptables-save` snapshots are pruned.
- `--allowed-hosts` for running behind a reverse proxy (entries may carry a
  port or IPv6 brackets).
- Outside demo mode an API token is always required. If `IPTLENS_TOKEN` is not
  set, one is generated in `<state-dir>/token` (mode 0600) on first start.
- `--version` flag. The version is shown in the UI and returned by `/api/v1/state`.
- `GET /healthz` for liveness checks.
- The simulator marks a result as approximate, with one warning per rule, when a
  matching rule uses conditions it cannot evaluate (ipset, limit, iprange,
  source ports, address types other than LOCAL, ...).
- `/api/v1/state` marks chains and rules as `protected`, so clients no longer
  keep their own copy of the managed-chain list.
- `/api/v1/confirm` returns `persisted`, telling whether the ruleset was saved.
- Tests for the watchdog, the HTTP API and flag handling.
- CI (gofmt, vet, race tests, staticcheck), GoReleaser releases for linux
  amd64/arm64, a hardened systemd unit and an env example. Workflow actions
  are pinned to commit SHAs and kept current by Dependabot.
- README, contributing guide, security policy, code of conduct, roadmap and
  architecture notes.

### Changed

- All UI text, API errors, logs and code comments are in English.
- Module path is `github.com/quvonchbek-devops/ipt-lens`.
- Undo commands run in reverse order of the applied steps.
- Backups, the pending record and the persisted ruleset are all written
  atomically.

### Fixed

- **Rollback could be skipped after a crash.** The pending change was recorded
  only after the rule was applied; a crash in between left the rule in place
  with nothing to roll it back. It is now written (atomically) first.
- If a step of a change failed, earlier steps stayed applied. They are now
  undone.
- **Cross-site requests could change the firewall** when no token was set: a
  web page could POST a `text/plain` body to `127.0.0.1`. POST now requires
  `application/json`, cross-site and foreign-origin requests are refused, and
  the `Host` header is checked to stop DNS rebinding.
- Comments containing `\"` or `\'` from `iptables-save` were parsed incorrectly.
- **Any local process could change the firewall** through the token-less
  loopback API (another user, or an SSRF in another app on the host). A token is
  now always required outside demo mode.
- New rules could be added to Docker, Kubernetes, Calico, libvirt and ufw chains.
- After a reboot, the undo of an unconfirmed change was replayed against the
  freshly restored ruleset and could duplicate or overwrite the wrong rule. It
  is now discarded when the boot ID differs.
- `pending.json` was trusted blindly. The state directory must now be private,
  and recorded undo commands are checked before they run.
- When a rollback failed (after a failed step, on timeout, or on restart), its
  record was deleted, so nothing showed that a change might still be applied
  and the next change could proceed. The record now stays in the state
  directory and blocks new changes until an operator checks the rules and
  removes it.
- `--persist-file` saved Docker and Kubernetes chains, whose stale copies broke
  container networking at boot, and replaced a symlinked file instead of
  writing its target.
- Behind a reverse proxy, every browser POST was rejected because the Origin
  (public name) did not match the Host header.
- The simulator presented guesses as exact when the request left out a field a
  rule checks (protocol, port, address, interface), treated targets it does not
  model (NFQUEUE, TPROXY, ...) as harmless, and warned about LOG and other rules
  that cannot change the verdict.
- The confirm message claimed the rule was saved permanently even though
  nothing was written to disk.
- Tertiary text in the UI did not meet WCAG AA contrast.

### Removed

- The "server address" setting in the UI. The page's Content Security Policy
  always blocked requests to other servers, so it never worked.

[Unreleased]: https://github.com/quvonchbek-devops/ipt-lens/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/quvonchbek-devops/ipt-lens/releases/tag/v0.1.0
