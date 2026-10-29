# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Each port in the simple view shows the program listening on it (`sshd`,
  `nginx`, ...), read from `/proc/<pid>/fd` and `/proc/<pid>/comm`.
- **Trusted addresses** in the simple view: IPv4 or IPv6 addresses or ranges,
  such as an office IP, let in wherever "VPN only" is set, with or without a
  VPN. Ranges wider than /8 (IPv4) or /16 (IPv6) are refused.
- **Slow down password guessing** on SSH when it is open to everyone: each
  source address gets at most 6 new connections a minute (`hashlimit`), on the
  host and container chains.
- **Undo now** next to **Keep this change** (the confirm button, renamed):
  undoes a pending change at once instead of waiting for the timer.
  `POST /api/v1/rollback`.

- Audit log: every apply, confirm and rollback (failed ones and rollbacks at
  start included) is appended to `<state-dir>/audit.log` as JSON lines, with
  the commands that ran. `GET /api/v1/audit` returns the latest 200 entries,
  and the simple view lists them under *Change history*.

- The simple view opens with one answer: how exposed this server is. Ports
  that should almost never be public (databases, the Docker API, kubelet and
  etcd, Prometheus, Telnet/FTP, SMB/NFS, remote desktop) are called out as
  risky, with one button that makes them VPN only (or closes them when no VPN
  is chosen). The change goes through the usual review and confirm steps.
  It also warns, before anything else, when a VPN endpoint (WireGuard,
  Tailscale, OpenVPN) would stop being reachable and take the VPN down.

### Changed

- The simple view is shorter: the quick-task cards are gone ("Lock the
  server" moved into the status card, "Add a port" sits under the port list,
  and closing a container port is the row's own *Nobody* button), the VPN
  card folds to one line once a VPN is chosen, port rows drop the repeated
  sentence, and "Everything else" is now "Any other port".

### Changed

- Safer rollback. Every undo command is checked against the live ruleset
  first, so a change interrupted by a crash rolls back cleanly instead of
  failing or adding a rule twice. A failed check (for example a lock timeout)
  keeps the record for an operator; it never skips the undo.
- Rolling back a deleted or edited rule puts the old rule back next to the
  rule that was above (or below) it, not at a bare position, so rules another
  tool inserts during the confirm window cannot shift it. An edit is undone by
  removing the new rule and re-inserting the old one, never by `-R` at a
  position. A rule that is unique in its chain is deleted by its spec.
- Editing a rule into one that already exists in the chain is refused.
- The simple view builds each managed chain with one atomic
  `iptables-restore --noflush` call instead of one `iptables` call per rule:
  much faster on large policies, and a chain is never left half-built.
  Requires iptables 1.6.2 or newer.
- More of what Docker manages is locked in the Advanced view: Docker 28's new
  chains (`DOCKER-FORWARD`, `DOCKER-BRIDGE`, `DOCKER-CT`, `DOCKER-INTERNAL`),
  which `--persist-file` also leaves out, and, where Docker manages the table,
  the plain `FORWARD -j DOCKER-USER` jump and the exact `FORWARD`/`POSTROUTING`
  rules Docker writes for `docker0` and `br-<id>` bridges. Those two are still
  saved by `--persist-file`, so a hand-written rule of the same shape is never
  lost on reboot. Deleting the jump used to be possible and silently
  switched off every `DOCKER-USER` rule, the simple view's included. Your own
  rules inside `DOCKER-USER` stay editable and persisted.
- The recovery check also refuses `-M` and abbreviations of `--modprobe`, and
  position-only undo records (`-R`, `-D <n>`) written by older versions.

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
  *VPN only*, neutral with a lock for *Nobody*, plus an icon per level; the
  selected level is a solid, bright fill in both themes. Red is
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
