# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-28

First public release.

### Added

- `--persist-file`: on confirm, save the full ruleset (for example to
  `/etc/iptables/rules.v4`) so confirmed changes survive a reboot.
- `--keep-backups` (default 20): old `iptables-save` snapshots are pruned.
- `--allowed-hosts` for running behind a reverse proxy.
- `--version` flag. The version is shown in the UI and returned by `/api/v1/state`.
- `GET /healthz` for liveness checks.
- The simulator marks a result as approximate, with a warning per rule, when a
  matching rule uses options it cannot evaluate (ipset, limit, iprange, ...).
- Tests for the watchdog, the HTTP API and flag handling.
- CI (gofmt, vet, race tests, staticcheck), GoReleaser releases for linux
  amd64/arm64, a hardened systemd unit and an env example.
- README, contributing guide, security policy, code of conduct, roadmap and
  architecture notes.

### Changed

- All UI text, API errors, logs and code comments are in English.
- Module path is `github.com/quvonchbek-devops/ipt-lens`.
- Undo commands run in reverse order of the applied steps.

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
- Comments containing `\"` from `iptables-save` were parsed incorrectly.
- The confirm message claimed the rule was saved permanently even though
  nothing was written to disk.
- Tertiary text in the UI did not meet WCAG AA contrast.

### Removed

- The "server address" setting in the UI. The page's Content Security Policy
  always blocked requests to other servers, so it never worked.

[Unreleased]: https://github.com/quvonchbek-devops/ipt-lens/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/quvonchbek-devops/ipt-lens/releases/tag/v0.1.0
