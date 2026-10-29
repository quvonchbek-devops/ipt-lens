# Architecture

IPT-Lens is a single Go binary with an embedded static UI and no external
dependencies beyond the `iptables` and `iptables-save` commands.

```
cmd/server/          flags, token rules, Host allowlist, HTTP server
internal/api/        routes, request guard, JSON handlers
internal/iptables/
  parser.go          iptables-save text -> SystemState (tables, chains, rules)
  simulator.go       walk a packet through the netfilter hooks
  validate.go        allowlist checks for rules submitted by clients
  rules.go           delete/edit plans, protected chains, stale-view check
  watchdog.go        apply with backup, pending record, timer, rollback, persist
  exec.go            the only place that runs iptables (replaced in tests)
internal/enricher/   interface addresses and Docker container names
web/dist/            index.html, app.js, style.css (embedded via web/embed.go)
```

## Request path

Every `/api/v1/*` request passes through, in order:

1. `securityHeaders`: CSP `default-src 'self'`, no framing, no referrer.
2. `checkHost`: the `Host` header must be an allowed name (421 otherwise). This
   blocks DNS rebinding, where a hostile domain is re-pointed at `127.0.0.1`.
3. `guard`: method check; `Sec-Fetch-Site` must be `same-origin` or `none`, and
   `Origin`, if present, must match `Host`; POST must be `application/json`
   (which a browser only sends cross-origin after a CORS preflight that is never
   granted); constant-time bearer token check. Outside demo mode a token always
   exists: `IPTLENS_TOKEN`, or one generated in `<state-dir>/token`.

## Changing the firewall

A change is a `plan`: a list of `step{do, undo}`. `Watchdog.begin`:

1. refuses if another change is pending, or if a `pending.json` from a failed
   rollback is still on disk,
2. builds the plan under the lock (for edit/delete this re-reads the live
   ruleset and compares the target rule with the one the client saw),
3. writes an `iptables-save -c` backup and prunes old ones,
4. writes `pending.json` with all undo commands and the boot ID, atomically
   (temp file, fsync, rename),
5. runs each step; if one fails, rewrites `pending.json` with the undo of the
   steps already applied and runs it. On success the file is removed; if the
   rollback itself fails, the file stays as the record of what is still applied
   and new changes are refused until an operator removes it,
6. starts the rollback timer.

`Confirm` stops the timer, removes `pending.json` and, with `--persist-file`,
writes `iptables-save` output without managed chains, atomically, through a
symlink if there is one. Expiry runs the undo commands.

At start, the state directory must not be a symlink, writable by group or
others, or owned by another user. A leftover `pending.json` is rolled back only
if it comes from the current boot (after a reboot the kernel ruleset was
rebuilt, so replaying would hit the wrong rules) and every undo command has the
shape `-t <table> -D|-I|-R <chain> ...` without `--modprobe`.

## Simulator

`SimulatePacket` evaluates `nat/PREROUTING`, then `filter/INPUT` when the
(possibly DNAT-rewritten) destination is a local address, or `filter/FORWARD`
and `nat/POSTROUTING` otherwise. It follows jumps into user-defined chains up to
a depth of 16 and handles `RETURN`, policies, DNAT/REDIRECT, SNAT/MASQUERADE and
non-terminating targets.

Matching covers protocol, interfaces, addresses, destination ports (lists and
ranges), conntrack state and `addrtype LOCAL`, with negation. An empty request
field matches anything. `matches` returns the conditions it could not check:
source ports, other address types, and any option the parser did not map to a
field (`Rule.Unsupported`). Such rules are assumed to match and the result is
marked `uncertain` with one warning per rule.

The parser also sets `protected` on chains and rules owned by Docker,
Kubernetes, Calico, libvirt or ufw; the server refuses to change them and the UI
shows them locked.

## Frontend

Plain JavaScript, no framework or build step. It polls `/api/v1/state` every two
seconds and re-renders only when the ruleset changed. The token is kept in
`sessionStorage`. All dynamic text is escaped before insertion.
