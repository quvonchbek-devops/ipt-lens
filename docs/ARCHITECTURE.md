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
shape `[-6] -t <table> -D <chain> <spec>`, `-I <chain> <pos> <spec>` or
`-F|-X` on an IPT-Lens chain, with no `--modprobe` (or abbreviation) and no
`-M`. Position-only undos (`-R`, `-D <n>`) that older versions wrote are
refused and left for an operator.

Every undo command is checked against the live ruleset before it runs, so a
record that names steps a crash prevented is still safe to replay: `-D <spec>`
runs only if `-C` finds the rule, `-F`/`-X` only if the chain exists, and an
`-I` only if the rule is missing. Only exit status 1 (no such rule or chain)
skips a command; any other failure of a check, such as a lock timeout, is an
error and the record stays. Undoing a delete or an edit re-inserts the old
rule using an *anchor* stored beside the command: the rules that were above
and below it and how many copies the chain held. The rule goes back below its
old upper neighbor (or above its lower one), the copy nearest the old position
when a neighbor repeats, so rules other tools add meanwhile cannot shift it.
An edit's anchor also names the new rule, which is deleted by spec first.

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
shows them locked. For Docker that is the chains it creates (`DOCKER`,
`DOCKER-FORWARD`, `DOCKER-BRIDGE`, `DOCKER-CT`, `DOCKER-INTERNAL`,
`DOCKER-INGRESS`, `DOCKER-ISOLATION-*`; not `DOCKER-USER` or chains you name
`DOCKER-something`) and rules jumping into them. Where Docker manages a table
(it holds Docker's `DOCKER` chain), the plain `FORWARD -j DOCKER-USER` jump and
the exact bridge rules Docker writes for `docker0` and `br-<id>` are locked too:
`FORWARD -o B --ctstate RELATED,ESTABLISHED -j ACCEPT`, `FORWARD -i B ! -o B
-j ACCEPT`, `FORWARD -i B -o B -j ACCEPT|DROP` and `POSTROUTING -s <subnet>
! -o B -j MASQUERADE`. Anything else on a bridge, and all of these on a host
where Docker does not manage iptables, counts as written by hand.
`--persist-file` leaves out only what is recognised by chain name (Docker's
chains and jumps into them, and the other tools' chains). The jump and bridge
rules above are locked in the UI but still saved: a hand-written rule can have
the same shape, and dropping a DROP would leave the host open after a reboot,
while restoring a copy of Docker's own rule is harmless.

## Frontend

Plain JavaScript, no framework or build step. It polls `/api/v1/state` every two
seconds and re-renders only when the ruleset changed. The token is kept in
`sessionStorage`. All dynamic text is escaped before insertion.
