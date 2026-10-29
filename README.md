# IPT-Lens

[![CI](https://github.com/quvonchbek-devops/ipt-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/quvonchbek-devops/ipt-lens/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small web panel for reading and safely changing **iptables** on a Linux server.
One static Go binary, no dependencies, no database.

![IPT-Lens simple view: each port with Everyone, VPN only or Nobody](docs/images/simple.png)

## Why

`iptables -L` is hard to read on a host that runs Docker, and one wrong rule over
SSH can lock you out. IPT-Lens shows the ruleset as it really is, chain by chain,
explains where a packet will go, and makes every change **temporary until you
confirm it**. If you lose access and cannot confirm, the change rolls itself back.

## Features

- **Simple view: who can reach which port.** One list of the ports this server
  listens on and the ports Docker publishes. For each, pick **Everyone**,
  **VPN only** or **Nobody**, plus one setting for every other port. Quick tasks
  cover the common jobs: *lock the server behind the VPN*, *open a port*,
  *close a container port*. Every change is shown in plain sentences before it
  is applied. You never write an iptables rule.
- **Readable ruleset (Advanced view).** ([screenshot](docs/images/advanced.png)) All four tables, chains in kernel order, packet and byte
  counters, interface and Docker container names next to addresses.
- **Packet simulator.** Enter source, destination, interfaces, protocol and port;
  see every chain and rule the packet passes through, including DNAT rewrites and
  jumps into user-defined chains. Results that depend on matches the simulator
  cannot evaluate (ipset, limit, ...) are marked approximate.
- **Safe changes.** Add, edit or delete a rule. Each change is applied together
  with its undo, and is rolled back automatically unless you confirm it in time.
  The pending change is written to disk first, so even a crash or restart
  rolls it back.
- **Protected chains.** Rules managed by Docker, Kubernetes, Calico, libvirt or
  ufw are shown with a lock and cannot be changed.
- **Strict input.** New rules are checked against an allowlist of options and
  targets and passed to `iptables` as arguments. No shell is ever involved.
- **Stale-view protection.** Edits and deletes carry the rule you saw; if the
  ruleset changed in the meantime, the request is refused instead of hitting
  the wrong rule.

## Quick start (demo, no root)

```sh
git clone https://github.com/quvonchbek-devops/ipt-lens
cd ipt-lens
make demo            # http://127.0.0.1:8090, sample data, the firewall is never touched
```

Requires Go 1.21 or newer.

## Install on a server

Download a release archive from the
[releases page](https://github.com/quvonchbek-devops/ipt-lens/releases) and
verify it before running it as root:

```sh
sha256sum --ignore-missing -c checksums.txt
gh attestation verify ipt-lens_*_linux_amd64.tar.gz -R quvonchbek-devops/ipt-lens
```

The second command checks GitHub's signed build provenance: the archive was
built by this repository's release workflow from the tagged commit.

Or build it yourself:

```sh
make build
sudo install -m 0755 ipt-lens /usr/local/bin/ipt-lens
```

Run it with systemd:

```sh
sudo install -D -m 0644 deploy/ipt-lens.service /etc/systemd/system/ipt-lens.service
sudo install -D -m 0600 deploy/ipt-lens.env.example /etc/ipt-lens/env
sudoedit /etc/ipt-lens/env          # set IPTLENS_ARGS (and IPTLENS_TOKEN, optional)
sudo systemctl daemon-reload
sudo systemctl enable --now ipt-lens
```

### Where to expose it

IPT-Lens controls your firewall. **Do not expose it to the internet.** Good options:

- Keep the default `127.0.0.1:8090` and reach it through an SSH tunnel:
  `ssh -L 8090:127.0.0.1:8090 you@server`.
- Bind it to a VPN address such as WireGuard (`--listen 10.8.0.1:8090`) and allow
  that port only on the VPN interface.

The API always needs a token outside demo mode, even on loopback: every local user
and any app on the host with an SSRF bug can reach `127.0.0.1`. Set
`IPTLENS_TOKEN` (at least 16 characters, e.g. `openssl rand -hex 24`), or let
IPT-Lens generate one on first start in `<state-dir>/token` (mode 0600):

```sh
sudo cat /var/lib/ipt-lens/token
```

On a non-loopback address, `IPTLENS_TOKEN` must be set explicitly. The UI asks for
the token once and keeps it for the browser session only.

### Keeping changes after a reboot

iptables rules live in the kernel and are lost on reboot. Pass
`--persist-file /etc/iptables/rules.v4` (and `--persist-file6
/etc/iptables/rules.v6` for IPv6) and IPT-Lens saves the ruleset there each
time you confirm a change. Chains that Docker, Kubernetes, Calico, libvirt or ufw
manage are left out, since those tools rebuild them and restoring stale copies at
boot breaks container networking. If the path is a symlink, its target is written. Pair it with a loader such as
`iptables-persistent` (Debian/Ubuntu) or `iptables-services` (RHEL family). Without
the flag, the UI tells you that a confirmed change lasts only until reboot.

## Configuration

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8090` | Address to listen on |
| `--demo` | `false` | Serve built-in sample data; never touch the firewall |
| `--rollback-timeout` | `60s` | Time to confirm a change before it is rolled back |
| `--state-dir` | `/var/lib/ipt-lens` | Backups and the pending change |
| `--keep-backups` | `20` | Number of `iptables-save` snapshots to keep |
| `--persist-file` | (empty) | Save the ruleset here on confirm |
| `--persist-file6` | (empty) | Save the IPv6 ruleset here on confirm |
| `--allowed-hosts` | (empty) | Extra host names accepted in the `Host` header, for reverse proxies |
| `--version` | | Print the version and exit |

| Environment | Meaning |
|---|---|
| `IPTLENS_TOKEN` | Bearer token for the API. Required on non-loopback addresses; otherwise generated in `<state-dir>/token` if unset |

## How the simple view works

IPT-Lens keeps its own chains: `IPTLENS-IN-*`, jumped from the top of `INPUT`,
and `IPTLENS-DK-*`, jumped from the top of `DOCKER-USER` for published container
ports (Docker sends those past `INPUT`). Packets it allows go back to your own
rules with `RETURN`, so rules you wrote by hand still apply. Loopback,
established connections, ICMP and the DHCP client are always allowed, and so is
traffic from local containers, pods and VMs (`docker0`, `br-*`, `cni0`, `cali*`,
`lxc*`, `virbr*`). Overlay tunnels such as `flannel.1` are filtered, since their
traffic comes from other hosts: on a Kubernetes node, allow node-to-node ports
explicitly. If you have a bridge named `br-*` that connects to an outside
network, it is trusted too; filter it in the Advanced view.

IPT-Lens' own port never drops below "VPN only", and a warning appears before
SSH or your VPN's own port (WireGuard, Tailscale, OpenVPN) leaves "Everyone".

The VPN is identified by its interface (`wg0`, `tailscale0`, ...). A subnet is
used only when no interface is chosen, since a source address can be spoofed.

**IPv6** gets the same policy through `ip6tables` when it is installed, in one
step with IPv4: if either fails, both roll back. ICMPv6 (needed for neighbour
discovery) and the DHCPv6 client from link-local addresses are always allowed.
VPN subnets are IPv4, so over IPv6 the VPN is recognised by its interface only.
Without `ip6tables`, the UI says plainly that IPv6 is not filtered.

## How a change works

1. Your request is validated and the target rule is checked against what you saw.
2. A full `iptables-save` snapshot is written to `--state-dir` (the newest 20 are kept).
3. The change and its undo are written to `pending.json`.
4. The change is applied. If a step fails, the steps already applied are undone.
5. A timer starts. **Confirm** keeps the change, and saves it to `--persist-file`
   if one is set. If the timer runs out, the undo runs.
6. On start, a leftover `pending.json` from the same boot means the last change was
   never confirmed, so it is rolled back. After a reboot it is discarded, since
   the kernel ruleset was rebuilt.

If a rollback itself fails, `pending.json` is kept and new changes are refused.
Check the rules by hand, then delete `<state-dir>/pending.json`.

Only one change can be pending at a time.

## HTTP API

All endpoints are under `/api/v1`, take and return JSON, and need
`Authorization: Bearer <token>` (demo mode on loopback needs none). POST requests must use
`Content-Type: application/json`. Cross-site requests are refused.

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/state` | | Ruleset, version, pending status |
| POST | `/simulate` | `src_ip, dst_ip, proto, dst_port, in_iface, out_iface, ct_state` | Trace a packet |
| POST | `/apply` | `table, chain, position, rule` | Add a rule (`position` 0 appends) |
| POST | `/rules/edit` | `table, chain, rule_id, expect, rule` | Replace a rule |
| POST | `/rules/delete` | `table, chain, rule_id, expect` | Delete a rule |
| POST | `/confirm` | | Keep the pending change; returns `persisted` |

`GET /healthz` returns `ok` without authentication.

## Limitations

- The Advanced view and the simulator are IPv4 only; the simple view covers
  IPv6 too.
- The simulator covers `nat/PREROUTING`, `filter/INPUT`, `filter/FORWARD` and
  `nat/POSTROUTING`. Locally generated traffic (`OUTPUT`) and the `mangle` and
  `raw` tables are shown but not simulated.
- New rules accept a limited set of options and the targets `ACCEPT`, `DROP`,
  `REJECT` and `RETURN`.
- Undoing a delete re-inserts the rule at its old position. If another tool
  changed the chain in the meantime, the position may be off.

See [docs/ROADMAP.md](docs/ROADMAP.md) for what is planned.

## Contributing

Bug reports, ideas and pull requests are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) first. Please report security problems
privately, as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Quvonchbek Nuriddinov
