# Simple access view — design

## Why

The maintainer is a DevOps engineer for whom iptables is the weakest skill. The
real task that went wrong: *"keep 80, 443 and SSH open to everyone, put
everything else behind the VPN"*. That is one decision, but iptables asks for a
dozen ordered rules, and Docker-published ports ignore `INPUT` entirely, which
was the most confusing part. The current UI (a dense rules table plus simulator
plus form on one screen) shows rules, not decisions.

## Goal

A default **Simple** view that answers one question: *who can reach which port?*
Each port has one of three levels: **Everyone**, **VPN only**, **Nobody**. Host
services and Docker-published ports are in one list. One row sets the level for
**everything else**. The existing UI stays as the **Advanced** view.

Decided with the maintainer: hybrid of three mockups — a port list with level
buttons (A), each row explained in a plain sentence (B), and quick tasks that
walk through common jobs (C). UI language: English.

## Non-goals

- IPv6 in the Advanced view. (Update 2026-10-29: the simple view now applies
  its policy with `ip6tables` too; without it, the UI says IPv6 is not filtered.)
- Editing rules that IPT-Lens did not create. They stay visible and untouched in
  Advanced.
- Outbound filtering, rate limits, port ranges.

## Anti-goals

- Locking the user out. Every change keeps the confirm-or-rollback flow, the
  review screen warns before SSH leaves "Everyone", and IPT-Lens' own port is
  never set below "VPN only".
- Silently breaking the host: loopback, established connections, ICMP, the DHCP
  client (udp/68) and traffic from Docker bridges are always allowed.

## How it works (decided)

**Managed chains.** IPT-Lens owns `IPTLENS-IN-A|B` (jumped from `filter/INPUT`
position 1) and `IPTLENS-DK-A|B` (jumped from `DOCKER-USER` position 1, only if
that chain exists). An apply builds the *inactive* letter, then swaps the jump
with one `-R`/`-I`, so the switch is atomic. The old chain is removed after
confirm. A timeout rolls back by swapping the jump back and deleting the new
chain.

**Rules are generated from typed fields only** (port int 1–65535, proto
tcp|udp, level enum, interface name regex, parsed CIDR), never from client text.

`IPTLENS-IN-x`:
1. `-i lo -j RETURN` carrying the metadata comment
   `iptlens:v1 default=<level> vpn=<if,...>;<cidr,...>`
2. `-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN`
3. `-p icmp -j RETURN`, `-p udp --dport 68 -j RETURN`
4. `RETURN` for local container/pod/VM interfaces: `docker0`, `br-+`, `cni0`,
   `cali+`, `lxc+`, `virbr+` (not overlay tunnels, whose traffic is remote)
5. per port: Everyone → `RETURN`; VPN only → `RETURN` per VPN interface and
   subnet, then `DROP`; Nobody → `DROP`. Comment `iptlens:port=<n>/<proto>
   level=<level>`.
6. default: Everyone → nothing; VPN only → `RETURN` per VPN interface/subnet,
   then `DROP`; Nobody → `DROP`.

`RETURN` hands the packet back to `INPUT`, so rules written by hand still apply.

`IPTLENS-DK-x` only judges connections to published ports:
1. `-m conntrack ! --ctstate DNAT -j RETURN` (metadata comment)
2. the same internal-interface `RETURN`s
3. per port: same levels, matched with `-p <proto> -m conntrack
   --ctorigdstport <n>`
4. default: same as `INPUT`, restricted to `--ctstate DNAT`.

**State is read back from the ruleset** (comments on the active chain), so it
survives a reboot with `--persist-file` and needs no extra file.

**Port discovery:** listening sockets from `/proc/net/{tcp,tcp6,udp,udp6}`,
excluding loopback-only binds; Docker published ports from the Docker API;
plus every port already in the policy. Well-known ports get names (SSH, HTTP,
HTTPS, PostgreSQL, ...). VPN candidates: interfaces named `wg*`, `tailscale*`,
`tun*`, `zt*`, with their subnets.

**API:** `GET /api/v1/access`, `POST /api/v1/access/preview` (plain-sentence
change list plus the iptables commands), `POST /api/v1/access/apply` (apply through
the watchdog; confirm with the existing `/api/v1/confirm`). Demo mode serves
sample ports and allows preview; apply returns 403 like other changes.

**UI (Simple):** VPN setup card when no VPN is chosen; quick tasks ("Lock the
server behind the VPN", "Open a port", "Close a container port"); the port list
with sentence and three buttons; the *everything else* row; a sticky "N changes
— Review and apply" bar; a review dialog in plain sentences with commands
folded away; the existing confirm banner. A Simple | Advanced switch in the top
bar, remembered per browser.

## Left to the builder

Visual details within the existing look; wording of sentences; the exact wizard
steps beyond the three listed.
