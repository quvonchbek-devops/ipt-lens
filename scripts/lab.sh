#!/usr/bin/env bash
# Try IPT-Lens on a real firewall without a server or VM.
#
# It builds a throwaway "server" in its own network namespace, with its own
# iptables, so this machine's firewall is never touched. The lab has two ways
# in, both reachable from this machine:
#
#   10.204.0.2  "the internet"  (interface pub0 inside the lab)
#   10.203.0.2  "your VPN"      (interface wg-lab, which IPT-Lens offers as a VPN)
#
# and sample services on ports 22, 80, 443, 5432 and 6379. The panel is at
# http://10.203.0.2:8090, reached through the VPN. Ctrl+C removes everything.
#
#   go build -o ipt-lens ./cmd/server && sudo scripts/lab.sh ./ipt-lens
#
# Then, from this machine, see what the firewall lets through:
#   curl -m 2 10.204.0.2:5432   # from the internet
#   curl -m 2 10.203.0.2:5432   # over the VPN
set -euo pipefail

NS=iptlens-lab
BIN=$(realpath "${1:-./ipt-lens}")
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0 $*" >&2; exit 1; }
[ -x "$BIN" ] || { echo "no ipt-lens binary at $BIN; build it with: go build -o ipt-lens ./cmd/server" >&2; exit 1; }

STATE=$(mktemp -d /tmp/iptlens-lab.XXXXXX)
chmod 700 "$STATE"

cleanup() {
	trap - EXIT INT TERM
	ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del iptl-vpn 2>/dev/null || true
	ip link del iptl-pub 2>/dev/null || true
	rm -rf "$STATE"
	echo "lab removed"
}
trap cleanup EXIT INT TERM

if ip netns list | grep -qw "$NS"; then
	echo "a lab is already running (ip netns $NS); stop it first" >&2
	trap - EXIT INT TERM
	rm -rf "$STATE"
	exit 1
fi

in_lab() { ip netns exec "$NS" "$@"; }

ip netns add "$NS"
in_lab ip link set lo up
# One veth pair per way in: the host end stays here, the other moves into the lab.
link() { # host-end lab-end host-ip lab-ip
	ip link add "$1" type veth peer name "$2"
	ip link set "$2" netns "$NS"
	ip addr add "$3/30" dev "$1"
	ip link set "$1" up
	in_lab ip addr add "$4/30" dev "$2"
	in_lab ip link set "$2" up
}
link iptl-pub pub0 10.204.0.1 10.204.0.2
link iptl-vpn wg-lab 10.203.0.1 10.203.0.2

for port in 22 80 443 5432 6379; do
	in_lab python3 -m http.server "$port" --bind 0.0.0.0 >/dev/null 2>&1 &
done

# Off loopback the panel insists on a token from the environment.
TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
IPTLENS_TOKEN=$TOKEN in_lab "$BIN" --listen 10.203.0.2:8090 --state-dir "$STATE" --allowed-hosts 10.203.0.2 \
	--rollback-timeout 60s &
for _ in $(seq 50); do
	curl -s -m 1 -o /dev/null http://10.203.0.2:8090/healthz && break
	sleep 0.1
done

cat <<EOF

  IPT-Lens lab is running. This machine's firewall is not touched.

  Panel:   http://10.203.0.2:8090
  Token:   $TOKEN

  Try it from another terminal:
    curl -m 2 10.204.0.2:5432    # from the internet
    curl -m 2 10.203.0.2:5432    # over the VPN (wg-lab)

  Press Ctrl+C here to remove the lab.

EOF
wait
