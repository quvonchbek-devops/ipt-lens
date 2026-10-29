package iptables

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Level is who may reach a port.
type Level string

const (
	LevelPublic Level = "public" // everyone
	LevelVPN    Level = "vpn"    // only through the VPN
	LevelClosed Level = "closed" // nobody
)

// VPN identifies who "VPN only" lets in: traffic arriving on a VPN interface
// (or, when none is chosen, from a VPN subnet), plus trusted addresses such as
// an office IP, IPv4 or IPv6, which apply in every case.
type VPN struct {
	Ifaces  []string `json:"ifaces"`
	Subnets []string `json:"subnets"`
	Trusted []string `json:"trusted,omitempty"`
}

// Empty reports whether nobody would count as "VPN only".
func (v VPN) Empty() bool { return len(v.Ifaces)+len(v.Subnets)+len(v.Trusted) == 0 }

// Reaches reports whether "VPN only" lets anyone in over IPv4 (v6 false) or
// IPv6: through an interface, an IPv4 subnet (used when no interface is set),
// or a trusted address of that family.
func (v VPN) Reaches(v6 bool) bool {
	return len(v.Ifaces) > 0 || (!v6 && len(v.Subnets) > 0) || len(v.trustedFor(v6)) > 0
}

// trustedFor returns the trusted addresses of one family.
func (v VPN) trustedFor(v6 bool) []string {
	var out []string
	for _, t := range v.Trusted {
		if strings.Contains(t, ":") == v6 {
			out = append(out, t)
		}
	}
	return out
}

type PortAccess struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Level Level  `json:"level"`
	// Limit slows down password guessing on a port open to everyone: each
	// source address gets at most limitRate new connections, the rest dropped.
	Limit bool `json:"limit,omitempty"`
}

const limitRate = "6/minute"

// AccessPolicy is the simple view's whole state: a level per port plus a
// default for every other port, applied to host services and Docker-published
// ports alike.
type AccessPolicy struct {
	VPN     VPN          `json:"vpn"`
	Default Level        `json:"default"`
	Ports   []PortAccess `json:"ports"`
}

const (
	accessPrefix = "IPTLENS-"
	accessIn     = "IPTLENS-IN-"
	accessDocker = "IPTLENS-DK-"
	commentJump  = "iptlens:jump"
	commentMeta  = "iptlens:v1"
	commentDef   = "iptlens:default"
	maxVPN       = 8
	maxComment   = 255 // iptables' limit for a comment
	maxPorts     = 256 // enough for any server; keeps the list and the review readable
)

// internalIfaces carry traffic from containers, pods and VMs on this host;
// filtering them would break Docker, Kubernetes CNIs and libvirt. Overlay
// tunnels (flannel.1, cilium_vxlan) are left out: their traffic comes from
// other hosts. br-+ is Docker's naming, but matches any bridge named br-*.
var internalIfaces = []string{"docker0", "br-+", "cni0", "cali+", "lxc+", "virbr+"}

// InternalIfaces lists the always-allowed interface patterns, for display.
func InternalIfaces() []string {
	out := make([]string, len(internalIfaces))
	for i, n := range internalIfaces {
		out[i] = strings.TrimSuffix(n, "+")
		if out[i] != n {
			out[i] += "*"
		}
	}
	return out
}

func internalRules() [][]string {
	out := make([][]string, len(internalIfaces))
	for i, ifc := range internalIfaces {
		out[i] = []string{"-i", ifc, "-j", "RETURN"}
	}
	return out
}

func validLevel(l Level) bool { return l == LevelPublic || l == LevelVPN || l == LevelClosed }

// Validate checks every field that ends up in a generated rule.
func (p AccessPolicy) Validate() error {
	if !validLevel(p.Default) {
		return invalidf("unknown default level %q", p.Default)
	}
	if len(p.VPN.Ifaces)+len(p.VPN.Subnets) > maxVPN {
		return invalidf("at most %d VPN interfaces and subnets", maxVPN)
	}
	if len(p.VPN.Trusted) > maxVPN {
		return invalidf("at most %d trusted addresses", maxVPN)
	}
	for _, t := range p.VPN.Trusted {
		if err := checkTrusted(t); err != nil {
			return err
		}
	}
	if len(p.metaComment()) > maxComment {
		return invalidf("too many VPN entries and trusted addresses to record; use fewer or wider ranges")
	}
	for _, i := range p.VPN.Ifaces {
		if !ifaceRe.MatchString(i) {
			return invalidf("invalid interface name: %q", i)
		}
	}
	for _, s := range p.VPN.Subnets {
		ip, _, err := net.ParseCIDR(s)
		if err != nil {
			ip = net.ParseIP(s)
		}
		if ip == nil {
			return invalidf("invalid VPN subnet: %q", s)
		}
		if ip.To4() == nil {
			return invalidf("VPN subnet %q is IPv6; only IPv4 is filtered", s)
		}
	}
	if len(p.Ports) > maxPorts {
		return invalidf("at most %d ports", maxPorts)
	}
	needsVPN := p.Default == LevelVPN
	seen := map[string]bool{}
	for _, pa := range p.Ports {
		if pa.Port < 1 || pa.Port > 65535 {
			return invalidf("invalid port: %d", pa.Port)
		}
		if pa.Proto != "tcp" && pa.Proto != "udp" {
			return invalidf("invalid protocol for port %d: %q", pa.Port, pa.Proto)
		}
		if !validLevel(pa.Level) {
			return invalidf("unknown level %q for port %d", pa.Level, pa.Port)
		}
		if pa.Limit && (pa.Proto != "tcp" || pa.Level != LevelPublic) {
			return invalidf("slowing down guesses works only on a TCP port open to everyone (port %d)", pa.Port)
		}
		key := fmt.Sprintf("%d/%s", pa.Port, pa.Proto)
		if seen[key] {
			return invalidf("port %s listed twice", key)
		}
		seen[key] = true
		needsVPN = needsVPN || pa.Level == LevelVPN
	}
	if needsVPN && p.VPN.Empty() {
		return invalidf("choose a VPN or add a trusted address before using \"VPN only\"")
	}
	return nil
}

// checkTrusted accepts an IPv4 or IPv6 address or range that is narrower
// than IPv4 /8 or IPv6 /16 (anything wider is as good as "Everyone"). The
// family is decided by ':' as in trustedFor; IPv4 must be written as IPv4,
// and a range must be written as its network address, so what the review
// shows is exactly what opens.
func checkTrusted(t string) error {
	v6 := strings.Contains(t, ":")
	s := t
	if !strings.Contains(s, "/") {
		s += map[bool]string{true: "/128", false: "/32"}[v6]
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return invalidf("invalid trusted address: %q", t)
	}
	if v6 && ip.To4() != nil {
		return invalidf("write the IPv4 address %s without the ::ffff: prefix", ip)
	}
	if !ip.Equal(n.IP) {
		return invalidf("%q has host bits set; the range it opens is %s", t, n)
	}
	if ones, _ := n.Mask.Size(); (!v6 && ones < 8) || (v6 && ones < 16) {
		return invalidf("trusted range %q is too wide; it would let in a large part of the internet", t)
	}
	return nil
}

func comment(text string) []string { return []string{"-m", "comment", "--comment", text} }

func cat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func (p AccessPolicy) metaComment() string {
	s := fmt.Sprintf("%s default=%s vpn=%s;%s", commentMeta, p.Default,
		strings.Join(p.VPN.Ifaces, ","), strings.Join(p.VPN.Subnets, ","))
	if len(p.VPN.Trusted) > 0 { // a third part only when used, so older chains read the same
		s += ";" + strings.Join(p.VPN.Trusted, ",")
	}
	return s
}

// levelRules returns the rules for one level: match narrows the packet, note is
// the rule comment. VPN subnets are IPv4, so v6 rules use interfaces only.
//
// limit, when set, names the hashlimit table that slows new connections to a
// public port; it must be unique per chain kind and port (at most 15 bytes).
func (p AccessPolicy) levelRules(level Level, match []string, note string, v6 bool, limit string) [][]string {
	switch level {
	case LevelPublic:
		var out [][]string
		if limit != "" {
			out = append(out, cat(match, []string{"-m", "conntrack", "--ctstate", "NEW", "-m", "hashlimit",
				"--hashlimit-above", limitRate, "--hashlimit-burst", "6", "--hashlimit-mode", "srcip",
				"--hashlimit-name", limit}, comment(note), []string{"-j", "DROP"}))
		}
		return append(out, cat(match, comment(note), []string{"-j", "RETURN"}))
	case LevelClosed:
		return [][]string{cat(match, comment(note), []string{"-j", "DROP"})}
	}
	var out [][]string
	for _, i := range p.VPN.Ifaces {
		out = append(out, cat([]string{"-i", i}, match, comment(note), []string{"-j", "RETURN"}))
	}
	// A source address can be spoofed from the internet; the incoming interface
	// cannot. Subnets identify the VPN only when no interface is chosen.
	if len(p.VPN.Ifaces) == 0 && !v6 {
		for _, s := range p.VPN.Subnets {
			out = append(out, cat([]string{"-s", s}, match, comment(note), []string{"-j", "RETURN"}))
		}
	}
	// Trusted addresses are deliberate exceptions, such as an office IP.
	for _, s := range p.VPN.trustedFor(v6) {
		out = append(out, cat([]string{"-s", s}, match, comment(note), []string{"-j", "RETURN"}))
	}
	return append(out, cat(match, comment(note), []string{"-j", "DROP"}))
}

func portNote(pa PortAccess) string {
	s := fmt.Sprintf("iptlens:port=%d/%s level=%s", pa.Port, pa.Proto, pa.Level)
	if pa.Limit {
		s += " limit"
	}
	return s
}

// limitName names a port's hashlimit table: kind is "in" or "dk".
func limitName(kind string, pa PortAccess) string {
	if !pa.Limit {
		return ""
	}
	return fmt.Sprintf("iptl-%s-%d", kind, pa.Port)
}

// inputRules generates the IPTLENS-IN chain for filter/INPUT.
func inputRules(p AccessPolicy, v6 bool) [][]string {
	rules := [][]string{
		cat([]string{"-i", "lo"}, comment(p.metaComment()), []string{"-j", "RETURN"}),
		{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"},
	}
	// ICMP carries errors and path MTU; ICMPv6 also neighbour discovery, without
	// which IPv6 stops working. The DHCP client must keep its lease.
	if v6 {
		rules = append(rules,
			[]string{"-p", "ipv6-icmp", "-j", "RETURN"},
			[]string{"-s", "fe80::/10", "-p", "udp", "--sport", "547", "--dport", "546", "-j", "RETURN"})
	} else {
		rules = append(rules,
			[]string{"-p", "icmp", "-j", "RETURN"},
			[]string{"-p", "udp", "--sport", "67", "--dport", "68", "-j", "RETURN"})
	}
	rules = append(rules, internalRules()...)
	for _, pa := range p.Ports {
		match := []string{"-p", pa.Proto, "--dport", strconv.Itoa(pa.Port)}
		rules = append(rules, p.levelRules(pa.Level, match, portNote(pa), v6, limitName("in", pa))...)
	}
	if p.Default != LevelPublic {
		rules = append(rules, p.levelRules(p.Default, nil, commentDef, v6, "")...)
	}
	return rules
}

// dockerRules generates the IPTLENS-DK chain for DOCKER-USER. It judges only
// connections to published ports (conntrack state DNAT), matched by the port
// the client connected to.
func dockerRules(p AccessPolicy, v6 bool) [][]string {
	rules := [][]string{
		cat([]string{"-m", "conntrack", "!", "--ctstate", "DNAT"}, comment(commentMeta), []string{"-j", "RETURN"}),
	}
	rules = append(rules, internalRules()...)
	for _, pa := range p.Ports {
		match := []string{"-p", pa.Proto, "-m", "conntrack", "--ctorigdstport", strconv.Itoa(pa.Port)}
		rules = append(rules, p.levelRules(pa.Level, match, portNote(pa), v6, limitName("dk", pa))...)
	}
	if p.Default != LevelPublic {
		rules = append(rules, p.levelRules(p.Default, nil, commentDef, v6, "")...)
	}
	return rules
}

// activeChain returns the managed chain that parent jumps to, or "".
func activeChain(tbl *Table, parent, prefix string) string {
	if tbl == nil {
		return ""
	}
	ch, ok := tbl.Chains[parent]
	if !ok {
		return ""
	}
	for _, r := range ch.Rules {
		if strings.HasPrefix(r.Target, prefix) {
			return r.Target
		}
	}
	return ""
}

// ReadAccess reads the policy back from the active managed chain's comments.
func ReadAccess(st *SystemState) (AccessPolicy, bool) {
	tbl := st.Tables["filter"]
	name := activeChain(tbl, "INPUT", accessIn)
	if name == "" {
		return AccessPolicy{}, false
	}
	ch, ok := tbl.Chains[name]
	if !ok || len(ch.Rules) == 0 {
		return AccessPolicy{}, false
	}
	var p AccessPolicy
	meta := ch.Rules[0].Comment
	if !strings.HasPrefix(meta, commentMeta+" ") {
		return AccessPolicy{}, false
	}
	for _, f := range strings.Fields(strings.TrimPrefix(meta, commentMeta)) {
		k, v, _ := strings.Cut(f, "=")
		switch k {
		case "default":
			p.Default = Level(v)
		case "vpn":
			ifs, rest, _ := strings.Cut(v, ";")
			nets, trusted, _ := strings.Cut(rest, ";")
			p.VPN.Ifaces = splitList(ifs)
			p.VPN.Subnets = splitList(nets)
			p.VPN.Trusted = splitList(trusted)
		}
	}
	seen := map[string]bool{}
	for _, r := range ch.Rules {
		rest, ok := strings.CutPrefix(r.Comment, "iptlens:port=")
		if !ok {
			continue
		}
		spec, lvl, _ := strings.Cut(rest, " level=")
		lvl, flag, _ := strings.Cut(lvl, " ")
		if seen[spec] {
			continue
		}
		seen[spec] = true
		port, proto, _ := strings.Cut(spec, "/")
		n, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
		p.Ports = append(p.Ports, PortAccess{Port: n, Proto: proto, Level: Level(lvl), Limit: flag == "limit"})
	}
	return p, true
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// otherLetter alternates managed chains so an apply can build the new chain
// fully before switching traffic to it with one jump replacement.
func otherLetter(active, prefix string) string {
	if active == prefix+"A" {
		return prefix + "B"
	}
	return prefix + "A"
}

// restoreInput renders rules for chain in iptables-restore format. Arguments
// with spaces are quoted; anything the format cannot carry safely is refused.
// The rules come from typed policy fields, so a refusal is a bug, not input.
func restoreInput(chain string, rules [][]string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("*filter\n:" + chain + " - [0:0]\n")
	for _, r := range rules {
		b.WriteString("-A " + chain)
		for _, a := range r {
			if a == "" || strings.ContainsAny(a, "\"\\'\n\r\t#") {
				return nil, fmt.Errorf("cannot pass %q to iptables-restore", a)
			}
			if strings.Contains(a, " ") {
				a = `"` + a + `"`
			}
			b.WriteString(" " + a)
		}
		b.WriteString("\n")
	}
	b.WriteString("COMMIT\n")
	return []byte(b.String()), nil
}

// managedPlan builds, for one parent chain, the steps that create the new
// managed chain and switch the parent's jump to it, plus the commands that
// remove the old chain after confirmation.
func managedPlan(tbl *Table, fam []string, parent, prefix string, rules [][]string) ([]step, [][]string, error) {
	active := activeChain(tbl, parent, prefix)
	next := otherLetter(active, prefix)
	if _, exists := tbl.Chains[next]; exists {
		// Left over from an interrupted cleanup and not referenced: remove it first.
		if out, err := ipt(cat(fam, []string{"-t", "filter", "-F", next})...); err != nil {
			return nil, nil, fmt.Errorf("cannot clear stale chain %s: %s", next, strings.TrimSpace(string(out)))
		}
		if out, err := ipt(cat(fam, []string{"-t", "filter", "-X", next})...); err != nil {
			return nil, nil, fmt.Errorf("cannot remove stale chain %s: %s", next, strings.TrimSpace(string(out)))
		}
	}
	tf := cat(fam, []string{"-t", "filter"})
	fill, err := restoreInput(next, rules)
	if err != nil {
		return nil, nil, err
	}
	// The chain is filled by one atomic iptables-restore, not one call per rule.
	steps := []step{
		{do: cat(tf, []string{"-N", next}), undo: cat(tf, []string{"-X", next})},
		{do: fam, restore: fill, undo: cat(tf, []string{"-F", next})},
	}
	// Switch by rule spec, never by position: another tool (fail2ban,
	// kube-proxy) may insert into the parent chain during the confirm window.
	jump := func(op, chain string) []string {
		args := cat(tf, []string{op, parent})
		if op == "-I" {
			args = append(args, "1")
		}
		return cat(args, comment(commentJump), []string{"-j", chain})
	}
	steps = append(steps, step{do: jump("-I", next), undo: jump("-D", next)})
	var cleanup [][]string
	if active != "" {
		steps = append(steps, step{do: jump("-D", active), undo: jump("-I", active)})
		cleanup = [][]string{cat(tf, []string{"-F", active}), cat(tf, []string{"-X", active})}
	}
	return steps, cleanup, nil
}

// ApplyAccess replaces the managed chains with ones generated from p, through
// the usual confirm-or-rollback flow.
func (w *Watchdog) ApplyAccess(p AccessPolicy) error {
	if w.demo {
		return ErrDemo
	}
	if err := p.Validate(); err != nil {
		return err
	}
	sort.SliceStable(p.Ports, func(i, j int) bool { return p.Ports[i].Port < p.Ports[j].Port })
	return w.begin(func() (plan, error) {
		st, err := currentState()
		if err != nil {
			return plan{}, err
		}
		// With nf_tables a fresh host has no filter table until the first
		// rule; it is empty, and the first command creates it.
		tbl := st.Tables["filter"]
		if tbl == nil {
			tbl = &Table{Name: "filter", Chains: map[string]*Chain{}}
		}
		pl := plan{desc: "access policy"}
		var jumps []step
		add := func(tbl *Table, fam []string, parent, prefix string, rules [][]string) error {
			steps, clean, err := managedPlan(tbl, fam, parent, prefix, rules)
			if err != nil {
				return err
			}
			const chain = 2 // -N and the restore that fills it; the rest switch jumps
			pl.steps = append(pl.steps, steps[:chain]...)
			jumps = append(jumps, steps[chain:]...)
			pl.cleanup = append(pl.cleanup, clean...)
			return nil
		}
		family := func(tbl *Table, fam []string, v6 bool) error {
			if err := add(tbl, fam, "INPUT", accessIn, inputRules(p, v6)); err != nil {
				return err
			}
			if _, ok := tbl.Chains["DOCKER-USER"]; ok {
				return add(tbl, fam, "DOCKER-USER", accessDocker, dockerRules(p, v6))
			}
			return nil
		}
		if err := family(tbl, nil, false); err != nil {
			return plan{}, err
		}
		// IPv6 gets the same policy whenever the host has it. If it cannot be
		// read, stop: applying to IPv4 alone would leave IPv6 silently open.
		st6, present, err := ipv6State()
		if err != nil {
			return plan{}, fmt.Errorf("the IPv6 firewall cannot be read, so the policy cannot cover IPv6; nothing was changed: %w", err)
		}
		if present {
			if err := family(st6.Tables["filter"], []string{v6Flag}, true); err != nil {
				return plan{}, err
			}
		}
		// Switch traffic only after every new chain is complete.
		pl.steps = append(pl.steps, jumps...)
		return pl, nil
	})
}

// IPv6Coverage reports whether the host has an IPv6 firewall and whether it
// carries the same policy as IPv4 (v4 is the live IPv4 ruleset). A policy
// applied before IPv6 support, or changed by hand, is not covered.
func IPv6Coverage(v4 *SystemState) (available, covered bool) {
	st6, present, err := ipv6State()
	if err != nil {
		return true, false
	}
	if !present {
		return false, false
	}
	p4, ok4 := ReadAccess(v4)
	p6, ok6 := ReadAccess(st6)
	return true, ok4 && ok6 && reflect.DeepEqual(p4, p6)
}

// DockerCoverage reports whether DOCKER-USER exists and whether it jumps to a
// managed chain, i.e. whether published container ports are filtered.
func DockerCoverage(st *SystemState) (hasChain, covered bool) {
	tbl := st.Tables["filter"]
	if tbl == nil {
		return false, false
	}
	_, hasChain = tbl.Chains["DOCKER-USER"]
	return hasChain, activeChain(tbl, "DOCKER-USER", accessDocker) != ""
}

// InputRules and DockerRules expose the generated chains for previews.
func InputRules(p AccessPolicy, v6 bool) [][]string  { return inputRules(p, v6) }
func DockerRules(p AccessPolicy, v6 bool) [][]string { return dockerRules(p, v6) }
