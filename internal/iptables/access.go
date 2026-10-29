package iptables

import (
	"fmt"
	"net"
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

// VPN identifies trusted traffic: by incoming interface, source subnet, or both.
type VPN struct {
	Ifaces  []string `json:"ifaces"`
	Subnets []string `json:"subnets"`
}

type PortAccess struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Level Level  `json:"level"`
}

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
	maxPorts     = 256 // each port is a few rules, applied one iptables call at a time
)

// internalIfaces carry traffic from containers, pods and VMs on this host;
// filtering them would break Docker, Kubernetes CNIs and libvirt.
var internalIfaces = []string{"docker0", "br-+", "cni0", "flannel.+", "cali+", "cilium_+", "lxc+", "virbr+"}

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
		key := fmt.Sprintf("%d/%s", pa.Port, pa.Proto)
		if seen[key] {
			return invalidf("port %s listed twice", key)
		}
		seen[key] = true
		needsVPN = needsVPN || pa.Level == LevelVPN
	}
	if needsVPN && len(p.VPN.Ifaces)+len(p.VPN.Subnets) == 0 {
		return invalidf("choose a VPN interface or subnet before using \"VPN only\"")
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
	return fmt.Sprintf("%s default=%s vpn=%s;%s", commentMeta, p.Default,
		strings.Join(p.VPN.Ifaces, ","), strings.Join(p.VPN.Subnets, ","))
}

// levelRules returns the rules for one level: match narrows the packet, note is
// the rule comment.
func (p AccessPolicy) levelRules(level Level, match []string, note string) [][]string {
	switch level {
	case LevelPublic:
		return [][]string{cat(match, comment(note), []string{"-j", "RETURN"})}
	case LevelClosed:
		return [][]string{cat(match, comment(note), []string{"-j", "DROP"})}
	}
	var out [][]string
	for _, i := range p.VPN.Ifaces {
		out = append(out, cat([]string{"-i", i}, match, comment(note), []string{"-j", "RETURN"}))
	}
	// A source address can be spoofed from the internet; the incoming interface
	// cannot. Subnets identify the VPN only when no interface is chosen.
	if len(p.VPN.Ifaces) == 0 {
		for _, s := range p.VPN.Subnets {
			out = append(out, cat([]string{"-s", s}, match, comment(note), []string{"-j", "RETURN"}))
		}
	}
	return append(out, cat(match, comment(note), []string{"-j", "DROP"}))
}

func portNote(pa PortAccess) string {
	return fmt.Sprintf("iptlens:port=%d/%s level=%s", pa.Port, pa.Proto, pa.Level)
}

// inputRules generates the IPTLENS-IN chain for filter/INPUT.
func inputRules(p AccessPolicy) [][]string {
	rules := [][]string{
		cat([]string{"-i", "lo"}, comment(p.metaComment()), []string{"-j", "RETURN"}),
		{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"},
		{"-p", "icmp", "-j", "RETURN"},
		{"-p", "udp", "--dport", "68", "-j", "RETURN"}, // DHCP client: losing the lease takes the host offline
	}
	rules = append(rules, internalRules()...)
	for _, pa := range p.Ports {
		match := []string{"-p", pa.Proto, "--dport", strconv.Itoa(pa.Port)}
		rules = append(rules, p.levelRules(pa.Level, match, portNote(pa))...)
	}
	if p.Default != LevelPublic {
		rules = append(rules, p.levelRules(p.Default, nil, commentDef)...)
	}
	return rules
}

// dockerRules generates the IPTLENS-DK chain for DOCKER-USER. It judges only
// connections to published ports (conntrack state DNAT), matched by the port
// the client connected to.
func dockerRules(p AccessPolicy) [][]string {
	rules := [][]string{
		cat([]string{"-m", "conntrack", "!", "--ctstate", "DNAT"}, comment(commentMeta), []string{"-j", "RETURN"}),
	}
	rules = append(rules, internalRules()...)
	for _, pa := range p.Ports {
		match := []string{"-p", pa.Proto, "-m", "conntrack", "--ctorigdstport", strconv.Itoa(pa.Port)}
		rules = append(rules, p.levelRules(pa.Level, match, portNote(pa))...)
	}
	if p.Default != LevelPublic {
		rules = append(rules, p.levelRules(p.Default, nil, commentDef)...)
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
			ifs, nets, _ := strings.Cut(v, ";")
			p.VPN.Ifaces = splitList(ifs)
			p.VPN.Subnets = splitList(nets)
		}
	}
	seen := map[string]bool{}
	for _, r := range ch.Rules {
		rest, ok := strings.CutPrefix(r.Comment, "iptlens:port=")
		if !ok {
			continue
		}
		spec, lvl, _ := strings.Cut(rest, " level=")
		if seen[spec] {
			continue
		}
		seen[spec] = true
		port, proto, _ := strings.Cut(spec, "/")
		n, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
		p.Ports = append(p.Ports, PortAccess{Port: n, Proto: proto, Level: Level(lvl)})
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

// managedPlan builds, for one parent chain, the steps that create the new
// managed chain and switch the parent's jump to it, plus the commands that
// remove the old chain after confirmation.
func managedPlan(tbl *Table, parent, prefix string, rules [][]string) ([]step, [][]string, error) {
	active := activeChain(tbl, parent, prefix)
	next := otherLetter(active, prefix)
	if _, exists := tbl.Chains[next]; exists {
		// Left over from an interrupted cleanup and not referenced: remove it first.
		if out, err := ipt("-t", "filter", "-F", next); err != nil {
			return nil, nil, fmt.Errorf("cannot clear stale chain %s: %s", next, strings.TrimSpace(string(out)))
		}
		if out, err := ipt("-t", "filter", "-X", next); err != nil {
			return nil, nil, fmt.Errorf("cannot remove stale chain %s: %s", next, strings.TrimSpace(string(out)))
		}
	}
	steps := []step{{do: []string{"-t", "filter", "-N", next}, undo: []string{"-t", "filter", "-X", next}}}
	for i, r := range rules {
		s := step{do: cat([]string{"-t", "filter", "-A", next}, r)}
		if i == 0 {
			s.undo = []string{"-t", "filter", "-F", next}
		}
		steps = append(steps, s)
	}
	// Switch by rule spec, never by position: another tool (fail2ban,
	// kube-proxy) may insert into the parent chain during the confirm window.
	jump := func(op, chain string) []string {
		args := []string{"-t", "filter", op, parent}
		if op == "-I" {
			args = append(args, "1")
		}
		return cat(args, comment(commentJump), []string{"-j", chain})
	}
	steps = append(steps, step{do: jump("-I", next), undo: jump("-D", next)})
	var cleanup [][]string
	if active != "" {
		steps = append(steps, step{do: jump("-D", active), undo: jump("-I", active)})
		cleanup = [][]string{{"-t", "filter", "-F", active}, {"-t", "filter", "-X", active}}
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
		tbl := st.Tables["filter"]
		if tbl == nil {
			return plan{}, fmt.Errorf("filter table not found")
		}
		pl := plan{desc: "access policy"}
		var jumps []step
		add := func(parent, prefix string, rules [][]string) error {
			steps, clean, err := managedPlan(tbl, parent, prefix, rules)
			if err != nil {
				return err
			}
			chain := 1 + len(rules) // -N plus one step per rule; the rest switch jumps
			pl.steps = append(pl.steps, steps[:chain]...)
			jumps = append(jumps, steps[chain:]...)
			pl.cleanup = append(pl.cleanup, clean...)
			return nil
		}
		if err := add("INPUT", accessIn, inputRules(p)); err != nil {
			return plan{}, err
		}
		if _, ok := tbl.Chains["DOCKER-USER"]; ok {
			if err := add("DOCKER-USER", accessDocker, dockerRules(p)); err != nil {
				return plan{}, err
			}
		}
		// Switch traffic only after every new chain is complete.
		pl.steps = append(pl.steps, jumps...)
		return pl, nil
	})
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
func InputRules(p AccessPolicy) [][]string  { return inputRules(p) }
func DockerRules(p AccessPolicy) [][]string { return dockerRules(p) }
