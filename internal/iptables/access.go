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
)

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
		if _, _, err := net.ParseCIDR(s); err != nil {
			if ip := net.ParseIP(s); ip == nil || ip.To4() == nil {
				return invalidf("invalid VPN subnet: %q", s)
			}
		}
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
	for _, s := range p.VPN.Subnets {
		out = append(out, cat([]string{"-s", s}, match, comment(note), []string{"-j", "RETURN"}))
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
		{"-i", "docker0", "-j", "RETURN"},
		{"-i", "br-+", "-j", "RETURN"},
	}
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
		{"-i", "docker0", "-j", "RETURN"},
		{"-i", "br-+", "-j", "RETURN"},
	}
	for _, pa := range p.Ports {
		match := []string{"-p", pa.Proto, "-m", "conntrack", "--ctorigdstport", strconv.Itoa(pa.Port)}
		rules = append(rules, p.levelRules(pa.Level, match, portNote(pa))...)
	}
	if p.Default != LevelPublic {
		rules = append(rules, p.levelRules(p.Default, nil, commentDef)...)
	}
	return rules
}

// activeChain returns the managed chain that parent jumps to, and the jump's
// 1-based position, or "" if there is none.
func activeChain(tbl *Table, parent, prefix string) (string, int) {
	if tbl == nil {
		return "", 0
	}
	ch, ok := tbl.Chains[parent]
	if !ok {
		return "", 0
	}
	for _, r := range ch.Rules {
		if strings.HasPrefix(r.Target, prefix) {
			return r.Target, r.ID
		}
	}
	return "", 0
}

// ReadAccess reads the policy back from the active managed chain's comments.
func ReadAccess(st *SystemState) (AccessPolicy, bool) {
	tbl := st.Tables["filter"]
	name, _ := activeChain(tbl, "INPUT", accessIn)
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
	active, pos := activeChain(tbl, parent, prefix)
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
	jump := cat(comment(commentJump), []string{"-j"})
	var cleanup [][]string
	if active == "" {
		steps = append(steps, step{
			do:   cat([]string{"-t", "filter", "-I", parent, "1"}, jump, []string{next}),
			undo: cat([]string{"-t", "filter", "-D", parent}, jump, []string{next}),
		})
	} else {
		n := strconv.Itoa(pos)
		steps = append(steps, step{
			do:   cat([]string{"-t", "filter", "-R", parent, n}, jump, []string{next}),
			undo: cat([]string{"-t", "filter", "-R", parent, n}, jump, []string{active}),
		})
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
		inSteps, inClean, err := managedPlan(tbl, "INPUT", accessIn, inputRules(p))
		if err != nil {
			return plan{}, err
		}
		pl := plan{desc: "access policy", cleanup: inClean}
		var jumps []step
		pl.steps = append(pl.steps, inSteps[:len(inSteps)-1]...)
		jumps = append(jumps, inSteps[len(inSteps)-1])
		if _, ok := tbl.Chains["DOCKER-USER"]; ok {
			dkSteps, dkClean, err := managedPlan(tbl, "DOCKER-USER", accessDocker, dockerRules(p))
			if err != nil {
				return plan{}, err
			}
			pl.steps = append(pl.steps, dkSteps[:len(dkSteps)-1]...)
			jumps = append(jumps, dkSteps[len(dkSteps)-1])
			pl.cleanup = append(pl.cleanup, dkClean...)
		}
		// Switch traffic only after every new chain is complete.
		pl.steps = append(pl.steps, jumps...)
		return pl, nil
	})
}

// InputRules and DockerRules expose the generated chains for previews.
func InputRules(p AccessPolicy) [][]string  { return inputRules(p) }
func DockerRules(p AccessPolicy) [][]string { return dockerRules(p) }
