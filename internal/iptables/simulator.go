package iptables

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const maxJumpDepth = 16

type hook struct{ table, chain string }

type simCtx struct {
	state    *SystemState
	src      string
	dst      string
	dstPort  string
	proto    string
	inIf     string
	outIf    string
	ctState  string
	steps    []SimStep
	warnings []string
	warned   map[*Rule]bool
}

// SimulatePacket walks a packet through the netfilter hooks in kernel order:
// nat/PREROUTING, then filter/INPUT for local destinations, or filter/FORWARD
// and nat/POSTROUTING otherwise. DNAT rewrites the destination, so later rules
// see the new address. Locally generated traffic (OUTPUT) and the mangle and
// raw tables are not simulated.
//
// Rules whose match conditions include options the simulator cannot evaluate
// are assumed to match; the result is then marked Uncertain with a warning.
func SimulatePacket(state *SystemState, req SimRequest) SimResult {
	s := &simCtx{
		state:    state,
		src:      req.SrcIP,
		dst:      req.DstIP,
		dstPort:  req.DstPort,
		proto:    strings.ToLower(req.Proto),
		inIf:     req.InIface,
		outIf:    req.OutIface,
		ctState:  strings.ToUpper(req.CtState),
		steps:    []SimStep{},
		warnings: []string{},
		warned:   map[*Rule]bool{},
	}
	if s.ctState == "" {
		s.ctState = "NEW"
	}

	verdict := s.runHook("nat", "PREROUTING")
	if !isBlocking(verdict) {
		var path []hook
		if s.isLocal(s.dst) {
			s.info("Destination is local: the packet is delivered to INPUT")
			path = []hook{{"filter", "INPUT"}}
		} else {
			s.info("Destination is not local: the packet goes through FORWARD and POSTROUTING")
			path = []hook{{"filter", "FORWARD"}, {"nat", "POSTROUTING"}}
		}
		for _, h := range path {
			verdict = s.runHook(h.table, h.chain)
			if isBlocking(verdict) {
				break
			}
		}
	}

	finalDst := s.dst
	if s.dstPort != "" {
		finalDst += ":" + s.dstPort
	}
	return SimResult{FinalVerdict: verdict, FinalDst: finalDst, Steps: s.steps,
		Uncertain: len(s.warnings) > 0, Warnings: s.warnings}
}

func isBlocking(v string) bool { return v == "DROP" || v == "REJECT" }

func (s *simCtx) info(msg string) {
	s.steps = append(s.steps, SimStep{Action: "INFO", Note: msg})
}

func (s *simCtx) runHook(table, chain string) string {
	tbl, ok := s.state.Tables[table]
	if !ok {
		return "ACCEPT"
	}
	ch, ok := tbl.Chains[chain]
	if !ok {
		return "ACCEPT"
	}
	return s.evalChain(tbl, ch, 0)
}

// evalChain checks the chain's rules in order and returns a verdict:
// ACCEPT/DROP/REJECT (terminal) or RETURN (end of a user-defined chain).
func (s *simCtx) evalChain(tbl *Table, ch *Chain, depth int) string {
	if depth > maxJumpDepth {
		s.steps = append(s.steps, SimStep{Table: tbl.Name, Chain: ch.Name, Action: "ERROR", Note: "Jump depth limit exceeded"})
		return "RETURN"
	}
	s.steps = append(s.steps, SimStep{
		Table: tbl.Name, Chain: ch.Name, Action: "ENTER_CHAIN",
		Note: fmt.Sprintf("Entering chain (policy: %s)", ch.Policy),
	})

rules:
	for _, r := range ch.Rules {
		ok, unchecked := s.matches(r)
		if !ok {
			continue
		}
		step := SimStep{Table: tbl.Name, Chain: ch.Name, RuleID: r.ID, RawRule: r.RawRule, Note: r.Comment}
		if len(unchecked) > 0 && decisive(r) {
			conds := strings.Join(unchecked, " ")
			step.Note = joinNote(step.Note, "assumed to match: "+conds)
			s.warn(r, fmt.Sprintf("%s/%s #%d uses %s, which the simulator cannot evaluate; it was assumed to match",
				tbl.Name, ch.Name, r.ID, conds))
		}

		switch r.Target {
		case "ACCEPT", "DROP", "REJECT":
			step.Action = "MATCH -> " + r.Target
			s.steps = append(s.steps, step)
			return r.Target

		case "RETURN":
			step.Action = "MATCH -> RETURN"
			s.steps = append(s.steps, step)
			break rules

		case "DNAT", "REDIRECT":
			step.Action = "MATCH -> " + r.Target
			if tbl.Name == "nat" {
				step.Note = joinNote(step.Note, s.applyDNAT(r))
			}
			s.steps = append(s.steps, step)
			return "ACCEPT"

		case "SNAT", "MASQUERADE":
			step.Action = "MATCH -> " + r.Target
			s.steps = append(s.steps, step)
			return "ACCEPT"

		default:
			if sub, ok := tbl.Chains[r.Target]; ok {
				step.Action = "MATCH -> JUMP " + r.Target
				s.steps = append(s.steps, step)
				v := s.evalChain(tbl, sub, depth+1)
				if isBlocking(v) || v == "ACCEPT" {
					return v
				}
				continue
			}
			step.Action = "MATCH -> " + r.Target
			if nonTerminating[r.Target] {
				step.Note = joinNote(step.Note, "non-terminating, evaluation continues")
			} else {
				step.Note = joinNote(step.Note, "target not simulated; evaluation continues as if it did not stop the packet")
				s.warn(r, fmt.Sprintf("%s/%s #%d jumps to %s, which the simulator does not model; the packet may stop there",
					tbl.Name, ch.Name, r.ID, r.Target))
			}
			s.steps = append(s.steps, step)
		}
	}

	if ch.IsCustom {
		s.steps = append(s.steps, SimStep{Table: tbl.Name, Chain: ch.Name, Action: "RETURN",
			Note: "End of user-defined chain, returning to the caller"})
		return "RETURN"
	}

	s.steps = append(s.steps, SimStep{Table: tbl.Name, Chain: ch.Name,
		Action: "DEFAULT_POLICY -> " + ch.Policy, Note: "No rule matched"})
	if isBlocking(ch.Policy) {
		return ch.Policy
	}
	return "ACCEPT"
}

// applyDNAT rewrites the packet destination from --to-destination.
func (s *simCtx) applyDNAT(r *Rule) string {
	if r.ToDest == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(r.ToDest)
	if err != nil {
		host, port = r.ToDest, ""
	}
	before := s.dst
	if s.dstPort != "" {
		before += ":" + s.dstPort
	}
	s.dst = host
	if port != "" {
		s.dstPort = port
	}
	after := s.dst
	if s.dstPort != "" {
		after += ":" + s.dstPort
	}
	return fmt.Sprintf("Destination rewritten: %s → %s", before, after)
}

// decisive reports whether r's target can change the verdict (a terminating
// target or a jump). Guessing the match of a LOG or MARK rule does not matter.
func decisive(r *Rule) bool { return !nonTerminating[r.Target] }

// nonTerminating targets let evaluation continue with the next rule. Any other
// target that is neither simulated nor a chain may decide the packet's fate.
var nonTerminating = map[string]bool{
	"LOG": true, "NFLOG": true, "ULOG": true, "TRACE": true, "AUDIT": true,
	"MARK": true, "CONNMARK": true, "SECMARK": true, "CONNSECMARK": true,
	"CLASSIFY": true, "DSCP": true, "TOS": true, "TTL": true, "HL": true,
	"TCPMSS": true, "CT": true, "CHECKSUM": true, "LED": true, "IDLETIMER": true, "SET": true,
}

// warn records one warning per rule, however often the rule is reached.
func (s *simCtx) warn(r *Rule, msg string) {
	if !s.warned[r] {
		s.warned[r] = true
		s.warnings = append(s.warnings, msg)
	}
}

// assumed lists rule conditions the request leaves unspecified; they match by
// default, so the verdict depends on an assumption.
func (s *simCtx) assumed(r *Rule) []string {
	var a []string
	if r.Proto != "" && r.Proto != "all" && s.proto == "" {
		a = append(a, "-p "+r.Proto)
	}
	if r.InIface != "" && s.inIf == "" {
		a = append(a, "-i "+r.InIface)
	}
	if r.OutIface != "" && s.outIf == "" {
		a = append(a, "-o "+r.OutIface)
	}
	if r.Source != "" && r.Source != "0.0.0.0/0" && s.src == "" {
		a = append(a, "-s "+r.Source)
	}
	if r.Destination != "" && r.Destination != "0.0.0.0/0" && s.dst == "" {
		a = append(a, "-d "+r.Destination)
	}
	if r.DstPort != "" && s.dstPort == "" {
		a = append(a, "--dport "+r.DstPort)
	}
	return a
}

// matches reports whether the packet matches r. Conditions the simulator
// cannot evaluate are assumed to match and returned in unchecked, so the
// caller can flag the result as approximate.
func (s *simCtx) matches(r *Rule) (ok bool, unchecked []string) {
	if r.Proto != "" && r.Proto != "all" && s.proto != "" && !matchField(r.Proto, s.proto) {
		return false, nil
	}
	if !matchIface(r.InIface, s.inIf) || !matchIface(r.OutIface, s.outIf) {
		return false, nil
	}
	if r.DstPort != "" && s.dstPort != "" && !matchPort(r.DstPort, s.dstPort) {
		return false, nil
	}
	if r.Source != "" && s.src != "" && !matchCIDR(r.Source, s.src) {
		return false, nil
	}
	if r.Destination != "" && s.dst != "" && !matchCIDR(r.Destination, s.dst) {
		return false, nil
	}
	if r.CtState != "" && !matchCtState(r.CtState, s.ctState) {
		return false, nil
	}
	unchecked = s.assumed(r)
	if r.DstType != "" {
		if strings.TrimPrefix(r.DstType, "!") == "LOCAL" {
			if s.isLocal(s.dst) == strings.HasPrefix(r.DstType, "!") {
				return false, nil
			}
		} else {
			unchecked = append(unchecked, "--dst-type "+r.DstType)
		}
	}
	if r.SrcPort != "" {
		unchecked = append(unchecked, "--sport "+r.SrcPort) // the request carries no source port
	}
	return true, append(unchecked, r.Unsupported...)
}

func (s *simCtx) isLocal(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	if addr.IsLoopback() {
		return true
	}
	for _, a := range s.state.LocalAddrs {
		if p := net.ParseIP(a); p != nil && p.Equal(addr) {
			return true
		}
	}
	return false
}

// matchIface: an empty value on either side (unknown) always matches.
func matchIface(rule, req string) bool {
	if rule == "" || req == "" {
		return true
	}
	return matchField(rule, req)
}

func matchField(rule, req string) bool {
	neg := strings.HasPrefix(rule, "!")
	clean := strings.TrimPrefix(rule, "!")
	return strings.EqualFold(clean, req) != neg
}

func matchPort(rule, req string) bool {
	neg := strings.HasPrefix(rule, "!")
	clean := strings.TrimPrefix(rule, "!")
	p, err := strconv.Atoi(req)
	hit := false
	for _, item := range strings.Split(clean, ",") {
		item = strings.TrimSpace(item)
		if err != nil {
			if item == req {
				hit = true
			}
			continue
		}
		lo, hi := item, item
		if i := strings.Index(item, ":"); i != -1 {
			lo, hi = item[:i], item[i+1:]
		}
		l, e1 := strconv.Atoi(lo)
		h, e2 := strconv.Atoi(hi)
		if e1 == nil && e2 == nil && p >= l && p <= h {
			hit = true
		}
	}
	return hit != neg
}

func matchCIDR(rule, ip string) bool {
	neg := strings.HasPrefix(rule, "!")
	clean := strings.TrimPrefix(rule, "!")
	if !strings.Contains(clean, "/") {
		clean += "/32"
	}
	_, network, err := net.ParseCIDR(clean)
	addr := net.ParseIP(ip)
	if err != nil || addr == nil {
		return true
	}
	return network.Contains(addr) != neg
}

func matchCtState(rule, state string) bool {
	neg := strings.HasPrefix(rule, "!")
	clean := strings.TrimPrefix(rule, "!")
	hit := false
	for _, st := range strings.Split(clean, ",") {
		if strings.EqualFold(strings.TrimSpace(st), state) {
			hit = true
		}
	}
	return hit != neg
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}
