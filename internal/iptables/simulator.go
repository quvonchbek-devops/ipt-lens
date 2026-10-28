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
	state   *SystemState
	src     string
	dst     string
	dstPort string
	proto   string
	inIf    string
	outIf   string
	ctState string
	steps   []SimStep
}

// SimulatePacket - paket yo'lini Linux netfilter tartibida simulyatsiya qiladi:
// nat/PREROUTING -> (lokal bo'lsa filter/INPUT) yoki (filter/FORWARD -> nat/POSTROUTING).
// DNAT manzilni o'zgartiradi, shu sababli keyingi qoidalar yangi manzilda tekshiriladi.
// Eslatma: OUTPUT zanjiri simulyatsiya qilinmaydi (paket manbasi lokal jarayon bo'lsa).
func SimulatePacket(state *SystemState, req SimRequest) SimResult {
	s := &simCtx{
		state:   state,
		src:     req.SrcIP,
		dst:     req.DstIP,
		dstPort: req.DstPort,
		proto:   strings.ToLower(req.Proto),
		inIf:    req.InIface,
		outIf:   req.OutIface,
		ctState: strings.ToUpper(req.CtState),
		steps:   []SimStep{},
	}
	if s.ctState == "" {
		s.ctState = "NEW"
	}

	verdict := s.runHook("nat", "PREROUTING")
	if !isBlocking(verdict) {
		var path []hook
		if s.isLocal(s.dst) {
			s.info("Manzil lokal: paket INPUT zanjiriga yetkaziladi")
			path = []hook{{"filter", "INPUT"}}
		} else {
			s.info("Manzil lokal emas: paket FORWARD va POSTROUTING orqali o'tadi")
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
	return SimResult{FinalVerdict: verdict, FinalDst: finalDst, Steps: s.steps}
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

// evalChain - zanjirdagi qoidalarni ketma-ket tekshiradi va hukm qaytaradi:
// ACCEPT/DROP/REJECT (terminal) yoki RETURN (custom zanjir oxiri).
func (s *simCtx) evalChain(tbl *Table, ch *Chain, depth int) string {
	if depth > maxJumpDepth {
		s.steps = append(s.steps, SimStep{Table: tbl.Name, Chain: ch.Name, Action: "ERROR", Note: "Jump chuqurligi chegaradan oshdi"})
		return "RETURN"
	}
	s.steps = append(s.steps, SimStep{
		Table: tbl.Name, Chain: ch.Name, Action: "ENTER_CHAIN",
		Note: fmt.Sprintf("Zanjirga kirish (policy: %s)", ch.Policy),
	})

rules:
	for _, r := range ch.Rules {
		if !s.matches(r) {
			continue
		}
		step := SimStep{Table: tbl.Name, Chain: ch.Name, RuleID: r.ID, RawRule: r.RawRule, Note: r.Comment}

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
			// LOG, MARK va boshqa terminal bo'lmagan targetlar
			step.Action = "MATCH -> " + r.Target
			step.Note = joinNote(step.Note, "terminal emas, qoida davom etadi")
			s.steps = append(s.steps, step)
		}
	}

	if ch.IsCustom {
		s.steps = append(s.steps, SimStep{Table: tbl.Name, Chain: ch.Name, Action: "RETURN",
			Note: "Custom zanjir oxiri, chaqiruvchi zanjirga qaytish"})
		return "RETURN"
	}

	s.steps = append(s.steps, SimStep{Table: tbl.Name, Chain: ch.Name,
		Action: "DEFAULT_POLICY -> " + ch.Policy, Note: "Hech qaysi qoida mos kelmadi"})
	if isBlocking(ch.Policy) {
		return ch.Policy
	}
	return "ACCEPT"
}

// applyDNAT - --to-destination bo'yicha paket manzilini o'zgartiradi.
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
	return fmt.Sprintf("Manzil o'zgardi: %s → %s", before, after)
}

func (s *simCtx) matches(r *Rule) bool {
	if r.Proto != "" && r.Proto != "all" && s.proto != "" && !matchField(r.Proto, s.proto) {
		return false
	}
	if !matchIface(r.InIface, s.inIf) || !matchIface(r.OutIface, s.outIf) {
		return false
	}
	if r.DstPort != "" && s.dstPort != "" && !matchPort(r.DstPort, s.dstPort) {
		return false
	}
	if r.Source != "" && s.src != "" && !matchCIDR(r.Source, s.src) {
		return false
	}
	if r.Destination != "" && s.dst != "" && !matchCIDR(r.Destination, s.dst) {
		return false
	}
	if r.CtState != "" && !matchCtState(r.CtState, s.ctState) {
		return false
	}
	if r.DstType != "" && !s.matchDstType(r.DstType) {
		return false
	}
	return true
}

func (s *simCtx) matchDstType(rule string) bool {
	neg := strings.HasPrefix(rule, "!")
	clean := strings.TrimPrefix(rule, "!")
	if clean == "LOCAL" {
		return s.isLocal(s.dst) != neg
	}
	// Boshqa turlar (UNICAST, BROADCAST...) simulyatsiya qilinmaydi: mos deb olinadi
	return true
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

// matchIface/matchField: bo'sh qiymat (noma'lum) har doim mos deb olinadi.
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
