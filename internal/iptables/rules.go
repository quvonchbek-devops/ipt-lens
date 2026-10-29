package iptables

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrProtected = errors.New("this rule is managed by Docker, Kubernetes, libvirt or ufw and cannot be changed here")
	ErrStale     = errors.New("the ruleset changed since it was loaded; refresh and try again")
)

var counterRe = regexp.MustCompile(`^\[\d+:\d+\]\s*`)

// stripCounters removes the "[pkts:bytes] " prefix (counters change constantly).
func stripCounters(raw string) string {
	return strings.TrimSpace(counterRe.ReplaceAllString(strings.TrimSpace(raw), ""))
}

// ruleArgs returns the rule arguments of a "-A CHAIN ..." line.
func ruleArgs(raw string) []string {
	toks := tokenizeRule(stripCounters(raw))
	if len(toks) >= 2 && toks[0] == "-A" {
		return toks[2:]
	}
	return toks
}

// dockerChains are the chains Docker creates. DOCKER-USER is not among them:
// Docker leaves it to the administrator, and so do we.
var dockerChains = map[string]bool{
	"DOCKER": true, "DOCKER-FORWARD": true, "DOCKER-BRIDGE": true, "DOCKER-CT": true,
	"DOCKER-INTERNAL": true, "DOCKER-INGRESS": true,
}

// protectedName reports whether a chain belongs to another tool.
func protectedName(n string) bool {
	if dockerChains[n] || strings.HasPrefix(n, "DOCKER-ISOLATION") {
		return true
	}
	for _, p := range []string{"KUBE-", "cali-", "LIBVIRT_", "ufw-"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// dockerBridge matches Docker's default bridge and its per-network bridges.
var dockerBridge = regexp.MustCompile(`^(docker0|br-[0-9a-f]{12})$`)

// isProtected reports whether the rule belongs to Docker, Kubernetes, Calico,
// libvirt or ufw: its chain or target is theirs or, where Docker manages the
// table (docker: it holds Docker's DOCKER chain), it is Docker's jump into
// DOCKER-USER or one of Docker's bridge rules. Docker re-creates those on
// start; without Docker managing the table, the same rules were written by
// hand and must stay editable and persisted.
func isProtected(chain string, r *Rule, docker bool) bool {
	if protectedName(chain) || protectedName(r.Target) {
		return true
	}
	return docker && (r.Target == "DOCKER-USER" || dockerBridgeRule(chain, r))
}

// dockerBridgeRule matches only the exact rules Docker writes for a bridge B:
//
//	FORWARD -o B -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
//	FORWARD -i B ! -o B -j ACCEPT
//	FORWARD -i B -o B -j ACCEPT|DROP   (DROP with inter-container traffic off)
//	POSTROUTING -s <subnet> ! -o B -j MASQUERADE
//
// Anything more or different (another interface, a port, protocol, address,
// comment or match) was written by hand.
func dockerBridgeRule(chain string, r *Rule) bool {
	anyAddr := func(a string) bool { return a == "" || a == "0.0.0.0/0" || a == "::/0" }
	if (r.Proto != "" && r.Proto != "all") || r.SrcPort != "" || r.DstPort != "" || !anyAddr(r.Destination) ||
		r.DstType != "" || r.Comment != "" || r.Extra != "" || len(r.Unsupported) > 0 {
		return false
	}
	in, out := r.InIface, r.OutIface
	switch chain {
	case "FORWARD":
		if !anyAddr(r.Source) {
			return false
		}
		if r.CtState == "RELATED,ESTABLISHED" {
			return in == "" && dockerBridge.MatchString(out) && r.Target == "ACCEPT"
		}
		if r.CtState != "" || !dockerBridge.MatchString(in) {
			return false
		}
		return (out == "!"+in && r.Target == "ACCEPT") || (out == in && (r.Target == "ACCEPT" || r.Target == "DROP"))
	case "POSTROUTING":
		return r.Target == "MASQUERADE" && in == "" && strings.HasPrefix(out, "!") && dockerBridge.MatchString(out[1:]) &&
			!anyAddr(r.Source) && !strings.HasPrefix(r.Source, "!")
	}
	return false
}

func checkNames(table, chain string) error {
	if !tableRe.MatchString(table) {
		return invalidf("invalid table: %q", table)
	}
	if !chainRe.MatchString(chain) {
		return invalidf("invalid chain name: %q", chain)
	}
	return nil
}

func currentState() (*SystemState, error) {
	out, err := runSave()
	if err != nil {
		return nil, fmt.Errorf("iptables-save failed: %w", err)
	}
	return ParseIptablesSave(bytes.NewReader(out))
}

func currentState6() (*SystemState, error) {
	out, err := runSave6()
	if err != nil {
		return nil, fmt.Errorf("ip6tables-save failed: %w", err)
	}
	return ParseIptablesSave(bytes.NewReader(out))
}

// findRule finds rule #num in the live ruleset and checks that it is still
// the rule the client saw (expect), so a stale view cannot delete the wrong rule.
func findRule(table, chain string, num int, expect string) (*Chain, *Rule, error) {
	st, err := currentState()
	if err != nil {
		return nil, nil, err
	}
	tbl, ok := st.Tables[table]
	if !ok {
		return nil, nil, invalidf("table not found: %s", table)
	}
	ch, ok := tbl.Chains[chain]
	if !ok {
		return nil, nil, invalidf("chain not found: %s", chain)
	}
	if num < 1 || num > len(ch.Rules) {
		return nil, nil, invalidf("rule #%d not found", num)
	}
	r := ch.Rules[num-1]
	if stripCounters(r.RawRule) != stripCounters(expect) {
		return nil, nil, ErrStale
	}
	if r.Protected {
		return nil, nil, ErrProtected
	}
	return ch, r, nil
}

// DeleteRule deletes a rule. If not confirmed, it is re-inserted below the
// rule that was above it.
func (w *Watchdog) DeleteRule(table, chain string, num int, expect string) error {
	if err := checkNames(table, chain); err != nil {
		return err
	}
	return w.begin(func() (plan, error) {
		ch, r, err := findRule(table, chain, num, expect)
		if err != nil {
			return plan{}, err
		}
		n := strconv.Itoa(num)
		at := anchorOf(ch, num)
		del := []string{"-t", table, "-D", chain, n}
		if at.Count == 1 { // by spec, so a rule inserted above it meanwhile cannot shift it
			del = append([]string{"-t", table, "-D", chain}, ruleArgs(r.RawRule)...)
		}
		return plan{
			desc:  fmt.Sprintf("delete %s/%s #%d", table, chain, num),
			steps: []step{{do: del, undo: append([]string{"-t", table, "-I", chain, n}, ruleArgs(r.RawRule)...), at: at}},
		}, nil
	})
}

// EditRule replaces a rule in place (-R). If not confirmed, the new rule is
// removed and the old one re-inserted where the new one was.
func (w *Watchdog) EditRule(table, chain string, num int, expect, newRule string) error {
	spec, err := ValidateRule(table, chain, newRule)
	if err != nil {
		return err
	}
	return w.begin(func() (plan, error) {
		ch, r, err := findRule(table, chain, num, expect)
		if err != nil {
			return plan{}, err
		}
		// The undo removes the new rule by spec, so it must be the only copy.
		if dup, err := query(nil, table, "-C", chain, spec); err != nil {
			return plan{}, err
		} else if dup {
			return plan{}, ErrDuplicate
		}
		n := strconv.Itoa(num)
		at := anchorOf(ch, num)
		at.Remove = spec
		return plan{
			desc:  fmt.Sprintf("edit %s/%s #%d", table, chain, num),
			steps: []step{{do: append([]string{"-t", table, "-R", chain, n}, spec...), undo: append([]string{"-t", table, "-I", chain, n}, ruleArgs(r.RawRule)...), at: at}},
		}, nil
	})
}

// anchorOf records the neighbors of rule #num and how many copies of it the chain holds.
func anchorOf(ch *Chain, num int) *anchor {
	args := func(r *Rule) string { return strings.Join(ruleArgs(r.RawRule), " ") }
	self := args(ch.Rules[num-1])
	a := &anchor{}
	for _, r := range ch.Rules {
		if args(r) == self {
			a.Count++
		}
	}
	if num > 1 {
		prev := args(ch.Rules[num-2])
		a.Prev = &prev
	}
	if num < len(ch.Rules) {
		next := args(ch.Rules[num])
		a.Next = &next
	}
	return a
}
