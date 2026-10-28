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

func protectedName(n string) bool {
	if n == "DOCKER" || strings.HasPrefix(n, "DOCKER-ISOLATION") {
		return true
	}
	for _, p := range []string{"KUBE-", "cali-", "LIBVIRT_", "ufw-"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// isProtected reports whether the chain or the rule's target belongs to
// Docker, Kubernetes, Calico, libvirt or ufw.
func isProtected(chain string, r *Rule) bool {
	return protectedName(chain) || protectedName(r.Target)
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

// findRule finds rule #num in the live ruleset and checks that it is still
// the rule the client saw (expect), so a stale view cannot delete the wrong rule.
func findRule(table, chain string, num int, expect string) (*Rule, error) {
	st, err := currentState()
	if err != nil {
		return nil, err
	}
	tbl, ok := st.Tables[table]
	if !ok {
		return nil, invalidf("table not found: %s", table)
	}
	ch, ok := tbl.Chains[chain]
	if !ok {
		return nil, invalidf("chain not found: %s", chain)
	}
	if num < 1 || num > len(ch.Rules) {
		return nil, invalidf("rule #%d not found", num)
	}
	r := ch.Rules[num-1]
	if stripCounters(r.RawRule) != stripCounters(expect) {
		return nil, ErrStale
	}
	if isProtected(chain, r) {
		return nil, ErrProtected
	}
	return r, nil
}

// DeleteRule deletes a rule. If not confirmed, it is re-inserted at the same position.
func (w *Watchdog) DeleteRule(table, chain string, num int, expect string) error {
	if err := checkNames(table, chain); err != nil {
		return err
	}
	return w.begin(func() (plan, error) {
		r, err := findRule(table, chain, num, expect)
		if err != nil {
			return plan{}, err
		}
		n := strconv.Itoa(num)
		return plan{
			desc:  fmt.Sprintf("delete %s/%s #%d", table, chain, num),
			steps: []step{{do: []string{"-t", table, "-D", chain, n}, undo: append([]string{"-t", table, "-I", chain, n}, ruleArgs(r.RawRule)...)}},
		}, nil
	})
}

// EditRule replaces a rule in place (-R). If not confirmed, the old rule is restored.
func (w *Watchdog) EditRule(table, chain string, num int, expect, newRule string) error {
	spec, err := ValidateRule(table, chain, newRule)
	if err != nil {
		return err
	}
	return w.begin(func() (plan, error) {
		r, err := findRule(table, chain, num, expect)
		if err != nil {
			return plan{}, err
		}
		n := strconv.Itoa(num)
		return plan{
			desc:  fmt.Sprintf("edit %s/%s #%d", table, chain, num),
			steps: []step{{do: append([]string{"-t", table, "-R", chain, n}, spec...), undo: append([]string{"-t", table, "-R", chain, n}, ruleArgs(r.RawRule)...)}},
		}, nil
	})
}
