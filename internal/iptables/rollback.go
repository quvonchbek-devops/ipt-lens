package iptables

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// anchor tells an undo that re-inserts a rule where the rule belongs, so
// rules that other tools add or remove meanwhile cannot shift it.
type anchor struct {
	Prev   *string  `json:"prev,omitempty"`   // the rule just above, as iptables -S prints it; nil: it was first
	Next   *string  `json:"next,omitempty"`   // the rule just below; nil: it was last
	Count  int      `json:"count"`            // copies of the rule in the chain before the change
	Remove []string `json:"remove,omitempty"` // a rule spec to delete first (the rule an edit wrote)
}

// safeUndoAt is safeUndo plus the checks for an anchored command: it must be
// an insert at a numeric position, and the rule it removes must be clean.
func safeUndoAt(cmd []string, a *anchor) bool {
	if !safeUndo(cmd) {
		return false
	}
	if a == nil {
		return true
	}
	_, rest := splitFamily(cmd)
	if rest[2] != "-I" || len(rest) < 6 {
		return false
	}
	if n, err := strconv.Atoi(rest[4]); err != nil || n < 1 || a.Count < 1 {
		return false
	}
	return safeArgs(a.Remove)
}

func splitFamily(cmd []string) (fam, rest []string) {
	if len(cmd) > 0 && cmd[0] == v6Flag {
		return cmd[:1], cmd[1:]
	}
	return nil, cmd
}

// runUndoCmd runs one undo command against the live ruleset. It first checks
// whether the command is still needed: after a crash the record may name steps
// that never ran, and replaying those blindly would fail or duplicate rules.
func runUndoCmd(cmd []string, a *anchor) error {
	fam, rest := splitFamily(cmd)
	if len(rest) < 4 {
		return run(cmd)
	}
	table, op, chain, args := rest[1], rest[2], rest[3], rest[4:]
	switch {
	case op == "-D" && len(args) > 1:
		if ok, err := query(fam, table, "-C", chain, args); err != nil || !ok {
			return err
		}
	case op == "-F" || op == "-X":
		if ok, err := query(fam, table, "-S", chain, nil); err != nil || !ok {
			return err
		}
	case op == "-I" && a != nil:
		return reinsert(fam, table, chain, args, a)
	case op == "-I" && len(args) > 1:
		if ok, err := query(fam, table, "-C", chain, args[1:]); err != nil || ok {
			return err
		}
	}
	return run(cmd)
}

// reinsert puts a deleted or edited rule back after its old neighbor.
func reinsert(fam []string, table, chain string, args []string, a *anchor) error {
	pos, _ := strconv.Atoi(args[0])
	spec := args[1:]
	if len(a.Remove) > 0 {
		ok, err := query(fam, table, "-C", chain, a.Remove)
		if err != nil {
			return err
		}
		if ok {
			if err := run(cat(fam, []string{"-t", table, "-D", chain}, a.Remove)); err != nil {
				return err
			}
		}
	}
	out, err := ipt(cat(fam, []string{"-t", table, "-S", chain})...)
	if err != nil {
		return fmt.Errorf("cannot list %s: %s", chain, strings.TrimSpace(string(out)))
	}
	var rules []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "-A ") {
			rules = append(rules, strings.Join(ruleArgs(line), " "))
		}
	}
	want := strings.Join(spec, " ")
	have := 0
	for _, r := range rules {
		if r == want {
			have++
		}
	}
	if have >= a.Count {
		// Still there: the delete or edit never ran. (A copy another tool
		// added meanwhile also counts; the rule then stays where that tool put it.)
		return nil
	}
	pos = anchorPosition(rules, a, pos)
	return run(cat(fam, []string{"-t", table, "-I", chain, strconv.Itoa(pos)}, spec))
}

// anchorPosition returns the 1-based position just below Prev or just above
// Next, taking the copy closest to the recorded position when a neighbor
// occurs more than once. Without either, the recorded position is used.
func anchorPosition(rules []string, a *anchor, recorded int) int {
	nearest := func(rule string, want int) int {
		best := -1
		for i, r := range rules {
			if r == rule && (best < 0 || abs(i-want) < abs(best-want)) {
				best = i
			}
		}
		return best
	}
	switch {
	case a.Prev == nil:
		return 1
	case slices.Contains(rules, *a.Prev):
		return nearest(*a.Prev, recorded-2) + 2
	case a.Next == nil:
		return len(rules) + 1
	case slices.Contains(rules, *a.Next):
		return nearest(*a.Next, recorded-1) + 1
	}
	return min(recorded, len(rules)+1)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// query runs a read-only check (-C or -S). It reports false when iptables
// exits with status 1 (no such rule or chain) and an error for anything else,
// such as a lock timeout, so an undo is never skipped on a failed check.
func query(fam []string, table, op, chain string, args []string) (bool, error) {
	out, err := ipt(cat(fam, []string{"-t", table, op, chain}, args)...)
	if err == nil {
		return true, nil
	}
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) && ec.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("cannot check %s: %v: %s", chain, err, strings.TrimSpace(string(out)))
}

func run(cmd []string) error {
	if out, err := ipt(cmd...); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
