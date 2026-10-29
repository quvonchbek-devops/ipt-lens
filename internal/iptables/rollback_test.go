package iptables

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const threeRules = `*filter
:INPUT ACCEPT [0:0]
[1:2] -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
[1:2] -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
[1:2] -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
COMMIT
`

// listing answers "-S INPUT" with the given rule specs.
func listing(specs ...string) func(string) (string, error) {
	return func(cmd string) (string, error) {
		if strings.Contains(cmd, " -C ") {
			for _, s := range specs {
				if strings.HasSuffix(cmd, "INPUT "+s) {
					return "", nil
				}
			}
			return "", exitErr(1)
		}
		out := "-P INPUT ACCEPT\n"
		for _, s := range specs {
			out += "-A INPUT " + s + "\n"
		}
		return out, nil
	}
}

func expireNow(t *testing.T, w *Watchdog) {
	t.Helper()
	w.mu.Lock()
	c := w.pending
	w.mu.Unlock()
	if c == nil {
		t.Fatal("no pending change")
	}
	c.timer.Stop()
	w.expire(c)
}

func TestDeleteUndoReinsertsAfterItsNeighbor(t *testing.T) {
	f := installFake(t)
	f.save = threeRules
	w := newTestWatchdog(t, time.Hour)
	if err := w.DeleteRule("filter", "INPUT", 2, "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT"); err != nil {
		t.Fatal(err)
	}
	// Another tool inserted two rules at the top during the confirm window.
	f.query = listing("-s 10.0.0.1/32 -j DROP", "-s 10.0.0.2/32 -j DROP",
		"-p tcp -m tcp --dport 22 -j ACCEPT", "-p tcp -m tcp --dport 443 -j ACCEPT")
	expireNow(t, w)
	calls := f.Calls()
	if want := "-t filter -I INPUT 4 -p tcp -m tcp --dport 80 -j ACCEPT"; calls[len(calls)-1] != want {
		t.Fatalf("calls = %q, want last %q", calls, want)
	}
}

func TestDeleteUsesSpecWhenRuleIsUnique(t *testing.T) {
	f := installFake(t)
	f.save = threeRules
	w := newTestWatchdog(t, time.Hour)
	if err := w.DeleteRule("filter", "INPUT", 2, "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.Calls(), "-t filter -D INPUT -p tcp -m tcp --dport 80 -j ACCEPT") {
		t.Fatalf("delete was not by spec: %q", f.Calls())
	}
}

func TestDeleteUndoSkippedWhenRuleNeverLeft(t *testing.T) {
	f := installFake(t)
	f.save = threeRules
	w := newTestWatchdog(t, time.Hour)
	if err := w.DeleteRule("filter", "INPUT", 2, "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT"); err != nil {
		t.Fatal(err)
	}
	// As after a crash between recording the change and running it.
	f.query = listing("-p tcp -m tcp --dport 22 -j ACCEPT", "-p tcp -m tcp --dport 80 -j ACCEPT",
		"-p tcp -m tcp --dport 443 -j ACCEPT")
	n := len(f.Calls())
	expireNow(t, w)
	if extra := f.Calls()[n:]; len(extra) != 0 {
		t.Fatalf("undo re-inserted a rule that is still there: %q", extra)
	}
}

func TestEditUndoRestoresOldRuleWhereTheNewOneIs(t *testing.T) {
	f := installFake(t)
	f.save = threeRules
	w := newTestWatchdog(t, time.Hour)
	f.query = listing() // the new rule is not a duplicate
	if err := w.EditRule("filter", "INPUT", 2, "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT",
		"-p tcp --dport 8080 -j ACCEPT"); err != nil {
		t.Fatal(err)
	}
	// The listing drops the new rule once the undo has deleted it: the
	// position must be computed from the chain as it is after that delete.
	before := listing("-s 10.0.0.1/32 -j DROP", "-p tcp -m tcp --dport 22 -j ACCEPT",
		"-p tcp --dport 8080 -j ACCEPT", "-p tcp -m tcp --dport 443 -j ACCEPT")
	after := listing("-s 10.0.0.1/32 -j DROP", "-p tcp -m tcp --dport 22 -j ACCEPT",
		"-p tcp -m tcp --dport 443 -j ACCEPT")
	f.query = func(cmd string) (string, error) {
		if slices.Contains(f.Calls(), "-t filter -D INPUT -p tcp --dport 8080 -j ACCEPT") {
			return after(cmd)
		}
		return before(cmd)
	}
	n := len(f.Calls())
	expireNow(t, w)
	want := []string{
		"-t filter -D INPUT -p tcp --dport 8080 -j ACCEPT",
		"-t filter -I INPUT 3 -p tcp -m tcp --dport 80 -j ACCEPT",
	}
	if got := f.Calls()[n:]; !slices.Equal(got, want) {
		t.Fatalf("undo = %q, want %q", got, want)
	}
}

func TestEditRefusesDuplicate(t *testing.T) {
	f := installFake(t)
	f.save = threeRules
	w := newTestWatchdog(t, time.Hour)
	f.query = listing("-p tcp --dport 22 -j ACCEPT")
	err := w.EditRule("filter", "INPUT", 2, "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT", "-p tcp --dport 22 -j ACCEPT")
	if err != ErrDuplicate {
		t.Fatalf("err = %v, want ErrDuplicate", err)
	}
	if err := w.EditRule("filter", "INPUT", 2, "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT", "-p tcp --dport 23 -j ACCEPT"); err != nil {
		t.Fatalf("a new rule was refused: %v", err)
	}
}

func TestUndoAfterBareNeighbor(t *testing.T) {
	// "-A INPUT" alone (a counter rule) has empty args; it is still a neighbor.
	empty := ""
	a := &anchor{Prev: &empty, Count: 1}
	if got := anchorPosition([]string{"-j DROP", ""}, a, 2); got != 3 {
		t.Fatalf("position = %d, want 3 (below the bare rule)", got)
	}
}

func TestReinsertIPv6(t *testing.T) {
	f := installFake(t)
	f.query = func(string) (string, error) { return "-P INPUT ACCEPT\n-A INPUT -j DROP\n", nil }
	prev := "-j DROP"
	err := runUndoCmd([]string{"-6", "-t", "filter", "-I", "INPUT", "1", "-j", "ACCEPT"}, &anchor{Prev: &prev, Count: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Calls(); !slices.Equal(got, []string{"-6 -t filter -I INPUT 2 -j ACCEPT"}) {
		t.Fatalf("calls = %q", got)
	}
}

func TestRecoverRefusesMismatchedAnchors(t *testing.T) {
	f := installFake(t)
	dir := privateDir(t)
	data := `{"desc":"x","undo":[["-t","filter","-D","INPUT","-j","ACCEPT"]],"anchors":[null,null]}`
	if err := os.WriteFile(dir+"/pending.json", []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWatchdog(dir, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls()) != 0 {
		t.Fatalf("ran commands from a malformed record: %q", f.Calls())
	}
	if _, err := os.Stat(dir + "/pending.json"); err != nil {
		t.Fatal("malformed record removed")
	}
}

func TestRecoverSkipsStepsThatNeverRan(t *testing.T) {
	f := installFake(t)
	dir := privateDir(t)
	rec := change{Desc: "crashed mid-apply", BootID: bootID(), Undo: [][]string{
		{"-t", "filter", "-D", "INPUT", "-j", "DROP"},   // never applied
		{"-t", "filter", "-X", "IPTLENS-IN-B"},          // never created
		{"-t", "filter", "-D", "INPUT", "-j", "ACCEPT"}, // applied
	}}
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(dir+"/pending.json", data, 0o600); err != nil {
		t.Fatal(err)
	}
	f.query = func(cmd string) (string, error) {
		if strings.HasSuffix(cmd, "-C INPUT -j ACCEPT") {
			return "", nil
		}
		return "", exitErr(1)
	}
	if _, err := NewWatchdog(dir, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := f.Calls(); !slices.Equal(got, []string{"-t filter -D INPUT -j ACCEPT"}) {
		t.Fatalf("calls = %q", got)
	}
	if _, err := os.Stat(dir + "/pending.json"); !os.IsNotExist(err) {
		t.Fatal("pending.json not removed")
	}
}

func TestUndoCheckFailureKeepsRecord(t *testing.T) {
	f := installFake(t)
	dir := privateDir(t)
	rec := change{Desc: "x", BootID: bootID(), Undo: [][]string{{"-t", "filter", "-D", "INPUT", "-j", "ACCEPT"}}}
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(dir+"/pending.json", data, 0o600); err != nil {
		t.Fatal(err)
	}
	f.query = func(string) (string, error) { return "xtables lock", exitErr(4) }
	if _, err := NewWatchdog(dir, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := f.Calls(); len(got) != 0 {
		t.Fatalf("ran commands although the check failed: %q", got)
	}
	if _, err := os.Stat(dir + "/pending.json"); err != nil {
		t.Fatal("pending.json removed although the rollback did not finish")
	}
}

func TestSafeUndoChecksAnchor(t *testing.T) {
	cmd := []string{"-t", "filter", "-I", "INPUT", "2", "-j", "ACCEPT"}
	if !safeUndoAt(cmd, &anchor{Count: 1, Remove: []string{"-j", "DROP"}}) {
		t.Fatal("plain anchor refused")
	}
	for _, bad := range [][]string{{"--modprobe=/tmp/x"}, {"--modp", "/tmp/x"}, {"-M", "/tmp/x"}, {"-M/tmp/x"}, {"-pM", "/tmp/x"}} {
		if safeUndoAt(cmd, &anchor{Count: 1, Remove: bad}) {
			t.Fatalf("module loader in anchor accepted: %q", bad)
		}
		if safeUndo(append([]string{"-t", "filter", "-D", "INPUT"}, bad...)) {
			t.Fatalf("module loader in undo accepted: %q", bad)
		}
	}
	for _, legacy := range [][]string{
		{"-t", "filter", "-R", "INPUT", "2", "-j", "ACCEPT"},
		{"-t", "filter", "-D", "INPUT", "2"},
	} {
		if safeUndo(legacy) {
			t.Fatalf("position-based undo accepted: %q", legacy)
		}
	}
	if safeUndoAt([]string{"-t", "filter", "-I", "INPUT", "x", "-j", "ACCEPT"}, &anchor{Count: 1}) {
		t.Fatal("anchored insert without a position accepted")
	}
}
