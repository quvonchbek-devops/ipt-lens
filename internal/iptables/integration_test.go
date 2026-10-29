//go:build integration

package iptables

// These tests drive the real iptables, ip6tables and iptables-restore. They
// change the firewall, so they run only as root in a fresh network namespace:
//
//	go test -c -tags integration -o it.test ./internal/iptables
//	sudo unshare -n env IPTLENS_INTEGRATION=1 ./it.test -test.run Integration -test.v
//
// and refuse to start when the namespace already has rules.

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func integration(t *testing.T) {
	t.Helper()
	if os.Getenv("IPTLENS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root in a fresh network namespace and IPTLENS_INTEGRATION=1")
	}
	for _, save := range []func() ([]byte, error){runSaveRules, runSaveRules6} {
		out, err := save()
		if err != nil {
			t.Fatalf("iptables-save: %v", err)
		}
		if strings.Contains(string(out), "\n-A ") {
			t.Fatal("refusing to run: this network namespace already has rules; use a fresh `unshare -n`")
		}
	}
	reset := func() {
		for _, bin := range []string{"iptables", "ip6tables"} {
			for _, tbl := range []string{"filter", "nat"} {
				_ = exec.Command(bin, "-t", tbl, "-F").Run()
				_ = exec.Command(bin, "-t", tbl, "-X").Run()
			}
		}
	}
	reset()
	t.Cleanup(reset)
	// Setting a policy makes sure both filter tables exist, so IPv6 is covered.
	sh(t, "iptables -P INPUT ACCEPT", "ip6tables -P INPUT ACCEPT")
}

// sh runs each line as a command and fails the test on any error.
func sh(t *testing.T, lines ...string) {
	t.Helper()
	for _, l := range lines {
		f := strings.Fields(l)
		if out, err := exec.Command(f[0], f[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", l, err, out)
		}
	}
}

var countersRe = regexp.MustCompile(`\s*\[\d+:\d+\]`)

// live returns the ruleset without comments and counters, for comparing.
func live(t *testing.T, v6 bool) string {
	t.Helper()
	save := runSaveRules
	if v6 {
		save = runSaveRules6
	}
	out, err := save()
	if err != nil {
		t.Fatal(err)
	}
	var keep []string
	for _, l := range strings.Split(string(out), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			keep = append(keep, countersRe.ReplaceAllString(l, ""))
		}
	}
	return strings.Join(keep, "\n")
}

// chain lists a chain's rules as iptables -S prints them.
func chain(t *testing.T, name string) []string {
	t.Helper()
	out, err := exec.Command("iptables", "-S", name).CombinedOutput()
	if err != nil {
		t.Fatalf("iptables -S %s: %v: %s", name, err, out)
	}
	var rules []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(l, "-A ") {
			rules = append(rules, l)
		}
	}
	return rules
}

func liveState(t *testing.T, v6 bool) *SystemState {
	t.Helper()
	get := currentState
	if v6 {
		get = currentState6
	}
	st, err := get()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func sortedPorts(p AccessPolicy) AccessPolicy {
	p.Ports = slices.Clone(p.Ports)
	slices.SortStableFunc(p.Ports, func(a, b PortAccess) int { return a.Port - b.Port })
	return p
}

func TestIntegrationAccessApplyRollbackConfirm(t *testing.T) {
	integration(t)
	sh(t, "iptables -N DOCKER-USER", "iptables -A FORWARD -j DOCKER-USER",
		"ip6tables -N DOCKER-USER", "ip6tables -A FORWARD -j DOCKER-USER")
	before, before6 := live(t, false), live(t, true)
	w, err := NewWatchdog(privateDir(t), false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	p := samplePolicy()
	if err := w.ApplyAccess(p); err != nil {
		t.Fatal(err)
	}
	for _, v6 := range []bool{false, true} {
		got, ok := ReadAccess(liveState(t, v6))
		if !ok || !reflect.DeepEqual(got, sortedPorts(p)) {
			t.Fatalf("v6=%v: read back %+v (ok=%v), want %+v", v6, got, ok, sortedPorts(p))
		}
	}
	if hasChain, covered := DockerCoverage(liveState(t, false)); !hasChain || !covered {
		t.Fatal("DOCKER-USER does not jump to the managed chain")
	}
	// The comment, with its space, survived iptables-restore intact.
	if out, err := exec.Command("iptables", "-C", "IPTLENS-IN-A", "-p", "tcp", "--dport", "22", "-m", "comment",
		"--comment", "iptlens:port=22/tcp level=public", "-j", "RETURN").CombinedOutput(); err != nil {
		t.Fatalf("rule with its comment not found: %v: %s", err, out)
	}

	expireNow(t, w)
	if got := live(t, false); got != before {
		t.Fatalf("IPv4 not restored:\n%s\nwant:\n%s", got, before)
	}
	if got := live(t, true); got != before6 {
		t.Fatalf("IPv6 not restored:\n%s\nwant:\n%s", got, before6)
	}

	// "Undo now" restores it just the same.
	if err := w.ApplyAccess(p); err != nil {
		t.Fatal(err)
	}
	if err := w.Rollback(); err != nil {
		t.Fatal(err)
	}
	if live(t, false) != before || live(t, true) != before6 {
		t.Fatal("Rollback did not restore the ruleset")
	}

	// Apply, confirm, then change it: the second apply builds the B chains,
	// and confirming it removes the A chains.
	if err := w.ApplyAccess(p); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Confirm(); err != nil {
		t.Fatal(err)
	}
	q := samplePolicy()
	q.Ports[0].Level = LevelClosed
	if err := w.ApplyAccess(q); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Confirm(); err != nil {
		t.Fatal(err)
	}
	st := liveState(t, false)
	if _, ok := st.Tables["filter"].Chains["IPTLENS-IN-A"]; ok {
		t.Fatal("old chain IPTLENS-IN-A left after confirm")
	}
	if got, _ := ReadAccess(st); !reflect.DeepEqual(got, sortedPorts(q)) {
		t.Fatalf("after the second apply read back %+v, want %+v", got, sortedPorts(q))
	}
}

func TestIntegrationDeleteAndEditRestoreNextToNeighbor(t *testing.T) {
	integration(t)
	sh(t, "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
		"iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
		"iptables -A INPUT -p tcp --dport 443 -j ACCEPT")
	want := chain(t, "INPUT")
	w, err := NewWatchdog(privateDir(t), false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw := func(i int) string { return liveState(t, false).Tables["filter"].Chains["INPUT"].Rules[i].RawRule }

	if err := w.DeleteRule("filter", "INPUT", 2, raw(1)); err != nil {
		t.Fatal(err)
	}
	// Another tool inserts at the top during the confirm window.
	sh(t, "iptables -I INPUT 1 -s 10.0.0.1 -j DROP")
	expireNow(t, w)
	got := chain(t, "INPUT")
	if !slices.Equal(got[1:], want) {
		t.Fatalf("after undoing the delete:\n%s\nwant below the new rule:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	if err := w.EditRule("filter", "INPUT", 3, raw(2), "-p tcp --dport 8080 -j ACCEPT"); err != nil {
		t.Fatal(err)
	}
	sh(t, "iptables -I INPUT 1 -s 10.0.0.2 -j DROP")
	expireNow(t, w)
	got = chain(t, "INPUT")
	if !slices.Equal(got[2:], want) {
		t.Fatalf("after undoing the edit:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestIntegrationRecoverAfterCrash(t *testing.T) {
	integration(t)
	before, before6 := live(t, false), live(t, true)
	dir := privateDir(t)
	w, err := NewWatchdog(dir, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	w.pending.timer.Stop() // the process dies before the timer fires

	if _, err := NewWatchdog(dir, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if live(t, false) != before || live(t, true) != before6 {
		t.Fatalf("recovery did not restore the ruleset:\n%s", live(t, false))
	}
	if _, err := os.Stat(filepath.Join(dir, "pending.json")); !os.IsNotExist(err) {
		t.Fatal("pending.json left after a successful recovery")
	}
}

func TestIntegrationRecoverSkipsStepsThatNeverRan(t *testing.T) {
	integration(t)
	sh(t, "iptables -A INPUT -p tcp --dport 22 -j ACCEPT")
	dir := privateDir(t)
	// A crash right after -N: the jump and the rules were never added.
	sh(t, "iptables -N IPTLENS-IN-A")
	rec := `{"desc":"crashed","boot_id":"` + bootID() + `","undo":[` +
		`["-t","filter","-D","INPUT","-m","comment","--comment","iptlens:jump","-j","IPTLENS-IN-A"],` +
		`["-t","filter","-F","IPTLENS-IN-A"],["-t","filter","-X","IPTLENS-IN-A"],` +
		`["-t","filter","-X","IPTLENS-DK-A"]]}`
	if err := os.WriteFile(filepath.Join(dir, "pending.json"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWatchdog(dir, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pending.json")); !os.IsNotExist(err) {
		t.Fatal("recovery failed on steps that never ran; pending.json kept")
	}
	if _, ok := liveState(t, false).Tables["filter"].Chains["IPTLENS-IN-A"]; ok {
		t.Fatal("the chain that was created is still there")
	}
}

func TestIntegrationDockerLockedAndPersisted(t *testing.T) {
	integration(t)
	sh(t, "iptables -N DOCKER", "iptables -N DOCKER-USER", "iptables -N DOCKER-FORWARD",
		"iptables -A FORWARD -j DOCKER-USER", "iptables -A FORWARD -j DOCKER-FORWARD",
		"iptables -A FORWARD -i docker0 -o docker0 -j DROP",
		"iptables -A DOCKER-FORWARD -o docker0 -j DOCKER",
		"iptables -t nat -N DOCKER",
		"iptables -t nat -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE")
	f := liveState(t, false).Tables["filter"]
	if !f.Chains["DOCKER-FORWARD"].Protected || !f.Chains["FORWARD"].Rules[0].Protected || !f.Chains["FORWARD"].Rules[2].Protected {
		t.Fatal("Docker's chains and rules are not locked")
	}
	if f.Chains["DOCKER-USER"].Protected {
		t.Fatal("DOCKER-USER is locked")
	}

	dir := privateDir(t)
	file := filepath.Join(dir, "rules.v4")
	w, err := NewWatchdog(dir, false, time.Hour, WithPersistFile(file))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Confirm(); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	s := string(saved)
	for _, keep := range []string{"-A FORWARD -i docker0 -o docker0 -j DROP", ":DOCKER-USER", "IPTLENS-IN-A"} {
		if !strings.Contains(s, keep) {
			t.Errorf("persist file lost %q", keep)
		}
	}
	if strings.Contains(s, ":DOCKER-FORWARD") || strings.Contains(s, "-j DOCKER-FORWARD") {
		t.Error("persist file keeps Docker's own chain")
	}
	cmd := exec.Command("iptables-restore", "--test")
	cmd.Stdin = strings.NewReader(s)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the persist file does not load: %v: %s\n%s", err, out, s)
	}
}

func TestIntegrationTrustedAddresses(t *testing.T) {
	integration(t)
	w, err := NewWatchdog(privateDir(t), false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p := trustedPolicy()
	if err := w.ApplyAccess(p); err != nil {
		t.Fatal(err)
	}
	for _, v6 := range []bool{false, true} {
		if got, ok := ReadAccess(liveState(t, v6)); !ok || !reflect.DeepEqual(got, p) {
			t.Fatalf("v6=%v: read back %+v (ok=%v), want %+v", v6, got, ok, p)
		}
	}
	for _, c := range [][]string{
		{"iptables", "-C", "IPTLENS-IN-A", "-s", "203.0.113.7", "-p", "tcp", "--dport", "5432", "-m", "comment",
			"--comment", "iptlens:port=5432/tcp level=vpn", "-j", "RETURN"},
		{"ip6tables", "-C", "IPTLENS-IN-A", "-s", "2001:db8::/48", "-p", "tcp", "--dport", "5432", "-m", "comment",
			"--comment", "iptlens:port=5432/tcp level=vpn", "-j", "RETURN"},
	} {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", strings.Join(c, " "), err, out)
		}
	}
	if err := w.Rollback(); err != nil {
		t.Fatal(err)
	}
}
