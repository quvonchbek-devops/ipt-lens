package iptables

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func events(t *testing.T, w *Watchdog) []string {
	t.Helper()
	es, err := w.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Event+": "+e.Desc)
	}
	return out
}

func TestAuditApplyConfirm(t *testing.T) {
	installFake(t)
	w := newTestWatchdog(t, time.Hour)
	if err := w.begin(twoStepPlan); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Confirm(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events(t, w), " | "); got != "applied: two steps | confirmed: two steps" {
		t.Fatalf("events = %q", got)
	}
	es, _ := w.Audit(1)
	if len(es) != 1 || es[0].Event != "confirmed" {
		t.Fatalf("Audit(1) = %+v, want the newest entry", es)
	}
	all, _ := w.Audit(10)
	if c := all[0].Commands; len(c) != 2 || c[0] != "iptables -t filter -A INPUT -j ACCEPT" {
		t.Fatalf("applied commands = %q", c)
	}
	fi, err := os.Stat(filepath.Join(w.dir, "audit.log"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("audit.log mode: %v %v", fi, err)
	}
}

func TestAuditRollbacks(t *testing.T) {
	f := installFake(t)
	w := newTestWatchdog(t, time.Hour)
	if err := w.begin(twoStepPlan); err != nil {
		t.Fatal(err)
	}
	expireNow(t, w)
	f.failOn = "-A INPUT -j DROP"
	if err := w.begin(twoStepPlan); err == nil {
		t.Fatal("expected failure")
	}
	got := strings.Join(events(t, w), " | ")
	want := "applied: two steps | rolled back (not confirmed in time): two steps | apply failed, rolled back: two steps"
	if got != want {
		t.Fatalf("events = %q\nwant     %q", got, want)
	}
}

func TestAuditRecoveryAndDetail(t *testing.T) {
	installFake(t)
	dir := privateDir(t)
	rec := change{Desc: "left over", BootID: bootID(), Undo: [][]string{{"-t", "filter", "-D", "INPUT", "-j", "ACCEPT"}}}
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(dir+"/pending.json", data, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewWatchdog(dir, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events(t, w), " | "); got != "rolled back at start (unconfirmed before a restart): left over" {
		t.Fatalf("events = %q", got)
	}
}

func TestAuditEmptyAndDemo(t *testing.T) {
	installFake(t)
	w := newTestWatchdog(t, time.Hour)
	if es, err := w.Audit(10); err != nil || len(es) != 0 {
		t.Fatalf("fresh audit = %v, %v", es, err)
	}
	d, err := NewWatchdog(privateDir(t), true, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if es, err := d.Audit(10); err != nil || len(es) != 0 {
		t.Fatalf("demo audit = %v, %v", es, err)
	}
}
