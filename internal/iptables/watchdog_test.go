package iptables

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIPT replaces the iptables binaries for the duration of a test and
// records every call (without the "-w 5" lock prefix).
type fakeIPT struct {
	mu     sync.Mutex
	calls  []string
	failOn string                 // a call containing this substring fails
	onCall func(cmd string) error // optional hook, runs before the call is recorded
	save   string
}

func installFake(t *testing.T) *fakeIPT {
	t.Helper()
	f := &fakeIPT{save: "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"}
	oldIPT, oldSave, oldRules := runIPT, runSave, runSaveRules
	runIPT = func(args ...string) ([]byte, error) {
		cmd := strings.Join(args[2:], " ")
		if f.onCall != nil {
			if err := f.onCall(cmd); err != nil {
				return []byte(err.Error()), err
			}
		}
		f.mu.Lock()
		f.calls = append(f.calls, cmd)
		f.mu.Unlock()
		if f.failOn != "" && strings.Contains(cmd, f.failOn) {
			return []byte("fake failure"), errors.New("exit status 1")
		}
		return nil, nil
	}
	runSave = func() ([]byte, error) { return []byte(f.save), nil }
	runSaveRules = func() ([]byte, error) { return []byte(f.save), nil }
	t.Cleanup(func() { runIPT, runSave, runSaveRules = oldIPT, oldSave, oldRules })
	return f
}

func (f *fakeIPT) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func twoStepPlan() (plan, error) {
	return plan{
		desc: "two steps",
		steps: []step{
			{do: []string{"-t", "filter", "-A", "INPUT", "-j", "ACCEPT"}, undo: []string{"-t", "filter", "-D", "INPUT", "-j", "ACCEPT"}},
			{do: []string{"-t", "filter", "-A", "INPUT", "-j", "DROP"}, undo: []string{"-t", "filter", "-D", "INPUT", "-j", "DROP"}},
		},
	}, nil
}

func newTestWatchdog(t *testing.T, timeout time.Duration, opts ...Option) *Watchdog {
	t.Helper()
	w, err := NewWatchdog(t.TempDir(), false, timeout, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestBeginWritesPendingBeforeApply(t *testing.T) {
	f := installFake(t)
	w := newTestWatchdog(t, time.Hour)
	f.onCall = func(cmd string) error {
		if !strings.Contains(cmd, "-A INPUT") {
			return nil
		}
		data, err := os.ReadFile(w.pendingPath())
		if err != nil {
			t.Errorf("pending.json missing while applying %q: %v", cmd, err)
			return nil
		}
		if !strings.Contains(string(data), `"-D","INPUT","-j","DROP"`) {
			t.Errorf("pending.json does not hold the full undo: %s", data)
		}
		return nil
	}
	if err := w.begin(twoStepPlan); err != nil {
		t.Fatal(err)
	}
}

func TestBeginForwardFailureCleansUp(t *testing.T) {
	f := installFake(t)
	f.failOn = "-A INPUT -j DROP"
	w := newTestWatchdog(t, time.Hour)

	if err := w.begin(twoStepPlan); err == nil {
		t.Fatal("expected an error when a forward command fails")
	}
	calls := f.Calls()
	if last := calls[len(calls)-1]; last != "-t filter -D INPUT -j ACCEPT" {
		t.Fatalf("first step was not rolled back, calls: %q", calls)
	}
	for _, c := range calls {
		if c == "-t filter -D INPUT -j DROP" {
			t.Fatalf("undo ran for a step that never applied: %q", calls)
		}
	}
	if _, err := os.Stat(w.pendingPath()); !os.IsNotExist(err) {
		t.Fatalf("pending.json left behind: %v", err)
	}
	if pending, _ := w.Status(); pending {
		t.Fatal("watchdog still reports a pending change")
	}
}

func TestExpireRunsUndoInReverse(t *testing.T) {
	f := installFake(t)
	w := newTestWatchdog(t, 20*time.Millisecond)
	if err := w.begin(twoStepPlan); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if pending, _ := w.Status(); !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("change never expired")
		}
		time.Sleep(5 * time.Millisecond)
	}
	calls := f.Calls()
	want := []string{"-t filter -D INPUT -j DROP", "-t filter -D INPUT -j ACCEPT"}
	got := calls[len(calls)-2:]
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("undo order = %q, want %q", got, want)
	}
	if _, err := os.Stat(w.pendingPath()); !os.IsNotExist(err) {
		t.Fatal("pending.json not removed after expiry")
	}
}

func TestConfirmClearsPending(t *testing.T) {
	installFake(t)
	w := newTestWatchdog(t, time.Hour)
	if err := w.begin(twoStepPlan); err != nil {
		t.Fatal(err)
	}
	if err := w.Confirm(); err != nil {
		t.Fatal(err)
	}
	if pending, _ := w.Status(); pending {
		t.Fatal("still pending after confirm")
	}
	if _, err := os.Stat(w.pendingPath()); !os.IsNotExist(err) {
		t.Fatal("pending.json not removed after confirm")
	}
	if err := w.Confirm(); !errors.Is(err, ErrNoPending) {
		t.Fatalf("second confirm: got %v, want ErrNoPending", err)
	}
}

func TestRecoverOnStart(t *testing.T) {
	f := installFake(t)
	dir := t.TempDir()
	pending := `{"desc":"left over","undo":[["-t","filter","-D","INPUT","-j","ACCEPT"]]}`
	if err := os.WriteFile(filepath.Join(dir, "pending.json"), []byte(pending), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWatchdog(dir, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if calls := f.Calls(); len(calls) != 1 || calls[0] != "-t filter -D INPUT -j ACCEPT" {
		t.Fatalf("recovery undo calls = %q", calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "pending.json")); !os.IsNotExist(err) {
		t.Fatal("pending.json not removed after recovery")
	}
}

func TestBackupsRotated(t *testing.T) {
	installFake(t)
	w := newTestWatchdog(t, time.Hour, WithKeepBackups(3))
	for i := 0; i < 5; i++ {
		if err := w.begin(twoStepPlan); err != nil {
			t.Fatal(err)
		}
		if err := w.Confirm(); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(w.dir, "backup-*.rules"))
	if len(files) != 3 {
		t.Fatalf("got %d backups, want 3: %v", len(files), files)
	}
}

func TestConfirmPersists(t *testing.T) {
	f := installFake(t)
	f.save = "*filter\n:INPUT DROP [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n"
	target := filepath.Join(t.TempDir(), "rules.v4")
	w := newTestWatchdog(t, time.Hour, WithPersistFile(target))
	if !w.Persistent() {
		t.Fatal("Persistent() = false with a persist file set")
	}
	if err := w.begin(twoStepPlan); err != nil {
		t.Fatal(err)
	}
	if err := w.Confirm(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != f.save {
		t.Fatalf("persisted rules = %q, want %q", data, f.save)
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o600 {
		t.Fatalf("persist file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestConfirmPersistFailureReported(t *testing.T) {
	installFake(t)
	target := filepath.Join(t.TempDir(), "missing-dir", "rules.v4")
	w := newTestWatchdog(t, time.Hour, WithPersistFile(target))
	if err := w.begin(twoStepPlan); err != nil {
		t.Fatal(err)
	}
	if err := w.Confirm(); err == nil {
		t.Fatal("expected a persistence error")
	}
	if pending, _ := w.Status(); pending {
		t.Fatal("change must stay confirmed even if persisting failed")
	}
}
