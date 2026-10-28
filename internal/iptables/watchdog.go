package iptables

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultKeepBackups is how many iptables-save snapshots are kept in the state directory.
const DefaultKeepBackups = 20

// Watchdog applies one change at a time and keeps its undo commands.
// If the change is not confirmed before the timeout, the undo commands run.
// The pending change is written to disk before anything is applied, so a
// crash or restart in the middle still rolls it back on the next start.
type Watchdog struct {
	mu          sync.Mutex
	dir         string
	demo        bool
	timeout     time.Duration
	keepBackups int
	persistFile string
	pending     *change
}

type change struct {
	Desc    string     `json:"desc"`
	Undo    [][]string `json:"undo"` // in execution order (reverse of the applied steps)
	Expires time.Time  `json:"expires"`
	timer   *time.Timer
}

// plan is one change: each step's undo reverses exactly that step.
type plan struct {
	desc  string
	steps []step
}

type step struct{ do, undo []string }

// Option configures a Watchdog.
type Option func(*Watchdog)

// WithKeepBackups sets how many backup snapshots to keep (n < 1 keeps the default).
func WithKeepBackups(n int) Option {
	return func(w *Watchdog) {
		if n > 0 {
			w.keepBackups = n
		}
	}
}

// WithPersistFile makes Confirm write the full ruleset to path (for example
// /etc/iptables/rules.v4), so confirmed changes survive a reboot.
func WithPersistFile(path string) Option {
	return func(w *Watchdog) { w.persistFile = path }
}

func NewWatchdog(dir string, demo bool, timeout time.Duration, opts ...Option) (*Watchdog, error) {
	w := &Watchdog{dir: dir, demo: demo, timeout: timeout, keepBackups: DefaultKeepBackups}
	for _, o := range opts {
		o(w)
	}
	if demo {
		return w, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create state directory %s: %w", dir, err)
	}
	if data, err := os.ReadFile(w.pendingPath()); err == nil {
		var c change
		if json.Unmarshal(data, &c) == nil {
			log.Printf("found unconfirmed change (%s), rolling it back", c.Desc)
			if err := runUndo(c.Undo); err != nil {
				log.Printf("rollback error: %v", err)
			}
		}
		_ = os.Remove(w.pendingPath())
	}
	return w, nil
}

func (w *Watchdog) pendingPath() string { return filepath.Join(w.dir, "pending.json") }

func runUndo(cmds [][]string) error {
	var errs []string
	for _, cmd := range cmds {
		if out, err := ipt(cmd...); err != nil {
			errs = append(errs, fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out))))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// reverseUndo returns the undo commands of steps in reverse order.
func reverseUndo(steps []step) [][]string {
	undo := make([][]string, 0, len(steps))
	for i := len(steps) - 1; i >= 0; i-- {
		undo = append(undo, steps[i].undo)
	}
	return undo
}

// begin builds the plan under the lock, takes a backup, records the pending
// change, applies the steps and arms the rollback timer.
func (w *Watchdog) begin(build func() (plan, error)) error {
	if w.demo {
		return ErrDemo
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.pending != nil {
		return ErrPending
	}
	p, err := build()
	if err != nil {
		return err
	}

	if err := w.backup(); err != nil {
		return err
	}

	c := &change{Desc: p.desc, Undo: reverseUndo(p.steps), Expires: time.Now().Add(w.timeout)}
	if err := w.writePending(c); err != nil {
		return fmt.Errorf("cannot record pending change, nothing was applied: %w", err)
	}

	for i, st := range p.steps {
		if out, err := ipt(st.do...); err != nil {
			applyErr := fmt.Errorf("iptables error: %s", strings.TrimSpace(string(out)))
			if rbErr := runUndo(reverseUndo(p.steps[:i])); rbErr != nil {
				log.Printf("rollback after failed apply: %v", rbErr)
				return fmt.Errorf("%w (rollback also failed: %v)", applyErr, rbErr)
			}
			_ = os.Remove(w.pendingPath())
			return applyErr
		}
	}

	w.pending = c
	c.timer = time.AfterFunc(w.timeout, func() { w.expire(c) })
	return nil
}

// backup writes an iptables-save snapshot and prunes old ones.
func (w *Watchdog) backup() error {
	save, err := runSave()
	if err != nil {
		return fmt.Errorf("cannot take a backup, nothing was changed: %w", err)
	}
	path := filepath.Join(w.dir, fmt.Sprintf("backup-%d.rules", time.Now().UnixNano()))
	if err := writeFileAtomic(path, save, 0o600); err != nil {
		return fmt.Errorf("cannot write backup: %w", err)
	}
	w.pruneBackups()
	return nil
}

func (w *Watchdog) pruneBackups() {
	files, err := filepath.Glob(filepath.Join(w.dir, "backup-*.rules"))
	if err != nil || len(files) <= w.keepBackups {
		return
	}
	// Names embed a nanosecond timestamp of equal width, so lexical order is age order.
	slices.Sort(files)
	for _, f := range files[:len(files)-w.keepBackups] {
		if err := os.Remove(f); err != nil {
			log.Printf("cannot remove old backup %s: %v", f, err)
		}
	}
}

// Apply adds a new rule (-A, or -I at a position).
func (w *Watchdog) Apply(req ApplyRequest) error {
	if w.demo {
		return ErrDemo
	}
	spec, err := ValidateRule(req.Table, req.Chain, req.Rule)
	if err != nil {
		return err
	}
	if req.Position < 0 || req.Position > 1000 {
		return invalidf("position must be between 0 and 1000")
	}
	return w.begin(func() (plan, error) {
		if _, err := ipt(append([]string{"-t", req.Table, "-C", req.Chain}, spec...)...); err == nil {
			return plan{}, ErrDuplicate
		}
		add := []string{"-t", req.Table}
		if req.Position > 0 {
			add = append(add, "-I", req.Chain, strconv.Itoa(req.Position))
		} else {
			add = append(add, "-A", req.Chain)
		}
		add = append(add, spec...)
		return plan{
			desc:  fmt.Sprintf("add %s/%s", req.Table, req.Chain),
			steps: []step{{do: add, undo: append([]string{"-t", req.Table, "-D", req.Chain}, spec...)}},
		}, nil
	})
}

func (w *Watchdog) expire(c *change) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending != c {
		return
	}
	log.Printf("not confirmed in time, rolling back: %s", c.Desc)
	if err := runUndo(c.Undo); err != nil {
		log.Printf("rollback error: %v", err)
	}
	w.pending = nil
	_ = os.Remove(w.pendingPath())
}

// Confirm keeps the pending change and reports whether the ruleset was saved
// to the persist file. A save failure is returned, but the change stays
// confirmed in the running firewall. The lock is held while saving so that no
// new unconfirmed change can end up in the saved ruleset.
func (w *Watchdog) Confirm() (persisted bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == nil {
		return false, ErrNoPending
	}
	w.pending.timer.Stop()
	w.pending = nil
	_ = os.Remove(w.pendingPath())
	if w.persistFile == "" {
		return false, nil
	}
	if err := w.persist(); err != nil {
		return false, fmt.Errorf("change confirmed, but saving it to %s failed: %w", w.persistFile, err)
	}
	return true, nil
}

func (w *Watchdog) persist() error {
	rules, err := runSaveRules()
	if err != nil {
		return err
	}
	return writeFileAtomic(w.persistFile, rules, 0o600)
}

// Status reports whether a change awaits confirmation and the seconds left.
func (w *Watchdog) Status() (bool, int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == nil {
		return false, 0
	}
	rem := int64(time.Until(w.pending.Expires).Seconds())
	if rem < 0 {
		rem = 0
	}
	return true, rem
}

func (w *Watchdog) writePending(c *change) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return writeFileAtomic(w.pendingPath(), data, 0o600)
}

// writeFileAtomic writes to a temp file in the same directory, syncs it and
// renames it over path, so readers never see a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(perm)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
