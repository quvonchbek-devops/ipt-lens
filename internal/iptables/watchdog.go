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
	"syscall"
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
	BootID  string     `json:"boot_id,omitempty"`
	Expires time.Time  `json:"expires"`
	cleanup [][]string // best-effort commands run after confirmation
	timer   *time.Timer
}

// plan is one change: each step's undo reverses exactly that step.
type plan struct {
	desc    string
	steps   []step
	cleanup [][]string // run after confirmation, e.g. removing a replaced chain
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
	if err := checkPrivateDir(dir); err != nil {
		return nil, err
	}
	w.recover()
	return w, nil
}

// checkPrivateDir refuses a state directory that is a symlink, writable by
// group or others, or owned by another user: its pending.json drives iptables.
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("state directory %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("state directory %s is writable by group or others (mode %v); use chmod 700", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("state directory %s is owned by uid %d, not by this process", dir, st.Uid)
	}
	return nil
}

// recover rolls back a change left unconfirmed by a crash or restart. A record
// from an earlier boot is discarded: the kernel ruleset was rebuilt since.
func (w *Watchdog) recover() {
	// The record is removed only when it is settled. A record that cannot be
	// read, is refused or fails to roll back stays, and blocks new changes
	// until an operator checks the rules and removes it.
	data, err := os.ReadFile(w.pendingPath())
	if err != nil {
		return
	}
	var c change
	if err := json.Unmarshal(data, &c); err != nil {
		log.Printf("cannot read %s, leaving it for an operator: %v", w.pendingPath(), err)
		return
	}
	if c.BootID != "" && c.BootID != bootID() {
		log.Printf("unconfirmed change (%s) predates the last reboot; not replaying its undo", c.Desc)
		_ = os.Remove(w.pendingPath())
		return
	}
	for _, cmd := range c.Undo {
		if !safeUndo(cmd) {
			log.Printf("refusing unexpected undo command in %s, leaving it for an operator: %q", w.pendingPath(), cmd)
			return
		}
	}
	log.Printf("found unconfirmed change (%s), rolling it back", c.Desc)
	if err := runUndo(c.Undo); err != nil {
		log.Printf("rollback error, leaving %s for an operator: %v", w.pendingPath(), err)
		return
	}
	_ = os.Remove(w.pendingPath())
}

// safeUndo accepts only the shapes this package writes:
// -t <table> -D|-I|-R <chain> ..., with no --modprobe.
func safeUndo(cmd []string) bool {
	if len(cmd) < 4 || cmd[0] != "-t" || checkNames(cmd[1], cmd[3]) != nil {
		return false
	}
	switch cmd[2] {
	case "-D", "-I", "-R":
	case "-F", "-X": // only IPT-Lens' own chains may be flushed or deleted
		if len(cmd) != 4 || !strings.HasPrefix(cmd[3], accessPrefix) {
			return false
		}
	default:
		return false
	}
	for _, a := range cmd {
		if strings.HasPrefix(a, "--modprobe") {
			return false
		}
	}
	return true
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
		if len(steps[i].undo) > 0 { // some steps are undone together by another step's undo
			undo = append(undo, steps[i].undo)
		}
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
	if _, err := os.Stat(w.pendingPath()); err == nil {
		return fmt.Errorf("%w: an earlier rollback failed; fix the rules by hand (see the log and %s), then remove that file",
			ErrPending, w.pendingPath())
	}
	p, err := build()
	if err != nil {
		return err
	}

	if err := w.backup(); err != nil {
		return err
	}

	c := &change{Desc: p.desc, Undo: reverseUndo(p.steps), Expires: time.Now().Add(w.timeout), BootID: bootID(),
		cleanup: p.cleanup}
	if err := w.writePending(c); err != nil {
		return fmt.Errorf("cannot record pending change, nothing was applied: %w", err)
	}

	for i, st := range p.steps {
		if out, err := ipt(st.do...); err != nil {
			applyErr := fmt.Errorf("iptables error: %s", strings.TrimSpace(string(out)))
			c.Undo = reverseUndo(p.steps[:i]) // only the steps that ran
			if err := w.writePending(c); err != nil {
				log.Printf("cannot update pending record: %v", err)
			}
			if rbErr := runUndo(c.Undo); rbErr != nil {
				// Keep pending.json: it is the only record of what is still applied.
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
	if protectedName(req.Chain) {
		return ErrProtected
	}
	if strings.HasPrefix(req.Chain, accessPrefix) {
		return fmt.Errorf("%w: %s belongs to IPT-Lens' simple view; change it there", ErrProtected, req.Chain)
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
	w.pending = nil
	if err := runUndo(c.Undo); err != nil {
		// Keep pending.json: it records what may still be applied, and blocks new changes.
		log.Printf("rollback error, leaving %s for an operator: %v", w.pendingPath(), err)
		return
	}
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
	cleanup := w.pending.cleanup
	w.pending = nil
	_ = os.Remove(w.pendingPath())
	for _, cmd := range cleanup {
		if out, err := ipt(cmd...); err != nil {
			log.Printf("cleanup %q: %v: %s", cmd, err, strings.TrimSpace(string(out)))
		}
	}
	if w.persistFile == "" {
		return false, nil
	}
	if err := w.persist(); err != nil {
		return false, fmt.Errorf("change confirmed, but saving it to %s failed: %w", w.persistFile, err)
	}
	return true, nil
}

// persist saves the ruleset without chains that Docker, Kubernetes and the
// like rebuild themselves; restoring their stale rules at boot breaks them.
// A symlinked persist file is written through to its target.
func (w *Watchdog) persist() error {
	rules, err := runSaveRules()
	if err != nil {
		return err
	}
	path, err := resolveLinks(w.persistFile)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, stripManaged(rules), 0o600)
}

// resolveLinks follows a chain of symlinks to the final path, which need not
// exist yet (filepath.EvalSymlinks fails on a dangling link).
func resolveLinks(path string) (string, error) {
	for i := 0; i < 40; i++ {
		target, err := os.Readlink(path)
		if err != nil {
			return path, nil // not a symlink (or missing): write here
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = target
	}
	return "", fmt.Errorf("too many levels of symlinks at %s", path)
}

// stripManaged drops managed chains, their rules and jumps into them from
// iptables-save output.
func stripManaged(save []byte) []byte {
	var out []byte
	for _, line := range strings.SplitAfter(string(save), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, ":") {
			if f := strings.Fields(t[1:]); len(f) > 0 && protectedName(f[0]) {
				continue
			}
		}
		if strings.HasPrefix(t, "-A ") {
			if chain, r, err := parseRuleLine(t); err == nil && isProtected(chain, r) {
				continue
			}
		}
		out = append(out, line...)
	}
	return out
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
