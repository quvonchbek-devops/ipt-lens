package iptables

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Watchdog - har bir o'zgarish uchun "undo" buyruqlarini saqlaydi.
// Tasdiqlanmasa, undo bajariladi. Holat diskka yoziladi (crash'dan keyin tiklanadi).
type Watchdog struct {
	mu      sync.Mutex
	dir     string
	demo    bool
	timeout time.Duration
	pending *change
}

type change struct {
	Desc    string     `json:"desc"`
	Undo    [][]string `json:"undo"`
	Expires time.Time  `json:"expires"`
	timer   *time.Timer
}

// plan - bitta o'zgarishning forward (bajarish) va undo (qaytarish) buyruqlari.
type plan struct {
	desc    string
	forward [][]string
	undo    [][]string
}

func NewWatchdog(dir string, demo bool, timeout time.Duration) (*Watchdog, error) {
	w := &Watchdog{dir: dir, demo: demo, timeout: timeout}
	if demo {
		return w, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state papkasi yaratilmadi (%s): %w", dir, err)
	}
	if data, err := os.ReadFile(w.pendingPath()); err == nil {
		var c change
		if json.Unmarshal(data, &c) == nil {
			log.Printf("tasdiqlanmagan o'zgarish topildi (%s), qaytarilmoqda", c.Desc)
			if err := runUndo(c.Undo); err != nil {
				log.Printf("qaytarish xatosi: %v", err)
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

// begin - lock ostida plan tuzadi, backup oladi, forward buyruqlarni bajaradi va rollback timer'ini qo'yadi.
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

	save, err := runSave()
	if err != nil {
		return fmt.Errorf("backup olinmadi, o'zgarish qilinmadi: %w", err)
	}
	backupPath := filepath.Join(w.dir, fmt.Sprintf("backup-%d.rules", time.Now().UnixNano()))
	if err := os.WriteFile(backupPath, save, 0o600); err != nil {
		return fmt.Errorf("backup yozilmadi: %w", err)
	}

	for _, cmd := range p.forward {
		if out, err := ipt(cmd...); err != nil {
			return fmt.Errorf("iptables xatosi: %s", strings.TrimSpace(string(out)))
		}
	}

	c := &change{Desc: p.desc, Undo: p.undo, Expires: time.Now().Add(w.timeout)}
	w.pending = c
	c.timer = time.AfterFunc(w.timeout, func() { w.expire(c) })
	if err := w.writePending(c); err != nil {
		log.Printf("pending holati yozilmadi: %v", err)
	}
	return nil
}

// Apply - yangi qoida qo'shadi (-A yoki -I pozitsiya).
func (w *Watchdog) Apply(req ApplyRequest) error {
	if w.demo {
		return ErrDemo
	}
	spec, err := ValidateRule(req.Table, req.Chain, req.Rule)
	if err != nil {
		return err
	}
	if req.Position < 0 || req.Position > 1000 {
		return invalidf("pozitsiya 0 dan 1000 gacha bo'lishi kerak")
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
			desc:    fmt.Sprintf("qo'shish %s/%s", req.Table, req.Chain),
			forward: [][]string{add},
			undo:    [][]string{append([]string{"-t", req.Table, "-D", req.Chain}, spec...)},
		}, nil
	})
}

func (w *Watchdog) expire(c *change) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending != c {
		return
	}
	log.Printf("tasdiqlanmadi, qaytarilmoqda: %s", c.Desc)
	if err := runUndo(c.Undo); err != nil {
		log.Printf("rollback xatosi: %v", err)
	}
	w.pending = nil
	_ = os.Remove(w.pendingPath())
}

// Confirm - o'zgarishni doimiy qoldiradi.
func (w *Watchdog) Confirm() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == nil {
		return ErrNoPending
	}
	w.pending.timer.Stop()
	w.pending = nil
	_ = os.Remove(w.pendingPath())
	return nil
}

// Status - tasdiqlash kutilayotganini va qolgan soniyalarni qaytaradi.
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
	return os.WriteFile(w.pendingPath(), data, 0o600)
}
