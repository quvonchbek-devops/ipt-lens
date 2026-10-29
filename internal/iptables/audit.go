package iptables

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AuditEntry is one line of the audit log: what was applied, confirmed or
// rolled back, and when.
type AuditEntry struct {
	Time     time.Time `json:"time"`
	Event    string    `json:"event"`
	Desc     string    `json:"desc,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Commands []string  `json:"commands,omitempty"`
}

// auditMax is the size at which audit.log is moved to audit.log.1.
const auditMax = 1 << 20

func (w *Watchdog) auditPath() string { return filepath.Join(w.dir, "audit.log") }

// audit appends an entry. It never blocks a firewall change: a write error is
// logged, since refusing a rollback because the log is full would be worse.
func (w *Watchdog) audit(event, desc, detail string, commands []string) {
	if w.demo {
		return
	}
	w.auditMu.Lock()
	defer w.auditMu.Unlock()
	line, err := json.Marshal(AuditEntry{Time: time.Now().UTC(), Event: event, Desc: desc, Detail: detail, Commands: commands})
	if err != nil {
		return
	}
	if fi, err := os.Stat(w.auditPath()); err == nil && fi.Size() > auditMax {
		if err := os.Rename(w.auditPath(), w.auditPath()+".1"); err != nil {
			log.Printf("cannot rotate audit log: %v", err)
		}
	}
	f, err := os.OpenFile(w.auditPath(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err == nil {
		_, err = f.Write(append(line, '\n'))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		log.Printf("cannot write audit log: %v", err)
	}
}

// Audit returns the last n entries, oldest first.
func (w *Watchdog) Audit(n int) ([]AuditEntry, error) {
	out := []AuditEntry{}
	if w.demo {
		return out, nil
	}
	w.auditMu.Lock()
	defer w.auditMu.Unlock()
	f, err := os.Open(w.auditPath())
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), auditMax)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

// commandsOf describes the steps of a plan as shell commands.
func commandsOf(steps []step) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		bin, args := "iptables", s.do
		if len(args) > 0 && args[0] == v6Flag {
			bin, args = "ip6tables", args[1:]
		}
		if s.restore != nil {
			chain, rules := "", 0
			for _, l := range strings.Split(string(s.restore), "\n") {
				if strings.HasPrefix(l, ":") {
					chain = strings.Fields(l[1:])[0]
				} else if strings.HasPrefix(l, "-A ") {
					rules++
				}
			}
			out = append(out, fmt.Sprintf("%s-restore --noflush (%d rules into %s)", bin, rules, chain))
			continue
		}
		out = append(out, bin+" "+strings.Join(args, " "))
	}
	return out
}
