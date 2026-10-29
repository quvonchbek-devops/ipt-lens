package iptables

import (
	"os"
	"os/exec"
	"strings"
)

// Commands are variables so tests can replace them.
var (
	runIPT  = func(args ...string) ([]byte, error) { return exec.Command("iptables", args...).CombinedOutput() }
	runSave = func() ([]byte, error) { return exec.Command("iptables-save", "-c").Output() }
	// runSaveRules dumps the ruleset without counters, in the format iptables-restore reads.
	runSaveRules = func() ([]byte, error) { return exec.Command("iptables-save").Output() }
)

// ipt runs iptables and waits up to 5s for the xtables lock (Docker holds it at times).
func ipt(args ...string) ([]byte, error) {
	return runIPT(append([]string{"-w", "5"}, args...)...)
}

// bootID identifies the current boot, so a pending change recorded before a
// reboot is not replayed against a freshly restored ruleset.
var bootID = func() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
