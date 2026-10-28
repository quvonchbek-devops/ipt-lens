package iptables

import "os/exec"

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
