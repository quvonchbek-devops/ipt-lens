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

	runIP6T       = func(args ...string) ([]byte, error) { return exec.Command("ip6tables", args...).CombinedOutput() }
	runSave6      = func() ([]byte, error) { return exec.Command("ip6tables-save", "-c").Output() }
	runSaveRules6 = func() ([]byte, error) { return exec.Command("ip6tables-save").Output() }
)

// ipt runs iptables and waits up to 5s for the xtables lock (Docker holds it at
// times). A leading "-6" runs ip6tables instead; iptables itself is never
// given -6, so the marker cannot collide with a real argument.
func ipt(args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == v6Flag {
		return runIP6T(append([]string{"-w", "5"}, args[1:]...)...)
	}
	return runIPT(append([]string{"-w", "5"}, args...)...)
}

const v6Flag = "-6"

// IPv6Available reports whether ip6tables can be read on this host.
func IPv6Available() bool {
	_, err := runSave6()
	return err == nil
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
