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

// IPv6Available reports whether this host has an IPv6 firewall to manage.
func IPv6Available() bool {
	_, present, _ := ipv6State()
	return present
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

// haveIP6 reports whether ip6tables is installed. When it is, failing to read
// it is an error, never a reason to leave IPv6 out.
var haveIP6 = func() bool {
	_, err := exec.LookPath("ip6tables-save")
	return err == nil
}

// ipv6State returns the live ip6tables ruleset. present is false when the
// host has no IPv6 firewall to manage: ip6tables is missing, or the kernel
// has IPv6 disabled (ip6tables-save lists no tables).
func ipv6State() (st *SystemState, present bool, err error) {
	if !haveIP6() {
		return nil, false, nil
	}
	st, err = currentState6()
	if err != nil {
		return nil, true, err
	}
	return st, len(st.Tables) > 0, nil
}
