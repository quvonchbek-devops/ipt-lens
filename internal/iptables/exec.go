package iptables

import "os/exec"

// Testda almashtirish mumkin bo'lishi uchun buyruqlar o'zgaruvchida.
var (
	runIPT  = func(args ...string) ([]byte, error) { return exec.Command("iptables", args...).CombinedOutput() }
	runSave = func() ([]byte, error) { return exec.Command("iptables-save", "-c").Output() }
)

// ipt - xtables lock kutish bilan iptables chaqiradi (Docker bilan to'qnashmaslik uchun).
func ipt(args ...string) ([]byte, error) {
	return runIPT(append([]string{"-w", "5"}, args...)...)
}
