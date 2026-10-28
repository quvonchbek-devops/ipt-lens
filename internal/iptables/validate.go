package iptables

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	ErrInvalid   = errors.New("invalid request")
	ErrDemo      = errors.New("the firewall cannot be changed in demo mode")
	ErrPending   = errors.New("the previous change has not been confirmed yet")
	ErrNoPending = errors.New("there is no change to confirm")
	ErrDuplicate = errors.New("this rule already exists")
)

type ApplyRequest struct {
	Table    string `json:"table"`
	Chain    string `json:"chain"`
	Position int    `json:"position"` // 0 = append (-A), N > 0 = insert at N (-I)
	Rule     string `json:"rule"`
}

var (
	tableRe    = regexp.MustCompile(`^(filter|nat|mangle|raw)$`)
	chainRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,28}$`)
	ifaceRe    = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,15}$`)
	portRe     = regexp.MustCompile(`^[0-9]{1,5}(:[0-9]{1,5})?(,[0-9]{1,5}(:[0-9]{1,5})?)*$`)
	addrTypeRe = regexp.MustCompile(`^[A-Z]{3,12}$`)
)

// allowedFlags lists the rule options accepted from clients. Command flags
// (-A, -F, -X, -P, -t, ...) are deliberately absent.
var allowedFlags = map[string]bool{
	"-i": true, "-o": true, "-p": true, "-s": true, "-d": true, "-m": true,
	"--dport": true, "--sport": true, "--dports": true, "--sports": true,
	"--comment": true, "-j": true, "--ctstate": true, "--state": true,
	"--dst-type": true, "--src-type": true,
}

var (
	allowedProto   = map[string]bool{"tcp": true, "udp": true, "icmp": true, "all": true}
	allowedTargets = map[string]bool{"ACCEPT": true, "DROP": true, "REJECT": true, "RETURN": true}
	allowedModules = map[string]bool{"tcp": true, "udp": true, "comment": true, "multiport": true,
		"conntrack": true, "state": true, "addrtype": true}
	allowedStates = map[string]bool{"NEW": true, "ESTABLISHED": true, "RELATED": true,
		"INVALID": true, "UNTRACKED": true}
)

// ValidateRule checks a rule spec and returns it as an argument list.
// No shell is involved: the arguments are passed directly to exec.
func ValidateRule(table, chain, spec string) ([]string, error) {
	if err := checkNames(table, chain); err != nil {
		return nil, err
	}
	tokens := tokenizeRule(spec)
	if len(tokens) == 0 || len(tokens) > 64 {
		return nil, invalidf("rule is empty or too long")
	}

	hasJump := false
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "!" {
			if i+1 >= len(tokens) || !allowedFlags[tokens[i+1]] {
				return nil, invalidf("'!' must be followed by an option")
			}
			continue
		}
		if !allowedFlags[tok] {
			return nil, invalidf("option not allowed: %s", tok)
		}
		if i+1 >= len(tokens) {
			return nil, invalidf("%s needs a value", tok)
		}
		val := tokens[i+1]
		i++
		if err := checkValue(tok, val); err != nil {
			return nil, err
		}
		if tok == "-j" {
			hasJump = true
		}
	}
	if !hasJump {
		return nil, invalidf("-j (target) is required")
	}
	return tokens, nil
}

func checkValue(flag, val string) error {
	switch flag {
	case "-i", "-o":
		if !ifaceRe.MatchString(val) {
			return invalidf("invalid interface name: %s", val)
		}
	case "-p":
		if !allowedProto[val] {
			return invalidf("invalid protocol: %s", val)
		}
	case "-s", "-d":
		if _, _, err := net.ParseCIDR(val); err != nil && net.ParseIP(val) == nil {
			return invalidf("invalid IP or CIDR: %s", val)
		}
	case "--dport", "--sport", "--dports", "--sports":
		if !portRe.MatchString(val) {
			return invalidf("invalid port: %s", val)
		}
	case "-j":
		if !allowedTargets[val] {
			return invalidf("target not allowed: %s (use ACCEPT, DROP, REJECT or RETURN)", val)
		}
	case "-m":
		if !allowedModules[val] {
			return invalidf("match module not allowed: %s", val)
		}
	case "--ctstate", "--state":
		for _, st := range strings.Split(val, ",") {
			if !allowedStates[st] {
				return invalidf("invalid connection state: %s", st)
			}
		}
	case "--dst-type", "--src-type":
		if !addrTypeRe.MatchString(val) {
			return invalidf("invalid address type: %s", val)
		}
	case "--comment":
		if len(val) > 128 {
			return invalidf("comment must be at most 128 characters")
		}
		for _, r := range val {
			if r < 32 || r == 127 {
				return invalidf("comment contains a control character")
			}
		}
	}
	return nil
}

func invalidf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}
