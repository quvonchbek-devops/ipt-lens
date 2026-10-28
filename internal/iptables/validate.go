package iptables

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	ErrInvalid   = errors.New("noto'g'ri so'rov")
	ErrDemo      = errors.New("demo rejimida firewall o'zgartirilmaydi")
	ErrPending   = errors.New("avvalgi o'zgarish hali tasdiqlanmagan")
	ErrNoPending = errors.New("tasdiqlanadigan o'zgarish yo'q")
	ErrDuplicate = errors.New("bunday qoida allaqachon mavjud")
)

type ApplyRequest struct {
	Table    string `json:"table"`
	Chain    string `json:"chain"`
	Position int    `json:"position"` // 0 = oxiriga (-A), N > 0 = N-pozitsiyaga (-I)
	Rule     string `json:"rule"`
}

var (
	tableRe    = regexp.MustCompile(`^(filter|nat|mangle|raw)$`)
	chainRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,28}$`)
	ifaceRe    = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,15}$`)
	portRe     = regexp.MustCompile(`^[0-9]{1,5}(:[0-9]{1,5})?(,[0-9]{1,5}(:[0-9]{1,5})?)*$`)
	addrTypeRe = regexp.MustCompile(`^[A-Z]{3,12}$`)
)

// Ruxsat etilgan flaglar. Buyruq bilan bog'liq flaglar (-A, -F, -X, -P, -t ...) yo'q.
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

// ValidateRule qoida matnini tekshiradi va argumentlar ro'yxatini qaytaradi.
// Shell ishlatilmaydi, argumentlar to'g'ridan-to'g'ri exec ga beriladi.
func ValidateRule(table, chain, spec string) ([]string, error) {
	if !tableRe.MatchString(table) {
		return nil, invalidf("jadval noto'g'ri: %q", table)
	}
	if !chainRe.MatchString(chain) {
		return nil, invalidf("zanjir nomi noto'g'ri: %q", chain)
	}
	tokens := tokenizeRule(spec)
	if len(tokens) == 0 || len(tokens) > 64 {
		return nil, invalidf("qoida bo'sh yoki juda uzun")
	}

	hasJump := false
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "!" {
			if i+1 >= len(tokens) || !allowedFlags[tokens[i+1]] {
				return nil, invalidf("'!' dan keyin flag kutiladi")
			}
			continue
		}
		if !allowedFlags[tok] {
			return nil, invalidf("ruxsat etilmagan flag: %s", tok)
		}
		if i+1 >= len(tokens) {
			return nil, invalidf("%s uchun qiymat kerak", tok)
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
		return nil, invalidf("-j (target) majburiy")
	}
	return tokens, nil
}

func checkValue(flag, val string) error {
	switch flag {
	case "-i", "-o":
		if !ifaceRe.MatchString(val) {
			return invalidf("interfeys nomi noto'g'ri: %s", val)
		}
	case "-p":
		if !allowedProto[val] {
			return invalidf("protokol noto'g'ri: %s", val)
		}
	case "-s", "-d":
		if _, _, err := net.ParseCIDR(val); err != nil && net.ParseIP(val) == nil {
			return invalidf("IP yoki CIDR noto'g'ri: %s", val)
		}
	case "--dport", "--sport", "--dports", "--sports":
		if !portRe.MatchString(val) {
			return invalidf("port noto'g'ri: %s", val)
		}
	case "-j":
		if !allowedTargets[val] {
			return invalidf("target ruxsat etilmagan: %s (ACCEPT, DROP, REJECT, RETURN)", val)
		}
	case "-m":
		if !allowedModules[val] {
			return invalidf("modul ruxsat etilmagan: %s", val)
		}
	case "--ctstate", "--state":
		for _, st := range strings.Split(val, ",") {
			if !allowedStates[st] {
				return invalidf("holat noto'g'ri: %s", st)
			}
		}
	case "--dst-type", "--src-type":
		if !addrTypeRe.MatchString(val) {
			return invalidf("address turi noto'g'ri: %s", val)
		}
	case "--comment":
		if len(val) > 128 {
			return invalidf("izoh 128 belgidan uzun bo'lmasligi kerak")
		}
		for _, r := range val {
			if r < 32 || r == 127 {
				return invalidf("izohda boshqaruv belgisi bor")
			}
		}
	}
	return nil
}

func invalidf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}
