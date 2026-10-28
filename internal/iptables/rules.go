package iptables

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrProtected = errors.New("bu qoida Docker yoki Kubernetes tomonidan boshqariladi, UI orqali o'zgartirilmaydi")
	ErrStale     = errors.New("qoidalar ro'yxati o'zgargan, sahifani yangilab qayta urinib ko'ring")
)

var counterRe = regexp.MustCompile(`^\[\d+:\d+\]\s*`)

// stripCounters - "[pkts:bytes] " prefiksini olib tashlaydi (counter'lar doim o'zgaradi).
func stripCounters(raw string) string {
	return strings.TrimSpace(counterRe.ReplaceAllString(strings.TrimSpace(raw), ""))
}

// ruleArgs - "-A CHAIN ..." qatoridan faqat qoida argumentlarini qaytaradi.
func ruleArgs(raw string) []string {
	toks := tokenizeRule(stripCounters(raw))
	if len(toks) >= 2 && toks[0] == "-A" {
		return toks[2:]
	}
	return toks
}

func protectedName(n string) bool {
	if n == "DOCKER" || strings.HasPrefix(n, "DOCKER-ISOLATION") {
		return true
	}
	for _, p := range []string{"KUBE-", "cali-", "LIBVIRT_", "ufw-"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// isProtected - zanjir yoki qoida maqsadi (target) Docker/Kubernetes'niki bo'lsa true.
func isProtected(chain string, r *Rule) bool {
	return protectedName(chain) || protectedName(r.Target)
}

func checkNames(table, chain string) error {
	if !tableRe.MatchString(table) {
		return invalidf("jadval noto'g'ri: %q", table)
	}
	if !chainRe.MatchString(chain) {
		return invalidf("zanjir nomi noto'g'ri: %q", chain)
	}
	return nil
}

func currentState() (*SystemState, error) {
	out, err := runSave()
	if err != nil {
		return nil, fmt.Errorf("iptables-save ishlamadi: %w", err)
	}
	return ParseIptablesSave(bytes.NewReader(out))
}

// findRule - hozirgi holatda #num qoidani topadi va UI kutgan qoida bilan solishtiradi.
func findRule(table, chain string, num int, expect string) (*Rule, error) {
	st, err := currentState()
	if err != nil {
		return nil, err
	}
	tbl, ok := st.Tables[table]
	if !ok {
		return nil, invalidf("jadval topilmadi: %s", table)
	}
	ch, ok := tbl.Chains[chain]
	if !ok {
		return nil, invalidf("zanjir topilmadi: %s", chain)
	}
	if num < 1 || num > len(ch.Rules) {
		return nil, invalidf("qoida #%d topilmadi", num)
	}
	r := ch.Rules[num-1]
	if stripCounters(r.RawRule) != stripCounters(expect) {
		return nil, ErrStale
	}
	if isProtected(chain, r) {
		return nil, ErrProtected
	}
	return r, nil
}

// DeleteRule - qoidani o'chiradi. Tasdiqlanmasa, aynan shu joyga qayta qo'yiladi.
func (w *Watchdog) DeleteRule(table, chain string, num int, expect string) error {
	if err := checkNames(table, chain); err != nil {
		return err
	}
	return w.begin(func() (plan, error) {
		r, err := findRule(table, chain, num, expect)
		if err != nil {
			return plan{}, err
		}
		n := strconv.Itoa(num)
		return plan{
			desc:    fmt.Sprintf("o'chirish %s/%s #%d", table, chain, num),
			forward: [][]string{{"-t", table, "-D", chain, n}},
			undo:    [][]string{append([]string{"-t", table, "-I", chain, n}, ruleArgs(r.RawRule)...)},
		}, nil
	})
}

// EditRule - qoidani atomik almashtiradi (-R). Tasdiqlanmasa, eski holatiga qaytariladi.
func (w *Watchdog) EditRule(table, chain string, num int, expect, newRule string) error {
	if err := checkNames(table, chain); err != nil {
		return err
	}
	spec, err := ValidateRule(table, chain, newRule)
	if err != nil {
		return err
	}
	return w.begin(func() (plan, error) {
		r, err := findRule(table, chain, num, expect)
		if err != nil {
			return plan{}, err
		}
		n := strconv.Itoa(num)
		return plan{
			desc:    fmt.Sprintf("tahrirlash %s/%s #%d", table, chain, num),
			forward: [][]string{append([]string{"-t", table, "-R", chain, n}, spec...)},
			undo:    [][]string{append([]string{"-t", table, "-R", chain, n}, ruleArgs(r.RawRule)...)},
		}, nil
	})
}
