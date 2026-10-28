package iptables

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, s string) *SystemState {
	t.Helper()
	st, err := ParseIptablesSave(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestChainOrderPreserved(t *testing.T) {
	st := mustParse(t, MockIptablesData)
	nat := st.Tables["nat"]
	if nat == nil {
		t.Fatal("nat table missing")
	}
	if len(nat.ChainOrder) == 0 || nat.ChainOrder[0] != "PREROUTING" {
		t.Fatalf("wrong chain order: %v", nat.ChainOrder)
	}
}

func TestParseRuleFields(t *testing.T) {
	st := mustParse(t, MockIptablesData)
	nat := st.Tables["nat"]
	dnat := nat.Chains["DOCKER"].Rules[0]
	if dnat.Target != "DNAT" || dnat.ToDest != "172.18.0.4:5432" {
		t.Fatalf("DNAT rule parsed wrong: target=%q to=%q", dnat.Target, dnat.ToDest)
	}
	if dnat.InIface != "!docker0" {
		t.Fatalf("negation lost: %q", dnat.InIface)
	}
}

func TestSimulateAccept(t *testing.T) {
	st := mustParse(t, MockIptablesData)
	res := SimulatePacket(st, SimRequest{
		SrcIP: "100.64.0.15", DstIP: "172.18.0.4", Proto: "tcp",
		DstPort: "5432", InIface: "wg0", OutIface: "docker0",
	})
	if res.FinalVerdict != "ACCEPT" {
		t.Fatalf("want ACCEPT, got %s", res.FinalVerdict)
	}
}

func TestSimulateDropMySQL(t *testing.T) {
	st := mustParse(t, MockIptablesData)
	res := SimulatePacket(st, SimRequest{
		SrcIP: "1.2.3.4", DstIP: "172.18.0.4", Proto: "tcp",
		DstPort: "3306", InIface: "eth0", OutIface: "docker0",
	})
	if res.FinalVerdict != "DROP" {
		t.Fatalf("want DROP, got %s", res.FinalVerdict)
	}
}

func TestValidateRule(t *testing.T) {
	good := []string{
		"-i wg0 -p tcp --dport 8080 -j ACCEPT",
		`-p tcp --dport 80 -m comment --comment "web server" -j ACCEPT`,
		"! -i docker0 -p tcp -m multiport --dports 80,443 -j DROP",
	}
	for _, g := range good {
		if _, err := ValidateRule("filter", "DOCKER-USER", g); err != nil {
			t.Errorf("valid rule rejected %q: %v", g, err)
		}
	}

	bad := []string{
		"-F",
		"-i wg0 -j ACCEPT; rm -rf /",
		"-i wg0 -p tcp --dport 8080",
		"-i wg0 -t nat -j ACCEPT",
		"-p tcp --dport abc -j ACCEPT",
	}
	for _, b := range bad {
		if _, err := ValidateRule("filter", "DOCKER-USER", b); err == nil {
			t.Errorf("invalid rule accepted: %q", b)
		}
	}

	if _, err := ValidateRule("foo", "DOCKER-USER", "-j ACCEPT"); err == nil {
		t.Error("invalid table accepted")
	}
}

func TestParseUnsupportedMatches(t *testing.T) {
	_, r, err := parseRuleLine(`-A INPUT -m set --match-set bad src -m limit --limit 5/s -j DROP`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Unsupported, " ") != "--match-set --limit" {
		t.Fatalf("Unsupported = %q", r.Unsupported)
	}

	_, r, _ = parseRuleLine(`-A INPUT -p tcp -m tcp --dport 22 -m addrtype --dst-type LOCAL -j REJECT --reject-with icmp-port-unreachable`)
	if len(r.Unsupported) != 0 {
		t.Fatalf("target options or known matches reported as unsupported: %q", r.Unsupported)
	}
}

func TestSimulateFlagsUnsupportedMatch(t *testing.T) {
	st := mustParse(t, "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m set --match-set bad src -j DROP\nCOMMIT\n")
	res := SimulatePacket(st, SimRequest{SrcIP: "1.2.3.4", DstIP: "127.0.0.1", Proto: "tcp", DstPort: "22"})
	if !res.Uncertain {
		t.Fatal("verdict depends on --match-set but is not marked uncertain")
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "--match-set") {
		t.Fatalf("Warnings = %q", res.Warnings)
	}
}

func TestSimulateExactWhenFullySupported(t *testing.T) {
	st := mustParse(t, MockIptablesData)
	res := SimulatePacket(st, SimRequest{SrcIP: "1.2.3.4", DstIP: "172.18.0.4", Proto: "tcp", DstPort: "3306", InIface: "eth0", OutIface: "docker0"})
	if res.Uncertain || len(res.Warnings) != 0 {
		t.Fatalf("unexpected uncertainty: %q", res.Warnings)
	}
}

func TestTokenizeEscapedQuotes(t *testing.T) {
	toks := tokenizeRule(`-m comment --comment "say \"hi\" \\ ok" -j ACCEPT`)
	want := []string{"-m", "comment", "--comment", `say "hi" \ ok`, "-j", "ACCEPT"}
	if strings.Join(toks, "|") != strings.Join(want, "|") {
		t.Fatalf("tokens = %q, want %q", toks, want)
	}
}

func TestSimulateFlagsUncheckedKnownFields(t *testing.T) {
	st := mustParse(t, "*filter\n:INPUT ACCEPT [0:0]\n"+
		"-A INPUT -p tcp -m tcp --sport 1024:65535 -j DROP\n"+
		"-A INPUT -m addrtype --dst-type BROADCAST -j DROP\nCOMMIT\n")
	res := SimulatePacket(st, SimRequest{SrcIP: "1.2.3.4", DstIP: "127.0.0.1", Proto: "tcp", DstPort: "22"})
	if !res.Uncertain || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "--sport") {
		t.Fatalf("source port match not flagged: %q", res.Warnings)
	}
}

func TestSimulateWarnsOncePerRule(t *testing.T) {
	st := mustParse(t, "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:CHK - [0:0]\n"+
		"-A INPUT -j CHK\n-A INPUT -j CHK\n-A CHK -m limit --limit 1/s -j LOG\nCOMMIT\n")
	res := SimulatePacket(st, SimRequest{DstIP: "127.0.0.1"})
	if len(res.Warnings) != 1 {
		t.Fatalf("want one warning for one rule, got %q", res.Warnings)
	}
}

func TestProtectedMarkedByParser(t *testing.T) {
	st := mustParse(t, MockIptablesData)
	f := st.Tables["filter"]
	if !f.Chains["DOCKER"].Protected || f.Chains["INPUT"].Protected {
		t.Fatal("chain protection flags wrong")
	}
	if !f.Chains["FORWARD"].Rules[1].Protected { // -j DOCKER-ISOLATION-STAGE-1
		t.Fatal("rule jumping to a managed chain not protected")
	}
	if f.Chains["INPUT"].Rules[0].Protected {
		t.Fatal("ordinary rule marked protected")
	}
}
