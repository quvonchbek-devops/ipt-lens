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
		t.Fatal("nat jadvali topilmadi")
	}
	if len(nat.ChainOrder) == 0 || nat.ChainOrder[0] != "PREROUTING" {
		t.Fatalf("zanjir tartibi noto'g'ri: %v", nat.ChainOrder)
	}
}

func TestParseRuleFields(t *testing.T) {
	st := mustParse(t, MockIptablesData)
	nat := st.Tables["nat"]
	dnat := nat.Chains["DOCKER"].Rules[0]
	if dnat.Target != "DNAT" || dnat.ToDest != "172.18.0.4:5432" {
		t.Fatalf("DNAT qoidasi noto'g'ri parse qilindi: target=%q to=%q", dnat.Target, dnat.ToDest)
	}
	if dnat.InIface != "!docker0" {
		t.Fatalf("negatsiya saqlanmadi: %q", dnat.InIface)
	}
}

func TestSimulateAccept(t *testing.T) {
	st := mustParse(t, MockIptablesData)
	res := SimulatePacket(st, SimRequest{
		SrcIP: "100.64.0.15", DstIP: "172.18.0.4", Proto: "tcp",
		DstPort: "5432", InIface: "wg0", OutIface: "docker0",
	})
	if res.FinalVerdict != "ACCEPT" {
		t.Fatalf("ACCEPT kutilgan edi, olindi: %s", res.FinalVerdict)
	}
}

func TestSimulateDropMySQL(t *testing.T) {
	st := mustParse(t, MockIptablesData)
	res := SimulatePacket(st, SimRequest{
		SrcIP: "1.2.3.4", DstIP: "172.18.0.4", Proto: "tcp",
		DstPort: "3306", InIface: "eth0", OutIface: "docker0",
	})
	if res.FinalVerdict != "DROP" {
		t.Fatalf("DROP kutilgan edi, olindi: %s", res.FinalVerdict)
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
			t.Errorf("to'g'ri qoida rad etildi %q: %v", g, err)
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
			t.Errorf("noto'g'ri qoida qabul qilindi: %q", b)
		}
	}

	if _, err := ValidateRule("foo", "DOCKER-USER", "-j ACCEPT"); err == nil {
		t.Error("noto'g'ri jadval qabul qilindi")
	}
}
