package iptables

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func samplePolicy() AccessPolicy {
	return AccessPolicy{
		VPN:     VPN{Ifaces: []string{"wg0"}, Subnets: []string{"100.64.0.0/10"}},
		Default: LevelVPN,
		Ports: []PortAccess{
			{Port: 22, Proto: "tcp", Level: LevelPublic},
			{Port: 5432, Proto: "tcp", Level: LevelVPN},
			{Port: 3306, Proto: "tcp", Level: LevelClosed},
		},
	}
}

func joinRules(rules [][]string) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = strings.Join(r, " ")
	}
	return out
}

func TestAccessInputRules(t *testing.T) {
	got := joinRules(inputRules(samplePolicy()))
	want := []string{
		"-i lo -m comment --comment iptlens:v1 default=vpn vpn=wg0;100.64.0.0/10 -j RETURN",
		"-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-p icmp -j RETURN",
		"-p udp --dport 68 -j RETURN",
		"-i docker0 -j RETURN",
		"-i br-+ -j RETURN",
		"-p tcp --dport 22 -m comment --comment iptlens:port=22/tcp level=public -j RETURN",
		"-i wg0 -p tcp --dport 5432 -m comment --comment iptlens:port=5432/tcp level=vpn -j RETURN",
		"-p tcp --dport 5432 -m comment --comment iptlens:port=5432/tcp level=vpn -j DROP",
		"-p tcp --dport 3306 -m comment --comment iptlens:port=3306/tcp level=closed -j DROP",
		"-i wg0 -m comment --comment iptlens:default -j RETURN",
		"-m comment --comment iptlens:default -j DROP",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("input rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestAccessDockerRules(t *testing.T) {
	got := joinRules(dockerRules(samplePolicy()))
	want := []string{
		"-m conntrack ! --ctstate DNAT -m comment --comment iptlens:v1 -j RETURN",
		"-i docker0 -j RETURN",
		"-i br-+ -j RETURN",
		"-p tcp -m conntrack --ctorigdstport 22 -m comment --comment iptlens:port=22/tcp level=public -j RETURN",
		"-i wg0 -p tcp -m conntrack --ctorigdstport 5432 -m comment --comment iptlens:port=5432/tcp level=vpn -j RETURN",
		"-p tcp -m conntrack --ctorigdstport 5432 -m comment --comment iptlens:port=5432/tcp level=vpn -j DROP",
		"-p tcp -m conntrack --ctorigdstport 3306 -m comment --comment iptlens:port=3306/tcp level=closed -j DROP",
		"-i wg0 -m comment --comment iptlens:default -j RETURN",
		"-m comment --comment iptlens:default -j DROP",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("docker rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestAccessPublicDefaultAddsNoCatchAll(t *testing.T) {
	p := samplePolicy()
	p.Default = LevelPublic
	for _, r := range joinRules(inputRules(p)) {
		if strings.Contains(r, "iptlens:default") {
			t.Fatalf("public default produced %q", r)
		}
	}
}

func TestAccessValidate(t *testing.T) {
	bad := map[string]func(*AccessPolicy){
		"port 0":          func(p *AccessPolicy) { p.Ports[0].Port = 0 },
		"port 70000":      func(p *AccessPolicy) { p.Ports[0].Port = 70000 },
		"proto sctp":      func(p *AccessPolicy) { p.Ports[0].Proto = "sctp" },
		"level unknown":   func(p *AccessPolicy) { p.Ports[0].Level = "maybe" },
		"default unknown": func(p *AccessPolicy) { p.Default = "" },
		"duplicate port": func(p *AccessPolicy) {
			p.Ports = append(p.Ports, PortAccess{Port: 22, Proto: "tcp", Level: LevelClosed})
		},
		"vpn level, no vpn": func(p *AccessPolicy) {
			p.VPN = VPN{}
		},
		"bad iface":  func(p *AccessPolicy) { p.VPN.Ifaces = []string{"wg0;rm"} },
		"bad subnet": func(p *AccessPolicy) { p.VPN.Subnets = []string{"10.0.0.0/33"} },
		"too many":   func(p *AccessPolicy) { p.VPN.Ifaces = strings.Split("a,b,c,d,e,f,g,h,i", ",") },
	}
	if err := samplePolicy().Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	for name, mutate := range bad {
		p := samplePolicy()
		mutate(&p)
		if err := p.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

// saveWith renders a filter table with the given managed chain contents, as
// iptables-save would print it.
func saveWith(p AccessPolicy, letter string, docker bool) string {
	var b strings.Builder
	b.WriteString("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n")
	in := "IPTLENS-IN-" + letter
	b.WriteString(":" + in + " - [0:0]\n")
	if docker {
		b.WriteString(":DOCKER-USER - [0:0]\n:IPTLENS-DK-" + letter + " - [0:0]\n")
	}
	b.WriteString("-A INPUT -m comment --comment \"iptlens:jump\" -j " + in + "\n")
	b.WriteString("-A INPUT -p tcp --dport 2222 -j ACCEPT\n")
	for _, r := range inputRules(p) {
		b.WriteString("-A " + in + " " + quoteArgs(r) + "\n")
	}
	if docker {
		dk := "IPTLENS-DK-" + letter
		b.WriteString("-A DOCKER-USER -m comment --comment \"iptlens:jump\" -j " + dk + "\n")
		b.WriteString("-A DOCKER-USER -j RETURN\n")
		for _, r := range dockerRules(p) {
			b.WriteString("-A " + dk + " " + quoteArgs(r) + "\n")
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func quoteArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " ;") {
			a = `"` + a + `"`
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

func TestReadAccessRoundTrip(t *testing.T) {
	st := mustParse(t, saveWith(samplePolicy(), "B", true))
	got, ok := ReadAccess(st)
	if !ok {
		t.Fatal("managed chain not found")
	}
	if !reflect.DeepEqual(got, samplePolicy()) {
		t.Fatalf("ReadAccess = %+v, want %+v", got, samplePolicy())
	}
	if _, ok := ReadAccess(mustParse(t, MockIptablesData)); ok {
		t.Fatal("unmanaged ruleset reported as configured")
	}
}

func TestManagedChainsLockedButPersisted(t *testing.T) {
	text := saveWith(samplePolicy(), "A", false)
	st := mustParse(t, text)
	if !st.Tables["filter"].Chains["IPTLENS-IN-A"].Protected {
		t.Fatal("managed chain is editable in Advanced view")
	}
	for _, r := range st.Tables["filter"].Chains["IPTLENS-IN-A"].Rules {
		if !r.Protected {
			t.Fatalf("managed rule #%d is editable in Advanced view", r.ID)
		}
	}
	if !st.Tables["filter"].Chains["INPUT"].Rules[0].Protected {
		t.Fatal("jump into the managed chain is editable")
	}
	if st.Tables["filter"].Chains["INPUT"].Rules[1].Protected {
		t.Fatal("ordinary INPUT rule locked")
	}
	if !strings.Contains(string(stripManaged([]byte(text))), "IPTLENS-IN-A") {
		t.Fatal("managed chain dropped from the persisted ruleset")
	}
}

func TestApplyAccessFirstTime(t *testing.T) {
	f := installFake(t)
	f.save = "*filter\n:INPUT ACCEPT [0:0]\n:DOCKER-USER - [0:0]\n-A DOCKER-USER -j RETURN\nCOMMIT\n"
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	mustContain(t, calls, "-t filter -N IPTLENS-IN-A")
	mustContain(t, calls, "-t filter -N IPTLENS-DK-A")
	mustContain(t, calls, "-t filter -I INPUT 1 -m comment --comment iptlens:jump -j IPTLENS-IN-A")
	mustContain(t, calls, "-t filter -I DOCKER-USER 1 -m comment --comment iptlens:jump -j IPTLENS-DK-A")
	// The jump must be the last thing applied, so the chain is complete before traffic reaches it.
	if last := calls[len(calls)-1]; !strings.Contains(last, "-j IPTLENS-") || !strings.Contains(last, " 1 ") {
		t.Fatalf("last call = %q, want a jump insert", last)
	}
}

func TestApplyAccessSwapsAndCleansUpOnConfirm(t *testing.T) {
	f := installFake(t)
	f.save = saveWith(samplePolicy(), "A", false)
	w := newTestWatchdog(t, time.Hour)
	p := samplePolicy()
	p.Default = LevelClosed
	if err := w.ApplyAccess(p); err != nil {
		t.Fatal(err)
	}
	mustContain(t, f.Calls(), "-t filter -N IPTLENS-IN-B")
	mustContain(t, f.Calls(), "-t filter -R INPUT 1 -m comment --comment iptlens:jump -j IPTLENS-IN-B")
	if _, err := w.Confirm(); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	mustContain(t, calls, "-t filter -F IPTLENS-IN-A")
	mustContain(t, calls, "-t filter -X IPTLENS-IN-A")
}

func TestApplyAccessRollbackRestoresOldChain(t *testing.T) {
	f := installFake(t)
	f.save = saveWith(samplePolicy(), "A", false)
	w := newTestWatchdog(t, 20*time.Millisecond)
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if pending, _ := w.Status(); !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never expired")
		}
		time.Sleep(5 * time.Millisecond)
	}
	calls := f.Calls()
	mustContain(t, calls, "-t filter -R INPUT 1 -m comment --comment iptlens:jump -j IPTLENS-IN-A")
	if last := calls[len(calls)-1]; last != "-t filter -X IPTLENS-IN-B" {
		t.Fatalf("last rollback call = %q, want the new chain deleted", last)
	}
	for _, c := range calls {
		if c == "-t filter -X IPTLENS-IN-A" {
			t.Fatal("rollback deleted the old chain")
		}
	}
}

func TestSafeUndoAllowsOnlyManagedChainDeletes(t *testing.T) {
	if !safeUndo([]string{"-t", "filter", "-X", "IPTLENS-IN-B"}) {
		t.Fatal("managed chain delete refused")
	}
	if safeUndo([]string{"-t", "filter", "-X", "INPUT"}) || safeUndo([]string{"-t", "filter", "-F", "DOCKER"}) {
		t.Fatal("delete of a foreign chain accepted")
	}
}

func mustContain(t *testing.T, calls []string, want string) {
	t.Helper()
	for _, c := range calls {
		if c == want {
			return
		}
	}
	t.Fatalf("missing call %q in:\n%s", want, strings.Join(calls, "\n"))
}

func TestAccessSubnetOnlyWithoutInterface(t *testing.T) {
	p := samplePolicy()
	p.VPN.Ifaces = nil
	got := strings.Join(joinRules(inputRules(p)), "\n")
	if !strings.Contains(got, "-s 100.64.0.0/10 -p tcp --dport 5432") {
		t.Fatalf("subnet not used when it is the only VPN identity:\n%s", got)
	}
}
