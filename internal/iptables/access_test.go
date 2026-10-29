package iptables

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
	got := joinRules(inputRules(samplePolicy(), false))
	want := []string{
		"-i lo -m comment --comment iptlens:v1 default=vpn vpn=wg0;100.64.0.0/10 -j RETURN",
		"-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-p icmp -j RETURN",
		"-p udp --sport 67 --dport 68 -j RETURN",
		"-i docker0 -j RETURN",
		"-i br-+ -j RETURN",
		"-i cni0 -j RETURN",
		"-i cali+ -j RETURN",
		"-i lxc+ -j RETURN",
		"-i virbr+ -j RETURN",
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
	got := joinRules(dockerRules(samplePolicy(), false))
	want := []string{
		"-m conntrack ! --ctstate DNAT -m comment --comment iptlens:v1 -j RETURN",
		"-i docker0 -j RETURN",
		"-i br-+ -j RETURN",
		"-i cni0 -j RETURN",
		"-i cali+ -j RETURN",
		"-i lxc+ -j RETURN",
		"-i virbr+ -j RETURN",
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
	for _, r := range joinRules(inputRules(p, false)) {
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
		"bad iface":   func(p *AccessPolicy) { p.VPN.Ifaces = []string{"wg0;rm"} },
		"bad subnet":  func(p *AccessPolicy) { p.VPN.Subnets = []string{"10.0.0.0/33"} },
		"too many":    func(p *AccessPolicy) { p.VPN.Ifaces = strings.Split("a,b,c,d,e,f,g,h,i", ",") },
		"ipv6 subnet": func(p *AccessPolicy) { p.VPN.Subnets = []string{"fd7a:115c:a1e0::/48"} },
		"too many ports": func(p *AccessPolicy) {
			for i := 1000; i < 1300; i++ {
				p.Ports = append(p.Ports, PortAccess{Port: i, Proto: "tcp", Level: LevelClosed})
			}
		},
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
	for _, r := range inputRules(p, false) {
		b.WriteString("-A " + in + " " + quoteArgs(r) + "\n")
	}
	if docker {
		dk := "IPTLENS-DK-" + letter
		b.WriteString("-A DOCKER-USER -m comment --comment \"iptlens:jump\" -j " + dk + "\n")
		b.WriteString("-A DOCKER-USER -j RETURN\n")
		for _, r := range dockerRules(p, false) {
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
	mustContain(t, f.Calls(), "-t filter -I INPUT 1 -m comment --comment iptlens:jump -j IPTLENS-IN-B")
	mustContain(t, f.Calls(), "-t filter -D INPUT -m comment --comment iptlens:jump -j IPTLENS-IN-A")
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
	f.query = func(cmd string) (string, error) {
		if strings.HasSuffix(cmd, "-j IPTLENS-IN-A") { // the apply removed the old jump
			return "", exitErr(1)
		}
		return "", nil
	}
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
	mustContain(t, calls, "-t filter -I INPUT 1 -m comment --comment iptlens:jump -j IPTLENS-IN-A")
	mustContain(t, calls, "-t filter -D INPUT -m comment --comment iptlens:jump -j IPTLENS-IN-B")
	for _, c := range calls {
		if strings.Contains(c, " -R ") {
			t.Fatalf("position-based replace %q can overwrite another tool's rule", c)
		}
	}
	if last := calls[len(calls)-1]; last != "-t filter -X IPTLENS-IN-B" {
		t.Fatalf("last rollback call = %q, want the new chain deleted", last)
	}
	// iptables refuses to delete a chain that still has rules.
	if prev := calls[len(calls)-2]; prev != "-t filter -F IPTLENS-IN-B" {
		t.Fatalf("rollback call before -X = %q, want the chain flushed first", prev)
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
	got := strings.Join(joinRules(inputRules(p, false)), "\n")
	if !strings.Contains(got, "-s 100.64.0.0/10 -p tcp --dport 5432") {
		t.Fatalf("subnet not used when it is the only VPN identity:\n%s", got)
	}
}

func TestApplyRefusesManagedChain(t *testing.T) {
	installFake(t)
	w := newTestWatchdog(t, time.Hour)
	err := w.Apply(ApplyRequest{Table: "filter", Chain: "IPTLENS-IN-A", Position: 1, Rule: "-j ACCEPT"})
	if !errors.Is(err, ErrProtected) || !strings.Contains(err.Error(), "IPT-Lens") {
		t.Fatalf("got %v", err)
	}
}

func TestAccessInputRulesIPv6(t *testing.T) {
	got := joinRules(inputRules(samplePolicy(), true))
	want := []string{
		"-i lo -m comment --comment iptlens:v1 default=vpn vpn=wg0;100.64.0.0/10 -j RETURN",
		"-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-p ipv6-icmp -j RETURN",
		"-s fe80::/10 -p udp --sport 547 --dport 546 -j RETURN",
		"-i docker0 -j RETURN",
		"-i br-+ -j RETURN",
		"-i cni0 -j RETURN",
		"-i cali+ -j RETURN",
		"-i lxc+ -j RETURN",
		"-i virbr+ -j RETURN",
		"-p tcp --dport 22 -m comment --comment iptlens:port=22/tcp level=public -j RETURN",
		"-i wg0 -p tcp --dport 5432 -m comment --comment iptlens:port=5432/tcp level=vpn -j RETURN",
		"-p tcp --dport 5432 -m comment --comment iptlens:port=5432/tcp level=vpn -j DROP",
		"-p tcp --dport 3306 -m comment --comment iptlens:port=3306/tcp level=closed -j DROP",
		"-i wg0 -m comment --comment iptlens:default -j RETURN",
		"-m comment --comment iptlens:default -j DROP",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ipv6 input rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestAccessIPv6IgnoresIPv4Subnets(t *testing.T) {
	p := samplePolicy()
	p.VPN.Ifaces = nil
	for _, r := range joinRules(inputRules(p, true)) {
		if strings.HasPrefix(r, "-s 100.64") {
			t.Fatalf("IPv4 subnet in an ip6tables rule: %q", r)
		}
	}
}

const v6Base = "*filter\n:INPUT ACCEPT [0:0]\n:DOCKER-USER - [0:0]\n-A DOCKER-USER -j RETURN\nCOMMIT\n"

func TestApplyAccessAlsoIPv6(t *testing.T) {
	f := installFake(t)
	f.save = v6Base
	f.save6 = v6Base
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	mustContain(t, calls, "-t filter -I INPUT 1 -m comment --comment iptlens:jump -j IPTLENS-IN-A")
	mustContain(t, calls, "-6 -t filter -N IPTLENS-IN-A")
	mustContain(t, calls, "-6 -t filter -A IPTLENS-IN-A -p ipv6-icmp -j RETURN")
	mustContain(t, calls, "-6 -t filter -I INPUT 1 -m comment --comment iptlens:jump -j IPTLENS-IN-A")
	mustContain(t, calls, "-6 -t filter -I DOCKER-USER 1 -m comment --comment iptlens:jump -j IPTLENS-DK-A")
	// Every chain, IPv4 and IPv6, is complete before the first jump switches traffic.
	firstJump := -1
	for i, c := range calls {
		if strings.Contains(c, "iptlens:jump") {
			firstJump = i
			break
		}
	}
	for _, c := range calls[firstJump:] {
		if strings.Contains(c, " -A IPTLENS-") {
			t.Fatalf("rule %q added after traffic was switched", c)
		}
	}
}

func TestApplyAccessSkipsIPv6WhenUnavailable(t *testing.T) {
	f := installFake(t)
	f.save = v6Base
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c, "-6 ") {
			t.Fatalf("ip6tables called although unavailable: %q", c)
		}
	}
}

func TestApplyAccessIPv6FailureRollsBackIPv4(t *testing.T) {
	f := installFake(t)
	f.save = v6Base
	f.save6 = v6Base
	f.failOn = "-6 -t filter -A IPTLENS-IN-A -p ipv6-icmp"
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err == nil {
		t.Fatal("expected an error")
	}
	calls := f.Calls()
	mustContain(t, calls, "-t filter -X IPTLENS-IN-A")
	mustContain(t, calls, "-6 -t filter -X IPTLENS-IN-A")
	for _, c := range calls {
		if strings.Contains(c, "iptlens:jump") {
			t.Fatalf("traffic was switched before every chain was built: %q", c)
		}
	}
}

func TestSafeUndoIPv6(t *testing.T) {
	if !safeUndo([]string{"-6", "-t", "filter", "-X", "IPTLENS-IN-B"}) ||
		!safeUndo([]string{"-6", "-t", "filter", "-D", "INPUT", "-j", "IPTLENS-IN-A"}) {
		t.Fatal("ipv6 undo refused")
	}
	if safeUndo([]string{"-6", "-t", "filter", "-F", "INPUT"}) || safeUndo([]string{"-6", "-6", "-t", "filter", "-D", "INPUT"}) {
		t.Fatal("unsafe ipv6 undo accepted")
	}
}

func TestConfirmPersistsIPv6(t *testing.T) {
	f := installFake(t)
	f.save = v6Base
	f.save6 = "*filter\n:INPUT DROP [0:0]\n:DOCKER - [0:0]\n-A DOCKER -j ACCEPT\nCOMMIT\n"
	dir := privateDir(t)
	w := newTestWatchdog(t, time.Hour, WithPersistFile(filepath.Join(dir, "rules.v4")), WithPersistFile6(filepath.Join(dir, "rules.v6")))
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Confirm(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "rules.v6"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), ":INPUT DROP") || strings.Contains(string(data), "DOCKER") {
		t.Fatalf("rules.v6 = %q", data)
	}
}

func TestApplyAccessBacksUpIPv6(t *testing.T) {
	f := installFake(t)
	f.save = v6Base
	f.save6 = v6Base
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(w.dir, "backup-*.rules6"))
	if len(files) != 1 {
		t.Fatalf("ipv6 backups = %v", files)
	}
}

func TestApplyAccessFailsWhenIPv6Unreadable(t *testing.T) {
	f := installFake(t)
	f.save = v6Base
	f.fail6 = true
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("got %v, want an IPv6 error instead of silently skipping IPv6", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c, "IPTLENS") {
			t.Fatalf("firewall changed although IPv6 could not be read: %q", c)
		}
	}
}

func TestIPv6Coverage(t *testing.T) {
	f := installFake(t)
	v4 := mustParse(t, saveWith(samplePolicy(), "A", false))
	if avail, _ := IPv6Coverage(v4); avail {
		t.Fatal("available without ip6tables")
	}
	f.save6 = v6Base
	if avail, covered := IPv6Coverage(v4); !avail || covered {
		t.Fatalf("v6 without managed chain: avail=%v covered=%v", avail, covered)
	}
	f.save6 = saveWith(samplePolicy(), "B", false)
	if _, covered := IPv6Coverage(v4); !covered {
		t.Fatal("same policy on IPv6 not reported as covered")
	}
	other := samplePolicy()
	other.Default = LevelPublic
	f.save6 = saveWith(other, "B", false)
	if _, covered := IPv6Coverage(v4); covered {
		t.Fatal("different IPv6 policy reported as covered")
	}
	f.fail6 = true
	if avail, covered := IPv6Coverage(v4); !avail || covered {
		t.Fatalf("unreadable ip6tables: avail=%v covered=%v", avail, covered)
	}
}

func TestIPv6DisabledKernelIsNotAnError(t *testing.T) {
	f := installFake(t)
	f.save = v6Base
	f.save6 = "# ip6tables-save on a kernel booted with ipv6.disable=1\n"
	f.noIPv6 = true
	if IPv6Available() {
		t.Fatal("IPv6 is off in the kernel, but reported available")
	}
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c, "-6 ") {
			t.Fatalf("ip6tables called: %q", c)
		}
	}
}

func TestApplyAccessBuildsEachChainWithOneRestore(t *testing.T) {
	f := installFake(t)
	f.save = v6Base
	f.save6 = v6Base
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	// IN and DK chains, IPv4 and IPv6.
	if len(f.restores) != 4 {
		t.Fatalf("restores = %d, want 4: %q", len(f.restores), f.restores)
	}
	in := f.restores[0]
	if !strings.HasPrefix(in, "*filter\n:IPTLENS-IN-A - [0:0]\n-A IPTLENS-IN-A ") || !strings.HasSuffix(in, "\nCOMMIT\n") {
		t.Fatalf("restore input:\n%s", in)
	}
	if !strings.Contains(in, `--comment "iptlens:port=22/tcp level=public"`) {
		t.Fatalf("comment with a space not quoted:\n%s", in)
	}
	if !strings.HasPrefix(f.restores[2], "-6 *filter\n") {
		t.Fatalf("third restore is not IPv6: %q", f.restores[2])
	}
}

func TestRestoreInputRejectsUnsafeArgs(t *testing.T) {
	for _, bad := range []string{`a"b`, "a\nb", `a\b`, "a\rb"} {
		if _, err := restoreInput("IPTLENS-IN-A", [][]string{{"-m", "comment", "--comment", bad, "-j", "RETURN"}}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := restoreInput("IPTLENS-IN-A", [][]string{{"-p", "tcp", "--dport", "22", "-j", "RETURN"}}); err != nil {
		t.Fatal(err)
	}
}

func trustedPolicy() AccessPolicy {
	return AccessPolicy{
		VPN:     VPN{Ifaces: []string{"wg0"}, Trusted: []string{"203.0.113.7", "2001:db8::/48"}},
		Default: LevelClosed,
		Ports:   []PortAccess{{Port: 5432, Proto: "tcp", Level: LevelVPN}},
	}
}

func TestTrustedAddressesAlongsideVPN(t *testing.T) {
	v4 := strings.Join(joinRules(inputRules(trustedPolicy(), false)), "\n")
	v6 := strings.Join(joinRules(inputRules(trustedPolicy(), true)), "\n")
	for _, want := range []string{
		"-i wg0 -p tcp --dport 5432 -m comment --comment iptlens:port=5432/tcp level=vpn -j RETURN",
		"-s 203.0.113.7 -p tcp --dport 5432 -m comment --comment iptlens:port=5432/tcp level=vpn -j RETURN",
	} {
		if !strings.Contains(v4, want) {
			t.Errorf("IPv4 rules lack %q:\n%s", want, v4)
		}
	}
	if strings.Contains(v4, "-s 2001:db8") || strings.Contains(v6, "-s 203.0.113.7") {
		t.Fatal("a trusted address landed in the other family's rules")
	}
	if !strings.Contains(v6, "-s 2001:db8::/48 -p tcp --dport 5432") {
		t.Fatalf("IPv6 rules lack the trusted IPv6 range:\n%s", v6)
	}
	dk := strings.Join(joinRules(dockerRules(trustedPolicy(), false)), "\n")
	if !strings.Contains(dk, "-s 203.0.113.7 -p tcp -m conntrack --ctorigdstport 5432") {
		t.Fatalf("container rules lack the trusted address:\n%s", dk)
	}
}

func TestTrustedOnlyIsEnoughForVPNLevel(t *testing.T) {
	p := AccessPolicy{VPN: VPN{Trusted: []string{"198.51.100.0/24"}}, Default: LevelVPN}
	if err := p.Validate(); err != nil {
		t.Fatalf("trusted addresses alone refused: %v", err)
	}
}

func TestTrustedValidation(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/7", "2001::/15", "example.com", "1.2.3.4/33", "-j ACCEPT",
		"::ffff:203.0.113.7", "::ffff:0:0/8", "10.1.2.3/8", "2001:db8::1/48"} {
		p := AccessPolicy{VPN: VPN{Trusted: []string{bad}}, Default: LevelPublic}
		if err := p.Validate(); err == nil {
			t.Errorf("accepted trusted address %q", bad)
		}
	}
	long := AccessPolicy{Default: LevelPublic}
	for i := 0; i < 8; i++ {
		long.VPN.Trusted = append(long.VPN.Trusted, fmt.Sprintf("2001:db8:aaaa:bbbb:cccc:dddd:eeee:%04x/128", i))
	}
	if err := long.Validate(); err == nil {
		t.Fatal("accepted a policy whose metadata does not fit in an iptables comment")
	}
}

func TestReadAccessTrustedRoundTrip(t *testing.T) {
	got, ok := ReadAccess(mustParse(t, saveWith(trustedPolicy(), "A", false)))
	if !ok || !reflect.DeepEqual(got, trustedPolicy()) {
		t.Fatalf("ReadAccess = %+v (ok=%v), want %+v", got, ok, trustedPolicy())
	}
	// A comment written before trusted addresses existed has two parts.
	old := strings.Replace(saveWith(samplePolicy(), "A", false), "vpn=wg0;100.64.0.0/10", "vpn=wg0;100.64.0.0/10", 1)
	if got, _ := ReadAccess(mustParse(t, old)); got.VPN.Trusted != nil {
		t.Fatalf("old comment read with trusted = %q", got.VPN.Trusted)
	}
}

func TestVPNReaches(t *testing.T) {
	v6only := VPN{Trusted: []string{"2001:db8::5"}}
	if v6only.Reaches(false) || !v6only.Reaches(true) {
		t.Fatal("an IPv6 trusted address alone reaches IPv4, or not IPv6")
	}
	if sub := (VPN{Subnets: []string{"10.8.0.0/24"}}); !sub.Reaches(false) || sub.Reaches(true) {
		t.Fatal("a subnet is IPv4 only")
	}
	if ifc := (VPN{Ifaces: []string{"wg0"}}); !ifc.Reaches(false) || !ifc.Reaches(true) {
		t.Fatal("an interface covers both families")
	}
}

func limitedPolicy() AccessPolicy {
	return AccessPolicy{
		VPN:     VPN{Ifaces: []string{"wg0"}},
		Default: LevelVPN,
		Ports:   []PortAccess{{Port: 22, Proto: "tcp", Level: LevelPublic, Limit: true}},
	}
}

func TestLimitSlowsNewConnectionsBeforeReturn(t *testing.T) {
	in := joinRules(inputRules(limitedPolicy(), false))
	drop := slices.IndexFunc(in, func(r string) bool { return strings.Contains(r, "--hashlimit-above") })
	ret := slices.Index(in, "-p tcp --dport 22 -m comment --comment iptlens:port=22/tcp level=public limit -j RETURN")
	if drop < 0 || ret < 0 || drop > ret {
		t.Fatalf("want the hashlimit DROP before the RETURN:\n%s", strings.Join(in, "\n"))
	}
	if want := "-p tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 6/minute --hashlimit-burst 6 " +
		"--hashlimit-mode srcip --hashlimit-name iptl-in-22 -m comment --comment iptlens:port=22/tcp level=public limit -j DROP"; in[drop] != want {
		t.Fatalf("limit rule = %q\nwant        %q", in[drop], want)
	}
	dk := strings.Join(joinRules(dockerRules(limitedPolicy(), false)), "\n")
	if !strings.Contains(dk, "--hashlimit-name iptl-dk-22") {
		t.Fatalf("container chain lacks its own limit:\n%s", dk)
	}
	got, ok := ReadAccess(mustParse(t, saveWith(limitedPolicy(), "A", false)))
	if !ok || !reflect.DeepEqual(got, limitedPolicy()) {
		t.Fatalf("ReadAccess = %+v, want %+v", got, limitedPolicy())
	}
}

func TestLimitOnlyForPublicTCP(t *testing.T) {
	for _, pa := range []PortAccess{
		{Port: 53, Proto: "udp", Level: LevelPublic, Limit: true},
		{Port: 22, Proto: "tcp", Level: LevelVPN, Limit: true},
	} {
		p := AccessPolicy{VPN: VPN{Ifaces: []string{"wg0"}}, Default: LevelPublic, Ports: []PortAccess{pa}}
		if err := p.Validate(); err == nil {
			t.Errorf("accepted %+v", pa)
		}
	}
}

func TestApplyAccessCoversIPv6BeforeAnyIPv6Table(t *testing.T) {
	// A fresh nf_tables host lists no IPv6 tables until the first rule. That
	// is not "no IPv6": the policy must still be applied to it.
	f := installFake(t)
	f.save = v6Base
	f.fresh6 = true
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	mustContain(t, f.Calls(), "-6 -t filter -N IPTLENS-IN-A")
	mustContain(t, f.Calls(), "-6 -t filter -I INPUT 1 -m comment --comment iptlens:jump -j IPTLENS-IN-A")
	if available, _ := IPv6Coverage(mustParse(t, v6Base)); !available {
		t.Fatal("IPv6 reported as unavailable on a host that has it")
	}
}

func TestApplyAccessOnHostWithoutFilterTable(t *testing.T) {
	f := installFake(t)
	f.save = "" // a fresh nf_tables host: no table until the first rule
	w := newTestWatchdog(t, time.Hour)
	if err := w.ApplyAccess(samplePolicy()); err != nil {
		t.Fatal(err)
	}
	mustContain(t, f.Calls(), "-t filter -I INPUT 1 -m comment --comment iptlens:jump -j IPTLENS-IN-A")
}
