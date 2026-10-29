package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/quvonchbek-devops/ipt-lens/internal/iptables"
)

func TestAccessViewDemo(t *testing.T) {
	h := newTestServer(t, "")
	rec := do(t, h, http.MethodGet, "/api/v1/access", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d (%s)", rec.Code, rec.Body)
	}
	var v accessView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Configured {
		t.Fatal("demo ruleset has no managed chain but reports configured")
	}
	row := func(port int) *accessRow {
		for i := range v.Rows {
			if v.Rows[i].Port == port {
				return &v.Rows[i]
			}
		}
		t.Fatalf("port %d missing from %+v", port, v.Rows)
		return nil
	}
	if r := row(22); r.Name != "SSH" || !r.Host || r.Level != iptables.LevelPublic {
		t.Fatalf("row 22 = %+v", r)
	}
	if r := row(5432); !reflect.DeepEqual(r.Containers, []string{"postgres"}) {
		t.Fatalf("row 5432 = %+v", r)
	}
	if len(v.VPNCandidates) == 0 || v.VPNCandidates[0].Name != "wg0" {
		t.Fatalf("vpn candidates = %+v", v.VPNCandidates)
	}
	if len(v.Notes) == 0 || !strings.Contains(v.Notes[0], "IPv6") {
		t.Fatalf("notes = %q", v.Notes)
	}
}

func preview(t *testing.T, body string) (int, accessPreview) {
	t.Helper()
	rec := do(t, newTestServer(t, ""), http.MethodPost, "/api/v1/access/preview", body)
	var p accessPreview
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return rec.Code, p
}

func TestAccessPreviewSentences(t *testing.T) {
	code, p := preview(t, `{"vpn":{"ifaces":["wg0"],"subnets":[]},"default":"vpn",
		"ports":[{"port":22,"proto":"tcp","level":"public"},{"port":3306,"proto":"tcp","level":"closed"}]}`)
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	all := strings.Join(p.Changes, "\n")
	for _, want := range []string{
		"Everything else: Everyone → VPN only",
		"Port 3306 (MySQL): Everyone → Nobody",
		"VPN: wg0",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("changes missing %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "Port 22 ") {
		t.Errorf("unchanged SSH listed as a change:\n%s", all)
	}
	if len(p.Commands) == 0 || !strings.HasPrefix(p.Commands[0], "iptables -A IPTLENS-IN") {
		t.Fatalf("commands = %q", p.Commands)
	}
}

func TestAccessPreviewWarnsAboutSSH(t *testing.T) {
	_, p := preview(t, `{"vpn":{"ifaces":["wg0"],"subnets":[]},"default":"public",
		"ports":[{"port":22,"proto":"tcp","level":"vpn"}]}`)
	if len(p.Warnings) == 0 || !strings.Contains(p.Warnings[0], "SSH") {
		t.Fatalf("warnings = %q", p.Warnings)
	}
}

func TestAccessPreviewInvalid(t *testing.T) {
	if code, _ := preview(t, `{"vpn":{"ifaces":[],"subnets":[]},"default":"vpn","ports":[]}`); code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", code)
	}
}

func TestAccessApplyDemo(t *testing.T) {
	h := newTestServer(t, "")
	rec := do(t, h, http.MethodPost, "/api/v1/access/apply", `{"vpn":{"ifaces":["wg0"],"subnets":[]},"default":"vpn","ports":[]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestPinLensPort(t *testing.T) {
	vpn := iptables.VPN{Ifaces: []string{"wg0"}}
	cases := []struct {
		in   iptables.AccessPolicy
		want iptables.Level
	}{
		{iptables.AccessPolicy{VPN: vpn, Default: iptables.LevelClosed}, iptables.LevelVPN},
		{iptables.AccessPolicy{VPN: vpn, Default: iptables.LevelPublic,
			Ports: []iptables.PortAccess{{Port: 8090, Proto: "tcp", Level: iptables.LevelClosed}}}, iptables.LevelVPN},
		{iptables.AccessPolicy{VPN: vpn, Default: iptables.LevelPublic}, ""}, // reachable already: no entry added
		{iptables.AccessPolicy{VPN: vpn, Default: iptables.LevelVPN,
			Ports: []iptables.PortAccess{{Port: 8090, Proto: "tcp", Level: iptables.LevelPublic}}}, iptables.LevelPublic},
	}
	for i, c := range cases {
		got := pinLensPort(c.in, 8090)
		var lvl iptables.Level
		for _, p := range got.Ports {
			if p.Port == 8090 {
				lvl = p.Level
			}
		}
		if lvl != c.want {
			t.Errorf("case %d: lens port level = %q, want %q", i, lvl, c.want)
		}
	}
}
