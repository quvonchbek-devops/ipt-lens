package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quvonchbek-devops/ipt-lens/internal/iptables"
)

const testToken = "0123456789abcdef0123"

func newTestServer(t *testing.T, token string) http.Handler {
	t.Helper()
	w, err := iptables.NewWatchdog(t.TempDir(), true, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Demo:         true,
		Token:        token,
		Version:      "1.2.3",
		Watch:        w,
		Static:       http.NotFoundHandler(),
		AllowedHosts: []string{"localhost", "127.0.0.1"},
	}
	return s.Routes()
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func do(t *testing.T, h http.Handler, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://127.0.0.1:8090"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestMethodNotAllowed(t *testing.T) {
	h := newTestServer(t, "")
	if rec := do(t, h, http.MethodGet, "/api/v1/apply", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestTokenRequired(t *testing.T) {
	h := newTestServer(t, testToken)
	if rec := do(t, h, http.MethodGet, "/api/v1/state", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: code = %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/state", "", withHeader("Authorization", "Bearer wrong-token-value-xx")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: code = %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/state", "", withHeader("Authorization", "Bearer "+testToken)); rec.Code != http.StatusOK {
		t.Fatalf("right token: code = %d", rec.Code)
	}
}

func TestPostRequiresJSON(t *testing.T) {
	h := newTestServer(t, "")
	rec := do(t, h, http.MethodPost, "/api/v1/confirm", "", withHeader("Content-Type", "text/plain"))
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain POST: code = %d, want 415", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/v1/confirm", "")
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("POST without Content-Type: code = %d, want 415", rec.Code)
	}
}

func TestCrossSiteRejected(t *testing.T) {
	h := newTestServer(t, "")
	body := `{"src_ip":"1.2.3.4","dst_ip":"172.18.0.4","proto":"tcp","dst_port":"5432"}`
	for _, site := range []string{"cross-site", "same-site"} {
		rec := do(t, h, http.MethodPost, "/api/v1/simulate", body, withHeader("Sec-Fetch-Site", site))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("Sec-Fetch-Site %s: code = %d, want 403", site, rec.Code)
		}
	}
	rec := do(t, h, http.MethodPost, "/api/v1/simulate", body, withHeader("Origin", "http://evil.example"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign Origin: code = %d, want 403", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/v1/simulate", body,
		withHeader("Origin", "http://127.0.0.1:8090"), withHeader("Sec-Fetch-Site", "same-origin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("same-origin: code = %d, want 200 (%s)", rec.Code, rec.Body)
	}
}

func TestHostHeaderRejected(t *testing.T) {
	h := newTestServer(t, "")
	rec := do(t, h, http.MethodGet, "/api/v1/state", "", func(r *http.Request) { r.Host = "evil.example:8090" })
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("code = %d, want 421", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/", "", func(r *http.Request) { r.Host = "evil.example" })
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("static: code = %d, want 421", rec.Code)
	}
}

func TestStateDemo(t *testing.T) {
	h := newTestServer(t, "")
	rec := do(t, h, http.MethodGet, "/api/v1/state", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var resp struct {
		State struct {
			IsMock bool `json:"is_mock"`
		} `json:"state"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.State.IsMock || resp.Version != "1.2.3" {
		t.Fatalf("unexpected state response: %s", rec.Body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestSimulateValidation(t *testing.T) {
	h := newTestServer(t, "")
	for _, body := range []string{
		`{"src_ip":"not-an-ip"}`,
		`{"dst_port":"70000"}`,
		`{"proto":"sctp"}`,
		`{"unknown_field":1}`,
	} {
		if rec := do(t, h, http.MethodPost, "/api/v1/simulate", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code = %d, want 400", body, rec.Code)
		}
	}
}

func TestApplyInDemo(t *testing.T) {
	h := newTestServer(t, "")
	body := `{"table":"filter","chain":"INPUT","position":1,"rule":"-p tcp --dport 22 -j ACCEPT"}`
	if rec := do(t, h, http.MethodPost, "/api/v1/apply", body); rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	h := newTestServer(t, testToken)
	rec := do(t, h, http.MethodGet, "/healthz", "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("code = %d body = %q", rec.Code, rec.Body)
	}
}

func TestOriginFromAllowedHostBehindProxy(t *testing.T) {
	w, _ := iptables.NewWatchdog(t.TempDir(), true, time.Minute)
	h := (&Server{Demo: true, Watch: w, Static: http.NotFoundHandler(),
		AllowedHosts: []string{"localhost", "127.0.0.1", "fw.example.com"}}).Routes()
	body := `{"dst_ip":"127.0.0.1"}`
	rec := do(t, h, http.MethodPost, "/api/v1/simulate", body,
		withHeader("Origin", "https://fw.example.com"), withHeader("Sec-Fetch-Site", "same-origin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("proxied same-origin request: code = %d (%s)", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodPost, "/api/v1/simulate", body, withHeader("Origin", "https://evil.example"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: code = %d, want 403", rec.Code)
	}
}

func TestOriginFromOtherLocalPortRejected(t *testing.T) {
	h := newTestServer(t, "")
	rec := do(t, h, http.MethodPost, "/api/v1/simulate", `{"dst_ip":"127.0.0.1"}`,
		withHeader("Origin", "http://127.0.0.1:3000"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestUnauthorizedCarriesTokenHint(t *testing.T) {
	w, _ := iptables.NewWatchdog(t.TempDir(), true, time.Minute)
	h := (&Server{Demo: true, Token: testToken, TokenHint: "sudo cat /srv/x/token", Watch: w,
		Static: http.NotFoundHandler()}).Routes()
	rec := do(t, h, http.MethodGet, "/api/v1/state", "")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "/srv/x/token") {
		t.Fatalf("code = %d body = %s", rec.Code, rec.Body)
	}
}
