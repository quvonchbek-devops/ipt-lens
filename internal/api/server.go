package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/quvonchbek-devops/ipt-lens/internal/enricher"
	"github.com/quvonchbek-devops/ipt-lens/internal/iptables"
)

type Server struct {
	Demo    bool
	Token   string
	Version string
	// AllowedHosts are the host names (without port) accepted in the Host
	// header. It defends against DNS rebinding. Empty disables the check.
	AllowedHosts []string
	Watch        *iptables.Watchdog
	Static       http.Handler
	TokenHint    string   // where to find the token, sent with 401 responses
	LensPort     int      // IPT-Lens' own port when reachable from outside; kept at least "VPN only"
	ExtraNotes   []string // shown in the simple view, e.g. configuration gaps found at startup
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/state", s.guard(http.MethodGet, s.handleState))
	mux.Handle("/api/v1/simulate", s.guard(http.MethodPost, s.handleSimulate))
	mux.Handle("/api/v1/apply", s.guard(http.MethodPost, s.handleApply))
	mux.Handle("/api/v1/confirm", s.guard(http.MethodPost, s.handleConfirm))
	mux.Handle("/api/v1/rules/delete", s.guard(http.MethodPost, s.handleRuleDelete))
	mux.Handle("/api/v1/rules/edit", s.guard(http.MethodPost, s.handleRuleEdit))
	mux.Handle("/api/v1/access", s.guard(http.MethodGet, s.handleAccess))
	mux.Handle("/api/v1/access/preview", s.guard(http.MethodPost, s.handleAccessPreview))
	mux.Handle("/api/v1/access/apply", s.guard(http.MethodPost, s.handleAccessApply))
	mux.Handle("/", s.Static)

	root := http.NewServeMux()
	root.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	root.Handle("/", s.checkHost(mux))
	return securityHeaders(root)
}

// checkHost rejects requests whose Host header is not an allowed name, so a
// hostile page cannot reach the API through a rebound DNS name.
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.AllowedHosts) > 0 && !s.hostAllowed(r.Host) {
			writeJSON(w, http.StatusMisdirectedRequest, errBody("host not allowed: "+r.Host))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(hostport string) bool {
	host := (&url.URL{Host: hostport}).Hostname()
	for _, a := range s.AllowedHosts {
		if strings.EqualFold(host, a) {
			return true
		}
	}
	return false
}

// guard enforces the method, rejects cross-site requests, requires a JSON
// body type on POST and checks the bearer token in constant time.
func (s *Server) guard(method string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeJSON(w, http.StatusMethodNotAllowed, errBody("method not allowed"))
			return
		}
		if !s.sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, errBody("cross-site request rejected"))
			return
		}
		if method == http.MethodPost && !isJSON(r) {
			writeJSON(w, http.StatusUnsupportedMediaType, errBody("Content-Type must be application/json"))
			return
		}
		if s.Token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid token", "hint": s.TokenHint})
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r)
	})
}

// sameOrigin reports whether the request comes from the UI's own origin (or
// from a non-browser client). "same-site" is rejected too: another port on
// the same host is same-site but a different application. Behind a reverse
// proxy the Origin carries the public name, so an allowed non-loopback host
// also counts; a loopback origin must match exactly (other ports are other apps).
func (s *Server) sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return len(s.AllowedHosts) > 0 && !isLoopbackName(u.Hostname()) && s.hostAllowed(u.Host)
}

func isLoopbackName(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// isJSON requires application/json. Browsers send it cross-origin only after
// a CORS preflight, which this server never approves.
func isJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	st, err := iptables.FetchState(s.Demo)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if !s.Demo {
		enricher.Enrich(st)
	}
	pending, rem := s.Watch.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"state":            st,
		"version":          s.Version,
		"watchdog_pending": pending,
		"watchdog_rem_sec": rem,
	})
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	var req iptables.SimRequest
	if !decode(w, r, &req) {
		return
	}
	if err := validateSim(req); err != nil {
		writeErr(w, err)
		return
	}
	st, err := iptables.FetchState(s.Demo)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if !s.Demo {
		enricher.Enrich(st)
	}
	writeJSON(w, http.StatusOK, iptables.SimulatePacket(st, req))
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req iptables.ApplyRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.Watch.Apply(req); err != nil {
		writeErr(w, err)
		return
	}
	_, rem := s.Watch.Status()
	writeJSON(w, http.StatusOK, map[string]any{"status": "pending_confirm", "timeout_sec": rem})
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	persisted, err := s.Watch.Confirm()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "confirmed", "persisted": persisted})
}

type ruleRef struct {
	Table  string `json:"table"`
	Chain  string `json:"chain"`
	RuleID int    `json:"rule_id"`
	Expect string `json:"expect"`
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	var req ruleRef
	if !decode(w, r, &req) {
		return
	}
	if err := s.Watch.DeleteRule(req.Table, req.Chain, req.RuleID, req.Expect); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "pending_confirm"})
}

func (s *Server) handleRuleEdit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ruleRef
		Rule string `json:"rule"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := s.Watch.EditRule(req.Table, req.Chain, req.RuleID, req.Expect, req.Rule); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "pending_confirm"})
}

func validateSim(q iptables.SimRequest) error {
	for _, ip := range []string{q.SrcIP, q.DstIP} {
		if ip != "" && net.ParseIP(ip) == nil {
			return fmt.Errorf("%w: invalid IP: %s", iptables.ErrInvalid, ip)
		}
	}
	if q.DstPort != "" {
		n, err := strconv.Atoi(q.DstPort)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%w: invalid port: %s", iptables.ErrInvalid, q.DstPort)
		}
	}
	switch strings.ToLower(q.Proto) {
	case "", "tcp", "udp", "icmp", "all":
	default:
		return fmt.Errorf("%w: invalid protocol: %s", iptables.ErrInvalid, q.Proto)
	}
	return nil
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid JSON: "+err.Error()))
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, iptables.ErrInvalid):
		code = http.StatusBadRequest
	case errors.Is(err, iptables.ErrDemo), errors.Is(err, iptables.ErrProtected):
		code = http.StatusForbidden
	case errors.Is(err, iptables.ErrStale), errors.Is(err, iptables.ErrPending),
		errors.Is(err, iptables.ErrDuplicate), errors.Is(err, iptables.ErrNoPending):
		code = http.StatusConflict
	}
	writeJSON(w, code, errBody(err.Error()))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
