package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/quvonchbek-devops/ipt-lens/internal/enricher"
	"github.com/quvonchbek-devops/ipt-lens/internal/iptables"
)

type Server struct {
	Demo   bool
	Token  string
	Watch  *iptables.Watchdog
	Static http.Handler
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/state", s.guard(http.MethodGet, s.handleState))
	mux.Handle("/api/v1/simulate", s.guard(http.MethodPost, s.handleSimulate))
	mux.Handle("/api/v1/apply", s.guard(http.MethodPost, s.handleApply))
	mux.Handle("/api/v1/confirm", s.guard(http.MethodPost, s.handleConfirm))
	mux.Handle("/api/v1/rules/delete", s.guard(http.MethodPost, s.handleRuleDelete))
	mux.Handle("/api/v1/rules/edit", s.guard(http.MethodPost, s.handleRuleEdit))
	mux.Handle("/", s.Static)
	return securityHeaders(mux)
}

// guard - metod tekshiruvi va Bearer token tekshiruvi (constant-time).
func (s *Server) guard(method string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeJSON(w, http.StatusMethodNotAllowed, errBody("metod ruxsat etilmagan"))
			return
		}
		if s.Token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, errBody("token noto'g'ri yoki yo'q"))
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r)
	})
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
	if err := s.Watch.Confirm(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Table  string `json:"table"`
		Chain  string `json:"chain"`
		RuleID int    `json:"rule_id"`
		Expect string `json:"expect"`
	}
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
		Table  string `json:"table"`
		Chain  string `json:"chain"`
		RuleID int    `json:"rule_id"`
		Expect string `json:"expect"`
		Rule   string `json:"rule"`
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
			return fmt.Errorf("%w: IP noto'g'ri: %s", iptables.ErrInvalid, ip)
		}
	}
	if q.DstPort != "" {
		n, err := strconv.Atoi(q.DstPort)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%w: port noto'g'ri: %s", iptables.ErrInvalid, q.DstPort)
		}
	}
	switch strings.ToLower(q.Proto) {
	case "", "tcp", "udp", "icmp", "all":
	default:
		return fmt.Errorf("%w: protokol noto'g'ri: %s", iptables.ErrInvalid, q.Proto)
	}
	return nil
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("JSON noto'g'ri: "+err.Error()))
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, iptables.ErrInvalid):
		code = http.StatusBadRequest
	case errors.Is(err, iptables.ErrDemo):
		code = http.StatusForbidden
	case errors.Is(err, iptables.ErrProtected):
		code = http.StatusForbidden
	case errors.Is(err, iptables.ErrStale):
		code = http.StatusConflict
	case errors.Is(err, iptables.ErrPending), errors.Is(err, iptables.ErrDuplicate),
		errors.Is(err, iptables.ErrNoPending):
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
