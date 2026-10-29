package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/quvonchbek-devops/ipt-lens/internal/enricher"
	"github.com/quvonchbek-devops/ipt-lens/internal/iptables"
	"github.com/quvonchbek-devops/ipt-lens/internal/ports"
)

// accessRow is one line of the simple view: a port, what uses it, and who can
// reach it now.
type accessRow struct {
	Port       int            `json:"port"`
	Proto      string         `json:"proto"`
	Name       string         `json:"name"`
	Host       bool           `json:"host"`       // a host process listens on it
	Containers []string       `json:"containers"` // containers publishing it
	Level      iptables.Level `json:"level"`      // effective level
	Explicit   bool           `json:"explicit"`   // set for this port, not inherited from "everything else"
	Locked     bool           `json:"locked"`     // IPT-Lens' own port: never below "VPN only"
}

type accessView struct {
	Configured    bool                  `json:"configured"`
	Policy        iptables.AccessPolicy `json:"policy"`
	Rows          []accessRow           `json:"rows"`
	VPNCandidates []enricher.VPNIface   `json:"vpn_candidates"`
	Notes         []string              `json:"notes"`
	dockerNotes   []string              // also shown as warnings in a preview
}

type accessPreview struct {
	Changes  []string `json:"changes"`
	Warnings []string `json:"warnings"`
	Commands []string `json:"commands"`
}

// discovery is what the host exposes: listening ports, published container
// ports and VPN-like interfaces.
type discovery struct {
	listening []ports.Port
	published []enricher.Published
	vpn       []enricher.VPNIface
}

func (s *Server) discover() discovery {
	if s.Demo {
		return discovery{
			listening: []ports.Port{{Number: 22, Proto: "tcp"}, {Number: 80, Proto: "tcp"}, {Number: 443, Proto: "tcp"},
				{Number: 8090, Proto: "tcp"}, {Number: 51820, Proto: "udp"}},
			published: []enricher.Published{{Port: 5432, Proto: "tcp", Container: "postgres"},
				{Port: 3306, Proto: "tcp", Container: "mysql"}},
			vpn: []enricher.VPNIface{{Name: "wg0", Subnets: []string{"10.8.0.0/24"}},
				{Name: "tailscale0", Subnets: []string{"100.64.0.0/10"}}},
		}
	}
	return discovery{listening: ports.Listening(), published: enricher.PublishedPorts(), vpn: enricher.VPNInterfaces()}
}

var levelLabel = map[iptables.Level]string{
	iptables.LevelPublic: "Everyone", iptables.LevelVPN: "VPN only", iptables.LevelClosed: "Nobody",
}

// vpnServices are VPN endpoints: clients reach them before they are on the VPN.
var vpnServices = map[string]bool{"WireGuard": true, "Tailscale": true, "OpenVPN": true}

const ipv6Note = "IPv6 traffic is not filtered by IPT-Lens. If this server has a public IPv6 address, protect it separately."

// levelOf returns the effective level of a port under p, and whether p sets it
// explicitly. An unconfigured policy (empty default) lets everything through.
func levelOf(p iptables.AccessPolicy, port int, proto string) (iptables.Level, bool) {
	for _, pa := range p.Ports {
		if pa.Port == port && pa.Proto == proto {
			return pa.Level, true
		}
	}
	if p.Default == "" {
		return iptables.LevelPublic, false
	}
	return p.Default, false
}

func portKey(port int, proto string) string { return fmt.Sprintf("%d/%s", port, proto) }

func (s *Server) buildView(st *iptables.SystemState, d discovery) accessView {
	cur, configured := iptables.ReadAccess(st)
	rows := map[string]*accessRow{}
	row := func(port int, proto string) *accessRow {
		k := portKey(port, proto)
		if r, ok := rows[k]; ok {
			return r
		}
		r := &accessRow{Port: port, Proto: proto, Name: ports.Name(ports.Port{Number: port, Proto: proto}), Containers: []string{}}
		rows[k] = r
		return r
	}
	for _, l := range d.listening {
		row(l.Number, l.Proto).Host = true
	}
	for _, p := range d.published {
		r := row(p.Port, p.Proto)
		r.Containers = append(r.Containers, p.Container)
	}
	for _, pa := range cur.Ports {
		row(pa.Port, pa.Proto)
	}
	if s.LensPort > 0 {
		row(s.LensPort, "tcp").Locked = true
	}
	hasChain, covered := iptables.DockerCoverage(st)
	dn := dockerNotes(hasChain, covered || !configured, len(d.published))
	v := accessView{Configured: configured, Policy: cur, VPNCandidates: d.vpn,
		Notes: append([]string{ipv6Note}, dn...), dockerNotes: dn}
	if v.VPNCandidates == nil {
		v.VPNCandidates = []enricher.VPNIface{}
	}
	if v.Policy.Ports == nil {
		v.Policy.Ports = []iptables.PortAccess{}
	}
	for _, r := range rows {
		r.Level, r.Explicit = levelOf(cur, r.Port, r.Proto)
		v.Rows = append(v.Rows, *r)
	}
	sort.Slice(v.Rows, func(i, j int) bool {
		if v.Rows[i].Port != v.Rows[j].Port {
			return v.Rows[i].Port < v.Rows[j].Port
		}
		return v.Rows[i].Proto < v.Rows[j].Proto
	})
	return v
}

func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	st, err := iptables.FetchState(s.Demo)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.buildView(st, s.discover()))
}

// pinLensPort keeps IPT-Lens' own port reachable at least over the VPN, so a
// policy cannot cut off the panel used to fix it.
func pinLensPort(p iptables.AccessPolicy, port int) (iptables.AccessPolicy, error) {
	if port == 0 {
		return p, nil
	}
	out := p
	out.Ports = append([]iptables.PortAccess(nil), p.Ports...)
	idx := -1
	for i, pa := range out.Ports {
		if pa.Port == port && pa.Proto == "tcp" {
			idx = i
		}
	}
	level := p.Default
	if idx >= 0 {
		level = out.Ports[idx].Level
	}
	if level != iptables.LevelClosed {
		return out, nil
	}
	if len(p.VPN.Ifaces)+len(p.VPN.Subnets) == 0 {
		return out, fmt.Errorf("%w: IPT-Lens itself listens on port %d and would become unreachable. "+
			"Choose your VPN first, so the panel stays reachable over it", iptables.ErrInvalid, port)
	}
	if idx >= 0 {
		out.Ports[idx].Level = iptables.LevelVPN
	} else {
		out.Ports = append(out.Ports, iptables.PortAccess{Port: port, Proto: "tcp", Level: iptables.LevelVPN})
	}
	return out, nil
}

func (s *Server) handleAccessPreview(w http.ResponseWriter, r *http.Request) {
	var next iptables.AccessPolicy
	if !decode(w, r, &next) {
		return
	}
	next, err := pinLensPort(next, s.LensPort)
	if err == nil {
		err = next.Validate()
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	st, err := iptables.FetchState(s.Demo)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	view := s.buildView(st, s.discover())
	pv := previewOf(view.Policy, next, view.Rows)
	pv.Warnings = append(pv.Warnings, view.dockerNotes...)
	writeJSON(w, http.StatusOK, pv)
}

func (s *Server) handleAccessApply(w http.ResponseWriter, r *http.Request) {
	var next iptables.AccessPolicy
	if !decode(w, r, &next) {
		return
	}
	next, err := pinLensPort(next, s.LensPort)
	if err == nil {
		err = s.Watch.ApplyAccess(next)
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	_, rem := s.Watch.Status()
	writeJSON(w, http.StatusOK, map[string]any{"status": "pending_confirm", "timeout_sec": rem})
}

func rowLabel(port int, proto, name string) string {
	label := fmt.Sprintf("Port %d", port)
	if proto != "tcp" {
		label += "/" + proto
	}
	if name != "" {
		label += " (" + name + ")"
	}
	return label
}

// previewOf describes the change from cur to next in plain sentences, with
// warnings and the iptables commands that implement next.
func previewOf(cur, next iptables.AccessPolicy, rows []accessRow) accessPreview {
	pv := accessPreview{Changes: []string{}, Warnings: []string{}}
	vpnText := func(v iptables.VPN) string {
		parts := append(append([]string{}, v.Ifaces...), v.Subnets...)
		if len(parts) == 0 {
			return "none"
		}
		return strings.Join(parts, ", ")
	}
	if vpnText(cur.VPN) != vpnText(next.VPN) {
		pv.Changes = append(pv.Changes, "VPN: "+vpnText(next.VPN))
	}
	curDef, _ := levelOf(cur, 0, "")
	nextDef, _ := levelOf(next, 0, "")
	if curDef != nextDef {
		pv.Changes = append(pv.Changes, fmt.Sprintf("Everything else: %s → %s", levelLabel[curDef], levelLabel[nextDef]))
	}

	type key struct {
		port  int
		proto string
	}
	names := map[key]string{}
	keys := map[key]bool{}
	for _, r := range rows {
		names[key{r.Port, r.Proto}] = r.Name
		keys[key{r.Port, r.Proto}] = true
	}
	for _, pa := range next.Ports {
		keys[key{pa.Port, pa.Proto}] = true
		if _, ok := names[key{pa.Port, pa.Proto}]; !ok {
			names[key{pa.Port, pa.Proto}] = ports.Name(ports.Port{Number: pa.Port, Proto: pa.Proto})
		}
	}
	sorted := make([]key, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].port != sorted[j].port {
			return sorted[i].port < sorted[j].port
		}
		return sorted[i].proto < sorted[j].proto
	})
	for _, k := range sorted {
		from, _ := levelOf(cur, k.port, k.proto)
		to, _ := levelOf(next, k.port, k.proto)
		if from == to {
			continue
		}
		pv.Changes = append(pv.Changes, fmt.Sprintf("%s: %s → %s", rowLabel(k.port, k.proto, names[k]), levelLabel[from], levelLabel[to]))
		if vpnServices[names[k]] && from == iptables.LevelPublic {
			pv.Warnings = append(pv.Warnings, fmt.Sprintf(
				"%s is your VPN's own port: devices connect to it from the internet. Setting it to %s disconnects the VPN. "+
					"Keep it at Everyone.", rowLabel(k.port, k.proto, names[k]), strings.ToLower(levelLabel[to])))
		}
		if names[k] == "SSH" && from == iptables.LevelPublic {
			pv.Warnings = append(pv.Warnings, fmt.Sprintf(
				"SSH will be reachable by %s. If you are connected over SSH without the VPN, you will be cut off. "+
					"The change rolls back automatically unless you confirm it.", strings.ToLower(levelLabel[to])))
		}
	}
	if len(pv.Changes) == 0 {
		pv.Changes = append(pv.Changes, "Nothing changes.")
	}
	if len(next.VPN.Ifaces) == 0 && len(next.VPN.Subnets) > 0 {
		pv.Warnings = append(pv.Warnings, "With only a subnet, IPT-Lens trusts the packet's source address, "+
			"which can be spoofed from the internet. Choose your VPN interface if you can.")
	}
	pv.Warnings = append(pv.Warnings, ipv6Note)
	for _, rule := range iptables.InputRules(next) {
		pv.Commands = append(pv.Commands, "iptables -A IPTLENS-IN "+shellJoin(rule))
	}
	for _, rule := range iptables.DockerRules(next) {
		pv.Commands = append(pv.Commands, "iptables -A IPTLENS-DK "+shellJoin(rule))
	}
	return pv
}

func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " ;!*+") && a != "!" {
			a = "'" + a + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

// dockerNotes explains when published container ports are not filtered.
func dockerNotes(hasChain, covered bool, published int) []string {
	switch {
	case published == 0:
		return nil
	case !hasChain:
		return []string{fmt.Sprintf("Docker publishes %d port(s), but its DOCKER-USER chain is missing, so container ports "+
			"cannot be filtered. Restart Docker, then apply again.", published)}
	case !covered:
		return []string{"Docker started after your last apply, so container ports are not filtered yet. Review and apply again."}
	}
	return nil
}
