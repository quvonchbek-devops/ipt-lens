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
	Host       bool           `json:"host"`              // a host process listens on it
	Containers []string       `json:"containers"`        // containers publishing it
	Level      iptables.Level `json:"level"`             // effective level
	Explicit   bool           `json:"explicit"`          // set for this port, not inherited from "everything else"
	Locked     bool           `json:"locked"`            // IPT-Lens' own port: never below "VPN only"
	Risk       string         `json:"risk,omitempty"`    // why it should not be open to everyone
	Program    string         `json:"program,omitempty"` // the process listening on it, e.g. nginx
}

type accessView struct {
	Configured    bool                  `json:"configured"`
	Policy        iptables.AccessPolicy `json:"policy"`
	Rows          []accessRow           `json:"rows"`
	VPNCandidates []enricher.VPNIface   `json:"vpn_candidates"`
	Notes         []string              `json:"notes"`
	dockerNotes   []string              // also shown as warnings in a preview
	ipv6          bool                  // the policy is applied with ip6tables too
}

type accessPreview struct {
	Changes  []string `json:"changes"`
	Warnings []string `json:"warnings"`
	Notes    []string `json:"notes"`
	Commands []string `json:"commands"`
}

// discovery is what the host exposes: listening ports, published container
// ports and VPN-like interfaces.
type discovery struct {
	listening []ports.Port
	programs  map[ports.Port]string
	published []enricher.Published
	vpn       []enricher.VPNIface
}

func (s *Server) discover() discovery {
	if s.Demo {
		return discovery{
			listening: []ports.Port{{Number: 22, Proto: "tcp"}, {Number: 80, Proto: "tcp"}, {Number: 443, Proto: "tcp"},
				{Number: 8090, Proto: "tcp"}, {Number: 51820, Proto: "udp"}},
			programs: map[ports.Port]string{{Number: 22, Proto: "tcp"}: "sshd", {Number: 80, Proto: "tcp"}: "nginx",
				{Number: 443, Proto: "tcp"}: "nginx", {Number: 8090, Proto: "tcp"}: "ipt-lens"},
			published: []enricher.Published{{Port: 5432, Proto: "tcp", Container: "postgres"},
				{Port: 3306, Proto: "tcp", Container: "mysql"}},
			vpn: []enricher.VPNIface{{Name: "wg0", Subnets: []string{"10.8.0.0/24"}},
				{Name: "tailscale0", Subnets: []string{"100.64.0.0/10"}}},
		}
	}
	return discovery{listening: ports.Listening(), programs: ports.Programs(), published: enricher.PublishedPorts(),
		vpn: enricher.VPNInterfaces()}
}

var levelLabel = map[iptables.Level]string{
	iptables.LevelPublic: "Everyone", iptables.LevelVPN: "VPN only", iptables.LevelClosed: "Nobody",
}

// vpnServices are VPN endpoints: clients reach them before they are on the VPN.
var vpnServices = map[string]bool{"WireGuard": true, "Tailscale": true, "OpenVPN": true}

// ipv6Notes says, from the live state, whether IPv6 is covered.
func ipv6Notes(available, covered, configured bool) string {
	switch {
	case !available:
		return "IPv6 is not filtered: ip6tables is not installed. If this server has a public IPv6 address, everything on it is open."
	case configured && !covered:
		return "IPv6 is not protected by these settings yet. Review and apply once to fix it."
	}
	// When "VPN only" lets nobody in over one family, the review warns.
	return "IPv6 is protected the same way."
}

func (s *Server) ipv6Coverage(st *iptables.SystemState) (available, covered bool) {
	if s.Demo {
		return true, true
	}
	return iptables.IPv6Coverage(st)
}

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
		r := &accessRow{Port: port, Proto: proto, Name: ports.Name(ports.Port{Number: port, Proto: proto}),
			Risk: ports.Risk(ports.Port{Number: port, Proto: proto}), Containers: []string{}}
		rows[k] = r
		return r
	}
	for _, l := range d.listening {
		r := row(l.Number, l.Proto)
		r.Host = true
		r.Program = d.programs[l]
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
	v6, v6covered := s.ipv6Coverage(st)
	v := accessView{Configured: configured, Policy: cur, VPNCandidates: d.vpn,
		Notes: append(append([]string{ipv6Notes(v6, v6covered, configured)}, dn...), s.ExtraNotes...), dockerNotes: dn, ipv6: v6}
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
	if !p.VPN.Reaches(false) {
		return out, fmt.Errorf("%w: IPT-Lens itself listens on port %d and would become unreachable over IPv4. "+
			"Choose your VPN or add an IPv4 trusted address first, so the panel stays reachable", iptables.ErrInvalid, port)
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
	pv := previewOf(view.Policy, next, view.Rows, view.ipv6)
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
func previewOf(cur, next iptables.AccessPolicy, rows []accessRow, ipv6 bool) accessPreview {
	pv := accessPreview{Changes: []string{}, Warnings: []string{}, Notes: []string{}}
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
	if a, b := strings.Join(cur.VPN.Trusted, ", "), strings.Join(next.VPN.Trusted, ", "); a != b {
		if b == "" {
			b = "none"
		}
		pv.Changes = append(pv.Changes, "Trusted addresses (let in wherever \"VPN only\" is set): "+b)
	}
	curDef, _ := levelOf(cur, 0, "")
	nextDef, _ := levelOf(next, 0, "")
	if curDef != nextDef {
		pv.Changes = append(pv.Changes, fmt.Sprintf("Any other port: %s → %s", levelLabel[curDef], levelLabel[nextDef]))
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
	limited := func(p iptables.AccessPolicy, k key) bool {
		for _, pa := range p.Ports {
			if pa.Port == k.port && pa.Proto == k.proto {
				return pa.Limit
			}
		}
		return false
	}
	for _, k := range sorted {
		from, _ := levelOf(cur, k.port, k.proto)
		to, _ := levelOf(next, k.port, k.proto)
		if from == to {
			if a, b := limited(cur, k), limited(next, k); a != b {
				verb := map[bool]string{true: "slow down password guessing (at most 6 new connections a minute per address)",
					false: "stop slowing down password guessing"}[b]
				pv.Changes = append(pv.Changes, fmt.Sprintf("%s: %s", rowLabel(k.port, k.proto, names[k]), verb))
			}
			continue
		}
		pv.Changes = append(pv.Changes, fmt.Sprintf("%s: %s → %s", rowLabel(k.port, k.proto, names[k]), levelLabel[from], levelLabel[to]))
		if limited(next, k) {
			pv.Changes = append(pv.Changes, fmt.Sprintf("%s: slow down password guessing (at most 6 new connections a minute per address)",
				rowLabel(k.port, k.proto, names[k])))
		}
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
	pv.Notes = append(pv.Notes, "Traffic from containers, pods and VMs on this host is always allowed, "+
		"through these interfaces: "+strings.Join(iptables.InternalIfaces(), ", ")+
		". If a bridge named br-* connects to an outside network, filter it in the Advanced view.")
	udpVPN := next.Default == iptables.LevelVPN
	for _, pa := range next.Ports {
		udpVPN = udpVPN || (pa.Proto == "udp" && pa.Level == iptables.LevelVPN)
	}
	if len(next.VPN.Trusted) > 0 && udpVPN {
		pv.Notes = append(pv.Notes, "Trusted addresses are matched by source address. That is reliable for TCP; "+
			"a UDP port can be reached with a forged source address.")
	}
	if usesVPN(next) && !next.VPN.Reaches(false) {
		pv.Warnings = append(pv.Warnings, "Over IPv4, \"VPN only\" lets in nobody: there is no VPN, IPv4 subnet or "+
			"IPv4 trusted address. Those ports are closed to everyone over IPv4.")
	}
	if ipv6 && usesVPN(next) && !next.VPN.Reaches(true) {
		pv.Warnings = append(pv.Warnings, "Over IPv6, \"VPN only\" lets in a VPN interface or IPv6 trusted addresses, "+
			"and neither is set: those ports are closed to everyone over IPv6.")
	}
	pv.Notes = append(pv.Notes, ipv6Notes(ipv6, true, true)) // describes the state after applying
	families := []bool{false}
	if ipv6 {
		families = append(families, true)
	}
	for _, v6 := range families {
		bin := "iptables"
		if v6 {
			bin = "ip6tables"
		}
		for _, rule := range iptables.InputRules(next, v6) {
			pv.Commands = append(pv.Commands, bin+" -A IPTLENS-IN "+shellJoin(rule))
		}
		for _, rule := range iptables.DockerRules(next, v6) {
			pv.Commands = append(pv.Commands, bin+" -A IPTLENS-DK "+shellJoin(rule))
		}
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

func usesVPN(p iptables.AccessPolicy) bool {
	if p.Default == iptables.LevelVPN {
		return true
	}
	for _, pa := range p.Ports {
		if pa.Level == iptables.LevelVPN {
			return true
		}
	}
	return false
}
