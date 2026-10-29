package enricher

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quvonchbek-devops/ipt-lens/internal/iptables"
)

// Enrich adds interface addresses, the host's local addresses and Docker
// container names. Nothing is hard-coded: every name comes from the live system.
func Enrich(st *iptables.SystemState) {
	if st.EnrichMap == nil {
		st.EnrichMap = make(map[string]iptables.MetaInfo)
	}
	addInterfaces(st)
	addDockerNames(st)
}

func addInterfaces(st *iptables.SystemState) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifc := range ifaces {
		typ := "iface"
		if isVPNName(ifc.Name) {
			typ = "vpn"
		}
		st.EnrichMap[ifc.Name] = iptables.MetaInfo{Type: typ, Name: ifc.Name}

		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP.String()
			st.LocalAddrs = append(st.LocalAddrs, ip)
			st.EnrichMap[ip] = iptables.MetaInfo{Type: typ, Name: ifc.Name}
		}
	}
}

func addDockerNames(st *iptables.SystemState) {
	for _, c := range containers() {
		for _, n := range c.NetworkSettings.Networks {
			if n.IPAddress != "" {
				st.EnrichMap[n.IPAddress] = iptables.MetaInfo{Type: "docker", Name: c.name()}
			}
		}
	}
}

type container struct {
	Names           []string `json:"Names"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Ports []struct {
		IP         string `json:"IP"`
		PublicPort int    `json:"PublicPort"`
		Type       string `json:"Type"`
	} `json:"Ports"`
}

func (c container) name() string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	return "container"
}

// containers lists running containers through the Docker socket, or nil if
// Docker is not available.
func containers() []container {
	const sock = "/var/run/docker.sock"
	if _, err := os.Stat(sock); err != nil {
		return nil
	}
	client := &http.Client{
		Timeout: 800 * time.Millisecond,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	resp, err := client.Get("http://docker/containers/json")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var cs []container
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&cs); err != nil {
		return nil
	}
	return cs
}

// Published is a container port reachable from outside the host.
type Published struct {
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Container string `json:"container"`
}

// PublishedPorts lists Docker ports published on a non-loopback address.
func PublishedPorts() []Published { return publishedFrom(containers()) }

func publishedFrom(cs []container) []Published {
	var out []Published
	seen := map[Published]bool{}
	for _, c := range cs {
		for _, p := range c.Ports {
			if p.PublicPort == 0 {
				continue // exposed but not published
			}
			if ip := net.ParseIP(p.IP); ip != nil && ip.IsLoopback() {
				continue
			}
			pub := Published{Port: p.PublicPort, Proto: p.Type, Container: c.name()}
			if !seen[pub] { // Docker lists IPv4 and IPv6 bindings separately
				seen[pub] = true
				out = append(out, pub)
			}
		}
	}
	return out
}

// VPNIface is a network interface that looks like a VPN, with its IPv4 subnets.
type VPNIface struct {
	Name    string   `json:"name"`
	Subnets []string `json:"subnets"`
}

func isVPNName(n string) bool {
	for _, p := range []string{"wg", "tailscale", "tun", "zt", "wt"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// VPNInterfaces lists interfaces named like WireGuard, Tailscale, OpenVPN,
// ZeroTier or NetBird ones.
func VPNInterfaces() []VPNIface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []VPNIface
	for _, ifc := range ifaces {
		if !isVPNName(ifc.Name) {
			continue
		}
		v := VPNIface{Name: ifc.Name}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				v.Subnets = append(v.Subnets, (&net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask}).String())
			}
		}
		out = append(out, v)
	}
	return out
}
