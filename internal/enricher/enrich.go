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
		if strings.HasPrefix(ifc.Name, "wg") || strings.HasPrefix(ifc.Name, "tun") ||
			strings.HasPrefix(ifc.Name, "tailscale") {
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
	const sock = "/var/run/docker.sock"
	if _, err := os.Stat(sock); err != nil {
		return
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
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var containers []struct {
		Names           []string `json:"Names"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&containers); err != nil {
		return
	}

	for _, c := range containers {
		name := "container"
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		for _, n := range c.NetworkSettings.Networks {
			if n.IPAddress != "" {
				st.EnrichMap[n.IPAddress] = iptables.MetaInfo{Type: "docker", Name: name}
			}
		}
	}
}
