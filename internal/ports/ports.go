// Package ports finds the ports this host listens on from the outside.
package ports

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Port struct {
	Number int    `json:"port"`
	Proto  string `json:"proto"`
}

// Listening returns tcp and udp ports bound to a non-loopback address, read
// from /proc/net. Errors (e.g. no IPv6) just leave that file out.
func Listening() []Port {
	var out []Port
	for file, proto := range map[string]string{
		"/proc/net/tcp": "tcp", "/proc/net/tcp6": "tcp", "/proc/net/udp": "udp", "/proc/net/udp6": "udp",
	} {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		out = append(out, parse(f, proto)...)
		f.Close()
	}
	return Dedupe(out)
}

// listenState is the socket state of a listening tcp socket (0A) or an
// unconnected udp socket (07).
var listenState = map[string]string{"tcp": "0A", "udp": "07"}

func parse(r io.Reader, proto string) []Port {
	var out []Port
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != listenState[proto] {
			continue
		}
		addr, port, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(port, 16, 16)
		if err != nil || n == 0 {
			continue
		}
		if ip := procIP(addr); ip == nil || ip.IsLoopback() {
			continue
		}
		out = append(out, Port{int(n), proto})
	}
	return out
}

// procIP decodes /proc/net's hex address: 32-bit words in host (little-endian) order.
func procIP(s string) net.IP {
	b, err := hex.DecodeString(s)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b)
}

// Dedupe sorts ports by number, then protocol, and drops duplicates.
func Dedupe(ps []Port) []Port {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Number != ps[j].Number {
			return ps[i].Number < ps[j].Number
		}
		return ps[i].Proto < ps[j].Proto
	})
	out := ps[:0]
	for i, p := range ps {
		if i == 0 || p != ps[i-1] {
			out = append(out, p)
		}
	}
	return out
}

var names = map[Port]string{
	{21, "tcp"}: "FTP", {22, "tcp"}: "SSH", {25, "tcp"}: "SMTP", {53, "tcp"}: "DNS", {53, "udp"}: "DNS",
	{80, "tcp"}: "HTTP", {110, "tcp"}: "POP3", {143, "tcp"}: "IMAP", {443, "tcp"}: "HTTPS", {443, "udp"}: "HTTP/3",
	{465, "tcp"}: "SMTPS", {587, "tcp"}: "SMTP submission", {993, "tcp"}: "IMAPS", {995, "tcp"}: "POP3S",
	{1194, "udp"}: "OpenVPN", {2049, "tcp"}: "NFS", {2375, "tcp"}: "Docker API", {2376, "tcp"}: "Docker API (TLS)",
	{3000, "tcp"}: "Grafana / dev server", {3306, "tcp"}: "MySQL", {5432, "tcp"}: "PostgreSQL",
	{5672, "tcp"}: "RabbitMQ", {6379, "tcp"}: "Redis", {6443, "tcp"}: "Kubernetes API", {8080, "tcp"}: "HTTP (alt)",
	{8090, "tcp"}: "IPT-Lens", {9090, "tcp"}: "Prometheus", {9100, "tcp"}: "Node exporter", {9200, "tcp"}: "Elasticsearch",
	{10250, "tcp"}: "Kubelet", {11211, "tcp"}: "Memcached", {27017, "tcp"}: "MongoDB", {41641, "udp"}: "Tailscale",
	{51820, "udp"}: "WireGuard",
	{23, "tcp"}:    "Telnet", {445, "tcp"}: "Windows file sharing (SMB)", {1433, "tcp"}: "SQL Server",
	{2379, "tcp"}: "etcd", {3389, "tcp"}: "Remote Desktop", {5900, "tcp"}: "VNC", {5984, "tcp"}: "CouchDB",
	{9042, "tcp"}: "Cassandra", {15672, "tcp"}: "RabbitMQ admin",
}

// risks holds ports that should almost never be open to the whole internet,
// each with the reason in a few plain words.
var risks = map[Port]string{
	{3306, "tcp"}: "database", {5432, "tcp"}: "database", {6379, "tcp"}: "database", {27017, "tcp"}: "database",
	{11211, "tcp"}: "database", {9200, "tcp"}: "database", {1433, "tcp"}: "database", {5984, "tcp"}: "database",
	{9042, "tcp"}: "database", {5672, "tcp"}: "message queue", {15672, "tcp"}: "admin panel",
	{2375, "tcp"}: "controls Docker as root", {2376, "tcp"}: "controls Docker as root",
	{10250, "tcp"}: "controls the cluster", {2379, "tcp"}: "controls the cluster",
	{9090, "tcp"}: "shows server internals", {9100, "tcp"}: "shows server internals",
	{21, "tcp"}: "sends passwords unencrypted", {23, "tcp"}: "sends passwords unencrypted",
	{445, "tcp"}: "file sharing", {2049, "tcp"}: "file sharing",
	{3389, "tcp"}: "remote desktop", {5900, "tcp"}: "remote desktop",
}

// Risk returns why p should not be open to everyone, or "" if it may be.
func Risk(p Port) string { return risks[p] }

// Name returns a well-known service name for p, or "".
func Name(p Port) string { return names[p] }
