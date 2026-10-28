package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quvonchbek-devops/ipt-lens/internal/api"
	"github.com/quvonchbek-devops/ipt-lens/internal/iptables"
	"github.com/quvonchbek-devops/ipt-lens/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "address to listen on, e.g. a WireGuard IP: 10.8.0.1:8090")
	demo := flag.Bool("demo", false, "serve built-in sample data; the firewall is never touched (no root needed)")
	timeout := flag.Duration("rollback-timeout", 60*time.Second, "how long a change waits for confirmation before it is rolled back")
	stateDir := flag.String("state-dir", "/var/lib/ipt-lens", "directory for backups and the pending change")
	keepBackups := flag.Int("keep-backups", iptables.DefaultKeepBackups, "number of iptables-save backups to keep")
	persistFile := flag.String("persist-file", "", "on confirm, save the ruleset here (e.g. /etc/iptables/rules.v4); empty = do not persist")
	allowedHosts := flag.String("allowed-hosts", "", "extra comma-separated host names accepted in the Host header (e.g. behind a reverse proxy)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("ipt-lens", version)
		return
	}

	token := os.Getenv("IPTLENS_TOKEN")
	if token != "" && len(token) < 16 {
		log.Fatal("IPTLENS_TOKEN must be at least 16 characters")
	}
	if !isLoopback(*listen) && token == "" {
		log.Fatal("IPTLENS_TOKEN is required when listening on a non-loopback address")
	}

	watch, err := iptables.NewWatchdog(*stateDir, *demo, *timeout,
		iptables.WithKeepBackups(*keepBackups), iptables.WithPersistFile(*persistFile))
	if err != nil {
		log.Fatal(err)
	}

	static, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		log.Fatal(err)
	}

	hosts := hostAllowlist(*listen, *allowedHosts)
	if hosts == nil {
		log.Printf("listening on all addresses without --allowed-hosts: Host header check disabled")
	}

	srv := &api.Server{
		Demo:         *demo,
		Token:        token,
		Version:      displayVersion(version),
		AllowedHosts: hosts,
		Watch:        watch,
		Static:       http.FileServer(http.FS(static)),
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if *persistFile == "" && !*demo {
		log.Printf("--persist-file not set: confirmed changes are lost on reboot unless saved another way")
	}
	log.Printf("IPT-Lens %s listening on http://%s (demo=%v, token=%v)", version, *listen, *demo, token != "")
	log.Fatal(httpSrv.ListenAndServe())
}

// hostAllowlist returns the Host header names to accept: loopback names, the
// listen host and any extras. It returns nil (check disabled) when listening
// on all addresses with no extras, since the reachable names are unknown;
// a token is mandatory in that case.
func hostAllowlist(listen, extra string) []string {
	host, _, _ := net.SplitHostPort(listen)
	var extras []string
	for _, h := range strings.Split(extra, ",") {
		if h = strings.TrimSpace(h); h != "" {
			extras = append(extras, h)
		}
	}
	ip := net.ParseIP(host)
	unspecified := host == "" || (ip != nil && ip.IsUnspecified())
	if unspecified && len(extras) == 0 {
		return nil
	}
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if !unspecified {
		hosts = append(hosts, host)
	}
	return append(hosts, extras...)
}

// displayVersion prefixes release numbers with "v" (0.1.0 -> v0.1.0) and leaves
// anything else, such as "dev" or a git describe string, as it is.
func displayVersion(v string) string {
	if v != "" && v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
