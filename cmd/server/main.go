package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

	version = displayVersion(version)
	if *showVersion {
		fmt.Println("ipt-lens", version)
		return
	}

	token := os.Getenv("IPTLENS_TOKEN")
	if token != "" && len(token) < 16 {
		log.Fatal("IPTLENS_TOKEN must be at least 16 characters")
	}
	if !isLoopback(*listen) && token == "" && !*demo {
		log.Fatal("IPTLENS_TOKEN is required when listening on a non-loopback address")
	}

	// NewWatchdog creates the state directory and checks that it is private.
	watch, err := iptables.NewWatchdog(*stateDir, *demo, *timeout,
		iptables.WithKeepBackups(*keepBackups), iptables.WithPersistFile(*persistFile))
	if err != nil {
		log.Fatal(err)
	}

	tokenHint := "Set in IPTLENS_TOKEN on the server."
	if token == "" && !*demo {
		// Loopback is reachable by every local user and by SSRF in local apps,
		// so a token is always required outside demo mode.
		t, created, err := loadOrCreateToken(*stateDir)
		if err != nil {
			log.Fatal(err)
		}
		token = t
		tokenPath := filepath.Join(*stateDir, "token")
		tokenHint = "On the server, run: sudo cat " + tokenPath
		if created {
			log.Printf("generated an API token in %s", tokenPath)
		}
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
		Version:      version,
		AllowedHosts: hosts,
		Watch:        watch,
		Static:       http.FileServer(http.FS(static)),
		TokenHint:    tokenHint,
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
		h = strings.TrimSpace(h)
		if net.ParseIP(h) == nil {
			h = (&url.URL{Host: h}).Hostname() // drop a port or IPv6 brackets
		}
		if h != "" {
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

// loadOrCreateToken returns the token stored in dir/token, creating a random
// one (mode 0600) on first use. created reports whether it was just made.
// An existing file must be a regular file that only its owner can read.
func loadOrCreateToken(dir string) (token string, created bool, err error) {
	path := filepath.Join(dir, "token")
	b, err := readPrivateFile(path)
	switch {
	case err == nil:
		t := strings.TrimSpace(string(b))
		if len(t) < 16 {
			return "", false, fmt.Errorf("token in %s is shorter than 16 characters; fix or delete it", path)
		}
		return t, false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return "", false, err
	}

	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", false, err
	}
	t := hex.EncodeToString(buf)
	// Write a complete temp file, then hard-link it into place: the token file
	// either does not exist or is complete, and an existing one is never replaced.
	tmp, err := os.CreateTemp(dir, ".token.tmp-*")
	if err != nil {
		return "", false, err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(t + "\n")
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", false, err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		return "", false, err
	}
	return t, true, nil
}

// readPrivateFile reads path if it is a regular file without group or other
// permission bits.
func readPrivateFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by group or others (mode %v); run: chmod 600 %s", path, fi.Mode().Perm(), path)
	}
	return os.ReadFile(path)
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
