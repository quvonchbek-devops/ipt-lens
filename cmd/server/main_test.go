package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostAllowlist(t *testing.T) {
	cases := []struct {
		listen, extra string
		want          string // joined with ",", "<nil>" for a disabled check
	}{
		{"127.0.0.1:8090", "", "localhost,127.0.0.1,::1,127.0.0.1"},
		{"10.8.0.1:8090", "", "localhost,127.0.0.1,::1,10.8.0.1"},
		{"0.0.0.0:8090", "", "<nil>"},
		{":8090", "", "<nil>"},
		{"0.0.0.0:8090", "fw.example.com, ", "localhost,127.0.0.1,::1,fw.example.com"},
		{"0.0.0.0:8090", "fw.example.com:8443,[fe80::1]", "localhost,127.0.0.1,::1,fw.example.com,fe80::1"},
	}
	for _, c := range cases {
		got := hostAllowlist(c.listen, c.extra)
		s := strings.Join(got, ",")
		if got == nil {
			s = "<nil>"
		}
		if s != c.want {
			t.Errorf("hostAllowlist(%q, %q) = %s, want %s", c.listen, c.extra, s, c.want)
		}
	}
}

func TestDisplayVersion(t *testing.T) {
	for in, want := range map[string]string{"0.1.0": "v0.1.0", "v0.1.0": "v0.1.0", "dev": "dev", "": ""} {
		if got := displayVersion(in); got != want {
			t.Errorf("displayVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8090": true, "localhost:8090": true, "[::1]:8090": true,
		"10.8.0.1:8090": false, ":8090": false, "0.0.0.0:8090": false, "bad": false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestLoadOrCreateToken(t *testing.T) {
	dir := t.TempDir()
	tok, created, err := loadOrCreateToken(dir)
	if err != nil || !created || len(tok) < 32 {
		t.Fatalf("first call: %q, %v, %v", tok, created, err)
	}
	info, err := os.Stat(filepath.Join(dir, "token"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode: %v, %v", info, err)
	}
	again, created, err := loadOrCreateToken(dir)
	if err != nil || created || again != tok {
		t.Fatalf("second call: %q, %v, %v (want %q, false)", again, created, err, tok)
	}
}

func TestLoadOrCreateTokenRefusesReadableFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("0123456789abcdef0123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateToken(dir); err == nil {
		t.Fatal("accepted a token file readable by others")
	}
}

func TestLoadOrCreateTokenReportsReadErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "token"), 0o700); err != nil { // unreadable as a file
		t.Fatal(err)
	}
	_, _, err := loadOrCreateToken(dir)
	if err == nil || strings.Contains(err.Error(), "file exists") {
		t.Fatalf("misleading or missing error: %v", err)
	}
}

func TestLensPort(t *testing.T) {
	for listen, want := range map[string]int{"127.0.0.1:8090": 0, "10.8.0.1:8090": 8090, ":9000": 9000, "bad": 0} {
		if got := lensPort(listen); got != want {
			t.Errorf("lensPort(%q) = %d, want %d", listen, got, want)
		}
	}
}
