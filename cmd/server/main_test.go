package main

import (
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
