package ports

import (
	"reflect"
	"strings"
	"testing"
)

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0A08000A:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
   3: 00000000:01BB 0101A8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 100 0 0 10 0
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6 1 0000000000000000 100 0 0 10 0
`

const procUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 00000000:CA6C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 7 2 0000000000000000 0
  11: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 8 2 0000000000000000 0
  12: 0A08000A:0044 0108000A:0043 01 00000000:00000000 00:00000000 00000000     0        0 9 2 0000000000000000 0
`

func TestParseListening(t *testing.T) {
	got := parse(strings.NewReader(procTCP), "tcp")
	got = append(got, parse(strings.NewReader(procTCP6), "tcp")...)
	got = append(got, parse(strings.NewReader(procUDP), "udp")...)
	// 127.0.0.1:8080, [::1]:5432 and 127.0.0.53:53 are loopback-only; the
	// established tcp/443 and connected udp/68 sockets are not listening.
	want := []Port{{22, "tcp"}, {80, "tcp"}, {443, "tcp"}, {51820, "udp"}}
	if !reflect.DeepEqual(Dedupe(got), want) {
		t.Fatalf("got %v, want %v", Dedupe(got), want)
	}
}

func TestName(t *testing.T) {
	for p, want := range map[Port]string{
		{22, "tcp"}: "SSH", {443, "tcp"}: "HTTPS", {5432, "tcp"}: "PostgreSQL",
		{51820, "udp"}: "WireGuard", {12345, "tcp"}: "",
	} {
		if got := Name(p); got != want {
			t.Errorf("Name(%v) = %q, want %q", p, got, want)
		}
	}
}

func TestRisk(t *testing.T) {
	for _, c := range []struct {
		p    Port
		want string
	}{
		{Port{3306, "tcp"}, "database"},
		{Port{6379, "tcp"}, "database"},
		{Port{2375, "tcp"}, "controls Docker as root"},
		{Port{23, "tcp"}, "sends passwords unencrypted"},
		{Port{3389, "tcp"}, "remote desktop"},
		{Port{22, "tcp"}, ""},
		{Port{443, "tcp"}, ""},
		{Port{3306, "udp"}, ""},
	} {
		if got := Risk(c.p); got != c.want {
			t.Errorf("Risk(%v) = %q, want %q", c.p, got, c.want)
		}
	}
	for p := range risks {
		if Name(p) == "" {
			t.Errorf("risky port %v has no name", p)
		}
	}
}
