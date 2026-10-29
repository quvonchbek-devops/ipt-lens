package enricher

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPublishedFromContainers(t *testing.T) {
	var cs []container
	raw := `[{"Names":["/postgres"],"Ports":[{"PrivatePort":5432,"PublicPort":5432,"Type":"tcp","IP":"0.0.0.0"},{"PrivatePort":5432,"PublicPort":5432,"Type":"tcp","IP":"::"}]},
	         {"Names":["/web"],"Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp","IP":"0.0.0.0"},{"PrivatePort":9000,"Type":"tcp"}]},
	         {"Names":["/local"],"Ports":[{"PrivatePort":6379,"PublicPort":6379,"Type":"tcp","IP":"127.0.0.1"}]}]`
	if err := json.Unmarshal([]byte(raw), &cs); err != nil {
		t.Fatal(err)
	}
	want := []Published{{Port: 5432, Proto: "tcp", Container: "postgres"}, {Port: 8080, Proto: "tcp", Container: "web"}}
	if got := publishedFrom(cs); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestIsVPNName(t *testing.T) {
	for name, want := range map[string]bool{
		"wg0": true, "tailscale0": true, "tun0": true, "ztabcdef": true, "wt0": true,
		"eth0": false, "docker0": false, "lo": false, "br-1234": false,
	} {
		if got := isVPNName(name); got != want {
			t.Errorf("isVPNName(%q) = %v, want %v", name, got, want)
		}
	}
}
