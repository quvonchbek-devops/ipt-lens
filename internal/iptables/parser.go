package iptables

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const MockIptablesData = `
*nat
:PREROUTING ACCEPT [450:28900]
:INPUT ACCEPT [120:7200]
:OUTPUT ACCEPT [80:5100]
:POSTROUTING ACCEPT [95:6200]
:DOCKER - [0:0]
[12:768] -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
[5420:894120] -A POSTROUTING -s 172.18.0.0/16 ! -o docker0 -j MASQUERADE
[85:5100] -A DOCKER ! -i docker0 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.18.0.4:5432
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [14:840]
:OUTPUT ACCEPT [1024:145200]
:DOCKER-USER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER - [0:0]
[9850:1420500] -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[45:2700] -A INPUT -i wg0 -p tcp -m tcp --dport 8090 -m comment --comment "Allow IPT-Lens UI from VPN" -j ACCEPT
[210:12400] -A INPUT -p tcp -m tcp --dport 22 -m comment --comment "SSH Access" -j ACCEPT
[1200:84000] -A FORWARD -j DOCKER-USER
[950:62000] -A FORWARD -j DOCKER-ISOLATION-STAGE-1
[890:59000] -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[110:7400] -A FORWARD -o docker0 -j DOCKER
[340:22100] -A DOCKER-USER -i wg0 -o docker0 -s 100.64.0.0/10 -d 172.18.0.4/32 -p tcp -m tcp --dport 5432 -m comment --comment "Headscale VPN to Postgres" -j ACCEPT
[18:1080] -A DOCKER-USER -i eth0 -p tcp -m tcp --dport 3306 -m comment --comment "Block External MySQL" -j DROP
[0:0] -A DOCKER-USER -j RETURN
[85:5100] -A DOCKER -d 172.18.0.4/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 5432 -j ACCEPT
COMMIT
`

// quietModules are -m modules whose options have their own Rule fields, so
// they are not repeated in Extra.
var quietModules = map[string]bool{
	"tcp": true, "udp": true, "comment": true, "multiport": true,
	"conntrack": true, "state": true, "addrtype": true,
}

// FetchState returns the live ruleset, or the sample data in demo mode.
// There is no silent fallback to sample data.
func FetchState(demo bool) (*SystemState, error) {
	if demo {
		st, err := ParseIptablesSave(strings.NewReader(MockIptablesData))
		if err != nil {
			return nil, err
		}
		st.IsMock = true
		return st, nil
	}
	out, err := runSave()
	if err != nil {
		return nil, fmt.Errorf("iptables-save failed (run as root, or start with --demo): %w", err)
	}
	return ParseIptablesSave(bytes.NewReader(out))
}

func newState() *SystemState {
	return &SystemState{
		Timestamp: time.Now().Unix(),
		Tables:    make(map[string]*Table),
		EnrichMap: make(map[string]MetaInfo),
	}
}

func newTable(name string) *Table {
	return &Table{Name: name, Chains: make(map[string]*Chain), ChainOrder: []string{}}
}

func (t *Table) addChain(c *Chain) {
	if _, exists := t.Chains[c.Name]; !exists {
		t.ChainOrder = append(t.ChainOrder, c.Name)
	}
	t.Chains[c.Name] = c
}

// ParseIptablesSave parses iptables-save output, keeping chain order.
func ParseIptablesSave(r io.Reader) (*SystemState, error) {
	state := newState()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 8*1024*1024)

	var cur *Table
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#") || line == "COMMIT":
			continue
		case strings.HasPrefix(line, "*"):
			name := strings.TrimPrefix(line, "*")
			cur = newTable(name)
			state.Tables[name] = cur
		case cur == nil:
			continue
		case strings.HasPrefix(line, ":"):
			if chain, err := parseChainHeader(line); err == nil {
				cur.addChain(chain)
			}
		case strings.HasPrefix(line, "[") || strings.HasPrefix(line, "-A "):
			chainName, rule, err := parseRuleLine(line)
			if err != nil {
				continue
			}
			chain, ok := cur.Chains[chainName]
			if !ok {
				chain = &Chain{Name: chainName, Policy: "-", IsCustom: true, Rules: []*Rule{}}
				cur.addChain(chain)
			}
			rule.ID = len(chain.Rules) + 1
			chain.Rules = append(chain.Rules, rule)
		}
	}
	markProtected(state)
	return state, scanner.Err()
}

// markProtected flags chains and rules owned by Docker, Kubernetes, Calico,
// libvirt or ufw, so every client gets the same answer as the server's checks.
func markProtected(st *SystemState) {
	for _, t := range st.Tables {
		for name, c := range t.Chains {
			// IPT-Lens' own chains are edited through the simple view only.
			lens := strings.HasPrefix(name, accessPrefix)
			c.Protected = protectedName(name) || lens
			for _, r := range c.Rules {
				r.Protected = isProtected(name, r) || lens || strings.HasPrefix(r.Target, accessPrefix)
			}
		}
	}
}

func parseChainHeader(line string) (*Chain, error) {
	parts := strings.Fields(strings.TrimPrefix(line, ":"))
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid chain header: %s", line)
	}
	var pkts, byts uint64
	if len(parts) >= 3 {
		pkts, byts = parseCounters(parts[2])
	}
	return &Chain{
		Name:     parts[0],
		Policy:   parts[1],
		Packets:  pkts,
		Bytes:    byts,
		IsCustom: parts[1] == "-",
		Rules:    make([]*Rule, 0),
	}, nil
}

func parseRuleLine(line string) (string, *Rule, error) {
	rule := &Rule{
		Proto:       "all",
		Source:      "0.0.0.0/0",
		Destination: "0.0.0.0/0",
		RawRule:     line,
	}

	rest := line
	if strings.HasPrefix(rest, "[") {
		if end := strings.Index(rest, "]"); end != -1 {
			rule.Packets, rule.Bytes = parseCounters(rest[:end+1])
			rest = strings.TrimSpace(rest[end+1:])
		}
	}

	tokens := tokenizeRule(rest)
	var chainName string
	var extra []string
	negate := false
	afterJump := false // tokens after -j are target options, not matches

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "!" {
			negate = true
			continue
		}
		prefix := ""
		if negate {
			prefix = "!"
			negate = false
		}
		// val consumes and returns the next token.
		val := func() string {
			if i+1 >= len(tokens) {
				return ""
			}
			i++
			return tokens[i]
		}

		switch tok {
		case "-A", "--append":
			chainName = val()
		case "-i", "--in-interface":
			rule.InIface = prefix + val()
		case "-o", "--out-interface":
			rule.OutIface = prefix + val()
		case "-p", "--protocol":
			rule.Proto = prefix + val()
		case "-s", "--source", "--src":
			rule.Source = prefix + val()
		case "-d", "--destination", "--dst":
			rule.Destination = prefix + val()
		case "--sport", "--source-port", "--sports":
			rule.SrcPort = prefix + val()
		case "--dport", "--destination-port", "--dports":
			rule.DstPort = prefix + val()
		case "--ctstate", "--state":
			rule.CtState = prefix + val()
		case "--dst-type":
			rule.DstType = prefix + val()
		case "--to-destination", "--to-destinations":
			rule.ToDest = val()
		case "-j", "--jump", "-g", "--goto":
			rule.Target = val()
			afterJump = true
		case "--comment":
			rule.Comment = val()
		case "-m", "--match":
			if mod := val(); !quietModules[mod] && mod != "" {
				extra = append(extra, "-m "+mod)
			}
		default:
			extra = append(extra, prefix+tok)
			if !afterJump && strings.HasPrefix(tok, "-") {
				rule.Unsupported = append(rule.Unsupported, prefix+tok)
			}
		}
	}

	rule.Extra = strings.Join(extra, " ")
	if chainName == "" {
		return "", nil, fmt.Errorf("no chain in rule line")
	}
	return chainName, rule, nil
}

func parseCounters(raw string) (uint64, uint64) {
	parts := strings.Split(strings.Trim(raw, "[]"), ":")
	if len(parts) != 2 {
		return 0, 0
	}
	p, _ := strconv.ParseUint(parts[0], 10, 64)
	b, _ := strconv.ParseUint(parts[1], 10, 64)
	return p, b
}

// tokenizeRule splits a rule into tokens. A double-quoted value (--comment "a b")
// is one token; inside quotes, \", \' and \\ are unescaped as iptables-save writes them.
func tokenizeRule(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuotes := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuotes && ch == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\' || s[i+1] == '\'') {
			i++
			cur.WriteByte(s[i])
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if (ch == ' ' || ch == '\t') && !inQuotes {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(ch)
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}
