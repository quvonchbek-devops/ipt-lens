package iptables

type SystemState struct {
	Timestamp  int64               `json:"timestamp"`
	IsMock     bool                `json:"is_mock"`
	Tables     map[string]*Table   `json:"tables"`
	EnrichMap  map[string]MetaInfo `json:"enrich_map"`
	LocalAddrs []string            `json:"local_addrs"`
}

type Table struct {
	Name       string            `json:"name"`
	ChainOrder []string          `json:"chain_order"`
	Chains     map[string]*Chain `json:"chains"`
}

type Chain struct {
	Name      string  `json:"name"`
	Policy    string  `json:"policy"`
	Packets   uint64  `json:"packets"`
	Bytes     uint64  `json:"bytes"`
	IsCustom  bool    `json:"is_custom"`
	Protected bool    `json:"protected"`
	Rules     []*Rule `json:"rules"`
}

type Rule struct {
	ID          int      `json:"id"`
	Packets     uint64   `json:"packets"`
	Bytes       uint64   `json:"bytes"`
	InIface     string   `json:"in_iface"`
	OutIface    string   `json:"out_iface"`
	Proto       string   `json:"proto"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	SrcPort     string   `json:"src_port"`
	DstPort     string   `json:"dst_port"`
	CtState     string   `json:"ct_state"`
	DstType     string   `json:"dst_type"`
	Target      string   `json:"target"`
	ToDest      string   `json:"to_dest"`
	Comment     string   `json:"comment"`
	Extra       string   `json:"extra"`
	RawRule     string   `json:"raw_rule"`
	Unsupported []string `json:"unsupported,omitempty"`
	Protected   bool     `json:"protected"`
}

type MetaInfo struct {
	Type string `json:"type"` // docker | iface | vpn
	Name string `json:"name"`
}

type SimRequest struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	Proto    string `json:"proto"`
	DstPort  string `json:"dst_port"`
	InIface  string `json:"in_iface"`
	OutIface string `json:"out_iface"`
	CtState  string `json:"ct_state"`
}

type SimStep struct {
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	RuleID  int    `json:"rule_id"`
	RawRule string `json:"raw_rule"`
	Action  string `json:"action"`
	Note    string `json:"note"`
}

type SimResult struct {
	FinalVerdict string    `json:"final_verdict"`
	FinalDst     string    `json:"final_dst"`
	Steps        []SimStep `json:"steps"`
	Uncertain    bool      `json:"uncertain"`
	Warnings     []string  `json:"warnings"`
}
