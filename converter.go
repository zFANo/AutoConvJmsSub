// Package main: converter.go
//
// Converts a JustMySocks-style base64 subscription (newline-separated
// ss:// / vmess:// links) into a Clash YAML config with:
//   * one Clash proxy per node
//   * one `select` proxy-group per node, prefixed `G-`, containing
//     [<node>, DIRECT, REJECT] — so per-domain rules can route to a
//     single node
//   * a master `PROXY` select group listing every per-node group
//   * Loyalsoldier rule-providers + sensible default rule chain
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const nodeGroupPrefix = "G-"

// loopbackRulesYAML are always emitted at the top of `rules:` so that
// traffic to AutoConvJmsSub itself (and any other local service) never gets
// tunneled through a proxy node.
const loopbackRulesYAML = `  # Loopback / link-local first: when clash-verge-rev refreshes its remote
  # profile through Clash itself, requests to 127.0.0.1:25500 (AutoConvJmsSub)
  # must stay local. Without these, traffic to the local converter could be
  # captured by other rules and tunneled through a proxy node — wrong both
  # for performance and safety.
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - IP-CIDR6,::1/128,DIRECT,no-resolve
  - IP-CIDR6,fe80::/10,DIRECT,no-resolve
  - DOMAIN-SUFFIX,localhost,DIRECT
`

// fallbackRulesYAML is appended when rule-providers is disabled. Minimal
// chain: bypass CN by GeoIP, route everything else to PROXY.
const fallbackRulesYAML = `  - GEOIP,CN,DIRECT
  - MATCH,PROXY
`

// loyalsoldierRules lists the rule files we wire up under <baseURL>/<name>.txt.
// Each entry is (name, behavior).
var loyalsoldierRules = []struct {
	Name     string
	Behavior string // "domain" or "ipcidr"
	RuleType string // RULE-SET target — "DIRECT", "PROXY", or "REJECT"
}{
	{"reject", "domain", "REJECT"},
	{"proxy", "domain", "PROXY"},
	{"direct", "domain", "DIRECT"},
	{"private", "domain", "DIRECT"},
	{"gfw", "domain", "PROXY"},
	{"telegramcidr", "ipcidr", "PROXY"},
	{"cncidr", "ipcidr", "DIRECT"},
}

// buildRulesAndProvidersYAML produces the rule-providers + rules sections of
// the Clash config. When `enabled` is false, only the loopback rules + a
// minimal GEOIP fallback are emitted (no rule-providers block at all).
func buildRulesAndProvidersYAML(enabled bool, baseURL string) string {
	if !enabled {
		var b strings.Builder
		b.WriteString("\nrules:\n")
		b.WriteString(loopbackRulesYAML)
		b.WriteString(fallbackRulesYAML)
		return b.String()
	}

	var b strings.Builder
	b.WriteString("\nrule-providers:\n")
	for _, r := range loyalsoldierRules {
		fmt.Fprintf(&b, "  %s:\n", r.Name)
		fmt.Fprintf(&b, "    type: http\n")
		fmt.Fprintf(&b, "    behavior: %s\n", r.Behavior)
		fmt.Fprintf(&b, "    url: %s/%s.txt\n", strings.TrimRight(baseURL, "/"), r.Name)
		fmt.Fprintf(&b, "    path: ./ruleset/%s.yaml\n", r.Name)
		fmt.Fprintf(&b, "    interval: 86400\n")
	}
	b.WriteString("\nrules:\n")
	b.WriteString(loopbackRulesYAML)
	b.WriteString("  # Standard Loyalsoldier rule chain\n")
	// Order matters: private -> reject -> direct -> cncidr -> proxy -> gfw -> telegramcidr.
	// First match wins; we want bypass / direct rules before proxy ones.
	rulesOrder := []struct{ Name, Target string }{
		{"private", "DIRECT"},
		{"reject", "REJECT"},
		{"direct", "DIRECT"},
		{"cncidr", "DIRECT"},
		{"proxy", "PROXY"},
		{"gfw", "PROXY"},
		{"telegramcidr", "PROXY"},
	}
	for _, r := range rulesOrder {
		fmt.Fprintf(&b, "  - RULE-SET,%s,%s\n", r.Name, r.Target)
	}
	b.WriteString("  - GEOIP,CN,DIRECT\n")
	b.WriteString("  - MATCH,PROXY\n")
	return b.String()
}

// Proxy is one Clash proxy entry.
type Proxy map[string]any

// ConvertOptions controls the YAML generation. Zero value is safe — all
// fields fall back to sensible defaults (rule-providers on, jsDelivr CDN,
// no preferred default node).
type ConvertOptions struct {
	// DefaultProxyMatch: case-insensitive substring; matched proxy's G-<name>
	// group is promoted to the top of the master PROXY group.
	DefaultProxyMatch string
	// RuleProvidersEnabled: when false, omit rule-providers entirely and
	// emit a minimal fallback rule chain.
	RuleProvidersEnabled bool
	// RuleProvidersBaseURL: base URL for Loyalsoldier rule files. Each
	// rule is fetched as `<base>/<name>.txt`. Empty = jsDelivr default.
	RuleProvidersBaseURL string
}

const defaultLoyalsoldierBaseURL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release"

// TryParseSubscription decodes a base64 subscription body and returns a
// generated Clash YAML using default options (rule-providers enabled,
// jsDelivr CDN, no preferred default node). Returns an error if the body
// is not valid base64 or contains no recognizable ss:// / vmess:// links.
func TryParseSubscription(raw string) (string, error) {
	return TryParseSubscriptionWithOptions(raw, ConvertOptions{
		RuleProvidersEnabled: true,
		RuleProvidersBaseURL: defaultLoyalsoldierBaseURL,
	})
}

// TryParseSubscriptionWithOptions is the full-options variant.
func TryParseSubscriptionWithOptions(raw string, opts ConvertOptions) (string, error) {
	if opts.RuleProvidersBaseURL == "" {
		opts.RuleProvidersBaseURL = defaultLoyalsoldierBaseURL
	}
	decoded, err := decodeBase64Relaxed(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("subscription body is not valid base64: %w", err)
	}
	text := string(decoded)

	var proxies []Proxy
	used := make(map[string]bool)

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var p Proxy
		var perr error
		switch {
		case strings.HasPrefix(line, "ss://"):
			p, perr = parseSS(strings.TrimPrefix(line, "ss://"))
		case strings.HasPrefix(line, "vmess://"):
			p, perr = parseVmess(strings.TrimPrefix(line, "vmess://"))
		default:
			continue
		}
		if perr != nil {
			continue
		}
		name, _ := p["name"].(string)
		if name == "" {
			name = "Proxy"
		}
		p["name"] = uniquify(name, used)
		proxies = append(proxies, p)
	}

	if len(proxies) == 0 {
		return "", errors.New("no valid ss:// or vmess:// nodes found after base64 decode")
	}

	return buildClashYAML(proxies, opts), nil
}

// decodeBase64Relaxed tries Std/URL/Raw variants in turn.
func decodeBase64Relaxed(s string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	encs := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, e := range encs {
		if b, err := e.DecodeString(cleaned); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

func parseSS(body string) (Proxy, error) {
	// Split off `#name` fragment first.
	var name string
	if i := strings.LastIndex(body, "#"); i >= 0 {
		decoded, _ := url.QueryUnescape(body[i+1:])
		name = decoded
		body = body[:i]
	}
	// Drop `?plugin=...` query (plugin not supported here).
	if i := strings.Index(body, "?"); i >= 0 {
		body = body[:i]
	}

	var method, password, host string
	var port uint64

	if at := strings.Index(body, "@"); at >= 0 {
		// SIP002: ss://base64(method:password)@host:port
		userInfoBytes, err := decodeBase64Relaxed(body[:at])
		if err != nil {
			return nil, fmt.Errorf("ss userinfo b64: %w", err)
		}
		userInfo := string(userInfoBytes)
		sep := strings.Index(userInfo, ":")
		if sep < 0 {
			return nil, errors.New("ss userinfo missing ':'")
		}
		method, password = userInfo[:sep], userInfo[sep+1:]
		hostPort := body[at+1:]
		colon := strings.LastIndex(hostPort, ":")
		if colon < 0 {
			return nil, errors.New("ss host:port malformed")
		}
		host = hostPort[:colon]
		port, err = strconv.ParseUint(hostPort[colon+1:], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("ss port: %w", err)
		}
	} else {
		// Legacy: ss://base64(method:password@host:port)
		decoded, err := decodeBase64Relaxed(body)
		if err != nil {
			return nil, fmt.Errorf("ss legacy b64: %w", err)
		}
		s := string(decoded)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, errors.New("ss legacy missing '@'")
		}
		userInfo, hostPort := s[:at], s[at+1:]
		sep := strings.Index(userInfo, ":")
		if sep < 0 {
			return nil, errors.New("ss userinfo missing ':'")
		}
		method, password = userInfo[:sep], userInfo[sep+1:]
		colon := strings.LastIndex(hostPort, ":")
		if colon < 0 {
			return nil, errors.New("ss host:port malformed")
		}
		host = hostPort[:colon]
		port, err = strconv.ParseUint(hostPort[colon+1:], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("ss port: %w", err)
		}
	}

	if name == "" {
		name = fmt.Sprintf("%s:%d", host, port)
	}

	return Proxy{
		"name":     name,
		"type":     "ss",
		"server":   host,
		"port":     int(port),
		"cipher":   method,
		"password": password,
		"udp":      true,
		"tfo":      false,
	}, nil
}

func parseVmess(body string) (Proxy, error) {
	decoded, err := decodeBase64Relaxed(body)
	if err != nil {
		return nil, fmt.Errorf("vmess b64: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(decoded, &raw); err != nil {
		return nil, fmt.Errorf("vmess json: %w", err)
	}

	getStr := func(k string) string {
		switch v := raw[k].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		case json.Number:
			return v.String()
		default:
			return ""
		}
	}
	getU64 := func(k string) (uint64, bool) {
		switch v := raw[k].(type) {
		case float64:
			return uint64(v), true
		case string:
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				return n, true
			}
		}
		return 0, false
	}

	server := getStr("add")
	uuid := getStr("id")
	port, ok := getU64("port")
	if !ok {
		return nil, errors.New("vmess missing port")
	}
	if server == "" || uuid == "" {
		return nil, errors.New("vmess missing add/id")
	}
	aid, _ := getU64("aid")

	net := getStr("net")
	if net == "" {
		net = "tcp"
	}
	host := getStr("host")
	path := getStr("path")
	tls := getStr("tls")
	scy := getStr("scy")
	if scy == "" {
		scy = "auto"
	}
	sni := getStr("sni")
	name := getStr("ps")
	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	p := Proxy{
		"name":              name,
		"type":              "vmess",
		"server":            server,
		"port":              int(port),
		"uuid":              uuid,
		"alterId":           int(aid),
		"cipher":            scy,
		"udp":               true,
		"tls":               tls == "tls",
		"skip-cert-verify":  true,
		"tfo":               false,
	}
	if sni != "" {
		p["servername"] = sni
	}

	switch net {
	case "ws":
		p["network"] = "ws"
		ws := map[string]any{}
		if path != "" {
			ws["path"] = path
		}
		if host != "" {
			ws["headers"] = map[string]any{"Host": host}
		}
		if len(ws) > 0 {
			p["ws-opts"] = ws
		}
	case "grpc":
		p["network"] = "grpc"
		if path != "" {
			p["grpc-opts"] = map[string]any{"grpc-service-name": path}
		}
	case "h2":
		p["network"] = "h2"
		h2 := map[string]any{}
		if path != "" {
			h2["path"] = path
		}
		if host != "" {
			h2["host"] = []string{host}
		}
		if len(h2) > 0 {
			p["h2-opts"] = h2
		}
	}
	return p, nil
}

func uniquify(name string, used map[string]bool) string {
	if !used[name] {
		used[name] = true
		return name
	}
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s-%d", name, i)
		if !used[cand] {
			used[cand] = true
			return cand
		}
	}
}

func buildClashYAML(proxies []Proxy, opts ConvertOptions) string {
	groups := make([]map[string]any, 0, len(proxies)+1)

	// Per-node `G-<name>` select groups.
	for _, p := range proxies {
		name, _ := p["name"].(string)
		groups = append(groups, map[string]any{
			"name":    nodeGroupPrefix + name,
			"type":    "select",
			"proxies": []string{name, "DIRECT", "REJECT"},
		})
	}

	// Master PROXY select group.
	// First, find the index of the proxy whose name matches DefaultProxyMatch
	// (case-insensitive substring). That node's G- group goes first, so Clash
	// uses it as the default selection.
	defaultIdx := -1
	if opts.DefaultProxyMatch != "" {
		needle := strings.ToLower(opts.DefaultProxyMatch)
		for i, p := range proxies {
			if name, _ := p["name"].(string); strings.Contains(strings.ToLower(name), needle) {
				defaultIdx = i
				break
			}
		}
	}
	masterOptions := make([]string, 0, len(proxies)+2)
	if defaultIdx >= 0 {
		name, _ := proxies[defaultIdx]["name"].(string)
		masterOptions = append(masterOptions, nodeGroupPrefix+name)
	}
	for i, p := range proxies {
		if i == defaultIdx {
			continue
		}
		name, _ := p["name"].(string)
		masterOptions = append(masterOptions, nodeGroupPrefix+name)
	}
	masterOptions = append(masterOptions, "DIRECT", "REJECT")
	groups = append(groups, map[string]any{
		"name":    "PROXY",
		"type":    "select",
		"proxies": masterOptions,
	})

	// Marshal proxies + groups via a struct so field order is stable
	// (gopkg.in/yaml.v3 honours struct field declaration order).
	body := struct {
		Proxies     []Proxy          `yaml:"proxies"`
		ProxyGroups []map[string]any `yaml:"proxy-groups"`
	}{Proxies: proxies, ProxyGroups: groups}

	out, err := yaml.Marshal(body)
	if err != nil {
		out = []byte(fmt.Sprintf("# yaml marshal error: %v\n", err))
	}

	return "# Auto-generated by AutoConvJmsSub from a base64 ss/vmess subscription.\n" +
		"# Each node has its own `G-<name>` select group so per-domain rules can route to a single node.\n" +
		"# Default rules use Loyalsoldier rule-providers (https://github.com/Loyalsoldier/clash-rules).\n\n" +
		string(out) +
		buildRulesAndProvidersYAML(opts.RuleProvidersEnabled, opts.RuleProvidersBaseURL)
}
