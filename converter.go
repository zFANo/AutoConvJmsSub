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

const rulesAndProvidersYAML = `
rule-providers:
  reject:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt
    path: ./ruleset/reject.yaml
    interval: 86400
  proxy:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt
    path: ./ruleset/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt
    path: ./ruleset/direct.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt
    path: ./ruleset/private.yaml
    interval: 86400
  gfw:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt
    path: ./ruleset/gfw.yaml
    interval: 86400
  telegramcidr:
    type: http
    behavior: ipcidr
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt
    path: ./ruleset/telegramcidr.yaml
    interval: 86400
  cncidr:
    type: http
    behavior: ipcidr
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt
    path: ./ruleset/cncidr.yaml
    interval: 86400

rules:
  # Loopback / link-local first: when clash-verge-rev refreshes its remote
  # profile through Clash itself, requests to 127.0.0.1:25500 (AutoConvJmsSub)
  # must stay local. Without these, traffic to the local converter could be
  # captured by other rules and tunnelled through a proxy node — wrong both
  # for performance and safety.
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - IP-CIDR6,::1/128,DIRECT,no-resolve
  - IP-CIDR6,fe80::/10,DIRECT,no-resolve
  - DOMAIN-SUFFIX,localhost,DIRECT
  # Standard Loyalsoldier rule chain
  - RULE-SET,private,DIRECT
  - RULE-SET,reject,REJECT
  - RULE-SET,direct,DIRECT
  - RULE-SET,cncidr,DIRECT
  - RULE-SET,proxy,PROXY
  - RULE-SET,gfw,PROXY
  - RULE-SET,telegramcidr,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
`

// Proxy is one Clash proxy entry.
type Proxy map[string]any

// TryParseSubscription decodes a base64 subscription body and returns a
// generated Clash YAML. Returns an error if the body is not valid base64
// or contains no recognizable ss:// / vmess:// links.
func TryParseSubscription(raw string) (string, error) {
	return TryParseSubscriptionWithDefault(raw, "")
}

// TryParseSubscriptionWithDefault is like TryParseSubscription but lets the
// caller pin a default proxy via case-insensitive substring match. The first
// proxy whose name contains `defaultProxyMatch` (if non-empty) gets its
// G-<name> select group promoted to the top of the master PROXY group, so
// Clash starts with that node selected.
func TryParseSubscriptionWithDefault(raw, defaultProxyMatch string) (string, error) {
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

	return buildClashYAML(proxies, defaultProxyMatch), nil
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
		"name":    name,
		"type":    "vmess",
		"server":  server,
		"port":    int(port),
		"uuid":    uuid,
		"alterId": int(aid),
		"cipher":  scy,
		"udp":     true,
		"tls":     tls == "tls",
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

func buildClashYAML(proxies []Proxy, defaultProxyMatch string) string {
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
	// First, find the index of the proxy whose name matches defaultProxyMatch
	// (case-insensitive substring). That node's G- group goes first, so Clash
	// uses it as the default selection.
	defaultIdx := -1
	if defaultProxyMatch != "" {
		needle := strings.ToLower(defaultProxyMatch)
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
		string(out) + rulesAndProvidersYAML
}
