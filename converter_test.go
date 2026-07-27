package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// strField unwraps a Proxy field that may be a plain string or a forceStr-
// wrapped *yaml.Node, returning the underlying string.
func strField(p Proxy, key string) string {
	switch v := p[key].(type) {
	case string:
		return v
	case *yaml.Node:
		return v.Value
	}
	return ""
}

// nodeStr unwraps a nested map value that may be a plain string or a
// forceStr-wrapped *yaml.Node.
func nodeStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case *yaml.Node:
		return t.Value
	}
	return ""
}

func TestParseSS_SIP002(t *testing.T) {
	// ss://YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388#HK-1
	body := "YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388#HK-1"
	p, err := parseSS(body)
	if err != nil {
		t.Fatalf("parseSS: %v", err)
	}
	if got := strField(p, "name"); got != "HK-1" {
		t.Errorf("name = %v, want HK-1", got)
	}
	if got := strField(p, "server"); got != "1.2.3.4" {
		t.Errorf("server = %v, want 1.2.3.4", got)
	}
	if got := p["port"]; got != 8388 {
		t.Errorf("port = %v, want 8388", got)
	}
	if got := strField(p, "cipher"); got != "aes-256-gcm" {
		t.Errorf("cipher = %v, want aes-256-gcm", got)
	}
	if got := strField(p, "password"); got != "passwd" {
		t.Errorf("password = %v, want passwd", got)
	}
}

// --- UDP is opt-in: only emitted when the subscription actually says so ---

func TestParseSS_OmitsUDPWhenSubscriptionSilent(t *testing.T) {
	p, err := parseSS("YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388#HK-1")
	if err != nil {
		t.Fatalf("parseSS: %v", err)
	}
	if v, ok := p["udp"]; ok {
		t.Errorf("udp must be absent when the link does not declare it, got %v", v)
	}
}

func TestParseSS_HonorsUDPParam(t *testing.T) {
	p, err := parseSS("YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388?udp=true#HK-1")
	if err != nil {
		t.Fatalf("parseSS: %v", err)
	}
	if got := p["udp"]; got != true {
		t.Errorf("udp = %v, want true", got)
	}
	// The query must not leak into the connection details.
	if got := strField(p, "server"); got != "1.2.3.4" {
		t.Errorf("server = %q, want 1.2.3.4", got)
	}
	if got := p["port"]; got != 8388 {
		t.Errorf("port = %v, want 8388", got)
	}
}

func TestParseSS_HonorsUDPDisabled(t *testing.T) {
	p, err := parseSS("YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388?udp=0#HK-1")
	if err != nil {
		t.Fatalf("parseSS: %v", err)
	}
	if got, ok := p["udp"]; !ok || got != false {
		t.Errorf("udp = %v (present=%v), want explicit false", got, ok)
	}
}

func TestParseVmess_OmitsUDPWhenSubscriptionSilent(t *testing.T) {
	jsonBody := `{"ps":"JP-1","add":"a.example.com","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":0,"net":"tcp","type":"none","tls":"none"}`
	p, err := parseVmess(base64.StdEncoding.EncodeToString([]byte(jsonBody)))
	if err != nil {
		t.Fatalf("parseVmess: %v", err)
	}
	if v, ok := p["udp"]; ok {
		t.Errorf("udp must be absent when the JSON omits it, got %v", v)
	}
}

func TestParseVmess_HonorsUDPField(t *testing.T) {
	jsonBody := `{"ps":"JP-1","add":"a.example.com","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":0,"net":"tcp","udp":true}`
	p, err := parseVmess(base64.StdEncoding.EncodeToString([]byte(jsonBody)))
	if err != nil {
		t.Fatalf("parseVmess: %v", err)
	}
	if got := p["udp"]; got != true {
		t.Errorf("udp = %v, want true", got)
	}
}

func TestParseVless_OmitsUDPWhenSubscriptionSilent(t *testing.T) {
	p, err := parseVless("550e8400-e29b-41d4-a716-446655440000@1.2.3.4:443?type=tcp#X")
	if err != nil {
		t.Fatalf("parseVless: %v", err)
	}
	if v, ok := p["udp"]; ok {
		t.Errorf("udp must be absent when the link does not declare it, got %v", v)
	}
}

func TestParseVless_HonorsUDPParam(t *testing.T) {
	p, err := parseVless("550e8400-e29b-41d4-a716-446655440000@1.2.3.4:443?type=tcp&udp=true#X")
	if err != nil {
		t.Fatalf("parseVless: %v", err)
	}
	if got := p["udp"]; got != true {
		t.Errorf("udp = %v, want true", got)
	}
}

func TestParseVmess_WS_TLS(t *testing.T) {
	jsonBody := `{"v":"2","ps":"JP-1","add":"a.example.com","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0","net":"ws","type":"none","host":"a.example.com","path":"/ray","tls":"tls"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(jsonBody))
	p, err := parseVmess(encoded)
	if err != nil {
		t.Fatalf("parseVmess: %v", err)
	}
	if got := strField(p, "name"); got != "JP-1" {
		t.Errorf("name = %v, want JP-1", got)
	}
	if got := p["port"]; got != 443 {
		t.Errorf("port = %v, want 443", got)
	}
	if got := p["network"]; got != "ws" {
		t.Errorf("network = %v, want ws", got)
	}
	if got := p["tls"]; got != true {
		t.Errorf("tls = %v, want true", got)
	}
}

func TestParseVless_RealityVision(t *testing.T) {
	// Shape emitted by JustMySocks for its c17sN nodes: REALITY + XTLS Vision
	// over plain TCP. `sni` is the borrowed handshake domain, not the server.
	body := "550e8400-e29b-41d4-a716-446655440000@1.2.3.4:443" +
		"?encryption=none&flow=xtls-rprx-vision&security=reality" +
		"&sni=portal.example.com&fp=chrome&pbk=PUBKEY123&sid=abcd1234&type=tcp" +
		"#JMS-1%40c17s3.example.com%3A443"
	p, err := parseVless(body)
	if err != nil {
		t.Fatalf("parseVless: %v", err)
	}
	if got := strField(p, "name"); got != "JMS-1@c17s3.example.com:443" {
		t.Errorf("name = %q, want JMS-1@c17s3.example.com:443", got)
	}
	if got := strField(p, "server"); got != "1.2.3.4" {
		t.Errorf("server = %q, want 1.2.3.4", got)
	}
	if got := p["port"]; got != 443 {
		t.Errorf("port = %v, want 443", got)
	}
	if got := p["type"]; got != "vless" {
		t.Errorf("type = %v, want vless", got)
	}
	if got := strField(p, "uuid"); got != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("uuid = %q, want 550e8400-...", got)
	}
	if got := p["tls"]; got != true {
		t.Errorf("tls = %v, want true (reality implies tls)", got)
	}
	if got := strField(p, "flow"); got != "xtls-rprx-vision" {
		t.Errorf("flow = %q, want xtls-rprx-vision", got)
	}
	if got := strField(p, "servername"); got != "portal.example.com" {
		t.Errorf("servername = %q, want portal.example.com", got)
	}
	if got := strField(p, "client-fingerprint"); got != "chrome" {
		t.Errorf("client-fingerprint = %q, want chrome", got)
	}
	if got := p["network"]; got != "tcp" {
		t.Errorf("network = %v, want tcp", got)
	}
	reality, ok := p["reality-opts"].(map[string]any)
	if !ok {
		t.Fatalf("reality-opts missing or wrong type: %#v", p["reality-opts"])
	}
	if got := nodeStr(reality["public-key"]); got != "PUBKEY123" {
		t.Errorf("reality-opts.public-key = %q, want PUBKEY123", got)
	}
	if got := nodeStr(reality["short-id"]); got != "abcd1234" {
		t.Errorf("reality-opts.short-id = %q, want abcd1234", got)
	}
	// REALITY does its own certificate pinning — skip-cert-verify must not be
	// set, and no `password`/`cipher` field belongs on a vless proxy.
	if _, ok := p["skip-cert-verify"]; ok {
		t.Errorf("skip-cert-verify must be absent for reality, got %v", p["skip-cert-verify"])
	}
	if _, ok := p["cipher"]; ok {
		t.Errorf("vless must not carry a cipher field, got %v", p["cipher"])
	}
}

func TestParseVless_WS_TLS(t *testing.T) {
	body := "550e8400-e29b-41d4-a716-446655440000@a.example.com:443" +
		"?encryption=none&security=tls&sni=a.example.com&type=ws" +
		"&path=%2Fray&host=a.example.com#WS-1"
	p, err := parseVless(body)
	if err != nil {
		t.Fatalf("parseVless: %v", err)
	}
	if got := p["network"]; got != "ws" {
		t.Errorf("network = %v, want ws", got)
	}
	if got := p["tls"]; got != true {
		t.Errorf("tls = %v, want true", got)
	}
	if _, ok := p["flow"]; ok {
		t.Errorf("flow must be absent when the link omits it, got %v", p["flow"])
	}
	if _, ok := p["reality-opts"]; ok {
		t.Errorf("reality-opts must be absent for plain tls, got %v", p["reality-opts"])
	}
	ws, ok := p["ws-opts"].(map[string]any)
	if !ok {
		t.Fatalf("ws-opts missing or wrong type: %#v", p["ws-opts"])
	}
	if got := ws["path"]; got != "/ray" {
		t.Errorf("ws-opts.path = %v, want /ray", got)
	}
	headers, ok := ws["headers"].(map[string]any)
	if !ok {
		t.Fatalf("ws-opts.headers missing: %#v", ws["headers"])
	}
	if got := headers["Host"]; got != "a.example.com" {
		t.Errorf("ws-opts.headers.Host = %v, want a.example.com", got)
	}
}

func TestParseVless_GRPC_NoTLS(t *testing.T) {
	body := "550e8400-e29b-41d4-a716-446655440000@a.example.com:80" +
		"?encryption=none&type=grpc&serviceName=mygrpc#GRPC-1"
	p, err := parseVless(body)
	if err != nil {
		t.Fatalf("parseVless: %v", err)
	}
	if got := p["network"]; got != "grpc" {
		t.Errorf("network = %v, want grpc", got)
	}
	if got := p["tls"]; got != false {
		t.Errorf("tls = %v, want false (no security param)", got)
	}
	grpc, ok := p["grpc-opts"].(map[string]any)
	if !ok {
		t.Fatalf("grpc-opts missing: %#v", p["grpc-opts"])
	}
	if got := grpc["grpc-service-name"]; got != "mygrpc" {
		t.Errorf("grpc-opts.grpc-service-name = %v, want mygrpc", got)
	}
}

func TestParseVless_RejectsMissingUUID(t *testing.T) {
	if _, err := parseVless("@1.2.3.4:443?type=tcp#X"); err == nil {
		t.Fatal("expected an error for a link with no uuid")
	}
}

func TestEndToEnd_VlessNodeSurvivesConversion(t *testing.T) {
	// Regression: vless links used to be silently dropped by the parser's
	// default branch, so JMS c17s3/c17s801 vanished from the generated config.
	vlessLink := "vless://550e8400-e29b-41d4-a716-446655440000@1.2.3.4:443" +
		"?encryption=none&flow=xtls-rprx-vision&security=reality" +
		"&sni=portal.example.com&fp=chrome&pbk=PUBKEY123&sid=abcd1234&type=tcp" +
		"#JMS-1%40c17s3.example.com%3A443"
	ssLink := "ss://YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388#HK-1"
	sub := base64.StdEncoding.EncodeToString([]byte(ssLink + "\n" + vlessLink))

	out, err := TryParseSubscription(sub)
	if err != nil {
		t.Fatalf("TryParseSubscription: %v", err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("generated yaml is invalid: %v\n%s", err, out)
	}
	proxies, ok := parsed["proxies"].([]any)
	if !ok || len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %#v", parsed["proxies"])
	}
	if !strings.Contains(out, "G-JMS-1@c17s3.example.com:443") {
		t.Errorf("vless node did not get its own G- group:\n%s", out)
	}
}

func TestEndToEnd_GeneratesGroupsAndRules(t *testing.T) {
	jsonBody := `{"v":"2","ps":"JP-1","add":"a.example.com","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0","net":"ws","type":"none","host":"a.example.com","path":"/ray","tls":"tls"}`
	vmessLink := "vmess://" + base64.StdEncoding.EncodeToString([]byte(jsonBody))
	ssLink := "ss://YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388#HK-1"
	body := ssLink + "\n" + vmessLink
	sub := base64.StdEncoding.EncodeToString([]byte(body))

	out, err := TryParseSubscription(sub)
	if err != nil {
		t.Fatalf("TryParseSubscription: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("generated yaml is invalid: %v\n%s", err, out)
	}
	for _, key := range []string{"proxies", "proxy-groups", "rule-providers", "rules"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}

	groups, ok := parsed["proxy-groups"].([]any)
	if !ok {
		t.Fatalf("proxy-groups is not a sequence: %T", parsed["proxy-groups"])
	}
	// 2 nodes -> 2 G- groups + 1 master PROXY group
	if len(groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(groups))
	}
	names := []string{}
	for _, g := range groups {
		if m, ok := g.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				names = append(names, n)
			}
		}
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"G-HK-1", "G-JP-1", "PROXY"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing group %q in [%s]", want, joined)
		}
	}
}

func TestEndToEnd_GeneratesProjectClashBehavior(t *testing.T) {
	jsonBody := `{"v":"2","ps":"JP-1","add":"a.example.com","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0","net":"ws","type":"none","host":"a.example.com","path":"/ray","tls":"tls"}`
	vmessLink := "vmess://" + base64.StdEncoding.EncodeToString([]byte(jsonBody))
	sub := base64.StdEncoding.EncodeToString([]byte(vmessLink))
	enabled := true
	ipv6 := true

	out, err := TryParseSubscriptionWithOptions(sub, ConvertOptions{
		RuleProvidersEnabled: true,
		RuleProvidersBaseURL: defaultLoyalsoldierBaseURL,
		DNS: ClashDNSConfig{
			Enable:                &enabled,
			Listen:                "0.0.0.0:1053",
			IPv6:                  &ipv6,
			EnhancedMode:          "fake-ip",
			FakeIPRange:           "198.18.0.1/16",
			FakeIPFilterMode:      "blacklist",
			FakeIPFilter:          []string{"private.example", "+.private.example", "+.tailnet.example"},
			DefaultNameserver:     []string{"223.6.6.6", "8.8.8.8"},
			Nameserver:            []string{"https://doh.pub/dns-query"},
			ProxyServerNameserver: []string{"https://doh.pub/dns-query"},
		},
		Tun: ClashTunConfig{
			RouteExcludeAddress: []string{"100.64.0.0/10", "203.0.113.10/32"},
		},
		PrependRules: []string{
			"DOMAIN-SUFFIX,private.example,DIRECT",
			"DOMAIN-SUFFIX,external.example,PROXY",
		},
	})
	if err != nil {
		t.Fatalf("TryParseSubscriptionWithOptions: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("generated yaml is invalid: %v\n%s", err, out)
	}

	dns, ok := parsed["dns"].(map[string]any)
	if !ok {
		t.Fatalf("missing dns block: %#v", parsed["dns"])
	}
	if got := strings.Join(anyStrings(dns["nameserver"]), ","); got != "https://doh.pub/dns-query" {
		t.Fatalf("dns.nameserver = %q, want https://doh.pub/dns-query", got)
	}
	if got := strings.Join(anyStrings(dns["fake-ip-filter"]), ","); !strings.Contains(got, "private.example") || !strings.Contains(got, "+.tailnet.example") {
		t.Fatalf("dns.fake-ip-filter missing expected entries: %q", got)
	}

	tun, ok := parsed["tun"].(map[string]any)
	if !ok {
		t.Fatalf("missing tun block: %#v", parsed["tun"])
	}
	if got := strings.Join(anyStrings(tun["route-exclude-address"]), ","); !strings.Contains(got, "203.0.113.10/32") {
		t.Fatalf("tun.route-exclude-address missing 203.0.113.10/32: %q", got)
	}

	rules := anyStrings(parsed["rules"])
	projectRuleIdx := indexOf(rules, "DOMAIN-SUFFIX,private.example,DIRECT")
	providerRuleIdx := indexOf(rules, "RULE-SET,proxy,PROXY")
	if projectRuleIdx < 0 {
		t.Fatalf("missing project rule in rules: %#v", rules)
	}
	if providerRuleIdx < 0 {
		t.Fatalf("missing provider proxy rule in rules: %#v", rules)
	}
	if projectRuleIdx > providerRuleIdx {
		t.Fatalf("project rules should be emitted before provider rules")
	}
	for _, forbidden := range []string{
		"IP-CIDR,198.51.100.77/32,DIRECT",
		"IP-CIDR,203.0.113.10/32,DIRECT",
	} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("generated yaml restored forbidden rule %q", forbidden)
		}
	}
}

func TestUniquify_DedupesRepeats(t *testing.T) {
	used := map[string]bool{}
	if got := uniquify("foo", used); got != "foo" {
		t.Errorf("first = %q, want foo", got)
	}
	if got := uniquify("foo", used); got != "foo-2" {
		t.Errorf("second = %q, want foo-2", got)
	}
	if got := uniquify("foo", used); got != "foo-3" {
		t.Errorf("third = %q, want foo-3", got)
	}
}

func TestDecodeBase64_Relaxed(t *testing.T) {
	// Plain Std with whitespace
	in := "YWVz" + "\n" + "LTI1Ni1nY206cGFzc3dk"
	out, err := decodeBase64Relaxed(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(out) != "aes-256-gcm:passwd" {
		t.Errorf("got %q", string(out))
	}
}

func anyStrings(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func indexOf(items []string, want string) int {
	for i, item := range items {
		if item == want {
			return i
		}
	}
	return -1
}
