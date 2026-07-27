package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// upstreamClashProfile mirrors the shape JustMySocks returns for
// `getsub.php?...&format=clash`: client-level settings we must drop, a
// proxies list that is authoritative (including its UDP declarations), and
// vendor proxy-groups / rules we replace wholesale.
const upstreamClashProfile = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false

proxies:
  - name: "JMS-1@node-a:5831"
    type: ss
    server: "1.2.3.4"
    port: 5831
    cipher: "aes-256-gcm"
    password: "secret"
    udp: true
  - name: "JMS-1@node-b:443"
    type: vless
    server: "5.6.7.8"
    port: 443
    uuid: "550e8400-e29b-41d4-a716-446655440000"
    flow: "xtls-rprx-vision"
    encryption: ""
    network: "tcp"
    tls: true
    servername: "portal.example.com"
    client-fingerprint: "chrome"
    reality-opts:
      public-key: "PUBKEY123"
      short-id: "abcd1234"

proxy-groups:
  - name: "JMS"
    type: select
    proxies:
      - "JMS Auto"
      - "JMS-1@node-a:5831"
      - "JMS-1@node-b:443"
      - DIRECT
  - name: "JMS Auto"
    type: url-test
    proxies:
      - "JMS-1@node-a:5831"
      - "JMS-1@node-b:443"
    url: "https://www.gstatic.com/generate_204"
    interval: 300

rules:
  - "MATCH,JMS"
`

func convertUpstream(t *testing.T, opts ConvertOptions) map[string]any {
	t.Helper()
	out, err := ConvertClashProfile(upstreamClashProfile, opts)
	if err != nil {
		t.Fatalf("ConvertClashProfile: %v", err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("generated yaml is invalid: %v\n%s", err, out)
	}
	return parsed
}

func TestClashProfile_PassesProxiesThroughVerbatim(t *testing.T) {
	parsed := convertUpstream(t, ConvertOptions{})
	proxies, ok := parsed["proxies"].([]any)
	if !ok || len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %#v", parsed["proxies"])
	}

	ss, _ := proxies[0].(map[string]any)
	// UDP must come from upstream, not from us: JMS declares it on ss only.
	if got, ok := ss["udp"]; !ok || got != true {
		t.Errorf("ss udp = %v (present=%v), want upstream's true", got, ok)
	}
	if got := ss["password"]; got != "secret" {
		t.Errorf("ss password = %v, want secret", got)
	}

	vless, _ := proxies[1].(map[string]any)
	if _, ok := vless["udp"]; ok {
		t.Errorf("vless must not gain a udp field upstream never declared, got %v", vless["udp"])
	}
	if got := vless["flow"]; got != "xtls-rprx-vision" {
		t.Errorf("vless flow = %v, want xtls-rprx-vision", got)
	}
	reality, ok := vless["reality-opts"].(map[string]any)
	if !ok {
		t.Fatalf("reality-opts lost in passthrough: %#v", vless["reality-opts"])
	}
	if got := reality["public-key"]; got != "PUBKEY123" {
		t.Errorf("reality-opts.public-key = %v, want PUBKEY123", got)
	}
}

func TestClashProfile_EmitsSingleProxyGroupNamedPROXY(t *testing.T) {
	parsed := convertUpstream(t, ConvertOptions{})
	groups, ok := parsed["proxy-groups"].([]any)
	if !ok {
		t.Fatalf("proxy-groups missing: %#v", parsed["proxy-groups"])
	}
	if len(groups) != 1 {
		t.Fatalf("expected exactly 1 group, got %d: %#v", len(groups), groups)
	}
	g, _ := groups[0].(map[string]any)
	if got := g["name"]; got != "PROXY" {
		t.Errorf("group name = %v, want PROXY (prepend-rules target it)", got)
	}
	if got := g["type"]; got != "select" {
		t.Errorf("group type = %v, want select", got)
	}
	members := anyStrings(g["proxies"])
	// DIRECT/REJECT are built-in policies; listing them here is what makes
	// the group manually switchable to bypass-all / block-all in the client.
	want := []string{"JMS-1@node-a:5831", "JMS-1@node-b:443", "DIRECT", "REJECT"}
	if strings.Join(members, "|") != strings.Join(want, "|") {
		t.Errorf("group members = %v, want %v", members, want)
	}
}

func TestClashProfile_DropsUpstreamGroupsAndClientSettings(t *testing.T) {
	parsed := convertUpstream(t, ConvertOptions{})
	for _, key := range []string{"mixed-port", "allow-lan", "mode", "log-level", "ipv6"} {
		if v, ok := parsed[key]; ok {
			t.Errorf("client-level key %q must be stripped, got %v", key, v)
		}
	}
	// The vendor's own groups must not survive under any name.
	out, err := ConvertClashProfile(upstreamClashProfile, ConvertOptions{})
	if err != nil {
		t.Fatalf("ConvertClashProfile: %v", err)
	}
	if strings.Contains(out, "JMS Auto") {
		t.Errorf("upstream group \"JMS Auto\" leaked into output:\n%s", out)
	}
	if strings.Contains(out, "MATCH,JMS\n") {
		t.Errorf("upstream rule \"MATCH,JMS\" leaked into output:\n%s", out)
	}
}

func TestClashProfile_InjectsProjectConfig(t *testing.T) {
	enabled := true
	parsed := convertUpstream(t, ConvertOptions{
		RuleProvidersEnabled: true,
		RuleProvidersBaseURL: defaultLoyalsoldierBaseURL,
		DNS: ClashDNSConfig{
			Enable:       &enabled,
			EnhancedMode: "fake-ip",
			Nameserver:   []string{"https://doh.pub/dns-query"},
		},
		Tun: ClashTunConfig{
			RouteExcludeAddress: []string{"100.64.0.0/10"},
		},
		PrependRules: []string{"DOMAIN-SUFFIX,unity.com,PROXY"},
	})

	dns, ok := parsed["dns"].(map[string]any)
	if !ok {
		t.Fatalf("dns block missing: %#v", parsed["dns"])
	}
	if got := dns["enhanced-mode"]; got != "fake-ip" {
		t.Errorf("dns.enhanced-mode = %v, want fake-ip", got)
	}
	tun, ok := parsed["tun"].(map[string]any)
	if !ok {
		t.Fatalf("tun block missing: %#v", parsed["tun"])
	}
	if got := strings.Join(anyStrings(tun["route-exclude-address"]), ","); got != "100.64.0.0/10" {
		t.Errorf("tun.route-exclude-address = %v", got)
	}
	if _, ok := parsed["rule-providers"]; !ok {
		t.Error("rule-providers block missing")
	}

	rules := anyStrings(parsed["rules"])
	loopbackIdx := indexOf(rules, "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
	projectIdx := indexOf(rules, "DOMAIN-SUFFIX,unity.com,PROXY")
	providerIdx := indexOf(rules, "RULE-SET,proxy,PROXY")
	matchIdx := indexOf(rules, "MATCH,PROXY")
	if loopbackIdx != 0 {
		t.Errorf("loopback rule must come first, got index %d in %v", loopbackIdx, rules)
	}
	if projectIdx < 0 || providerIdx < 0 || matchIdx < 0 {
		t.Fatalf("missing expected rules in %v", rules)
	}
	if !(loopbackIdx < projectIdx && projectIdx < providerIdx && providerIdx < matchIdx) {
		t.Errorf("rule order wrong: loopback=%d project=%d provider=%d match=%d",
			loopbackIdx, projectIdx, providerIdx, matchIdx)
	}
}

func TestClashProfile_DefaultProxyMatchPromotesNode(t *testing.T) {
	parsed := convertUpstream(t, ConvertOptions{DefaultProxyMatch: "node-b"})
	groups, _ := parsed["proxy-groups"].([]any)
	g, _ := groups[0].(map[string]any)
	members := anyStrings(g["proxies"])
	if len(members) == 0 || members[0] != "JMS-1@node-b:443" {
		t.Errorf("matched node must be promoted to first slot, got %v", members)
	}
	if len(members) != 4 {
		t.Errorf("promotion must not duplicate or drop members, got %v", members)
	}
}

func TestClashProfile_RejectsProfileWithoutProxies(t *testing.T) {
	if _, err := ConvertClashProfile("mixed-port: 7890\nproxies: []\n", ConvertOptions{}); err == nil {
		t.Fatal("expected an error for a profile with no proxies")
	}
}

// --- entrypoint dispatch: YAML profile vs legacy base64 ---

func TestTryParseSubscription_DispatchesClashYAML(t *testing.T) {
	out, err := TryParseSubscriptionWithOptions(upstreamClashProfile, ConvertOptions{})
	if err != nil {
		t.Fatalf("TryParseSubscriptionWithOptions: %v", err)
	}
	if !strings.Contains(out, "name: PROXY") {
		t.Errorf("a raw clash profile should be converted, got:\n%s", out)
	}
}

func TestTryParseSubscription_StillHandlesBase64(t *testing.T) {
	ssLink := "ss://YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388#HK-1"
	sub := base64.StdEncoding.EncodeToString([]byte(ssLink))
	out, err := TryParseSubscriptionWithOptions(sub, ConvertOptions{})
	if err != nil {
		t.Fatalf("legacy base64 path broke: %v", err)
	}
	if !strings.Contains(out, "HK-1") {
		t.Errorf("legacy base64 path lost the node:\n%s", out)
	}
}
