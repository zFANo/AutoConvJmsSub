package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseSS_SIP002(t *testing.T) {
	// ss://YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388#HK-1
	body := "YWVzLTI1Ni1nY206cGFzc3dk@1.2.3.4:8388#HK-1"
	p, err := parseSS(body)
	if err != nil {
		t.Fatalf("parseSS: %v", err)
	}
	if got := p["name"]; got != "HK-1" {
		t.Errorf("name = %v, want HK-1", got)
	}
	if got := p["server"]; got != "1.2.3.4" {
		t.Errorf("server = %v, want 1.2.3.4", got)
	}
	if got := p["port"]; got != 8388 {
		t.Errorf("port = %v, want 8388", got)
	}
	if got := p["cipher"]; got != "aes-256-gcm" {
		t.Errorf("cipher = %v, want aes-256-gcm", got)
	}
	if got := p["password"]; got != "passwd" {
		t.Errorf("password = %v, want passwd", got)
	}
}

func TestParseVmess_WS_TLS(t *testing.T) {
	jsonBody := `{"v":"2","ps":"JP-1","add":"a.example.com","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0","net":"ws","type":"none","host":"a.example.com","path":"/ray","tls":"tls"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(jsonBody))
	p, err := parseVmess(encoded)
	if err != nil {
		t.Fatalf("parseVmess: %v", err)
	}
	if got := p["name"]; got != "JP-1" {
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
