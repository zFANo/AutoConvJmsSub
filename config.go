package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk configuration. One subscription URL per name; the
// `/sub` endpoint returns the `default` entry, `/sub/<name>` returns the
// named entry.
type Config struct {
	Subscriptions map[string]string `yaml:"subscriptions"`
	Server        ServerConfig      `yaml:"server"`
	Defaults      DefaultsConfig    `yaml:"defaults"`
}

type ServerConfig struct {
	Addr              string        `yaml:"addr"`
	UpstreamTimeout   time.Duration `yaml:"upstream_timeout"`
	UpstreamUserAgent string        `yaml:"upstream_user_agent"`
}

type DefaultsConfig struct {
	// DefaultProxyMatch: case-insensitive substring matched against proxy
	// names. The first proxy that matches has its G-<name> select group
	// promoted to the top of the master PROXY group, becoming the default
	// selection in Clash. Empty = no preference (first-defined wins).
	DefaultProxyMatch string               `yaml:"default_proxy_match"`
	RuleProviders    RuleProvidersConfig `yaml:"rule_providers"`
}

type RuleProvidersConfig struct {
	// Enabled: when false, the generated YAML omits rule-providers entirely
	// and falls back to a minimal hard-coded rule chain (loopback DIRECT +
	// GEOIP CN DIRECT + MATCH PROXY). Useful when the chosen mirror is
	// unreachable. Pointer so we can distinguish "absent" (default true)
	// from "explicitly false".
	Enabled *bool `yaml:"enabled"`
	// BaseURL: where to download Loyalsoldier rule files from. Each rule
	// (reject/proxy/direct/private/gfw/telegramcidr/cncidr) is appended as
	// `<base>/<name>.txt`. Defaults to jsDelivr CDN; switch to a CN-friendly
	// mirror (see config.yaml template) if jsDelivr is blocked.
	BaseURL string `yaml:"base_url"`
}

const defaultRuleProvidersBaseURL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release"

const configTemplate = `# AutoConvJmsSub configuration
#
# Each entry under "subscriptions" maps a name to an upstream subscription URL.
#   - GET /sub          returns the entry named "default"
#   - GET /sub/<name>   returns the named entry
#
# Edit the URL below to your real JustMySocks subscription link, then restart.
# IMPORTANT: this file contains credentials — do not share or commit it.
subscriptions:
  default: https://jmssub.net/members/getsub.php?service=YOUR_SERVICE_ID&id=YOUR_UUID
  # backup: https://jmssub.net/members/getsub.php?service=ANOTHER_ID&id=ANOTHER_UUID

server:
  # Keep 127.0.0.1 — binding to 0.0.0.0 exposes your subscription contents
  # (passwords, UUIDs) to anyone who can reach the port.
  addr: 127.0.0.1:25500
  upstream_timeout: 30s
  upstream_user_agent: ClashforWindows/0.20.39

defaults:
  # Case-insensitive substring of a proxy name. The matched node's G-<name>
  # group is promoted to the first slot of the master PROXY group, so it
  # becomes the default selection in Clash. Leave empty to keep
  # subscription-defined order.
  default_proxy_match: ""

  # Loyalsoldier rule-providers. Set enabled: false to skip them entirely
  # and fall back to a minimal rule chain. base_url is appended with
  # /<name>.txt to fetch each rule list.
  rule_providers:
    enabled: true
    base_url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release
    # CN-friendly mirrors (try if jsDelivr is unreachable):
    #   https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release
    #   https://gcore.jsdelivr.net/gh/Loyalsoldier/clash-rules@release
    #   https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release
    #   https://ghfast.top/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release
    #   https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release  (sometimes blocked in CN)
`

// LoadConfig reads the config file at `path`. If `path` is empty, the loader
// looks for `config.yaml` first in the current directory and then next to
// the binary. When no config is found, an example file is written and the
// caller is asked to edit it.
func LoadConfig(path string) (*Config, string, error) {
	resolved, err := resolveConfigPath(path)
	if err != nil {
		// No config found — write a template and tell the user.
		written, werr := writeTemplateConfig()
		if werr != nil {
			return nil, "", fmt.Errorf("no config found and could not write template: %w", werr)
		}
		return nil, written, fmt.Errorf("config not found; wrote a template at %s — edit it and re-run", written)
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, resolved, fmt.Errorf("read config %s: %w", resolved, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, resolved, fmt.Errorf("parse config %s: %w", resolved, err)
	}

	// Defaults for missing fields.
	if cfg.Server.Addr == "" {
		cfg.Server.Addr = "127.0.0.1:25500"
	}
	if cfg.Server.UpstreamTimeout == 0 {
		cfg.Server.UpstreamTimeout = 30 * time.Second
	}
	if cfg.Server.UpstreamUserAgent == "" {
		cfg.Server.UpstreamUserAgent = "ClashforWindows/0.20.39"
	}
	if len(cfg.Subscriptions) == 0 {
		return &cfg, resolved, fmt.Errorf("config %s: `subscriptions` is empty — add at least one entry", resolved)
	}
	// Default rule-providers to enabled if user did not explicitly set it.
	if cfg.Defaults.RuleProviders.Enabled == nil {
		t := true
		cfg.Defaults.RuleProviders.Enabled = &t
	}
	if cfg.Defaults.RuleProviders.BaseURL == "" {
		cfg.Defaults.RuleProviders.BaseURL = defaultRuleProvidersBaseURL
	}

	return &cfg, resolved, nil
}

func resolveConfigPath(flagPath string) (string, error) {
	if flagPath != "" {
		if _, err := os.Stat(flagPath); err != nil {
			return "", err
		}
		abs, _ := filepath.Abs(flagPath)
		return abs, nil
	}
	if _, err := os.Stat("config.yaml"); err == nil {
		abs, _ := filepath.Abs("config.yaml")
		return abs, nil
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "config.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}

// writeTemplateConfig drops a starter config.yaml in the current working
// directory and returns the absolute path it wrote to.
func writeTemplateConfig() (string, error) {
	path := "config.yaml"
	abs, _ := filepath.Abs(path)
	if _, err := os.Stat(path); err == nil {
		// Don't overwrite an existing file.
		return abs, nil
	}
	if err := os.WriteFile(path, []byte(configTemplate), 0o600); err != nil {
		return abs, err
	}
	return abs, nil
}
