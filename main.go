// AutoConvJmsSub: a tiny local HTTP service that converts JustMySocks-style
// base64 ss/vmess subscriptions into Clash YAML.
//
// Subscription URLs are read from config.yaml (created automatically on first
// run). Then the service exposes a fixed local URL per subscription:
//
//   GET /sub          → returns YAML for the entry named "default"
//   GET /sub/<name>   → returns YAML for the named entry
//
// Drop the URL into clash-verge-rev as a remote profile. Credentials never
// leave config.yaml.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", "", "path to config.yaml (default: ./config.yaml or next to binary)")
	flag.Parse()

	cfg, resolved, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	log.Printf("loaded config: %s", resolved)

	mux := http.NewServeMux()
	handler := subHandler(cfg)
	mux.HandleFunc("/sub", handler)
	mux.HandleFunc("/sub/", handler)
	mux.HandleFunc("/list", listHandler(cfg))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("AutoConvJmsSub listening on http://%s", cfg.Server.Addr)
		log.Printf("Configured subscriptions: %s", strings.Join(subNames(cfg), ", "))
		log.Printf("Use:  http://%s/sub            (returns 'default')", cfg.Server.Addr)
		log.Printf("      http://%s/sub/<name>     (returns named entry)", cfg.Server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func subNames(cfg *Config) []string {
	names := make([]string, 0, len(cfg.Subscriptions))
	for n := range cfg.Subscriptions {
		names = append(names, n)
	}
	return names
}

func subHandler(cfg *Config) http.HandlerFunc {
	// Build an http.Client that explicitly bypasses any HTTP_PROXY /
	// HTTPS_PROXY environment variable. Otherwise — when AutoConvJmsSub is
	// launched from a shell that has those vars set to a running Clash
	// instance — fetching the JMS subscription would route through Clash,
	// risking circular dependency (proxy depends on the very subscription
	// being fetched) and leaking credentials to whichever proxy node was
	// selected. Subscription fetches must always go direct.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{
		Timeout:   cfg.Server.UpstreamTimeout,
		Transport: transport,
	}
	ua := cfg.Server.UpstreamUserAgent
	return func(w http.ResponseWriter, r *http.Request) {
		// Determine which named subscription to serve.
		name := strings.TrimPrefix(r.URL.Path, "/sub")
		name = strings.TrimPrefix(name, "/")
		if name == "" {
			name = "default"
		}
		upstream, ok := cfg.Subscriptions[name]
		if !ok || upstream == "" {
			http.Error(w,
				fmt.Sprintf("subscription %q is not configured. Edit config.yaml and add it under `subscriptions:`.", name),
				http.StatusNotFound)
			return
		}

		req, err := http.NewRequestWithContext(r.Context(), "GET", upstream, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Header.Set("User-Agent", ua)

		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "upstream fetch failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("upstream returned %d", resp.StatusCode), http.StatusBadGateway)
			return
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		// Forward subscription metadata headers so Clash clients can show
		// traffic / expiry / update interval correctly.
		for k, vs := range resp.Header {
			kl := strings.ToLower(k)
			forward := strings.HasSuffix(kl, "subscription-userinfo") ||
				kl == "profile-update-interval" ||
				kl == "profile-web-page-url"
			if forward {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
		}

		yaml, err := TryParseSubscriptionWithDefault(string(body), cfg.Defaults.DefaultProxyMatch)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.yaml"`, name))
		_, _ = w.Write([]byte(yaml))
	}
}

func listHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "Configured subscriptions:\n")
		for _, n := range subNames(cfg) {
			_, _ = fmt.Fprintf(w, "  http://%s/sub/%s\n", r.Host, n)
		}
	}
}
