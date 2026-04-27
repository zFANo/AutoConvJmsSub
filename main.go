// AutoConvJmsSub: a tiny local HTTP service that converts JustMySocks-style
// base64 ss/vmess subscriptions into Clash YAML.
//
// Usage:
//   AutoConvJmsSub                       # listens on 127.0.0.1:25500
//   AutoConvJmsSub -addr 127.0.0.1:8080
//   curl 'http://127.0.0.1:25500/sub?url=<url-encoded JMS subscription URL>'
//
// In Clash Verge / Clash Meta, set the remote subscription URL to the
// /sub?url=... endpoint above instead of the raw JMS URL.
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
	addr := flag.String("addr", "127.0.0.1:25500", "listen address (use 127.0.0.1 to keep it local)")
	timeout := flag.Duration("timeout", 30*time.Second, "upstream subscription fetch timeout")
	ua := flag.String("ua", "ClashforWindows/0.20.39", "user-agent for upstream fetch (some providers require a clash-like UA)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/sub", subHandler(*timeout, *ua))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("AutoConvJmsSub listening on http://%s", *addr)
		log.Printf("Usage: GET http://%s/sub?url=<url-encoded JMS subscription URL>", *addr)
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

func subHandler(timeout time.Duration, ua string) http.HandlerFunc {
	client := &http.Client{Timeout: timeout}
	return func(w http.ResponseWriter, r *http.Request) {
		upstream := r.URL.Query().Get("url")
		if upstream == "" {
			http.Error(w, "missing 'url' query parameter", http.StatusBadRequest)
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

		// Forward subscription metadata headers so the Clash client can show
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

		yaml, err := TryParseSubscription(string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="jms.yaml"`)
		_, _ = w.Write([]byte(yaml))
	}
}
