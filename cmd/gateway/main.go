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
	"syscall"
	"time"

	"open-democracy/internal/gateway"
)

// main is the entrypoint of the open-democracy dashboard gateway.
//
// The gateway runs the bill ledger in-process (the same Service that the
// Fabric chaincode wraps) backed by a JSON file under DATA_DIR. It exposes
// a REST API and a server-rendered dashboard so the entire project can be
// brought up with a single `docker compose up` and immediately drive the
// chaincode workflows from a browser.
//
// Configuration is environment-driven so it composes cleanly with Docker:
//
//	GATEWAY_ADDR    listen address (default :8080)
//	GATEWAY_DATA    data directory mounted as a volume (default ./data)
//	GATEWAY_USER    default acting user when no X-User header is set
func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local /api/health endpoint and exit 0 on success; intended for distroless container HEALTHCHECK")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck(envOr("GATEWAY_ADDR", ":8080")))
	}

	cfg := gateway.Config{
		Addr:        envOr("GATEWAY_ADDR", ":8080"),
		StorePath:   envOr("GATEWAY_DATA", "./data") + "/ledger.json",
		DefaultUser: envOr("GATEWAY_USER", "savio"),
	}
	srv, err := gateway.NewServer(cfg)
	if err != nil {
		log.Fatalf("gateway: init: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("gateway: run: %v", err)
	}
}

// runHealthcheck performs a single GET against /api/health on the configured
// address. Distroless images contain no curl/wget, so the binary self-checks.
func runHealthcheck(addr string) int {
	host := addr
	if len(host) > 0 && host[0] == ':' {
		host = "127.0.0.1" + host
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + host + "/api/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
