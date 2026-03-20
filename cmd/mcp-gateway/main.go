// Command mcp-gateway runs the Kill-AI-Leak MCP security gateway.
// It intercepts Model Context Protocol traffic between AI agents and MCP
// servers, enforcing tool-use policies, audit logging, and shadow server
// detection.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/mcp"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-gateway: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listenAddr   = flag.String("addr", ":9090", "listen address for the MCP gateway")
		upstreamURL  = flag.String("upstream", "", "upstream MCP server URL to proxy to")
		policyFile   = flag.String("policy", "", "path to MCP policy JSON file")
		logLevel     = flag.String("log-level", "info", "log level (debug|info|warn|error)")
		maxBody      = flag.Int64("max-body", 10<<20, "maximum request body size in bytes")
		timeout      = flag.Duration("timeout", 30*time.Second, "upstream request timeout")
		shadowDetect = flag.Bool("shadow-detect", true, "enable shadow MCP server detection")
		defaultDeny  = flag.Bool("default-deny", false, "deny all tool calls unless explicitly allowed")
	)
	flag.Parse()

	// Initialize structured logger.
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	logger.Info("starting mcp-gateway",
		"version", version,
		"addr", *listenAddr,
		"upstream", *upstreamURL,
		"shadow_detect", *shadowDetect,
		"default_deny", *defaultDeny,
	)

	// Load or create policy.
	policy, err := loadPolicy(*policyFile, *defaultDeny)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	logger.Info("policy loaded",
		"tool_rules", len(policy.ToolRules),
		"allowed_servers", len(policy.ServerRules.Allow),
		"denied_servers", len(policy.ServerRules.Deny),
		"default_deny", policy.DefaultDeny,
	)

	// Create audit log.
	auditLog := mcp.NewMCPAuditLog(mcp.DefaultAuditLogConfig(), logger)

	// Create gateway.
	gatewayCfg := mcp.GatewayConfig{
		UpstreamURL:           *upstreamURL,
		MaxBodyBytes:          *maxBody,
		RequestTimeout:        *timeout,
		EnableShadowDetection: *shadowDetect,
	}

	gateway := mcp.NewMCPGateway(gatewayCfg, policy, auditLog, logger)

	// Build HTTP mux.
	serveMux := http.NewServeMux()

	// MCP proxy endpoint — all MCP traffic goes through here.
	serveMux.Handle("/mcp", gateway)
	serveMux.Handle("/mcp/", gateway)

	// Health and metrics endpoints.
	serveMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := gateway.HealthCheck(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy","error":%q}`, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"healthy"}`)
	})

	serveMux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ready"}`)
	})

	serveMux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := gateway.Stats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	serveMux.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		filter := mcp.AuditFilter{
			User:   r.URL.Query().Get("user"),
			Server: r.URL.Query().Get("server"),
			Tool:   r.URL.Query().Get("tool"),
			Limit:  100,
		}
		if d := r.URL.Query().Get("decision"); d != "" {
			filter.Decision = mcp.AuditDecision(d)
		}

		entries := auditLog.Search(filter)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})

	serveMux.HandleFunc("/shadow-servers", func(w http.ResponseWriter, r *http.Request) {
		shadows := gateway.ShadowServers()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(shadows)
	})

	// Start HTTP server.
	srv := &http.Server{
		Addr:         *listenAddr,
		Handler:      serveMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", srv.Addr)
		errCh <- srv.ListenAndServe()
	}()

	// Graceful shutdown on signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	logger.Info("shutting down gracefully")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	logger.Info("mcp-gateway stopped cleanly")
	return nil
}

// loadPolicy reads a policy from a JSON file, or creates a default policy
// if no file is specified.
func loadPolicy(path string, defaultDeny bool) (*mcp.MCPPolicy, error) {
	policy := mcp.NewMCPPolicy()
	policy.DefaultDeny = defaultDeny

	if path == "" {
		return policy, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", path, err)
	}

	if err := json.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("parse policy file %q: %w", path, err)
	}

	return policy, nil
}
