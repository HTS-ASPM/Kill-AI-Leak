package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/kill-ai-leak/kill-ai-leak/internal/health"
	"github.com/kill-ai-leak/kill-ai-leak/internal/logger"
	"github.com/kill-ai-leak/kill-ai-leak/internal/middleware"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/config"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/proxy"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gateway: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// --- CLI flags ---
	var (
		configFile = flag.String("config", "", "path to YAML config file")
		port       = flag.Int("port", 0, "override server port")
		logLevel   = flag.String("log-level", "", "override log level (debug|info|warn|error)")
	)
	flag.Parse()

	// --- Load configuration ---
	cfg, err := config.LoadFromFile(*configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	config.ApplyEnvOverrides(cfg)

	// Apply CLI flag overrides (highest priority).
	if *port > 0 {
		cfg.Server.Port = *port
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}

	// --- Initialize logger ---
	log := logger.New(logger.ParseLevel(cfg.Logging.Level), os.Stdout)
	ctx := context.Background()
	log.Info(ctx, "starting kill-ai-leak gateway", map[string]any{
		"version": version,
		"port":    cfg.Server.Port,
	})

	// --- Health checker ---
	hc := health.NewChecker(version)
	hc.RegisterComponent("guardrails")
	hc.RegisterComponent("proxy")

	// --- Initialize guardrail engine ---
	// The engine is pluggable. For now we use a no-op placeholder so the
	// gateway boots cleanly. Real detection rules are wired in by the
	// platform initialisation layer.
	var engine proxy.GuardrailEngine // nil → guardrails disabled at runtime
	hc.SetComponentHealth("guardrails", health.StatusHealthy, "engine loaded (no-op)")

	// --- Create proxy ---
	llmProxy, err := proxy.NewLLMProxy(cfg, engine, log)
	if err != nil {
		return fmt.Errorf("create proxy: %w", err)
	}
	hc.SetComponentHealth("proxy", health.StatusHealthy, "provider targets resolved")

	// --- Build handler ---
	handler := proxy.NewHandler(llmProxy, hc, log, cfg)
	mux := http.NewServeMux()
	handler.Register(mux)

	// --- Build middleware chain ---
	registry := middleware.NewServiceRegistry(cfg.Auth)
	authMw := middleware.Auth(cfg.Auth, registry, log)

	root := proxy.Chain(
		mux,
		proxy.Recovery(log),
		proxy.RequestID,
		proxy.Logging(log),
		proxy.CORS(proxy.DefaultCORSOptions()),
		proxy.Timeout(cfg.Proxy.DefaultTimeout),
		authMw,
	)

	// --- Start HTTP server ---
	srv := &http.Server{
		Addr:         cfg.Server.Addr(),
		Handler:      root,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Mark as ready.
	hc.SetReady(true)

	// --- Graceful shutdown ---
	errCh := make(chan error, 1)
	go func() {
		log.Info(ctx, "http server listening", map[string]any{"addr": srv.Addr})
		if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
			errCh <- srv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Info(ctx, "shutdown signal received", map[string]any{"signal": sig.String()})
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	}

	hc.SetReady(false)

	shutdownCtx, cancel := context.WithTimeout(ctx, cfg.Server.ShutdownTimeout)
	defer cancel()

	log.Info(ctx, "shutting down gracefully", map[string]any{
		"timeout": cfg.Server.ShutdownTimeout.String(),
	})

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	log.Info(ctx, "gateway stopped cleanly")
	return nil
}
