package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/internal/health"
	"github.com/kill-ai-leak/kill-ai-leak/internal/logger"
	"github.com/kill-ai-leak/kill-ai-leak/internal/middleware"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/config"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/proxy"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "api-server: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// --- CLI flags ---
	var (
		configFile = flag.String("config", "", "path to YAML config file")
		port       = flag.Int("port", 0, "override server port (default 8081)")
		logLevel   = flag.String("log-level", "", "override log level (debug|info|warn|error)")
	)
	flag.Parse()

	// --- Load configuration ---
	cfg, err := config.LoadFromFile(*configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	config.ApplyEnvOverrides(cfg)

	// The API server defaults to port 8081 to avoid colliding with the
	// gateway on 8080, unless explicitly overridden.
	if cfg.Server.Port == 8080 {
		cfg.Server.Port = 8081
	}
	if *port > 0 {
		cfg.Server.Port = *port
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}

	// --- Initialize logger ---
	log := logger.New(logger.ParseLevel(cfg.Logging.Level), os.Stdout)
	ctx := context.Background()
	log.Info(ctx, "starting kill-ai-leak api server", map[string]any{
		"version": version,
		"port":    cfg.Server.Port,
	})

	// --- Health checker ---
	hc := health.NewChecker(version)
	hc.RegisterComponent("api")
	hc.SetComponentHealth("api", health.StatusHealthy, "ok")

	// --- Build routes ---
	mux := http.NewServeMux()

	// Health endpoints.
	mux.HandleFunc("/healthz", hc.LivenessHandler())
	mux.HandleFunc("/readyz", hc.ReadinessHandler())
	mux.HandleFunc("/health", hc.DetailedHandler())

	// REST API routes.
	mux.HandleFunc("/api/v1/policies", handlePolicies(log))
	mux.HandleFunc("/api/v1/services", handleServices(log))
	mux.HandleFunc("/api/v1/events", handleEvents(log))
	mux.HandleFunc("/api/v1/guardrails/rules", handleGuardrailRules(log))
	mux.HandleFunc("/api/v1/config", handleConfig(log, cfg))
	mux.HandleFunc("/api/v1/version", handleVersion())

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

	hc.SetReady(true)

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

	log.Info(ctx, "api server stopped cleanly")
	return nil
}

// --- REST API handler stubs ---
// These return placeholder responses. A real implementation would back onto
// a storage layer (database, etcd, etc.).

func handlePolicies(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			respondAPI(w, http.StatusOK, apiListResponse{
				Kind:  "PolicyList",
				Items: []any{},
				Total: 0,
			})
		case http.MethodPost:
			log.Info(r.Context(), "policy create request received")
			respondAPI(w, http.StatusCreated, map[string]string{
				"status": "created",
			})
		default:
			respondAPI(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed",
			})
		}
	}
}

func handleServices(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondAPI(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed",
			})
			return
		}
		respondAPI(w, http.StatusOK, apiListResponse{
			Kind:  "ServiceList",
			Items: []any{},
			Total: 0,
		})
	}
}

func handleEvents(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondAPI(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed",
			})
			return
		}
		respondAPI(w, http.StatusOK, apiListResponse{
			Kind:  "EventList",
			Items: []any{},
			Total: 0,
		})
	}
}

func handleGuardrailRules(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondAPI(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed",
			})
			return
		}
		respondAPI(w, http.StatusOK, apiListResponse{
			Kind:  "GuardrailRuleList",
			Items: []any{},
			Total: 0,
		})
	}
}

func handleConfig(log *logger.Logger, cfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondAPI(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed",
			})
			return
		}
		// Return a sanitized view that does not expose secrets.
		safe := map[string]any{
			"server": map[string]any{
				"host": cfg.Server.Host,
				"port": cfg.Server.Port,
			},
			"guardrails": map[string]any{
				"enabled":      cfg.Guardrails.Enabled,
				"default_mode": cfg.Guardrails.DefaultMode,
			},
			"logging": cfg.Logging,
		}
		respondAPI(w, http.StatusOK, safe)
	}
}

func handleVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		respondAPI(w, http.StatusOK, map[string]string{
			"version":   version,
			"build":     "dev",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// apiListResponse is a generic list envelope for REST responses.
type apiListResponse struct {
	Kind  string `json:"kind"`
	Items []any  `json:"items"`
	Total int    `json:"total"`
}

func respondAPI(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
