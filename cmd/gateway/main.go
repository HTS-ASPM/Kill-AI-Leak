package main

import (
	"context"
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
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/code"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/injection"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/jailbreak"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/pii"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/ratelimit"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/secrets"
	detstateful "github.com/kill-ai-leak/kill-ai-leak/pkg/detection/stateful"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/toxicity"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/ml"
	mlinjection "github.com/kill-ai-leak/kill-ai-leak/pkg/ml/injection"
	mltoxicity "github.com/kill-ai-leak/kill-ai-leak/pkg/ml/toxicity"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/proxy"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/stateful"
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
		configFile  = flag.String("config", "", "path to YAML config file")
		port        = flag.Int("port", 0, "override server port")
		logLevel    = flag.String("log-level", "", "override log level (debug|info|warn|error)")
		mlServerURL = flag.String("ml-server", "", "ML inference server URL (e.g. http://localhost:5000); empty to disable ML scoring")
	)
	flag.Parse()

	// Also accept ML server URL from environment variable.
	if *mlServerURL == "" {
		if envURL := os.Getenv("ML_SERVER_URL"); envURL != "" {
			*mlServerURL = envURL
		}
	}

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

	// --- Validate configuration ---
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
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

	// --- Initialize guardrail engine with detection rules ---
	var engine proxy.GuardrailEngine

	// Create a session tracker for multi-turn analysis (used even if
	// guardrails are disabled so it can be stopped cleanly on shutdown).
	sessionTracker := stateful.NewSessionTracker(stateful.DefaultTrackerConfig())
	defer sessionTracker.Stop()

	if cfg.Guardrails.Enabled {
		registry := guardrails.NewRegistry()

		// Create detection rules.
		injDet := injection.New()
		toxDet := toxicity.New()

		// --- ML inference layer ---
		if *mlServerURL != "" {
			mlClient := ml.NewInferenceClient(*mlServerURL, 2*time.Second)
			injDet.SetMLScorer(mlinjection.NewMLInjectionScorer(mlClient))
			toxDet.SetMLScorer(mltoxicity.NewMLToxicityScorer(mlClient))
			log.Info(ctx, "ML inference enabled", map[string]any{
				"ml_server": *mlServerURL,
			})
		} else {
			log.Info(ctx, "ML inference disabled (regex-only mode)")
		}

		// Register all detection rules with default config.
		rules := []guardrails.Rule{
			ratelimit.New(),
			pii.New(),
			secrets.New(),
			injDet,
			jailbreak.New(),
			toxDet,
			code.New(),
			detstateful.New(sessionTracker),
		}
		for _, rule := range rules {
			ruleCfg := &models.GuardrailRuleConfig{
				ID:       rule.ID(),
				Name:     rule.Name(),
				Stage:    rule.Stage(),
				Category: rule.Category(),
				Mode:     models.EnforcementMode(cfg.Guardrails.DefaultMode),
				Enabled:  true,
			}
			if err := registry.Register(rule, ruleCfg); err != nil {
				log.Warn(ctx, "failed to register rule", map[string]any{
					"rule": rule.ID(),
					"error": err.Error(),
				})
			}
		}

		grEngine := guardrails.NewEngine(registry, guardrails.DefaultEngineConfig())
		engine = guardrails.NewEngineAdapter(grEngine)

		log.Info(ctx, "guardrail engine initialized", map[string]any{
			"rules_loaded": len(registry.All()),
			"mode":         cfg.Guardrails.DefaultMode,
		})
		hc.SetComponentHealth("guardrails", health.StatusHealthy, fmt.Sprintf("%d rules loaded", len(registry.All())))
	} else {
		log.Info(ctx, "guardrails disabled")
		hc.SetComponentHealth("guardrails", health.StatusHealthy, "disabled")
	}

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
	serviceRegistry := middleware.NewServiceRegistry(cfg.Auth)
	authMw := middleware.Auth(cfg.Auth, serviceRegistry, log)

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
