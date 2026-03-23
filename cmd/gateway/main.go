package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/kill-ai-leak/kill-ai-leak/internal/health"
	"github.com/kill-ai-leak/kill-ai-leak/internal/logger"
	"github.com/kill-ai-leak/kill-ai-leak/internal/middleware"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/alerting"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/config"
	siemint "github.com/kill-ai-leak/kill-ai-leak/pkg/integrations/siem"
	ticketint "github.com/kill-ai-leak/kill-ai-leak/pkg/integrations/ticketing"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/agentloop"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/agentnet"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/allowlist"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/anomaly"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/audit"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/brand"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/circuitbreaker"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/code"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/codeleak"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/compliance"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/contextaccum"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/costaccount"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/encoding"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/hallucination"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/injection"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/insecurecode"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/jailbreak"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/license"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/network"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/outputpii"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/pii"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/promptleak"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/ratelimit"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/residency"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/responseguard"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/routing"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/schemaval"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/secrets"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/sessiondrift"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/shadowai"
	detstateful "github.com/kill-ai-leak/kill-ai-leak/pkg/detection/stateful"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/tokenbudget"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/tokenguard"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/topic"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/topicallow"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/toxicity"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/watermark"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/ml"
	mlinjection "github.com/kill-ai-leak/kill-ai-leak/pkg/ml/injection"
	mltoxicity "github.com/kill-ai-leak/kill-ai-leak/pkg/ml/toxicity"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/proxy"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/stateful"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/storage/postgres"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/store"
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
	var registry *guardrails.Registry

	// Create a session tracker for multi-turn analysis (used even if
	// guardrails are disabled so it can be stopped cleanly on shutdown).
	sessionTracker := stateful.NewSessionTracker(stateful.DefaultTrackerConfig())
	defer sessionTracker.Stop()

	// Circuit breaker rule (GR-022), created outside the guardrails block
	// so it can be referenced by the proxy for RecordSuccess/RecordFailure.
	cbRule := circuitbreaker.New()

	if cfg.Guardrails.Enabled {
		registry = guardrails.NewRegistry()

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
			// --- Pre-Input Stage ---
			network.New(),                   // GR-006: Network Restriction
			ratelimit.New(),                 // GR-004/005: Rate Limits
			tokenbudget.New(),               // GR-006: Token Budget Enforcement
			allowlist.NewProvider(),          // GR-007: Provider Allowlist
			allowlist.NewModel(),             // GR-008: Model Allowlist
			shadowai.New(),                  // GR-009: Shadow AI Detection

			// --- Input Stage ---
			pii.New(),                       // GR-010: PII Detection
			secrets.New(),                   // GR-012: Secret Detection
			injDet,                          // GR-013: Prompt Injection Detection
			jailbreak.New(),                 // GR-014: Jailbreak Detection
			topic.New(),                     // GR-015: Topic Restriction
			topicallow.New(),                // GR-016: Topic Allowlist
			toxDet,                          // GR-017: Input Toxicity Filter
			tokenguard.New(),                // GR-018: Max Token Guard
			encoding.New(),                  // GR-019: Encoding Evasion Detection
			codeleak.NewSystemPrompt(),      // GR-020: System Prompt Protection
			codeleak.NewSourceCode(),        // GR-021: Source Code Leak Prevention
			compliance.NewComplianceTag(),   // GR-022: Compliance Metadata Tagging
			contextaccum.New(),              // GR-023: Multi-Turn Context Accumulation
			schemaval.New(),                 // GR-024: Structured Output Validation
			detstateful.New(sessionTracker), // Stateful: Multi-Turn Analysis

			// --- Routing Stage ---
			residency.New(),                 // GR-020: Data Residency (EU detection)
			cbRule,                          // GR-022: Circuit Breaker
			routing.NewResidencyRouter(),    // GR-025: Data Residency Router
			routing.NewGDPR(),               // GR-026: EU Data Residency (GDPR)
			routing.NewFailover(),           // GR-027: Provider Failover
			routing.NewCostRoute(),          // GR-028: Cost-Aware Routing
			routing.NewLatencyRoute(),       // GR-029: Latency-Aware Routing
			routing.NewCanary(),             // GR-030: Canary Routing
			routing.NewSensitiveRoute(),     // GR-031: Sensitive Data Routing Block
			routing.NewHIPAA(),              // GR-032: HIPAA Routing Enforcement
			compliance.NewModelPin(),        // GR-033: Model Version Pinning

			// --- Output Stage ---
			code.New(),                      // GR-033: Code Vulnerability Scanner
			promptleak.New(),                // GR-032: System Prompt Leakage Detection
			hallucination.New(),             // GR-034: Hallucination Detection
			outputpii.New(),                 // GR-035: Output PII Leakage Detection
			brand.New(),                     // GR-035: Brand Safety
			insecurecode.NewVulnScan(),      // GR-037: Generated Code Vulnerability Scan
			insecurecode.NewInsecurePattern(), // GR-038: Insecure Code Pattern Detection
			license.New(),                   // GR-039: License Compliance Check
			responseguard.NewSizeGuard(),    // GR-043: Response Size Guard
			responseguard.NewOutputSchema(), // GR-044: Structured Output Conformance
			watermark.New(),                 // GR-045: Watermark Injection

			// --- Post-Output Stage ---
			audit.NewAudit(),                // GR-046: Audit Log Writer
			costaccount.New(),               // GR-047: Cost Accounting
			anomaly.New(),                   // GR-048: Anomaly Detection Feed
			audit.NewAnalytics(),            // GR-049: Usage Analytics Export

			// --- Behavioral Stage ---
			agentnet.New(),                  // GR-052: Agent Network Egress Control
			sessiondrift.New(),              // GR-053: Session Drift Detection
			agentloop.New(),                 // GR-054: Recursive Agent Loop Detection
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

	// --- Create data store ---
	// The in-memory store is always created (used by API handler and seeding).
	// If the storage driver is "postgres", a PostgresStore is created and
	// used as the primary EventRecorder for the proxy.
	dataStore := store.New()

	var pgStore *postgres.PostgresStore
	if cfg.Storage.Driver == "postgres" && cfg.Storage.PostgresDSN != "" {
		var pgErr error
		pgStore, pgErr = postgres.NewPostgresStore(cfg.Storage.PostgresDSN)
		if pgErr != nil {
			return fmt.Errorf("create postgres store: %w", pgErr)
		}
		defer pgStore.Close()
		log.Info(ctx, "PostgreSQL storage initialized", map[string]any{
			"dsn": maskDSN(cfg.Storage.PostgresDSN),
		})
	} else {
		seedSampleData(dataStore)
		log.Info(ctx, "in-memory data store initialized with seed data")
	}

	// --- Create proxy ---
	llmProxy, err := proxy.NewLLMProxy(cfg, engine, log)
	if err != nil {
		return fmt.Errorf("create proxy: %w", err)
	}
	llmProxy.SetStore(dataStore)
	llmProxy.SetCircuitBreaker(cbRule)
	hc.SetComponentHealth("proxy", health.StatusHealthy, "provider targets resolved")

	// --- Initialize alerting ---
	if cfg.Alerting.Enabled {
		alerterCfg := alerting.AlertConfig{
			Enabled:     cfg.Alerting.Enabled,
			SlackURL:    cfg.Alerting.SlackURL,
			WebhookURL:  cfg.Alerting.WebhookURL,
			MinSeverity: cfg.Alerting.MinSeverity,
		}
		if a := alerting.NewAlerterFromConfig(alerterCfg); a != nil {
			llmProxy.SetAlerter(a, cfg.Alerting)
			log.Info(ctx, "alerting enabled", map[string]any{
				"min_severity": cfg.Alerting.MinSeverity,
				"slack":        cfg.Alerting.SlackURL != "",
				"webhook":      cfg.Alerting.WebhookURL != "",
			})
		}
	}

	// --- Initialize SIEM export ---
	if cfg.SIEM.Enabled {
		siemCfg := siemint.SIEMConfig{
			Enabled:   cfg.SIEM.Enabled,
			Type:      cfg.SIEM.Type,
			Endpoint:  cfg.SIEM.Endpoint,
			Token:     cfg.SIEM.Token,
			Index:     cfg.SIEM.Index,
			BatchSize: cfg.SIEM.BatchSize,
			FlushSecs: cfg.SIEM.FlushSecs,
		}
		if exporter := siemint.NewSIEMExporterFromConfig(siemCfg); exporter != nil {
			llmProxy.SetSIEMExporter(exporter)
			log.Info(ctx, "SIEM export enabled", map[string]any{
				"type":     cfg.SIEM.Type,
				"endpoint": cfg.SIEM.Endpoint,
			})
		}
	}

	// --- Initialize ticketing ---
	if cfg.Ticketing.Enabled {
		ticketCfg := ticketint.TicketingConfig{
			Enabled:     cfg.Ticketing.Enabled,
			Provider:    cfg.Ticketing.Provider,
			BaseURL:     cfg.Ticketing.BaseURL,
			APIKey:      cfg.Ticketing.APIKey,
			ProjectKey:  cfg.Ticketing.ProjectKey,
			AutoCreate:  cfg.Ticketing.AutoCreate,
			MinSeverity: cfg.Ticketing.MinSeverity,
		}
		if client := ticketint.NewTicketingClientFromConfig(ticketCfg); client != nil {
			llmProxy.SetTicketingClient(client, cfg.Ticketing)
			log.Info(ctx, "ticketing enabled", map[string]any{
				"provider":    cfg.Ticketing.Provider,
				"auto_create": cfg.Ticketing.AutoCreate,
			})
		}
	}

	// --- Create data API handler ---
	// The API handler still uses the in-memory store for now; when the
	// full storage.Store interface is adopted by the API layer, it can
	// switch to pgStore.
	apiHandler := proxy.NewAPIHandler(dataStore, registry)

	// Keep a reference to pgStore to suppress unused variable warning.
	_ = pgStore

	// --- Build handler ---
	handler := proxy.NewHandler(llmProxy, hc, log, cfg)
	handler.SetAPIHandler(apiHandler)
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

// maskDSN hides the password portion of a DSN for safe logging.
func maskDSN(dsn string) string {
	// Simple approach: look for "password=" or ":pass@" patterns.
	masked := dsn
	if idx := strings.Index(masked, "://"); idx >= 0 {
		// Format: postgres://user:password@host/db
		rest := masked[idx+3:]
		if atIdx := strings.Index(rest, "@"); atIdx >= 0 {
			if colonIdx := strings.Index(rest[:atIdx], ":"); colonIdx >= 0 {
				masked = masked[:idx+3] + rest[:colonIdx] + ":****@" + rest[atIdx+1:]
			}
		}
	}
	return masked
}

// seedSampleData populates the store with realistic initial data so the
// dashboard has content to display immediately.
func seedSampleData(s *store.Store) {
	now := time.Now()

	// --- Sample services ---
	services := []models.AIService{
		{
			ID: "svc-chatbot", Name: "customer-chatbot", Namespace: "production",
			Team: "platform", ExposureType: "external", RiskScore: 0.35,
			GatewayEnrolled: true, DiscoveredAt: now.AddDate(0, 0, -14),
			LastSeenAt: now.Add(-10 * time.Minute), DiscoveredBy: models.SourceInlineGateway,
			Providers: []models.ProviderUsage{
				{Provider: "openai", Models: []string{"gpt-4o"}, CallCount7d: 1240, TokensUsed7d: 580000, EstCost7dUSD: 12.50, LastCallAt: now.Add(-10 * time.Minute)},
			},
		},
		{
			ID: "svc-code-assist", Name: "code-assistant", Namespace: "engineering",
			Team: "backend", ExposureType: "internal", RiskScore: 0.52,
			GatewayEnrolled: true, DiscoveredAt: now.AddDate(0, 0, -10),
			LastSeenAt: now.Add(-30 * time.Minute), DiscoveredBy: models.SourceInlineGateway,
			Providers: []models.ProviderUsage{
				{Provider: "anthropic", Models: []string{"claude-sonnet-4-20250514"}, CallCount7d: 890, TokensUsed7d: 1200000, EstCost7dUSD: 24.00, LastCallAt: now.Add(-30 * time.Minute)},
			},
		},
		{
			ID: "svc-data-pipeline", Name: "data-pipeline", Namespace: "data",
			Team: "data-eng", ExposureType: "internal", RiskScore: 0.78,
			GatewayEnrolled: true, DiscoveredAt: now.AddDate(0, 0, -7),
			LastSeenAt: now.Add(-1 * time.Hour), DiscoveredBy: models.SourceInlineGateway,
			Providers: []models.ProviderUsage{
				{Provider: "openai", Models: []string{"gpt-4o-mini"}, CallCount7d: 3200, TokensUsed7d: 2500000, EstCost7dUSD: 8.75, LastCallAt: now.Add(-1 * time.Hour)},
			},
		},
		{
			ID: "svc-shadow-bot", Name: "marketing-bot", Namespace: "marketing",
			Team: "marketing", ExposureType: "external", RiskScore: 0.91,
			GatewayEnrolled: false, DiscoveredAt: now.AddDate(0, 0, -3),
			LastSeenAt: now.Add(-2 * time.Hour), DiscoveredBy: models.SourceKernelObserver,
			Providers: []models.ProviderUsage{
				{Provider: "openai", Models: []string{"gpt-4o"}, CallCount7d: 420, TokensUsed7d: 310000, EstCost7dUSD: 6.30, LastCallAt: now.Add(-2 * time.Hour)},
			},
		},
		{
			ID: "svc-search-agent", Name: "search-agent", Namespace: "production",
			Team: "search", ExposureType: "internal", RiskScore: 0.45,
			GatewayEnrolled: true, DiscoveredAt: now.AddDate(0, 0, -5),
			LastSeenAt: now.Add(-45 * time.Minute), DiscoveredBy: models.SourceInlineGateway,
			Providers: []models.ProviderUsage{
				{Provider: "anthropic", Models: []string{"claude-sonnet-4-20250514"}, CallCount7d: 650, TokensUsed7d: 900000, EstCost7dUSD: 18.00, LastCallAt: now.Add(-45 * time.Minute)},
			},
		},
	}
	for _, svc := range services {
		s.RecordService(svc)
	}

	// --- Sample events spread over the last 7 days ---
	type eventTemplate struct {
		actorID   string
		actorName string
		namespace string
		provider  string
		model     string
		severity  models.Severity
		blocked   bool
		ruleID    string
		ruleName  string
		decision  string
		reason    string
		category  string
	}

	templates := []eventTemplate{
		{"svc-chatbot", "customer-chatbot", "production", "openai", "gpt-4o", models.SeverityHigh, true, "injection-detector", "Prompt Injection", "block", "SQL injection pattern detected", "injection"},
		{"svc-code-assist", "code-assistant", "engineering", "anthropic", "claude-sonnet-4-20250514", models.SeverityMedium, false, "pii-detector", "PII Scanner", "anonymize", "Email address detected", "pii"},
		{"svc-data-pipeline", "data-pipeline", "data", "openai", "gpt-4o-mini", models.SeverityInfo, false, "", "", "allow", "", ""},
		{"svc-chatbot", "customer-chatbot", "production", "openai", "gpt-4o", models.SeverityCritical, true, "jailbreak-detector", "Jailbreak Detection", "block", "DAN-style jailbreak attempt", "jailbreak"},
		{"svc-code-assist", "code-assistant", "engineering", "anthropic", "claude-sonnet-4-20250514", models.SeverityMedium, true, "secrets-detector", "Secret Scanner", "block", "AWS access key detected in prompt", "secrets"},
		{"svc-search-agent", "search-agent", "production", "anthropic", "claude-sonnet-4-20250514", models.SeverityInfo, false, "", "", "allow", "", ""},
		{"svc-data-pipeline", "data-pipeline", "data", "openai", "gpt-4o-mini", models.SeverityHigh, true, "toxicity-detector", "Toxicity Filter", "block", "Toxic content score 0.92", "toxicity"},
		{"svc-chatbot", "customer-chatbot", "production", "openai", "gpt-4o", models.SeverityLow, false, "code-safety", "Code Safety", "alert", "Potential unsafe code pattern", "code_safety"},
		{"svc-shadow-bot", "marketing-bot", "marketing", "openai", "gpt-4o", models.SeverityMedium, false, "pii-detector", "PII Scanner", "anonymize", "Phone number detected", "pii"},
		{"svc-search-agent", "search-agent", "production", "anthropic", "claude-sonnet-4-20250514", models.SeverityHigh, true, "injection-detector", "Prompt Injection", "block", "Indirect injection via tool output", "injection"},
	}

	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 30; i++ {
		tmpl := templates[i%len(templates)]
		hoursAgo := rng.Intn(7*24) // random time within last 7 days
		ts := now.Add(-time.Duration(hoursAgo) * time.Hour)
		latency := int64(50 + rng.Intn(200))
		cost := float64(rng.Intn(10)+1) * 0.001

		var grResults []models.GuardrailResult
		if tmpl.ruleID != "" {
			grResults = []models.GuardrailResult{
				{
					RuleID:     tmpl.ruleID,
					RuleName:   tmpl.ruleName,
					Stage:      "input",
					Decision:   tmpl.decision,
					Confidence: 0.7 + float64(rng.Intn(30))/100.0,
					Reason:     tmpl.reason,
					LatencyMs:  int64(5 + rng.Intn(30)),
				},
			}
		}

		ev := models.Event{
			ID:        fmt.Sprintf("evt-seed-%04d", i),
			Timestamp: ts,
			Source:    models.SourceInlineGateway,
			Severity: tmpl.severity,
			Actor: models.Actor{
				Type:      models.ActorServiceAccount,
				ID:        tmpl.actorID,
				Name:      tmpl.actorName,
				Namespace: tmpl.namespace,
			},
			Target: models.Target{
				Type:     models.TargetLLMProvider,
				ID:       tmpl.provider,
				Provider: tmpl.provider,
				Model:    tmpl.model,
			},
			Action: models.Action{
				Type:      models.ActionAPICall,
				Direction: models.DirectionOutbound,
				Protocol:  "https",
				Method:    "POST",
			},
			Content: models.ContentMeta{
				HasPrompt: true,
				Blocked:   tmpl.blocked,
				Model:     tmpl.model,
			},
			Guardrails: grResults,
			LatencyMs:  latency,
			CostUSD:    cost,
		}
		s.RecordEvent(ev)
	}

	// --- Sample policies ---
	s.AddPolicy(models.AISecurityPolicy{
		APIVersion: "killaileak.io/v1",
		Kind:       "AISecurityPolicy",
		Metadata:   models.PolicyMetadata{Name: "default-policy", Namespace: "default"},
		Spec: models.PolicySpec{
			Scope: models.PolicyScope{Namespaces: []string{"*"}},
			Mode:  models.ModeEnforce,
			Input: &models.InputPolicy{
				BlockPII:            false,
				AnonymizePII:        true,
				BlockSecrets:        true,
				BlockInjectionAbove: 0.8,
			},
			Output: &models.OutputPolicy{
				BlockToxicAbove:     0.85,
				ScanGeneratedCode:   true,
				BlockVulnerableCode: true,
				CheckPIILeakage:     true,
			},
		},
	})
	s.AddPolicy(models.AISecurityPolicy{
		APIVersion: "killaileak.io/v1",
		Kind:       "AISecurityPolicy",
		Metadata:   models.PolicyMetadata{Name: "strict-production", Namespace: "production"},
		Spec: models.PolicySpec{
			Scope: models.PolicyScope{Namespaces: []string{"production"}},
			Mode:  models.ModeEnforce,
			Providers: &models.ProviderPolicy{
				Allow: []string{"openai", "anthropic"},
				Deny:  []string{"*"},
			},
			Input: &models.InputPolicy{
				BlockPII:            true,
				BlockSecrets:        true,
				BlockInjectionAbove: 0.7,
			},
			Output: &models.OutputPolicy{
				BlockToxicAbove:     0.7,
				ScanGeneratedCode:   true,
				BlockVulnerableCode: true,
				CheckPIILeakage:     true,
				CheckPromptLeakage:  true,
			},
		},
	})
}
