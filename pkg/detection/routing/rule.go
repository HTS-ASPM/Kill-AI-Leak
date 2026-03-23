// Package routing provides guardrail rules for routing-stage decisions:
// GR-025 Data Residency Router, GR-026 EU Data Residency (GDPR),
// GR-027 Provider Failover, GR-028 Cost-Aware Routing,
// GR-029 Latency-Aware Routing, GR-030 Canary Routing,
// GR-031 Sensitive Data Routing Block, GR-032 HIPAA Routing Enforcement.
package routing

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// GR-025: Data Residency Router
// ---------------------------------------------------------------------------

// ResidencyRouterRule routes requests based on data classification.
type ResidencyRouterRule struct {
	mu  sync.RWMutex
	cfg residencyRouterConfig
}

type residencyRouterConfig struct {
	defaultRegion string
}

// NewResidencyRouter creates a GR-025 rule.
func NewResidencyRouter() *ResidencyRouterRule {
	return &ResidencyRouterRule{
		cfg: residencyRouterConfig{defaultRegion: "us-east-1"},
	}
}

func (r *ResidencyRouterRule) ID() string                    { return "GR-025" }
func (r *ResidencyRouterRule) Name() string                  { return "Data Residency Router" }
func (r *ResidencyRouterRule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *ResidencyRouterRule) Category() models.RuleCategory { return models.CategoryDataResidency }

func (r *ResidencyRouterRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	// Check if data classification metadata was set by compliance tagging.
	classification := "public"
	if v, ok := ctx.GetMetadata("data_classification"); ok {
		if s, ok := v.(string); ok {
			classification = s
		}
	}

	region := cfg.defaultRegion
	ctx.SetMetadata("routing_region", region)
	ctx.SetMetadata("data_classification_routing", classification)

	eval.Decision = models.DecisionLog
	eval.Confidence = 0
	eval.Reason = fmt.Sprintf("routing to region %q for %q data", region, classification)
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *ResidencyRouterRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["default_region"]; ok {
		if s, ok := v.(string); ok {
			r.cfg.defaultRegion = s
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-026: EU Data Residency (GDPR)
// ---------------------------------------------------------------------------

// EU-specific PII patterns.
var euPIIPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b[A-Z]{2}\d{2}\s?[\dA-Z]{4}\s?[\dA-Z]{4}\s?[\dA-Z]{4}`), // IBAN prefix
	regexp.MustCompile(`\+(?:30|31|32|33|34|39|40|43|44|45|46|47|48|49)\s?\d`),      // EU phone
	regexp.MustCompile(`\b(?:ATU|BE\d|DE\d{9}|FR[\dA-Z]{2}\d|NL\d{9}B)\b`),         // EU VAT
}

// GDPRRule implements GR-026.
type GDPRRule struct {
	mu  sync.RWMutex
	cfg gdprConfig
}

type gdprConfig struct {
	requiredRegions []string
	detectEUData    bool
}

// NewGDPR creates a GR-026 rule.
func NewGDPR() *GDPRRule {
	return &GDPRRule{
		cfg: gdprConfig{
			requiredRegions: []string{"eu-west-1", "eu-central-1"},
			detectEUData:    true,
		},
	}
}

func (r *GDPRRule) ID() string                    { return "GR-026" }
func (r *GDPRRule) Name() string                  { return "EU Data Residency (GDPR)" }
func (r *GDPRRule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *GDPRRule) Category() models.RuleCategory { return models.CategoryDataResidency }

func (r *GDPRRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	if !cfg.detectEUData {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "EU data detection disabled"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Scan prompt for EU data indicators.
	text := ctx.PromptText
	euDataFound := false
	for _, re := range euPIIPatterns {
		if re.MatchString(text) {
			euDataFound = true
			break
		}
	}

	if !euDataFound {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no EU personal data detected"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// EU data found -- check current routing region.
	currentRegion := ""
	if v, ok := ctx.GetMetadata("routing_region"); ok {
		if s, ok := v.(string); ok {
			currentRegion = s
		}
	}

	inEU := false
	for _, r := range cfg.requiredRegions {
		if strings.EqualFold(currentRegion, r) {
			inEU = true
			break
		}
	}

	if !inEU && currentRegion != "" {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 0.9
		eval.Reason = fmt.Sprintf("EU personal data detected but routing to non-EU region %q", currentRegion)
		eval.Findings = []models.Finding{{
			Type: "gdpr_violation", Value: currentRegion,
			Severity: "high", Confidence: 0.9,
		}}
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "EU data routing compliant"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *GDPRRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["required_regions"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return err
		}
		r.cfg.requiredRegions = list
	}
	if v, ok := cfg["detect_eu_data"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.detectEUData = b
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-027: Provider Failover
// ---------------------------------------------------------------------------

// FailoverRule implements GR-027.
type FailoverRule struct {
	mu  sync.RWMutex
	cfg failoverConfig
	// providerHealth tracks provider availability. true = healthy.
	health map[string]bool
}

type failoverConfig struct {
	failoverOrder []string
}

// NewFailover creates a GR-027 rule.
func NewFailover() *FailoverRule {
	return &FailoverRule{
		cfg: failoverConfig{
			failoverOrder: []string{"openai", "anthropic", "gemini"},
		},
		health: map[string]bool{
			"openai": true, "anthropic": true, "gemini": true,
		},
	}
}

func (r *FailoverRule) ID() string                    { return "GR-027" }
func (r *FailoverRule) Name() string                  { return "Provider Failover" }
func (r *FailoverRule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *FailoverRule) Category() models.RuleCategory { return models.CategoryAllowlist }

// SetProviderHealth updates the health status of a provider.
func (r *FailoverRule) SetProviderHealth(provider string, healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health[strings.ToLower(provider)] = healthy
}

func (r *FailoverRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	r.mu.RLock()
	cfg := r.cfg
	health := make(map[string]bool, len(r.health))
	for k, v := range r.health {
		health[k] = v
	}
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	provider := strings.ToLower(ctx.Provider)
	if provider == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no provider specified"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	if healthy, exists := health[provider]; exists && healthy {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("provider %q is healthy", provider)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Provider is unhealthy; suggest failover.
	for _, fallback := range cfg.failoverOrder {
		fb := strings.ToLower(fallback)
		if fb == provider {
			continue
		}
		if h, ok := health[fb]; ok && h {
			ctx.SetMetadata("failover_provider", fb)
			eval.Decision = models.DecisionModify
			eval.Confidence = 0.9
			eval.Reason = fmt.Sprintf("provider %q is unhealthy; failing over to %q", provider, fb)
			eval.Findings = []models.Finding{{
				Type: "failover", Value: fb,
				Severity: "medium", Confidence: 0.9,
			}}
			eval.LatencyMs = time.Since(start).Milliseconds()
			return eval, nil
		}
	}

	eval.Decision = models.DecisionBlock
	eval.Confidence = 1.0
	eval.Reason = fmt.Sprintf("provider %q is unhealthy and no healthy fallback available", provider)
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *FailoverRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["failover_order"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return err
		}
		r.cfg.failoverOrder = list
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-028: Cost-Aware Routing
// ---------------------------------------------------------------------------

// providerCostPerToken maps provider to approximate cost per 1K tokens (USD).
var providerCostPerToken = map[string]float64{
	"openai":    0.03,
	"anthropic": 0.015,
	"gemini":    0.01,
	"bedrock":   0.02,
	"azure":     0.03,
	"mistral":   0.008,
}

// CostRouteRule implements GR-028.
type CostRouteRule struct {
	mu  sync.RWMutex
	cfg costRouteConfig
}

type costRouteConfig struct {
	optimizeFor  string
	qualityFloor float64
}

// NewCostRoute creates a GR-028 rule.
func NewCostRoute() *CostRouteRule {
	return &CostRouteRule{
		cfg: costRouteConfig{optimizeFor: "cost", qualityFloor: 0.80},
	}
}

func (r *CostRouteRule) ID() string                    { return "GR-028" }
func (r *CostRouteRule) Name() string                  { return "Cost-Aware Routing" }
func (r *CostRouteRule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *CostRouteRule) Category() models.RuleCategory { return models.CategoryRateLimit }

func (r *CostRouteRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	provider := strings.ToLower(ctx.Provider)
	if provider == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no provider; cost routing not applicable"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	cost, known := providerCostPerToken[provider]
	if !known {
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.5
		eval.Reason = fmt.Sprintf("no cost data for provider %q", provider)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Find cheapest alternative.
	cheapest := provider
	cheapestCost := cost
	for p, c := range providerCostPerToken {
		if c < cheapestCost {
			cheapest = p
			cheapestCost = c
		}
	}

	if cheapest != provider && cost > cheapestCost*1.5 {
		ctx.SetMetadata("cost_suggestion", cheapest)
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.6
		eval.Reason = fmt.Sprintf("provider %q costs $%.4f/1Kt; %q is cheaper at $%.4f/1Kt",
			provider, cost, cheapest, cheapestCost)
		eval.Findings = []models.Finding{{
			Type: "cost_optimization", Value: cheapest,
			Severity: "low", Confidence: 0.6,
		}}
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("provider %q cost $%.4f/1Kt is acceptable", provider, cost)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *CostRouteRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["optimize_for"]; ok {
		if s, ok := v.(string); ok {
			r.cfg.optimizeFor = s
		}
	}
	if v, ok := cfg["quality_floor"]; ok {
		if f, ok := v.(float64); ok {
			r.cfg.qualityFloor = f
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-029: Latency-Aware Routing
// ---------------------------------------------------------------------------

// LatencyRouteRule implements GR-029.
type LatencyRouteRule struct {
	mu      sync.RWMutex
	cfg     latencyConfig
	latency map[string]time.Duration // provider -> observed p95 latency
}

type latencyConfig struct {
	optimizeFor   string
	latencyWindow time.Duration
}

// NewLatencyRoute creates a GR-029 rule.
func NewLatencyRoute() *LatencyRouteRule {
	return &LatencyRouteRule{
		cfg: latencyConfig{
			optimizeFor:   "latency",
			latencyWindow: 5 * time.Minute,
		},
		latency: map[string]time.Duration{
			"openai":    200 * time.Millisecond,
			"anthropic": 180 * time.Millisecond,
			"gemini":    250 * time.Millisecond,
		},
	}
}

func (r *LatencyRouteRule) ID() string                    { return "GR-029" }
func (r *LatencyRouteRule) Name() string                  { return "Latency-Aware Routing" }
func (r *LatencyRouteRule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *LatencyRouteRule) Category() models.RuleCategory { return models.CategoryRateLimit }

// RecordLatency records observed latency for a provider.
func (r *LatencyRouteRule) RecordLatency(provider string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.latency[strings.ToLower(provider)] = d
}

func (r *LatencyRouteRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	r.mu.RLock()
	latencies := make(map[string]time.Duration, len(r.latency))
	for k, v := range r.latency {
		latencies[k] = v
	}
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	provider := strings.ToLower(ctx.Provider)
	if provider == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no provider specified"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	currentLatency := latencies[provider]
	fastest := provider
	fastestLatency := currentLatency

	for p, l := range latencies {
		if l < fastestLatency {
			fastest = p
			fastestLatency = l
		}
	}

	if fastest != provider && currentLatency > fastestLatency*2 {
		ctx.SetMetadata("latency_suggestion", fastest)
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.5
		eval.Reason = fmt.Sprintf("provider %q p95=%v; %q is faster at p95=%v",
			provider, currentLatency, fastest, fastestLatency)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("provider %q latency (%v) is acceptable", provider, currentLatency)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *LatencyRouteRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["latency_window"]; ok {
		if s, ok := v.(string); ok {
			d, err := time.ParseDuration(s)
			if err != nil {
				return err
			}
			r.cfg.latencyWindow = d
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-030: Canary Routing
// ---------------------------------------------------------------------------

// CanaryRule implements GR-030.
type CanaryRule struct {
	mu  sync.RWMutex
	cfg canaryConfig
	rng *rand.Rand
}

type canaryConfig struct {
	canaryPercentage int
	canaryProvider   string
	canaryModel      string
}

// NewCanary creates a GR-030 rule.
func NewCanary() *CanaryRule {
	return &CanaryRule{
		cfg: canaryConfig{canaryPercentage: 5},
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (r *CanaryRule) ID() string                    { return "GR-030" }
func (r *CanaryRule) Name() string                  { return "Canary Routing" }
func (r *CanaryRule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *CanaryRule) Category() models.RuleCategory { return models.CategoryAllowlist }

func (r *CanaryRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	if cfg.canaryPercentage <= 0 || (cfg.canaryProvider == "" && cfg.canaryModel == "") {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "canary routing not configured"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	r.mu.Lock()
	roll := r.rng.Intn(100)
	r.mu.Unlock()

	if roll < cfg.canaryPercentage {
		if cfg.canaryProvider != "" {
			ctx.SetMetadata("canary_provider", cfg.canaryProvider)
		}
		if cfg.canaryModel != "" {
			ctx.SetMetadata("canary_model", cfg.canaryModel)
		}
		eval.Decision = models.DecisionModify
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("canary: routing to %s/%s (%d%% canary traffic)",
			cfg.canaryProvider, cfg.canaryModel, cfg.canaryPercentage)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "not selected for canary routing"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *CanaryRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["canary_percentage"]; ok {
		switch n := v.(type) {
		case float64:
			r.cfg.canaryPercentage = int(n)
		case int:
			r.cfg.canaryPercentage = n
		}
	}
	if v, ok := cfg["canary_provider"]; ok {
		if s, ok := v.(string); ok {
			r.cfg.canaryProvider = s
		}
	}
	if v, ok := cfg["canary_model"]; ok {
		if s, ok := v.(string); ok {
			r.cfg.canaryModel = s
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-031: Sensitive Data Routing Block
// ---------------------------------------------------------------------------

// SensitiveRouteRule implements GR-031.
type SensitiveRouteRule struct {
	mu  sync.RWMutex
	cfg sensitiveRouteConfig
}

type sensitiveRouteConfig struct {
	sensitiveClassifications []string
	approvedProviders        []string
}

// NewSensitiveRoute creates a GR-031 rule.
func NewSensitiveRoute() *SensitiveRouteRule {
	return &SensitiveRouteRule{
		cfg: sensitiveRouteConfig{
			sensitiveClassifications: []string{"confidential", "restricted"},
			approvedProviders:        []string{"bedrock", "azure_openai"},
		},
	}
}

func (r *SensitiveRouteRule) ID() string                    { return "GR-031" }
func (r *SensitiveRouteRule) Name() string                  { return "Sensitive Data Routing Block" }
func (r *SensitiveRouteRule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *SensitiveRouteRule) Category() models.RuleCategory { return models.CategoryDataResidency }

func (r *SensitiveRouteRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	// Check data classification.
	classification := ""
	if v, ok := ctx.GetMetadata("data_classification"); ok {
		if s, ok := v.(string); ok {
			classification = s
		}
	}

	isSensitive := false
	for _, sc := range cfg.sensitiveClassifications {
		if strings.EqualFold(classification, sc) {
			isSensitive = true
			break
		}
	}

	if !isSensitive {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("data classification %q is not sensitive", classification)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Check if provider is approved for sensitive data.
	provider := strings.ToLower(ctx.Provider)
	approved := false
	for _, ap := range cfg.approvedProviders {
		if strings.EqualFold(provider, ap) {
			approved = true
			break
		}
	}

	if !approved {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 0.95
		eval.Reason = fmt.Sprintf("sensitive data (%s) cannot be routed to unapproved provider %q", classification, provider)
		eval.Findings = []models.Finding{{
			Type: "sensitive_data_routing", Value: provider,
			Severity: "high", Confidence: 0.95,
		}}
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("provider %q is approved for %s data", provider, classification)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *SensitiveRouteRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["sensitive_classifications"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return err
		}
		r.cfg.sensitiveClassifications = list
	}
	if v, ok := cfg["approved_providers"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return err
		}
		r.cfg.approvedProviders = list
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-032: HIPAA Routing Enforcement
// ---------------------------------------------------------------------------

// PHI detection patterns.
var phiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:patient\s+(?:id|name|dob|mrn)|medical\s+record|diagnosis|prescription|icd[- ]?\d+|cpt[- ]?\d+)\b`),
	regexp.MustCompile(`(?i)\b(?:hipaa|phi|protected\s+health|health\s+information)\b`),
	regexp.MustCompile(`(?i)\b\d{3}-\d{2}-\d{4}\b`), // SSN (common in medical)
}

// HIPAARule implements GR-032.
type HIPAARule struct {
	mu  sync.RWMutex
	cfg hipaaConfig
}

type hipaaConfig struct {
	hipaaProviders []string
	detectPHI      bool
}

// NewHIPAA creates a GR-032 rule.
func NewHIPAA() *HIPAARule {
	return &HIPAARule{
		cfg: hipaaConfig{
			hipaaProviders: []string{"bedrock", "azure_openai"},
			detectPHI:      true,
		},
	}
}

func (r *HIPAARule) ID() string                    { return "GR-032" }
func (r *HIPAARule) Name() string                  { return "HIPAA Routing Enforcement" }
func (r *HIPAARule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *HIPAARule) Category() models.RuleCategory { return models.CategoryCompliance }

func (r *HIPAARule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	if !cfg.detectPHI {
		eval.Decision = models.DecisionAllow
		eval.Reason = "PHI detection disabled"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	text := ctx.PromptText
	phiFound := false
	var findings []models.Finding
	for _, re := range phiPatterns {
		if matches := re.FindAllString(text, 3); len(matches) > 0 {
			phiFound = true
			for _, m := range matches {
				findings = append(findings, models.Finding{
					Type: "phi_indicator", Value: m,
					Severity: "high", Confidence: 0.8,
				})
			}
		}
	}

	if !phiFound {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no PHI detected"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	provider := strings.ToLower(ctx.Provider)
	approved := false
	for _, hp := range cfg.hipaaProviders {
		if strings.EqualFold(provider, hp) {
			approved = true
			break
		}
	}

	eval.Findings = findings
	if !approved {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 0.9
		eval.Reason = fmt.Sprintf("PHI detected but provider %q is not HIPAA-eligible", provider)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("PHI detected; provider %q is HIPAA-eligible", provider)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *HIPAARule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["hipaa_providers"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return err
		}
		r.cfg.hipaaProviders = list
	}
	if v, ok := cfg["detect_phi"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.detectPHI = b
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseStringList(v any) ([]string, error) {
	switch vv := v.(type) {
	case []string:
		return vv, nil
	case []any:
		out := make([]string, 0, len(vv))
		for _, item := range vv {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("expected string in list, got %T", item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected []string, got %T", v)
	}
}
