// Package shadow detects and tracks shadow AI usage -- AI services and
// local LLM runners that are not in the organisation's approved inventory.
// It assigns risk scores based on provider reputation, data volume, PII
// exposure, and ownership, and generates alerts when new shadow services
// are discovered.
package shadow

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/fingerprint"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// DetectorConfig holds tunables for the shadow AI detector.
type DetectorConfig struct {
	// ApprovedProviders is the set of provider names (matching the
	// fingerprint database) that are explicitly approved.
	ApprovedProviders map[string]bool

	// ApprovedDomains is an additional set of domain substrings that are
	// considered approved even if they don't appear in the fingerprint DB.
	ApprovedDomains map[string]bool

	// RiskWeights controls how much each factor contributes to the overall
	// risk score (0-1 each, summed and normalised).
	RiskWeights RiskWeights

	// AlertCooldown prevents duplicate alerts for the same service within
	// this window. Default: 1 hour.
	AlertCooldown time.Duration

	// KnownLocalRunners is the list of process names that indicate a local
	// LLM runner. Default list is populated by DefaultDetectorConfig.
	KnownLocalRunners []string

	// Logger is the structured logger. If nil slog.Default() is used.
	Logger *slog.Logger
}

// RiskWeights controls relative contribution of each risk factor.
type RiskWeights struct {
	UnknownProvider float64 // Provider not in fingerprint DB
	HighDataVolume  float64 // Large amount of data transferred
	PIIExposure     float64 // PII detected in traffic
	NoOwner         float64 // No identifiable team/owner
}

// DefaultDetectorConfig returns a config with sensible defaults.
func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		ApprovedProviders: make(map[string]bool),
		ApprovedDomains:   make(map[string]bool),
		RiskWeights: RiskWeights{
			UnknownProvider: 0.35,
			HighDataVolume:  0.20,
			PIIExposure:     0.30,
			NoOwner:         0.15,
		},
		AlertCooldown: 1 * time.Hour,
		KnownLocalRunners: []string{
			"ollama",
			"llama.cpp",
			"llama-server",
			"llamafile",
			"vllm",
			"text-generation-launcher",
			"tgi",
			"localai",
			"koboldcpp",
			"lmstudio",
			"jan",
			"gpt4all",
		},
		Logger: slog.Default(),
	}
}

// ---------------------------------------------------------------------------
// Shadow service tracking
// ---------------------------------------------------------------------------

// ShadowService represents a detected unapproved AI service.
type ShadowService struct {
	// ID is a stable identifier derived from provider + endpoint.
	ID string `json:"id"`

	// Provider is the resolved provider name, or "unknown" if not in the
	// fingerprint database.
	Provider string `json:"provider"`

	// Endpoint is the target host/domain.
	Endpoint string `json:"endpoint"`

	// Model is the most recently observed model, if known.
	Model string `json:"model,omitempty"`

	// FirstSeen is the timestamp of the first observed call.
	FirstSeen time.Time `json:"first_seen"`

	// LastSeen is the timestamp of the most recent observed call.
	LastSeen time.Time `json:"last_seen"`

	// CallCount is the total number of observed calls.
	CallCount int64 `json:"call_count"`

	// DataVolumeBytes is the total approximate data transferred.
	DataVolumeBytes int64 `json:"data_volume_bytes"`

	// PIITypes lists the types of PII detected in traffic.
	PIITypes map[string]int `json:"pii_types,omitempty"`

	// Actors maps actor IDs to the number of calls they made.
	Actors map[string]int64 `json:"actors,omitempty"`

	// Namespaces tracks which namespaces are calling this service.
	Namespaces map[string]bool `json:"namespaces,omitempty"`

	// RiskScore is the computed risk score (0.0 - 1.0).
	RiskScore float64 `json:"risk_score"`

	// RiskFactors describes what contributes to the risk score.
	RiskFactors []string `json:"risk_factors,omitempty"`

	// IsLocalRunner is true if this was detected as a local LLM process.
	IsLocalRunner bool `json:"is_local_runner,omitempty"`
}

// ---------------------------------------------------------------------------
// Alert types
// ---------------------------------------------------------------------------

// AlertSeverity classifies shadow AI alert severity.
type AlertSeverity string

const (
	AlertInfo     AlertSeverity = "info"
	AlertWarning  AlertSeverity = "warning"
	AlertCritical AlertSeverity = "critical"
)

// Alert represents a shadow AI discovery or risk alert.
type Alert struct {
	ID          string        `json:"id"`
	Timestamp   time.Time     `json:"timestamp"`
	Severity    AlertSeverity `json:"severity"`
	ServiceID   string        `json:"service_id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Suggestion  string        `json:"suggestion,omitempty"`
}

// AlertHandler is a callback for alert delivery.
type AlertHandler func(alert Alert)

// ---------------------------------------------------------------------------
// ShadowAIDetector
// ---------------------------------------------------------------------------

// ShadowAIDetector monitors events for unapproved AI service usage and
// tracks shadow services. All public methods are safe for concurrent use.
type ShadowAIDetector struct {
	cfg DetectorConfig

	mu       sync.RWMutex
	services map[string]*ShadowService // keyed by service ID
	alerts   []Alert
	lastAlert map[string]time.Time      // service ID -> last alert time

	fingerprintMatcher *fingerprint.Matcher
	alertHandler       AlertHandler

	logger *slog.Logger
}

// NewShadowAIDetector creates a new detector with the given configuration.
func NewShadowAIDetector(cfg DetectorConfig) *ShadowAIDetector {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &ShadowAIDetector{
		cfg:                cfg,
		services:           make(map[string]*ShadowService),
		alerts:             make([]Alert, 0, 64),
		lastAlert:          make(map[string]time.Time),
		fingerprintMatcher: fingerprint.NewMatcher(),
		logger:             cfg.Logger,
	}
}

// OnAlert registers a callback that is invoked whenever a new alert is
// generated. There can be at most one handler; setting a new one replaces
// the previous one.
func (d *ShadowAIDetector) OnAlert(handler AlertHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.alertHandler = handler
}

// ---------------------------------------------------------------------------
// Event processing
// ---------------------------------------------------------------------------

// ProcessEvent examines an event and determines whether the target AI
// service is in the approved inventory. If NOT approved, the service is
// flagged as shadow AI and tracked. Returns true if the event was flagged.
func (d *ShadowAIDetector) ProcessEvent(event *models.Event) bool {
	if event == nil {
		return false
	}

	// Only process events that target an LLM provider.
	if event.Target.Type != models.TargetLLMProvider {
		return false
	}

	endpoint := event.Target.Endpoint
	provider := event.Target.Provider

	// Resolve provider if not set.
	if provider == "" {
		provider = fingerprint.ProviderForDomain(endpoint)
	}

	// Check if this provider/endpoint is approved.
	if d.isApproved(provider, endpoint) {
		return false
	}

	// This is shadow AI. Track it.
	svcID := d.serviceID(provider, endpoint)

	d.mu.Lock()
	svc, exists := d.services[svcID]
	if !exists {
		svc = &ShadowService{
			ID:          svcID,
			Provider:    provider,
			Endpoint:    endpoint,
			FirstSeen:   event.Timestamp,
			PIITypes:    make(map[string]int),
			Actors:      make(map[string]int64),
			Namespaces:  make(map[string]bool),
		}
		d.services[svcID] = svc
	}

	svc.LastSeen = event.Timestamp
	svc.CallCount++

	if event.Target.Model != "" {
		svc.Model = event.Target.Model
	}

	// Estimate data volume from token counts.
	estimatedBytes := int64((event.Content.TokensInput + event.Content.TokensOutput) * 4)
	svc.DataVolumeBytes += estimatedBytes

	// Track PII.
	for _, piiType := range event.Content.PIIDetected {
		svc.PIITypes[piiType]++
	}

	// Track actors and namespaces.
	if event.Actor.ID != "" {
		svc.Actors[event.Actor.ID]++
	}
	if event.Actor.Namespace != "" {
		svc.Namespaces[event.Actor.Namespace] = true
	}

	// Recompute risk score.
	svc.RiskScore, svc.RiskFactors = d.computeRiskScore(svc)

	// Determine if we should alert.
	shouldAlert := !exists || d.shouldAlert(svcID)
	d.mu.Unlock()

	if shouldAlert {
		d.generateAlert(svc, !exists)
	}

	d.logger.Debug("shadow AI event processed",
		"service_id", svcID,
		"provider", provider,
		"endpoint", endpoint,
		"call_count", svc.CallCount,
		"risk_score", svc.RiskScore,
	)

	return true
}

// ProcessLocalRunner checks if a process name matches a known local LLM
// runner and tracks it as shadow AI. Returns true if it matched.
func (d *ShadowAIDetector) ProcessLocalRunner(processName string, pid int, actor models.Actor) bool {
	processLower := strings.ToLower(processName)
	matched := false
	for _, runner := range d.cfg.KnownLocalRunners {
		if strings.Contains(processLower, strings.ToLower(runner)) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	svcID := fmt.Sprintf("local:%s:%d", processName, pid)

	d.mu.Lock()
	svc, exists := d.services[svcID]
	if !exists {
		svc = &ShadowService{
			ID:            svcID,
			Provider:      "local:" + processName,
			Endpoint:      fmt.Sprintf("localhost (pid %d)", pid),
			FirstSeen:     time.Now(),
			PIITypes:      make(map[string]int),
			Actors:        make(map[string]int64),
			Namespaces:    make(map[string]bool),
			IsLocalRunner: true,
		}
		d.services[svcID] = svc
	}
	svc.LastSeen = time.Now()
	svc.CallCount++

	if actor.ID != "" {
		svc.Actors[actor.ID]++
	}
	if actor.Namespace != "" {
		svc.Namespaces[actor.Namespace] = true
	}

	svc.RiskScore, svc.RiskFactors = d.computeRiskScore(svc)
	shouldAlert := !exists
	d.mu.Unlock()

	if shouldAlert {
		d.generateAlert(svc, true)
	}

	return true
}

// CheckDomain examines a domain to see if it is a new, unapproved AI API
// endpoint not in the fingerprint database. Returns true if flagged.
func (d *ShadowAIDetector) CheckDomain(domain string) bool {
	// If it is a known approved domain, skip.
	if d.isDomainApproved(domain) {
		return false
	}

	// If it matches the fingerprint DB, the provider is known.
	provider := fingerprint.ProviderForDomain(domain)
	if provider != "" {
		// Known provider but not approved -- track it.
		svcID := d.serviceID(provider, domain)
		d.mu.Lock()
		if _, exists := d.services[svcID]; !exists {
			svc := &ShadowService{
				ID:         svcID,
				Provider:   provider,
				Endpoint:   domain,
				FirstSeen:  time.Now(),
				PIITypes:   make(map[string]int),
				Actors:     make(map[string]int64),
				Namespaces: make(map[string]bool),
			}
			svc.RiskScore, svc.RiskFactors = d.computeRiskScore(svc)
			d.services[svcID] = svc
			d.mu.Unlock()
			d.generateAlert(svc, true)
			return true
		}
		d.mu.Unlock()
		return false
	}

	// Not in fingerprint DB at all -- could be a new AI provider.
	// Flag as unknown for manual review.
	return d.flagUnknownDomain(domain)
}

// flagUnknownDomain records an unknown domain that might be a new AI API.
func (d *ShadowAIDetector) flagUnknownDomain(domain string) bool {
	svcID := "unknown:" + strings.ToLower(domain)

	d.mu.Lock()
	if _, exists := d.services[svcID]; exists {
		d.mu.Unlock()
		return false
	}
	svc := &ShadowService{
		ID:         svcID,
		Provider:   "unknown",
		Endpoint:   domain,
		FirstSeen:  time.Now(),
		PIITypes:   make(map[string]int),
		Actors:     make(map[string]int64),
		Namespaces: make(map[string]bool),
	}
	svc.RiskScore = d.cfg.RiskWeights.UnknownProvider // Starts at the unknown-provider base.
	svc.RiskFactors = []string{"unknown_provider"}
	d.services[svcID] = svc
	d.mu.Unlock()

	d.generateAlert(svc, true)
	return true
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// GetShadowServices returns a snapshot of all currently tracked shadow AI
// services, sorted by risk score descending.
func (d *ShadowAIDetector) GetShadowServices() []ShadowService {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]ShadowService, 0, len(d.services))
	for _, svc := range d.services {
		result = append(result, *svc)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].RiskScore > result[j].RiskScore
	})

	return result
}

// GetShadowService returns a single shadow service by ID.
func (d *ShadowAIDetector) GetShadowService(id string) (ShadowService, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	svc, ok := d.services[id]
	if !ok {
		return ShadowService{}, false
	}
	return *svc, true
}

// GetAlerts returns all generated alerts.
func (d *ShadowAIDetector) GetAlerts() []Alert {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Alert, len(d.alerts))
	copy(out, d.alerts)
	return out
}

// SuggestEnrollment generates a suggestion for routing a shadow AI service
// through the inline gateway for policy enforcement.
func (d *ShadowAIDetector) SuggestEnrollment(serviceID string) (string, error) {
	d.mu.RLock()
	svc, ok := d.services[serviceID]
	d.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("shadow service %q not found", serviceID)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Enrollment Suggestion for Shadow AI Service: %s\n\n", svc.ID))
	sb.WriteString(fmt.Sprintf("Provider: %s\n", svc.Provider))
	sb.WriteString(fmt.Sprintf("Endpoint: %s\n", svc.Endpoint))
	sb.WriteString(fmt.Sprintf("Risk Score: %.2f\n", svc.RiskScore))
	sb.WriteString(fmt.Sprintf("Call Count: %d\n", svc.CallCount))
	sb.WriteString(fmt.Sprintf("First Seen: %s\n\n", svc.FirstSeen.Format(time.RFC3339)))

	sb.WriteString("## Recommended Actions\n\n")
	sb.WriteString("1. Route traffic through the Kill-AI-Leak inline gateway:\n")
	sb.WriteString(fmt.Sprintf("   - Redirect DNS for %s to the gateway\n", svc.Endpoint))
	sb.WriteString("   - Or configure an egress NetworkPolicy to force traffic through the proxy\n\n")

	sb.WriteString("2. Apply an AISecurityPolicy:\n")
	sb.WriteString("   ```yaml\n")
	sb.WriteString("   apiVersion: killaileak.io/v1\n")
	sb.WriteString("   kind: AISecurityPolicy\n")
	sb.WriteString("   metadata:\n")
	sb.WriteString(fmt.Sprintf("     name: shadow-%s\n", sanitizeID(svc.Provider)))

	namespaces := make([]string, 0, len(svc.Namespaces))
	for ns := range svc.Namespaces {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	if len(namespaces) > 0 {
		sb.WriteString("   spec:\n")
		sb.WriteString("     scope:\n")
		sb.WriteString("       namespaces:\n")
		for _, ns := range namespaces {
			sb.WriteString(fmt.Sprintf("       - %s\n", ns))
		}
	}
	sb.WriteString("   ```\n\n")

	if len(svc.PIITypes) > 0 {
		sb.WriteString("3. PII was detected in traffic -- enable anonymization rules.\n")
	}

	return sb.String(), nil
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

// isApproved checks whether a provider/endpoint pair is in the approved
// set.
func (d *ShadowAIDetector) isApproved(provider, endpoint string) bool {
	if provider != "" && d.cfg.ApprovedProviders[provider] {
		return true
	}
	return d.isDomainApproved(endpoint)
}

// isDomainApproved checks whether a domain is in the approved domains set.
func (d *ShadowAIDetector) isDomainApproved(domain string) bool {
	domain = strings.ToLower(domain)
	for approvedDomain := range d.cfg.ApprovedDomains {
		if strings.Contains(domain, strings.ToLower(approvedDomain)) {
			return true
		}
	}
	return false
}

// serviceID generates a stable identifier for a shadow service.
func (d *ShadowAIDetector) serviceID(provider, endpoint string) string {
	if provider == "" {
		provider = "unknown"
	}
	return fmt.Sprintf("%s:%s", strings.ToLower(provider), strings.ToLower(endpoint))
}

// computeRiskScore calculates the risk score for a shadow service.
func (d *ShadowAIDetector) computeRiskScore(svc *ShadowService) (float64, []string) {
	score := 0.0
	factors := make([]string, 0, 4)
	w := d.cfg.RiskWeights

	// Unknown provider contributes risk.
	if svc.Provider == "" || svc.Provider == "unknown" || svc.IsLocalRunner {
		score += w.UnknownProvider
		factors = append(factors, "unknown_provider")
	}

	// High data volume (>10 MB).
	if svc.DataVolumeBytes > 10*1024*1024 {
		score += w.HighDataVolume
		factors = append(factors, "high_data_volume")
	}

	// PII exposure.
	if len(svc.PIITypes) > 0 {
		score += w.PIIExposure
		factors = append(factors, fmt.Sprintf("pii_exposure(%d types)", len(svc.PIITypes)))
	}

	// No owner / no namespace information.
	if len(svc.Namespaces) == 0 && len(svc.Actors) == 0 {
		score += w.NoOwner
		factors = append(factors, "no_owner")
	}

	// Normalise to [0, 1].
	if score > 1.0 {
		score = 1.0
	}

	return score, factors
}

// shouldAlert checks whether enough time has passed since the last alert
// for this service.
func (d *ShadowAIDetector) shouldAlert(serviceID string) bool {
	last, ok := d.lastAlert[serviceID]
	if !ok {
		return true
	}
	return time.Since(last) > d.cfg.AlertCooldown
}

// generateAlert creates an alert for a shadow AI service.
func (d *ShadowAIDetector) generateAlert(svc *ShadowService, isNew bool) {
	severity := AlertWarning
	if svc.RiskScore >= 0.7 {
		severity = AlertCritical
	} else if svc.RiskScore < 0.3 {
		severity = AlertInfo
	}

	title := "Shadow AI service detected"
	if isNew {
		title = "New shadow AI service discovered"
	}
	if svc.IsLocalRunner {
		title = "Local LLM runner detected"
	}

	alert := Alert{
		ID:        fmt.Sprintf("shadow-%s-%d", svc.ID, time.Now().UnixNano()),
		Timestamp: time.Now(),
		Severity:  severity,
		ServiceID: svc.ID,
		Title:     title,
		Description: fmt.Sprintf(
			"Provider=%s Endpoint=%s Calls=%d DataVolume=%d bytes RiskScore=%.2f Factors=%v",
			svc.Provider, svc.Endpoint, svc.CallCount,
			svc.DataVolumeBytes, svc.RiskScore, svc.RiskFactors,
		),
		Suggestion: "Route through inline gateway for policy enforcement. Run SuggestEnrollment() for details.",
	}

	d.mu.Lock()
	d.alerts = append(d.alerts, alert)
	d.lastAlert[svc.ID] = time.Now()
	handler := d.alertHandler
	d.mu.Unlock()

	if handler != nil {
		handler(alert)
	}

	d.logger.Warn("shadow AI alert",
		"alert_id", alert.ID,
		"severity", alert.Severity,
		"service_id", svc.ID,
		"title", alert.Title,
	)
}

// sanitizeID produces a DNS-safe name from a provider string.
func sanitizeID(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, s)
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}
