// Package network provides a guardrail rule that restricts access based on
// source IP address, CIDR ranges, and geographic location.
package network

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Detector implements guardrails.Rule for GR-006 Network Restriction.
type Detector struct {
	mu  sync.RWMutex
	cfg detectorConfig
}

type detectorConfig struct {
	allowedCIDRs   []*net.IPNet
	deniedCIDRs    []*net.IPNet
	deniedCountries map[string]bool
}

// New creates a new network restriction detector with sensible defaults.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{
			deniedCountries: make(map[string]bool),
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-006" }
func (d *Detector) Name() string                  { return "Network Restriction" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StagePreInput }
func (d *Detector) Category() models.RuleCategory { return models.CategoryAllowlist }

// Evaluate checks the source IP from EvalContext metadata against configured
// allow/deny CIDR lists.
func (d *Detector) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	eval := &models.GuardrailEvaluation{
		RuleID:   d.ID(),
		RuleName: d.Name(),
		Stage:    d.Stage(),
	}

	// Extract remote_addr from metadata.
	rawAddr, ok := ctx.GetMetadata("remote_addr")
	if !ok {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = "no remote_addr in metadata; skipping network check"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	addrStr, ok := rawAddr.(string)
	if !ok || addrStr == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = "remote_addr metadata is not a valid string"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Strip port if present (e.g. "192.168.1.1:8080").
	host := addrStr
	if h, _, err := net.SplitHostPort(addrStr); err == nil {
		host = h
	}

	ip := net.ParseIP(host)
	if ip == nil {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("could not parse IP from remote_addr %q", addrStr)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	var findings []models.Finding

	// Check denied CIDRs first.
	for _, cidr := range cfg.deniedCIDRs {
		if cidr.Contains(ip) {
			findings = append(findings, models.Finding{
				Type:       "denied_cidr",
				Value:      ip.String(),
				Severity:   "high",
				Confidence: 1.0,
			})
			eval.Decision = models.DecisionBlock
			eval.Confidence = 1.0
			eval.Reason = fmt.Sprintf("source IP %s is in denied CIDR %s", ip, cidr)
			eval.Findings = findings
			eval.LatencyMs = time.Since(start).Milliseconds()
			return eval, nil
		}
	}

	// If allowed CIDRs are configured, IP must match at least one.
	if len(cfg.allowedCIDRs) > 0 {
		allowed := false
		for _, cidr := range cfg.allowedCIDRs {
			if cidr.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			findings = append(findings, models.Finding{
				Type:       "not_in_allowlist",
				Value:      ip.String(),
				Severity:   "high",
				Confidence: 1.0,
			})
			eval.Decision = models.DecisionBlock
			eval.Confidence = 1.0
			eval.Reason = fmt.Sprintf("source IP %s is not in any allowed CIDR range", ip)
			eval.Findings = findings
			eval.LatencyMs = time.Since(start).Milliseconds()
			return eval, nil
		}
	}

	// Check geographic restriction via metadata hint.
	if len(cfg.deniedCountries) > 0 {
		if countryRaw, ok := ctx.GetMetadata("geo_country"); ok {
			if country, ok := countryRaw.(string); ok {
				if cfg.deniedCountries[strings.ToUpper(country)] {
					findings = append(findings, models.Finding{
						Type:       "denied_country",
						Value:      country,
						Severity:   "high",
						Confidence: 0.9,
					})
					eval.Decision = models.DecisionBlock
					eval.Confidence = 0.9
					eval.Reason = fmt.Sprintf("source country %q is denied", country)
					eval.Findings = findings
					eval.LatencyMs = time.Since(start).Milliseconds()
					return eval, nil
				}
			}
		}
	}

	// Check for known datacenter IP ranges (simple heuristic).
	if isKnownDatacenterIP(ip) {
		findings = append(findings, models.Finding{
			Type:       "datacenter_ip",
			Value:      ip.String(),
			Severity:   "medium",
			Confidence: 0.7,
		})
	}

	if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.7
		eval.Reason = fmt.Sprintf("source IP %s matched datacenter range", ip)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = fmt.Sprintf("source IP %s passed all network checks", ip)
	}
	eval.Findings = findings
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "allowed_cidrs" ([]string): list of allowed CIDR ranges
//   - "denied_cidrs" ([]string): list of denied CIDR ranges
//   - "denied_countries" ([]string): list of denied country codes
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["allowed_cidrs"]; ok {
		cidrs, err := parseCIDRList(v)
		if err != nil {
			return fmt.Errorf("network: allowed_cidrs: %w", err)
		}
		d.cfg.allowedCIDRs = cidrs
	}

	if v, ok := cfg["denied_cidrs"]; ok {
		cidrs, err := parseCIDRList(v)
		if err != nil {
			return fmt.Errorf("network: denied_cidrs: %w", err)
		}
		d.cfg.deniedCIDRs = cidrs
	}

	if v, ok := cfg["denied_countries"]; ok {
		countries, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("network: denied_countries: %w", err)
		}
		d.cfg.deniedCountries = make(map[string]bool, len(countries))
		for _, c := range countries {
			d.cfg.deniedCountries[strings.ToUpper(c)] = true
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// knownDatacenterCIDRs contains a sample of well-known cloud/datacenter
// IP ranges. In production this would be loaded from a regularly updated
// feed.
var knownDatacenterCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		// AWS partial ranges
		"3.0.0.0/8",
		"52.0.0.0/8",
		"54.0.0.0/8",
		// GCP partial ranges
		"35.190.0.0/16",
		"35.240.0.0/13",
		// Azure partial ranges
		"13.64.0.0/11",
		"40.64.0.0/10",
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err == nil {
			knownDatacenterCIDRs = append(knownDatacenterCIDRs, ipnet)
		}
	}
}

func isKnownDatacenterIP(ip net.IP) bool {
	for _, cidr := range knownDatacenterCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDRList(v any) ([]*net.IPNet, error) {
	strs, err := parseStringList(v)
	if err != nil {
		return nil, err
	}
	var nets []*net.IPNet
	for _, s := range strs {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		nets = append(nets, ipnet)
	}
	return nets, nil
}

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
