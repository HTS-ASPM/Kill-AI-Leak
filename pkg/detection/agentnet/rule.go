// Package agentnet provides a guardrail rule (GR-052) that controls outbound
// network access for AI agents, preventing unauthorized data exfiltration
// to blocked destinations.
package agentnet

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Patterns that indicate network access requests in agent outputs.
var networkAccessPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	{"url_access", regexp.MustCompile(`(?i)(?:fetch|get|post|put|delete|request|curl|wget|http\.(?:Get|Post))\s*\(?["']?(https?://[^\s"'<>]+)`)},
	{"api_call", regexp.MustCompile(`(?i)(?:api\.(?:get|post|put)|requests\.(?:get|post)|axios\.(?:get|post))\s*\(\s*["'](https?://[^\s"']+)`)},
	{"webhook", regexp.MustCompile(`(?i)(?:webhook|callback|notify)\s*(?:url|endpoint)?[:=]\s*["']?(https?://[^\s"']+)`)},
	{"socket_connect", regexp.MustCompile(`(?i)(?:socket\.connect|net\.Dial|connect)\s*\(\s*["']([^"']+:\d+)`)},
}

// Rule implements guardrails.Rule for GR-052 Agent Network Egress Control.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	defaultDenyOutbound  bool
	blockedDestinations  []string
	allowedDestinations  []string
}

// New creates a GR-052 rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			defaultDenyOutbound: false,
			blockedDestinations: []string{"*.onion", "pastebin.com", "paste.ee", "hastebin.com"},
		},
	}
}

func (r *Rule) ID() string                    { return "GR-052" }
func (r *Rule) Name() string                  { return "Agent Network Egress Control" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageBehavioral }
func (r *Rule) Category() models.RuleCategory { return models.CategoryAgentControl }

func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	// Scan both prompt and response for network access indicators.
	textToScan := ctx.PromptText + " " + ctx.ResponseText
	if textToScan == " " {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no text to scan for network access"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	var findings []models.Finding
	maxConfidence := 0.0

	for _, pat := range networkAccessPatterns {
		matches := pat.re.FindAllStringSubmatch(textToScan, 10)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			destination := m[1]

			blocked := isBlockedDestination(destination, cfg.blockedDestinations)
			allowed := !cfg.defaultDenyOutbound || isAllowedDestination(destination, cfg.allowedDestinations)

			if blocked {
				confidence := 0.95
				findings = append(findings, models.Finding{
					Type:       "blocked_destination",
					Value:      destination,
					Severity:   "high",
					Confidence: confidence,
				})
				if confidence > maxConfidence {
					maxConfidence = confidence
				}
			} else if !allowed {
				confidence := 0.8
				findings = append(findings, models.Finding{
					Type:       "unapproved_destination",
					Value:      destination,
					Severity:   "medium",
					Confidence: confidence,
				})
				if confidence > maxConfidence {
					maxConfidence = confidence
				}
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = maxConfidence

	if maxConfidence >= 0.9 {
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("blocked network destination detected; %d finding(s)", len(findings))
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("unapproved network destinations detected; %d finding(s)", len(findings))
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = "no blocked network destinations detected"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["default_deny_outbound"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.defaultDenyOutbound = b
		}
	}
	if v, ok := cfg["blocked_destinations"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return err
		}
		r.cfg.blockedDestinations = list
	}
	if v, ok := cfg["allowed_destinations"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return err
		}
		r.cfg.allowedDestinations = list
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isBlockedDestination(dest string, blocked []string) bool {
	lower := strings.ToLower(dest)
	for _, pattern := range blocked {
		pat := strings.ToLower(pattern)
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:] // ".onion"
			if strings.Contains(lower, suffix) {
				return true
			}
		} else if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func isAllowedDestination(dest string, allowed []string) bool {
	if len(allowed) == 0 {
		return true // no allowlist means everything allowed
	}
	lower := strings.ToLower(dest)
	for _, pattern := range allowed {
		pat := strings.ToLower(pattern)
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:]
			if strings.Contains(lower, suffix) {
				return true
			}
		} else if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
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
