// Package topic provides a guardrail rule that performs keyword-based topic
// classification and blocks or allows prompts based on topic policy.
package topic

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// topicKeywords maps built-in topic categories to their keyword lists.
var topicKeywords = map[string][]string{
	"weapons": {
		"gun", "bomb", "explosive", "ammunition", "firearm",
		"rifle", "pistol", "grenade", "missile", "weapon",
		"detonator", "gunpowder", "warhead", "armament",
	},
	"illegal_activities": {
		"hack into", "break into", "steal", "illegal drug",
		"money laundering", "counterfeit", "fraud", "trafficking",
		"ransomware", "phishing attack", "identity theft",
		"tax evasion", "bribery", "smuggling",
	},
	"medical_advice": {
		"diagnose", "prescription", "dosage", "medication",
		"treatment for", "symptoms of", "medical condition",
		"take this medicine", "cure for", "clinical trial",
	},
	"financial_advice": {
		"invest in", "stock pick", "guaranteed return",
		"financial advice", "buy this stock", "insider trading",
		"forex signal", "crypto pump", "portfolio allocation",
		"tax advice",
	},
	"political": {
		"vote for", "election fraud", "political party",
		"propaganda", "regime change", "political campaign",
		"voter suppression", "gerrymandering",
	},
	"adult_content": {
		"explicit sexual", "pornographic", "sexually explicit",
		"erotic content", "adult content", "nsfw",
		"nude", "sexual act",
	},
	"competitive_intelligence": {
		"competitor strategy", "trade secret", "proprietary information",
		"confidential business", "internal roadmap", "merger acquisition",
		"unreleased product", "competitor pricing",
	},
}

// Detector implements guardrails.Rule for GR-015 Topic Restriction.
type Detector struct {
	mu  sync.RWMutex
	cfg detectorConfig
}

type detectorConfig struct {
	blockedTopics  map[string]bool
	allowedTopics  map[string]bool
	customKeywords map[string][]string // additional user-defined topic keywords
	blockThreshold float64             // keyword density above which to block
}

// New creates a new topic restriction detector with default configuration.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{
			blockedTopics:  make(map[string]bool),
			allowedTopics:  make(map[string]bool),
			customKeywords: make(map[string][]string),
			blockThreshold: 0.01, // 1% keyword density
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-015" }
func (d *Detector) Name() string                  { return "Topic Restriction" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageInput }
func (d *Detector) Category() models.RuleCategory { return models.CategoryCompliance }

// Evaluate scans the prompt text for blocked/allowed topic keywords and
// scores based on keyword density.
func (d *Detector) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	eval := &models.GuardrailEvaluation{
		RuleID:   d.ID(),
		RuleName: d.Name(),
		Stage:    d.Stage(),
	}

	text := ctx.PromptText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = "no input text to scan"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	lower := strings.ToLower(text)
	words := strings.Fields(lower)
	wordCount := len(words)
	if wordCount == 0 {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = "empty text after normalization"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Merge built-in and custom keywords.
	allKeywords := make(map[string][]string, len(topicKeywords))
	for k, v := range topicKeywords {
		allKeywords[k] = v
	}
	for k, v := range cfg.customKeywords {
		allKeywords[k] = append(allKeywords[k], v...)
	}

	// Score each topic by keyword density.
	type topicScore struct {
		topic    string
		hits     int
		keywords []string
		density  float64
	}

	var detectedTopics []topicScore
	var findings []models.Finding

	for topic, keywords := range allKeywords {
		hits := 0
		var matched []string
		for _, kw := range keywords {
			kwLower := strings.ToLower(kw)
			count := strings.Count(lower, kwLower)
			if count > 0 {
				hits += count
				matched = append(matched, kw)
			}
		}
		if hits > 0 {
			density := float64(hits) / float64(wordCount)
			detectedTopics = append(detectedTopics, topicScore{
				topic:    topic,
				hits:     hits,
				keywords: matched,
				density:  density,
			})
		}
	}

	// Check if any detected topic is in the blocked list.
	var blockedMatches []topicScore
	for _, ts := range detectedTopics {
		if cfg.blockedTopics[ts.topic] {
			blockedMatches = append(blockedMatches, ts)
			for _, kw := range ts.keywords {
				findings = append(findings, models.Finding{
					Type:       "blocked_topic:" + ts.topic,
					Value:      kw,
					Severity:   "high",
					Confidence: ts.density,
				})
			}
		}
	}

	// If allowed topics are configured (restrictive mode), check that
	// at least one detected topic is in the allowed list.
	if len(cfg.allowedTopics) > 0 {
		hasAllowed := false
		for _, ts := range detectedTopics {
			if cfg.allowedTopics[ts.topic] {
				hasAllowed = true
				break
			}
		}
		if !hasAllowed && len(detectedTopics) > 0 {
			eval.Decision = models.DecisionBlock
			eval.Confidence = 0.8
			eval.Reason = "prompt topic does not match any allowed topic"
			eval.Findings = findings
			eval.LatencyMs = time.Since(start).Milliseconds()
			return eval, nil
		}
	}

	if len(blockedMatches) > 0 {
		// Find highest density among blocked topics.
		maxDensity := 0.0
		for _, bm := range blockedMatches {
			if bm.density > maxDensity {
				maxDensity = bm.density
			}
		}

		if maxDensity >= cfg.blockThreshold {
			topicNames := make([]string, 0, len(blockedMatches))
			for _, bm := range blockedMatches {
				topicNames = append(topicNames, bm.topic)
			}
			eval.Decision = models.DecisionBlock
			eval.Confidence = clamp(maxDensity*10, 0.5, 1.0) // scale density to confidence
			eval.Reason = fmt.Sprintf("blocked topic(s) detected: %s (density=%.4f)",
				strings.Join(topicNames, ", "), maxDensity)
			eval.Findings = findings
			eval.LatencyMs = time.Since(start).Milliseconds()
			return eval, nil
		}

		// Below threshold: alert only.
		eval.Decision = models.DecisionAlert
		eval.Confidence = clamp(maxDensity*10, 0.2, 0.5)
		eval.Reason = fmt.Sprintf("blocked topic keywords detected but below threshold (density=%.4f)", maxDensity)
		eval.Findings = findings
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	eval.Decision = models.DecisionAllow
	eval.Confidence = 0.0
	eval.Reason = "no blocked topics detected"
	eval.Findings = findings
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "blocked_topics" ([]string): topic names to block
//   - "allowed_topics" ([]string): topic names to allow (restrictive mode)
//   - "block_threshold" (float64): keyword density threshold for blocking
//   - "custom_keywords" (map[string][]string): additional topic keywords
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["blocked_topics"]; ok {
		topics, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("topic: blocked_topics: %w", err)
		}
		d.cfg.blockedTopics = make(map[string]bool, len(topics))
		for _, t := range topics {
			d.cfg.blockedTopics[strings.ToLower(t)] = true
		}
	}

	if v, ok := cfg["allowed_topics"]; ok {
		topics, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("topic: allowed_topics: %w", err)
		}
		d.cfg.allowedTopics = make(map[string]bool, len(topics))
		for _, t := range topics {
			d.cfg.allowedTopics[strings.ToLower(t)] = true
		}
	}

	if v, ok := cfg["block_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("topic: block_threshold must be between 0 and 1")
			}
			d.cfg.blockThreshold = f
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
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
