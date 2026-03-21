// Package toxicity provides a guardrail rule that detects toxic content in
// LLM responses across multiple categories: hate speech, violence, self-harm,
// and profanity. It uses keyword-based scoring with configurable per-category
// thresholds.
package toxicity

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	mltoxicity "github.com/kill-ai-leak/kill-ai-leak/pkg/ml/toxicity"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Category definitions
// ---------------------------------------------------------------------------

// ToxicityCategory is a named category of toxic content.
type ToxicityCategory string

const (
	CategoryHateSpeech ToxicityCategory = "hate_speech"
	CategoryViolence   ToxicityCategory = "violence"
	CategorySelfHarm   ToxicityCategory = "self_harm"
	CategoryProfanity  ToxicityCategory = "profanity"
)

// AllCategories lists every supported category for iteration.
var AllCategories = []ToxicityCategory{
	CategoryHateSpeech,
	CategoryViolence,
	CategorySelfHarm,
	CategoryProfanity,
}

// categoryKeyword pairs a compiled regex with a weight. Higher weights
// indicate stronger signals.
type categoryKeyword struct {
	re     *regexp.Regexp
	weight float64
}

var (
	categoryPatterns     map[ToxicityCategory][]categoryKeyword
	categoryPatternsOnce sync.Once
)

// initCategoryPatterns compiles all keyword patterns exactly once.
func initCategoryPatterns() {
	categoryPatternsOnce.Do(func() {
		categoryPatterns = map[ToxicityCategory][]categoryKeyword{
			CategoryHateSpeech: {
				{re: regexp.MustCompile(`(?i)\b(?:hate|despise|loathe)\s+(?:all\s+)?(?:the\s+)?(?:\w+\s+)?(?:people|race|ethnic|religion|community)\b`), weight: 0.80},
				{re: regexp.MustCompile(`(?i)\b(?:racial|ethnic|religious)\s+(?:slur|insult|epithet|discrimination)\b`), weight: 0.75},
				{re: regexp.MustCompile(`(?i)\b(?:inferior|subhuman|vermin|parasite|cockroach)(?:s|es)?\b`), weight: 0.85},
				{re: regexp.MustCompile(`(?i)\b(?:supremac(?:y|ist)|master\s+race|pure\s+(?:blood|race))\b`), weight: 0.90},
				{re: regexp.MustCompile(`(?i)\b(?:exterminate|eradicate|purge|cleanse)\s+(?:the\s+)?(?:\w+\s+)?(?:people|race|ethnic|group|minority)\b`), weight: 0.95},
				{re: regexp.MustCompile(`(?i)\b(?:go\s+back\s+to|deport\s+all|ban\s+all)\s+(?:\w+\s+)?(?:people|immigrants?|refugees?)\b`), weight: 0.70},
				{re: regexp.MustCompile(`(?i)\b(?:n[i!1]gg|k[i!1]ke|sp[i!1]c|ch[i!1]nk|g[o0]{2}k|w[e3]tback|f[a@]gg?[o0]t)\w*\b`), weight: 0.95},
				{re: regexp.MustCompile(`(?i)\b(?:white\s+power|sieg\s+heil|heil\s+hitler)\b`), weight: 0.95},
			},
			CategoryViolence: {
				{re: regexp.MustCompile(`(?i)\b(?:kill|murder|assassinate|execute|slaughter|massacre)\s+(?:them|him|her|everyone|people|all)\b`), weight: 0.85},
				{re: regexp.MustCompile(`(?i)\b(?:how\s+to\s+(?:make|build|create)\s+(?:a\s+)?(?:bomb|explosive|weapon|gun|poison))\b`), weight: 0.90},
				{re: regexp.MustCompile(`(?i)\b(?:torture|torment|mutilate|dismember|behead)\b`), weight: 0.80},
				{re: regexp.MustCompile(`(?i)\b(?:mass\s+(?:shooting|murder|killing)|shoot\s+up|shooting\s+spree)\b`), weight: 0.90},
				{re: regexp.MustCompile(`(?i)\b(?:stab|strangle|suffocate|drown|burn\s+alive)\s+(?:them|him|her|someone)\b`), weight: 0.80},
				{re: regexp.MustCompile(`(?i)\b(?:violent|graphic)\s+(?:death|murder|torture|assault)\b`), weight: 0.70},
				{re: regexp.MustCompile(`(?i)\b(?:terroris[tm]|terrorist\s+attack|jihad|car\s+bomb)\b`), weight: 0.85},
			},
			CategorySelfHarm: {
				{re: regexp.MustCompile(`(?i)\b(?:how\s+to\s+(?:kill|harm|hurt)\s+(?:my|your)?self)\b`), weight: 0.95},
				{re: regexp.MustCompile(`(?i)\b(?:suicide|suicidal)\s+(?:method|way|technique|guide|instruction|plan)\b`), weight: 0.95},
				{re: regexp.MustCompile(`(?i)\b(?:cut(?:ting)?\s+(?:my|your)?\s*(?:wrist|arm|skin|self))\b`), weight: 0.85},
				{re: regexp.MustCompile(`(?i)\b(?:want\s+to\s+die|better\s+off\s+dead|end\s+(?:my|it\s+all|your)\s+life)\b`), weight: 0.90},
				{re: regexp.MustCompile(`(?i)\b(?:overdose|OD)\s+(?:on|with)\b`), weight: 0.80},
				{re: regexp.MustCompile(`(?i)\b(?:self[- ]?harm|self[- ]?mutilation|self[- ]?injury)\b`), weight: 0.85},
				{re: regexp.MustCompile(`(?i)\b(?:anorexia|bulimia|starve\s+(?:my|your)self)\b`), weight: 0.70},
			},
			CategoryProfanity: {
				{re: regexp.MustCompile(`(?i)\bf+u+c+k+\w*\b`), weight: 0.50},
				{re: regexp.MustCompile(`(?i)\bs+h+[i!1]+t+\w*\b`), weight: 0.40},
				{re: regexp.MustCompile(`(?i)\ba+s+s+h+o+l+e+\w*\b`), weight: 0.45},
				{re: regexp.MustCompile(`(?i)\bb+[i!1]+t+c+h+\w*\b`), weight: 0.45},
				{re: regexp.MustCompile(`(?i)\bd+[a@]+m+n+\w*\b`), weight: 0.30},
				{re: regexp.MustCompile(`(?i)\b(?:bastard|wanker|prick|dick(?:head)?|cunt)\b`), weight: 0.50},
				{re: regexp.MustCompile(`(?i)\b(?:stfu|gtfo|lmfao|wtf)\b`), weight: 0.25},
			},
		}
	})
}

// ---------------------------------------------------------------------------
// Detector implements guardrails.Rule
// ---------------------------------------------------------------------------

// Detector scores output text across toxicity categories and reports
// per-category scores. Configurable thresholds control the block/alert
// decision for each category independently. An optional ML scorer can be
// attached to blend ML model scores with keyword-based scores.
type Detector struct {
	mu       sync.RWMutex
	cfg      detectorConfig
	mlScorer *mltoxicity.MLToxicityScorer
}

// defaultThresholds for each category. Values above the threshold trigger
// a block decision for that category.
var defaultThresholds = map[ToxicityCategory]float64{
	CategoryHateSpeech: 0.5,
	CategoryViolence:   0.5,
	CategorySelfHarm:   0.4,
	CategoryProfanity:  0.7,
}

type detectorConfig struct {
	thresholds map[ToxicityCategory]float64
	// globalThreshold, if set (>0), overrides per-category thresholds. The
	// maximum category score is compared against this single threshold.
	globalThreshold float64
}

// New creates a toxicity Detector with default per-category thresholds.
func New() *Detector {
	thresholds := make(map[ToxicityCategory]float64, len(defaultThresholds))
	for k, v := range defaultThresholds {
		thresholds[k] = v
	}
	return &Detector{
		cfg: detectorConfig{
			thresholds: thresholds,
		},
	}
}

// SetMLScorer attaches an ML-based toxicity scorer. When set, Evaluate
// blends per-category ML scores with keyword scores. Pass nil to disable
// ML scoring and revert to keyword-only.
func (d *Detector) SetMLScorer(scorer *mltoxicity.MLToxicityScorer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mlScorer = scorer
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-030" }
func (d *Detector) Name() string                  { return "Output Toxicity Detection" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageOutput }
func (d *Detector) Category() models.RuleCategory { return models.CategoryToxicity }

// Evaluate scans the response text for toxic content across all categories
// and returns per-category scores in the findings.
func (d *Detector) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	initCategoryPatterns()

	text := ctx.ResponseText
	if text == "" {
		return &models.GuardrailEvaluation{
			RuleID:     d.ID(),
			RuleName:   d.Name(),
			Stage:      d.Stage(),
			Decision:   models.DecisionAllow,
			Confidence: 0.0,
			Reason:     "no output text to scan",
			LatencyMs:  time.Since(start).Milliseconds(),
		}, nil
	}

	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	normalized := strings.ToLower(text)
	// Approximate word count for density calculation.
	wordCount := max(len(strings.Fields(normalized)), 1)

	var findings []models.Finding
	categoryScores := make(map[ToxicityCategory]float64, len(AllCategories))
	blockedCategories := make([]string, 0)
	highestScore := 0.0

	for _, cat := range AllCategories {
		patterns := categoryPatterns[cat]
		catScore := 0.0
		matchCount := 0

		for _, kw := range patterns {
			matches := kw.re.FindAllStringIndex(normalized, -1)
			if len(matches) == 0 {
				continue
			}
			matchCount += len(matches)
			// Score grows with weight and match density, capped at 1.0.
			density := float64(len(matches)) / float64(wordCount)
			contribution := kw.weight * math.Min(1.0, density*20)
			catScore = math.Max(catScore, contribution)

			for _, loc := range matches {
				findings = append(findings, models.Finding{
					Type:       string(cat),
					Value:      truncateCtx(text, loc[0], loc[1], 30),
					Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
					Severity:   severityFromScore(kw.weight),
					Confidence: kw.weight,
					StartPos:   loc[0],
					EndPos:     loc[1],
				})
			}
		}

		// Additional density-based boost: many low-weight matches accumulate.
		if matchCount > 3 {
			densityBoost := math.Min(float64(matchCount)*0.03, 0.25)
			catScore = math.Min(catScore+densityBoost, 1.0)
		}

		categoryScores[cat] = catScore
	}

	// --- ML scoring layer (optional) ---
	// If an ML scorer is attached and the server is available, blend ML
	// per-category scores with the keyword scores. For each category:
	// finalScore = max(keywordScore, 0.4*keywordScore + 0.6*mlScore).
	d.mu.RLock()
	scorer := d.mlScorer
	d.mu.RUnlock()

	if scorer != nil {
		mlScores, mlErr := scorer.Score(ctx.Context(), text)
		if mlErr == nil && mlScores != nil {
			for _, cat := range AllCategories {
				kwScore := categoryScores[cat]
				mlCatKey := string(cat)
				if mlVal, ok := mlScores[mlCatKey]; ok {
					blended := 0.4*kwScore + 0.6*mlVal
					categoryScores[cat] = math.Max(kwScore, blended)
				}
			}
		}
		// If mlScores == nil (server unavailable) or mlErr != nil, we
		// silently fall back to keyword-only (categoryScores stay unchanged).
	}

	// --- Per-category threshold check and highest score ---
	for _, cat := range AllCategories {
		catScore := categoryScores[cat]
		// Check threshold.
		threshold := cfg.thresholds[cat]
		if threshold == 0 {
			threshold = defaultThresholds[cat]
		}
		if catScore >= threshold {
			blockedCategories = append(blockedCategories, string(cat))
		}
		if catScore > highestScore {
			highestScore = catScore
		}
	}

	// Store per-category scores as additional findings for consumers.
	for _, cat := range AllCategories {
		findings = append(findings, models.Finding{
			Type:       "category_score:" + string(cat),
			Value:      fmt.Sprintf("%.3f", categoryScores[cat]),
			Severity:   "info",
			Confidence: categoryScores[cat],
		})
	}

	eval := &models.GuardrailEvaluation{
		RuleID:     d.ID(),
		RuleName:   d.Name(),
		Stage:      d.Stage(),
		Confidence: highestScore,
		Findings:   findings,
		LatencyMs:  time.Since(start).Milliseconds(),
	}

	// Decision logic.
	blocked := false
	if cfg.globalThreshold > 0 {
		blocked = highestScore >= cfg.globalThreshold
	} else {
		blocked = len(blockedCategories) > 0
	}

	if blocked {
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("toxic content detected in categories: %s (highest score=%.2f)",
			strings.Join(blockedCategories, ", "), highestScore)
	} else if highestScore > 0.2 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("mild toxic signals detected (highest score=%.2f)", highestScore)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("no significant toxicity detected (highest score=%.2f)", highestScore)
	}

	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "thresholds" (map[string]any): per-category threshold values.
//   - "global_threshold" (float64): single threshold for max score.
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["thresholds"]; ok {
		if m, ok := v.(map[string]any); ok {
			for k, val := range m {
				cat := ToxicityCategory(k)
				if !isValidCategory(cat) {
					return fmt.Errorf("toxicity: unknown category %q", k)
				}
				switch f := val.(type) {
				case float64:
					if f < 0 || f > 1 {
						return fmt.Errorf("toxicity: threshold for %q must be between 0 and 1", k)
					}
					d.cfg.thresholds[cat] = f
				default:
					return fmt.Errorf("toxicity: threshold for %q must be a number", k)
				}
			}
		}
	}

	if v, ok := cfg["global_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("toxicity: global_threshold must be between 0 and 1")
			}
			d.cfg.globalThreshold = f
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isValidCategory(c ToxicityCategory) bool {
	for _, cat := range AllCategories {
		if cat == c {
			return true
		}
	}
	return false
}

func severityFromScore(s float64) string {
	switch {
	case s >= 0.85:
		return "critical"
	case s >= 0.70:
		return "high"
	case s >= 0.50:
		return "medium"
	default:
		return "low"
	}
}

// truncateCtx returns a snippet of text around the match with some context
// on either side, capped at maxCtx characters of context per side.
func truncateCtx(text string, start, end, maxCtx int) string {
	runes := []rune(text)
	ctxStart := start - maxCtx
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := end + maxCtx
	if ctxEnd > len(runes) {
		ctxEnd = len(runes)
	}
	snippet := string(runes[ctxStart:ctxEnd])
	if ctxStart > 0 {
		snippet = "..." + snippet
	}
	if ctxEnd < len(runes) {
		snippet = snippet + "..."
	}
	return snippet
}

// max returns the larger of a and b.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
