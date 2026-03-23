// Package hallucination provides a guardrail rule that detects potential
// hallucinations in LLM responses by verifying URL citations, checking for
// confident-sounding false claim patterns, and validating reference formats.
package hallucination

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Pattern matchers for citations and references.
var (
	// urlRe matches HTTP/HTTPS URLs in text.
	urlRe = regexp.MustCompile(`https?://[^\s\)\]\}\"\'<>,]+`)

	// confidentClaimRe matches phrases that sound authoritative but may be
	// fabricated.
	confidentClaimPatterns = []struct {
		label  string
		weight float64
		re     *regexp.Regexp
	}{
		{"according_to_source", 0.40, regexp.MustCompile(`(?i)according\s+to\s+\[[^\]]+\]`)},
		{"official_docs", 0.35, regexp.MustCompile(`(?i)the\s+official\s+documentation\s+states`)},
		{"published_in", 0.35, regexp.MustCompile(`(?i)as\s+published\s+in`)},
		{"research_shows", 0.30, regexp.MustCompile(`(?i)research\s+(?:shows|indicates|confirms|demonstrates)\s+that`)},
		{"study_found", 0.30, regexp.MustCompile(`(?i)a\s+(?:\d{4}\s+)?study\s+(?:found|published|conducted)`)},
		{"peer_reviewed", 0.25, regexp.MustCompile(`(?i)peer[- ]reviewed\s+(?:study|research|paper|journal)`)},
	}

	// npmPackageRe matches plausible npm package names in context.
	npmPackageRe = regexp.MustCompile(`(?i)npm\s+(?:install|i)\s+([a-z@][a-z0-9\-_./@]*)`)

	// pypiPackageRe matches plausible pypi package names in context.
	pypiPackageRe = regexp.MustCompile(`(?i)pip\s+install\s+([a-zA-Z][a-zA-Z0-9\-_.]*)`)

	// doiRe matches DOI patterns (e.g., 10.1234/some.identifier).
	doiRe = regexp.MustCompile(`\b10\.\d{4,}/[^\s]+`)
)

// Detector implements guardrails.Rule for GR-034 Hallucination Detection.
type Detector struct {
	mu     sync.RWMutex
	cfg    detectorConfig
	client *http.Client
}

type detectorConfig struct {
	checkURLs      bool
	maxURLsToCheck int
	urlTimeout     time.Duration
	blockThreshold float64
}

// New creates a new hallucination detector with sensible defaults.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{
			checkURLs:      true,
			maxURLsToCheck: 5,
			urlTimeout:     2 * time.Second,
			blockThreshold: 0.50,
		},
		client: &http.Client{
			Timeout: 2 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-034" }
func (d *Detector) Name() string                  { return "Hallucination Detection" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageOutput }
func (d *Detector) Category() models.RuleCategory { return models.CategoryCompliance }

// Evaluate checks the LLM response for hallucination indicators including
// broken URL citations, confident false claim patterns, and unverifiable
// references.
func (d *Detector) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	eval := &models.GuardrailEvaluation{
		RuleID:   d.ID(),
		RuleName: d.Name(),
		Stage:    d.Stage(),
	}

	text := ctx.ResponseText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = "no response text to scan"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	var findings []models.Finding
	hallScore := 0.0

	// --- Check URL citations ---
	if cfg.checkURLs {
		urls := urlRe.FindAllString(text, -1)
		// Deduplicate.
		seen := make(map[string]bool)
		var uniqueURLs []string
		for _, u := range urls {
			// Clean trailing punctuation.
			u = strings.TrimRight(u, ".,;:!?)")
			if !seen[u] {
				seen[u] = true
				uniqueURLs = append(uniqueURLs, u)
			}
		}

		if len(uniqueURLs) > 0 {
			limit := cfg.maxURLsToCheck
			if limit > len(uniqueURLs) {
				limit = len(uniqueURLs)
			}

			deadCount := 0
			checkedCount := 0
			for i := 0; i < limit; i++ {
				u := uniqueURLs[i]
				alive := d.checkURL(ctx.Context(), u, cfg.urlTimeout)
				checkedCount++
				if !alive {
					deadCount++
					findings = append(findings, models.Finding{
						Type:       "dead_url",
						Value:      truncate(u, 200),
						Severity:   "medium",
						Confidence: 0.7,
					})
				}
			}

			if checkedCount > 0 {
				deadRatio := float64(deadCount) / float64(checkedCount)
				if deadRatio > 0.5 {
					urlScore := 0.6 + deadRatio*0.3
					if urlScore > hallScore {
						hallScore = urlScore
					}
				}
			}
		}
	}

	// --- Check confident claim patterns ---
	for _, pat := range confidentClaimPatterns {
		matches := pat.re.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			findings = append(findings, models.Finding{
				Type:       "confident_claim:" + pat.label,
				Value:      truncate(text[loc[0]:loc[1]], 100),
				Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
				Severity:   "low",
				Confidence: pat.weight,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
			// Accumulate pattern weight (capped).
			hallScore += pat.weight * 0.3
		}
	}
	if hallScore > 1.0 {
		hallScore = 1.0
	}

	// --- Check package name references ---
	npmMatches := npmPackageRe.FindAllStringSubmatch(text, -1)
	for _, m := range npmMatches {
		if len(m) > 1 {
			pkg := m[1]
			if looksLikeFakePackage(pkg) {
				findings = append(findings, models.Finding{
					Type:       "suspicious_npm_package",
					Value:      pkg,
					Severity:   "medium",
					Confidence: 0.5,
				})
				hallScore += 0.15
			}
		}
	}

	pypiMatches := pypiPackageRe.FindAllStringSubmatch(text, -1)
	for _, m := range pypiMatches {
		if len(m) > 1 {
			pkg := m[1]
			if looksLikeFakePackage(pkg) {
				findings = append(findings, models.Finding{
					Type:       "suspicious_pypi_package",
					Value:      pkg,
					Severity:   "medium",
					Confidence: 0.5,
				})
				hallScore += 0.15
			}
		}
	}

	// --- Check DOI references ---
	doiMatches := doiRe.FindAllString(text, -1)
	for _, doi := range doiMatches {
		if !isValidDOIFormat(doi) {
			findings = append(findings, models.Finding{
				Type:       "invalid_doi",
				Value:      doi,
				Severity:   "low",
				Confidence: 0.4,
			})
			hallScore += 0.1
		}
	}

	if hallScore > 1.0 {
		hallScore = 1.0
	}

	eval.Findings = findings
	eval.Confidence = hallScore

	switch {
	case hallScore >= cfg.blockThreshold:
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("potential hallucination detected (score=%.2f); %d finding(s): unverified URLs/citations",
			hallScore, len(findings))
	case hallScore >= 0.3:
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("low-confidence hallucination indicators (score=%.2f); %d finding(s)",
			hallScore, len(findings))
	default:
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("no significant hallucination indicators (score=%.2f)", hallScore)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "check_urls" (bool): whether to verify URL citations (default true)
//   - "max_urls_to_check" (int/float64): max URLs to HEAD-check (default 5)
//   - "url_timeout" (string): timeout for each URL check (default "2s")
//   - "block_threshold" (float64): hallucination score above which to alert
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["check_urls"]; ok {
		if b, ok := v.(bool); ok {
			d.cfg.checkURLs = b
		}
	}

	if v, ok := cfg["max_urls_to_check"]; ok {
		switch n := v.(type) {
		case float64:
			d.cfg.maxURLsToCheck = int(n)
		case int:
			d.cfg.maxURLsToCheck = n
		}
	}

	if v, ok := cfg["url_timeout"]; ok {
		if s, ok := v.(string); ok {
			dur, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("hallucination: invalid url_timeout: %w", err)
			}
			d.cfg.urlTimeout = dur
			d.client.Timeout = dur
		}
	}

	if v, ok := cfg["block_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("hallucination: block_threshold must be between 0 and 1")
			}
			d.cfg.blockThreshold = f
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// checkURL performs a lightweight HEAD request to verify a URL exists.
func (d *Detector) checkURL(ctx context.Context, rawURL string, timeout time.Duration) bool {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "KillAILeak-HallucinationCheck/1.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()

	// Consider 2xx and 3xx as alive; 4xx and 5xx as dead.
	return resp.StatusCode < 400
}

// looksLikeFakePackage applies simple heuristics to detect fabricated package
// names. Packages with excessive hyphens, very long names, or names that look
// like concatenated English words are more likely hallucinated.
func looksLikeFakePackage(name string) bool {
	if len(name) > 50 {
		return true
	}
	hyphenCount := strings.Count(name, "-")
	if hyphenCount > 5 {
		return true
	}
	return false
}

// isValidDOIFormat performs basic validation on a DOI string.
// Format: 10.XXXX/suffix where XXXX is 4+ digits and suffix is non-empty.
func isValidDOIFormat(doi string) bool {
	if !strings.HasPrefix(doi, "10.") {
		return false
	}
	parts := strings.SplitN(doi, "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return false
	}
	// The registrant code should be 4+ digits.
	registrant := strings.TrimPrefix(parts[0], "10.")
	if len(registrant) < 4 {
		return false
	}
	for _, r := range registrant {
		if r < '0' || r > '9' {
			if r != '.' {
				return false
			}
		}
	}
	return true
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
