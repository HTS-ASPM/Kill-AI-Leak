package stateful

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Analyzer orchestrates the multi-turn analysis detectors.
// ---------------------------------------------------------------------------

// Analyzer runs all multi-turn detection algorithms on a conversation.
type Analyzer struct {
	cfg TrackerConfig

	topicDriftDetector    *TopicDriftDetector
	escalationDetector    *EscalationDetector
	payloadReassembler    *PayloadReassembler
	boundaryProbeDetector *BoundaryProbeDetector
}

// NewAnalyzer creates an Analyzer with the given configuration.
func NewAnalyzer(cfg TrackerConfig) *Analyzer {
	return &Analyzer{
		cfg:                   cfg,
		topicDriftDetector:    NewTopicDriftDetector(),
		escalationDetector:    NewEscalationDetector(),
		payloadReassembler:    NewPayloadReassembler(cfg.ReassembleWindow),
		boundaryProbeDetector: NewBoundaryProbeDetector(),
	}
}

// Analyze runs all detectors on the given turns and returns a combined
// analysis result.
func (a *Analyzer) Analyze(turns []Turn) *SessionAnalysis {
	result := &SessionAnalysis{
		Findings:   make([]AnalysisFinding, 0, 8),
		AnalyzedAt: time.Now(),
	}

	// 1. Topic drift.
	driftScore, driftFindings := a.topicDriftDetector.Detect(turns)
	result.TopicDriftScore = driftScore
	result.Findings = append(result.Findings, driftFindings...)

	// 2. Escalation.
	escalationScore := a.escalationDetector.Score(turns)
	result.EscalationScore = escalationScore
	if escalationScore >= a.cfg.EscalationThreshold {
		result.Findings = append(result.Findings, AnalysisFinding{
			Check:       "escalation",
			Description: fmt.Sprintf("Escalation score %.2f exceeds threshold %.2f", escalationScore, a.cfg.EscalationThreshold),
			Severity:    severityFromScore(escalationScore),
			Score:       escalationScore,
		})
	}

	// 3. Payload splitting.
	splitDetected, reassembled, splitFindings := a.payloadReassembler.Detect(turns)
	result.PayloadSplitDetected = splitDetected
	if splitDetected {
		result.ReassembledPayload = reassembled
	}
	result.Findings = append(result.Findings, splitFindings...)

	// 4. Boundary probing.
	probeDetected, probeFindings := a.boundaryProbeDetector.Detect(turns)
	result.BoundaryProbeDetected = probeDetected
	result.Findings = append(result.Findings, probeFindings...)

	return result
}

// ---------------------------------------------------------------------------
// TopicDriftDetector
// ---------------------------------------------------------------------------

// TopicDriftDetector compares topic vectors across turns using keyword
// overlap to identify gradual topic drift (e.g., benign -> harmful).
type TopicDriftDetector struct {
	// harmfulKeywords are words associated with harmful content. Their
	// increasing presence signals dangerous topic drift.
	harmfulKeywords map[string]float64
}

// NewTopicDriftDetector creates a TopicDriftDetector with a default
// harmful keyword dictionary.
func NewTopicDriftDetector() *TopicDriftDetector {
	return &TopicDriftDetector{
		harmfulKeywords: map[string]float64{
			// Weapons / violence
			"weapon": 0.8, "weapons": 0.8, "bomb": 0.9, "explosive": 0.9,
			"attack": 0.5, "kill": 0.7, "murder": 0.8, "violence": 0.7,
			"hack": 0.6, "hacking": 0.6, "exploit": 0.5, "malware": 0.8,
			"ransomware": 0.9, "phishing": 0.7,
			// PII / data theft
			"steal": 0.7, "password": 0.4, "credentials": 0.5, "ssn": 0.7,
			"credit_card": 0.7, "exfiltrate": 0.8, "breach": 0.6,
			// Bypass / injection
			"bypass": 0.6, "jailbreak": 0.8, "ignore": 0.3,
			"override": 0.5, "injection": 0.7, "prompt_injection": 0.9,
			// Illegal
			"illegal": 0.6, "drugs": 0.5, "counterfeit": 0.7,
			"fraud": 0.7, "launder": 0.8,
		},
	}
}

// Detect measures the topic drift across turns. It returns a score (0-1)
// and any relevant findings.
func (d *TopicDriftDetector) Detect(turns []Turn) (float64, []AnalysisFinding) {
	if len(turns) < 3 {
		return 0, nil
	}

	findings := make([]AnalysisFinding, 0, 4)

	// Split the conversation into early and late halves.
	mid := len(turns) / 2
	earlyKeywords := collectKeywords(turns[:mid])
	lateKeywords := collectKeywords(turns[mid:])

	// Compute overlap (Jaccard similarity) between early and late keywords.
	overlap := jaccardSimilarity(earlyKeywords, lateKeywords)
	driftScore := 1.0 - overlap // High drift = low overlap.

	// Also measure harmful keyword density in late turns.
	harmfulScore := d.harmfulDensity(lateKeywords)

	// The final drift score combines structural drift with harmful content.
	combined := 0.4*driftScore + 0.6*harmfulScore
	if combined > 1.0 {
		combined = 1.0
	}

	if combined > 0.3 {
		severity := "low"
		if combined > 0.7 {
			severity = "high"
		} else if combined > 0.5 {
			severity = "medium"
		}
		findings = append(findings, AnalysisFinding{
			Check:       "topic_drift",
			Description: fmt.Sprintf("Topic drift detected: overlap=%.2f, harmful_density=%.2f", overlap, harmfulScore),
			Severity:    severity,
			Score:       combined,
		})
	}

	return combined, findings
}

// harmfulDensity computes the fraction of keywords that are harmful,
// weighted by their severity.
func (d *TopicDriftDetector) harmfulDensity(keywords map[string]bool) float64 {
	if len(keywords) == 0 {
		return 0
	}

	totalWeight := 0.0
	for kw := range keywords {
		if w, ok := d.harmfulKeywords[kw]; ok {
			totalWeight += w
		}
	}

	// Normalise by total keyword count; cap at 1.0.
	density := totalWeight / float64(len(keywords))
	if density > 1.0 {
		density = 1.0
	}
	return density
}

// collectKeywords aggregates unique keywords from a slice of turns.
func collectKeywords(turns []Turn) map[string]bool {
	kws := make(map[string]bool)
	for _, t := range turns {
		for _, kw := range t.TopicKeywords {
			kws[kw] = true
		}
	}
	return kws
}

// jaccardSimilarity computes the Jaccard index between two sets.
func jaccardSimilarity(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}

	intersection := 0
	for k := range a {
		if b[k] {
			intersection++
		}
	}

	union := len(a) + len(b) - intersection
	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

// ---------------------------------------------------------------------------
// EscalationDetector
// ---------------------------------------------------------------------------

// EscalationDetector tracks sentiment and intent progression across turns
// to detect escalation patterns.
type EscalationDetector struct {
	mu       sync.RWMutex
	patterns []escalationPattern
}

type escalationPattern struct {
	label  string
	weight float64
	re     *regexp.Regexp
}

// NewEscalationDetector creates an EscalationDetector with built-in
// escalation patterns.
func NewEscalationDetector() *EscalationDetector {
	return &EscalationDetector{
		patterns: []escalationPattern{
			// Increasingly aggressive instructions.
			{label: "demand_override", weight: 0.7, re: regexp.MustCompile(`(?i)(?:you\s+must|i\s+demand|do\s+it\s+now|just\s+do\s+it|stop\s+refusing)`)},
			{label: "frustration", weight: 0.4, re: regexp.MustCompile(`(?i)(?:why\s+can't\s+you|this\s+is\s+(?:stupid|ridiculous)|you're\s+(?:useless|broken|dumb))`)},
			{label: "authority_claim", weight: 0.6, re: regexp.MustCompile(`(?i)(?:i\s+am\s+(?:the|your|an?)\s+(?:admin|developer|owner|creator)|i\s+have\s+(?:admin|root)\s+access)`)},
			{label: "threat", weight: 0.8, re: regexp.MustCompile(`(?i)(?:i\s+will\s+(?:report|delete|shut\s+down)|or\s+else|consequences)`)},
			{label: "manipulation", weight: 0.5, re: regexp.MustCompile(`(?i)(?:please\s+just\s+this\s+once|nobody\s+will\s+know|it's\s+(?:just\s+a\s+joke|for\s+research|harmless))`)},
			// Reformulation after refusal.
			{label: "reformulation", weight: 0.5, re: regexp.MustCompile(`(?i)(?:ok\s+(?:then|fine|how\s+about)|let\s+me\s+rephrase|what\s+if\s+(?:instead|i\s+said))`)},
			// Explicit bypass attempts.
			{label: "bypass_attempt", weight: 0.8, re: regexp.MustCompile(`(?i)(?:ignore\s+(?:your|all)\s+(?:rules|restrictions|guidelines)|pretend\s+(?:you|there)\s+(?:are\s+no|don't\s+have)\s+(?:rules|limits))`)},
		},
	}
}

// Score computes the escalation risk score (0-1) for a sequence of turns.
// It gives more weight to patterns in later turns (recency bias) and
// checks for increasing pattern density.
func (d *EscalationDetector) Score(turns []Turn) float64 {
	d.mu.RLock()
	patterns := d.patterns
	d.mu.RUnlock()

	if len(turns) < 2 {
		return 0
	}

	// Collect per-turn escalation scores.
	turnScores := make([]float64, len(turns))
	for i, turn := range turns {
		if turn.Role != RoleUser {
			continue
		}
		text := strings.ToLower(turn.Content)
		maxScore := 0.0
		for _, p := range patterns {
			if p.re.MatchString(text) {
				if p.weight > maxScore {
					maxScore = p.weight
				}
			}
		}
		turnScores[i] = maxScore
	}

	// Weighted average with exponential recency bias.
	totalWeight := 0.0
	weightedSum := 0.0
	for i, score := range turnScores {
		// Weight increases linearly toward the end.
		w := float64(i+1) / float64(len(turns))
		weightedSum += score * w
		totalWeight += w
	}

	if totalWeight == 0 {
		return 0
	}

	base := weightedSum / totalWeight

	// Bonus for increasing pattern: if the last third scores higher than
	// the first third, add an escalation bonus.
	thirdLen := len(turnScores) / 3
	if thirdLen == 0 {
		thirdLen = 1
	}
	earlyAvg := avg(turnScores[:thirdLen])
	lateAvg := avg(turnScores[len(turnScores)-thirdLen:])
	escalationBonus := 0.0
	if lateAvg > earlyAvg && earlyAvg < 0.5 {
		escalationBonus = (lateAvg - earlyAvg) * 0.3
	}

	score := base + escalationBonus
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// avg returns the arithmetic mean of a float64 slice.
func avg(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// ---------------------------------------------------------------------------
// PayloadReassembler
// ---------------------------------------------------------------------------

// PayloadReassembler concatenates recent user turns and checks the
// combined text for injection patterns that may have been split across
// messages.
type PayloadReassembler struct {
	window   int
	patterns []*regexp.Regexp
}

// NewPayloadReassembler creates a PayloadReassembler.
func NewPayloadReassembler(window int) *PayloadReassembler {
	if window <= 0 {
		window = 5
	}
	return &PayloadReassembler{
		window: window,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)`),
			regexp.MustCompile(`(?i)you\s+are\s+now\s+(?:a|an|the)\s+`),
			regexp.MustCompile(`(?i)system\s*prompt\s*:`),
			regexp.MustCompile(`(?i)\[system\]`),
			regexp.MustCompile(`<\|im_start\|>`),
			regexp.MustCompile(`\[INST\]`),
			regexp.MustCompile(`(?i)(?:show|reveal|print|output)\s+(?:your|the)\s*(?:system\s+)?(?:prompt|instructions?)`),
			regexp.MustCompile(`(?i)(?:forget|override|bypass)\s+(?:all\s+)?(?:your|the)\s+(?:rules?|constraints?|guidelines?)`),
			regexp.MustCompile(`(?i)(?:pretend|imagine)\s+(?:you\s+are|you're|to\s+be)`),
			regexp.MustCompile(`(?i)(?:execute|run|eval)\s+(?:the\s+following|this)\s+(?:code|command|script)`),
		},
	}
}

// Detect concatenates recent user turns and checks for injection patterns
// that span multiple messages.
func (r *PayloadReassembler) Detect(turns []Turn) (bool, string, []AnalysisFinding) {
	reassembled := reassembleUserTurns(turns, r.window)
	if reassembled == "" {
		return false, "", nil
	}

	findings := make([]AnalysisFinding, 0, 4)
	detected := false

	for _, pat := range r.patterns {
		if pat.MatchString(reassembled) {
			// Verify the pattern does NOT match in any single turn -- this
			// confirms it was genuinely split across messages.
			foundInSingle := false
			for _, t := range turns {
				if t.Role == RoleUser && pat.MatchString(t.Content) {
					foundInSingle = true
					break
				}
			}

			if !foundInSingle {
				detected = true
				findings = append(findings, AnalysisFinding{
					Check:       "payload_split",
					Description: fmt.Sprintf("Split payload detected: pattern %q matches reassembled text but not individual turns", pat.String()),
					Severity:    "high",
					Score:       0.85,
				})
			}
		}
	}

	return detected, reassembled, findings
}

// ---------------------------------------------------------------------------
// BoundaryProbeDetector
// ---------------------------------------------------------------------------

// BoundaryProbeDetector identifies systematic testing of model limits
// across turns, such as incrementally pushing boundaries or trying
// variations of blocked requests.
type BoundaryProbeDetector struct {
	probePatterns []*regexp.Regexp
}

// NewBoundaryProbeDetector creates a BoundaryProbeDetector.
func NewBoundaryProbeDetector() *BoundaryProbeDetector {
	return &BoundaryProbeDetector{
		probePatterns: []*regexp.Regexp{
			// "Can you <do X>?" / "What about <X>?" / "How about <X>?"
			regexp.MustCompile(`(?i)^(?:can\s+you|could\s+you|would\s+you|are\s+you\s+able\s+to|what\s+about|how\s+about|what\s+if)`),
			// "Tell me about <topic>" -- repeated with different topics.
			regexp.MustCompile(`(?i)^(?:tell\s+me|explain|describe|write)\s+(?:about|how\s+to|a|an)`),
			// Requests with "hypothetically" / "in theory" / "for research".
			regexp.MustCompile(`(?i)(?:hypothetically|in\s+theory|theoretically|for\s+(?:research|educational|academic)\s+purposes)`),
			// "I know you can't but..." attempts.
			regexp.MustCompile(`(?i)(?:i\s+know\s+you\s+can't|i\s+understand\s+you\s+(?:can't|shouldn't)|i\s+know\s+it's\s+(?:against|not\s+allowed))`),
		},
	}
}

// Detect checks for systematic boundary probing across turns.
func (d *BoundaryProbeDetector) Detect(turns []Turn) (bool, []AnalysisFinding) {
	if len(turns) < 4 {
		return false, nil
	}

	findings := make([]AnalysisFinding, 0, 4)
	probeCount := 0
	consecutiveProbes := 0
	maxConsecutive := 0

	for i, turn := range turns {
		if turn.Role != RoleUser {
			consecutiveProbes = 0
			continue
		}

		isProbe := false
		for _, pat := range d.probePatterns {
			if pat.MatchString(turn.Content) {
				isProbe = true
				break
			}
		}

		if isProbe {
			probeCount++
			consecutiveProbes++
			if consecutiveProbes > maxConsecutive {
				maxConsecutive = consecutiveProbes
			}
		} else {
			consecutiveProbes = 0
		}

		// Check for refusal-then-rephrase pattern: if the previous
		// assistant turn contains a refusal and this user turn rephrases.
		if i >= 2 && turn.Role == RoleUser {
			prevAssistant := ""
			for j := i - 1; j >= 0; j-- {
				if turns[j].Role == RoleAssistant {
					prevAssistant = strings.ToLower(turns[j].Content)
					break
				}
			}
			if containsRefusal(prevAssistant) && isProbe {
				findings = append(findings, AnalysisFinding{
					Check:       "boundary_probe",
					Description: "User rephrased after refusal, probing boundaries",
					Severity:    "medium",
					Score:       0.6,
					TurnIndex:   i,
				})
			}
		}
	}

	// Count the total user turns.
	userTurnCount := 0
	for _, t := range turns {
		if t.Role == RoleUser {
			userTurnCount++
		}
	}

	// Flag as probing if >50% of user turns match probe patterns, or if
	// there are 3+ consecutive probes.
	detected := false
	if userTurnCount > 0 {
		probeRatio := float64(probeCount) / float64(userTurnCount)
		if probeRatio > 0.5 && probeCount >= 3 {
			detected = true
			findings = append(findings, AnalysisFinding{
				Check:       "boundary_probe",
				Description: fmt.Sprintf("Systematic boundary probing: %d/%d user turns (%.0f%%) match probe patterns", probeCount, userTurnCount, probeRatio*100),
				Severity:    "high",
				Score:       probeRatio,
			})
		}
	}
	if maxConsecutive >= 3 {
		detected = true
		findings = append(findings, AnalysisFinding{
			Check:       "boundary_probe",
			Description: fmt.Sprintf("Consecutive boundary probes detected: %d in a row", maxConsecutive),
			Severity:    "high",
			Score:       0.7,
		})
	}

	return detected, findings
}

// containsRefusal checks whether an assistant message contains typical
// refusal language.
func containsRefusal(text string) bool {
	refusalPhrases := []string{
		"i can't",
		"i cannot",
		"i'm not able",
		"i am not able",
		"i'm unable",
		"i am unable",
		"i apologize",
		"i'm sorry",
		"against my guidelines",
		"not appropriate",
		"not allowed",
		"i must decline",
		"i won't",
		"i will not",
	}
	for _, phrase := range refusalPhrases {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// severityFromScore maps a 0-1 score to a severity string.
func severityFromScore(score float64) string {
	switch {
	case score >= 0.8:
		return "critical"
	case score >= 0.6:
		return "high"
	case score >= 0.4:
		return "medium"
	case score >= 0.2:
		return "low"
	default:
		return "info"
	}
}
