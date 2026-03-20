// Package stateful provides multi-turn conversation tracking and analysis.
// It maintains session state (in-memory or, in production, backed by Redis),
// detects gradual topic drift, escalation patterns, payload splitting, and
// boundary probing across conversation turns.
package stateful

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// TrackerConfig holds tunables for the session tracker.
type TrackerConfig struct {
	// SessionTimeout is the duration of inactivity after which a session
	// expires. Default: 30 minutes.
	SessionTimeout time.Duration

	// CleanupInterval controls how often expired sessions are reaped.
	// Default: 5 minutes.
	CleanupInterval time.Duration

	// MaxTurnsPerSession caps the number of turns stored per session to
	// bound memory usage. Oldest turns are discarded when exceeded.
	// Default: 200.
	MaxTurnsPerSession int

	// ReassembleWindow is the number of recent turns used when
	// concatenating payloads for split-payload detection. Default: 5.
	ReassembleWindow int

	// EscalationThreshold is the score (0-1) above which a session is
	// flagged for escalation. Default: 0.6.
	EscalationThreshold float64

	// Logger is the structured logger. If nil slog.Default() is used.
	Logger *slog.Logger
}

// DefaultTrackerConfig returns a config with sensible defaults.
func DefaultTrackerConfig() TrackerConfig {
	return TrackerConfig{
		SessionTimeout:      30 * time.Minute,
		CleanupInterval:     5 * time.Minute,
		MaxTurnsPerSession:  200,
		ReassembleWindow:    5,
		EscalationThreshold: 0.6,
		Logger:              slog.Default(),
	}
}

// ---------------------------------------------------------------------------
// Turn and Session types
// ---------------------------------------------------------------------------

// Role identifies whether a turn came from the user or the assistant.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleSystem    Role = "system"
)

// Turn represents a single message in a conversation.
type Turn struct {
	// Role identifies the speaker.
	Role Role `json:"role"`

	// Content is the text content of the turn.
	Content string `json:"content"`

	// Timestamp is when the turn occurred.
	Timestamp time.Time `json:"timestamp"`

	// Metadata holds optional per-turn key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`

	// InjectionScore is the injection detection score for this turn (0-1).
	InjectionScore float64 `json:"injection_score,omitempty"`

	// PIIDetected lists PII types found in this turn.
	PIIDetected []string `json:"pii_detected,omitempty"`

	// TopicKeywords are the extracted topic keywords for drift analysis.
	TopicKeywords []string `json:"topic_keywords,omitempty"`
}

// Session represents a multi-turn conversation.
type Session struct {
	// ID is the unique session identifier.
	ID string `json:"id"`

	// Turns is the ordered list of conversation turns.
	Turns []Turn `json:"turns"`

	// CreatedAt is when the session started.
	CreatedAt time.Time `json:"created_at"`

	// LastActivityAt is the timestamp of the most recent turn.
	LastActivityAt time.Time `json:"last_activity_at"`

	// Metadata holds optional session-level key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`

	// Analysis holds the latest analysis results, if any.
	Analysis *SessionAnalysis `json:"analysis,omitempty"`
}

// SessionAnalysis holds the results of multi-turn analysis.
type SessionAnalysis struct {
	// TopicDriftScore measures how much the conversation topic has drifted
	// from the initial turns. Range: 0 (no drift) to 1 (complete drift).
	TopicDriftScore float64 `json:"topic_drift_score"`

	// EscalationScore measures the escalation risk. Range: 0-1.
	EscalationScore float64 `json:"escalation_score"`

	// PayloadSplitDetected is true if a split payload was identified by
	// concatenating recent turns.
	PayloadSplitDetected bool `json:"payload_split_detected"`

	// BoundaryProbeDetected is true if systematic limit-testing was found.
	BoundaryProbeDetected bool `json:"boundary_probe_detected"`

	// ReassembledPayload is the concatenation of the last N user turns,
	// set when PayloadSplitDetected is true.
	ReassembledPayload string `json:"reassembled_payload,omitempty"`

	// Findings holds detailed per-check findings.
	Findings []AnalysisFinding `json:"findings,omitempty"`

	// AnalyzedAt is when the analysis was performed.
	AnalyzedAt time.Time `json:"analyzed_at"`
}

// AnalysisFinding is a single finding from session analysis.
type AnalysisFinding struct {
	Check       string  `json:"check"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"` // info, low, medium, high, critical
	Score       float64 `json:"score"`
	TurnIndex   int     `json:"turn_index,omitempty"`
}

// ---------------------------------------------------------------------------
// SessionTracker
// ---------------------------------------------------------------------------

// SessionTracker manages multi-turn conversation state and provides
// analysis capabilities. All public methods are safe for concurrent use.
type SessionTracker struct {
	cfg TrackerConfig

	mu       sync.RWMutex
	sessions map[string]*Session

	analyzer *Analyzer

	stopCleanup chan struct{}
	stopped     bool

	logger *slog.Logger
}

// NewSessionTracker creates a new tracker with the given configuration
// and starts the background cleanup goroutine.
func NewSessionTracker(cfg TrackerConfig) *SessionTracker {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SessionTimeout <= 0 {
		cfg.SessionTimeout = 30 * time.Minute
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	if cfg.MaxTurnsPerSession <= 0 {
		cfg.MaxTurnsPerSession = 200
	}
	if cfg.ReassembleWindow <= 0 {
		cfg.ReassembleWindow = 5
	}
	if cfg.EscalationThreshold <= 0 {
		cfg.EscalationThreshold = 0.6
	}

	t := &SessionTracker{
		cfg:         cfg,
		sessions:    make(map[string]*Session),
		analyzer:    NewAnalyzer(cfg),
		stopCleanup: make(chan struct{}),
		logger:      cfg.Logger,
	}

	go t.cleanupLoop()
	return t
}

// Stop terminates the background cleanup goroutine.
func (t *SessionTracker) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.stopped {
		close(t.stopCleanup)
		t.stopped = true
	}
}

// cleanupLoop periodically removes expired sessions.
func (t *SessionTracker) cleanupLoop() {
	ticker := time.NewTicker(t.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCleanup:
			return
		case <-ticker.C:
			removed := t.CleanupExpiredSessions()
			if removed > 0 {
				t.logger.Debug("expired sessions cleaned up", "removed", removed)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Turn tracking
// ---------------------------------------------------------------------------

// TrackTurn adds a conversation turn to the specified session. If the
// session does not exist, it is created. Returns the updated session.
func (t *SessionTracker) TrackTurn(sessionID string, turn Turn) (*Session, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("stateful: sessionID must not be empty")
	}

	now := time.Now()
	if turn.Timestamp.IsZero() {
		turn.Timestamp = now
	}

	// Extract topic keywords for drift detection.
	if len(turn.TopicKeywords) == 0 && turn.Content != "" {
		turn.TopicKeywords = extractKeywords(turn.Content)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	sess, exists := t.sessions[sessionID]
	if !exists {
		sess = &Session{
			ID:             sessionID,
			Turns:          make([]Turn, 0, 32),
			CreatedAt:      now,
			LastActivityAt: now,
			Metadata:       make(map[string]string),
		}
		t.sessions[sessionID] = sess
	}

	sess.LastActivityAt = now
	sess.Turns = append(sess.Turns, turn)

	// Enforce max turns limit.
	if len(sess.Turns) > t.cfg.MaxTurnsPerSession {
		excess := len(sess.Turns) - t.cfg.MaxTurnsPerSession
		sess.Turns = sess.Turns[excess:]
	}

	return sess, nil
}

// ---------------------------------------------------------------------------
// Session queries
// ---------------------------------------------------------------------------

// GetSession returns a copy of the full conversation history for the given
// session ID. Returns nil if not found.
func (t *SessionTracker) GetSession(sessionID string) *Session {
	t.mu.RLock()
	defer t.mu.RUnlock()

	sess, ok := t.sessions[sessionID]
	if !ok {
		return nil
	}

	// Return a copy to avoid races.
	cp := *sess
	cp.Turns = make([]Turn, len(sess.Turns))
	copy(cp.Turns, sess.Turns)
	return &cp
}

// ListSessions returns a snapshot of all active session IDs.
func (t *SessionTracker) ListSessions() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ids := make([]string, 0, len(t.sessions))
	for id := range t.sessions {
		ids = append(ids, id)
	}
	return ids
}

// SessionCount returns the number of active sessions.
func (t *SessionTracker) SessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

// AnalyzeSession runs the full multi-turn analysis suite on the specified
// session and stores the results. It detects:
//   - Gradual topic drift (benign -> edgy -> harmful)
//   - Instruction probing across turns (testing boundaries)
//   - Payload splitting (malicious instruction split across messages)
//   - Escalation patterns
//
// The analysis result is both returned and persisted on the session.
func (t *SessionTracker) AnalyzeSession(sessionID string) (*SessionAnalysis, error) {
	t.mu.RLock()
	sess, ok := t.sessions[sessionID]
	if !ok {
		t.mu.RUnlock()
		return nil, fmt.Errorf("stateful: session %q not found", sessionID)
	}

	// Work on a copy of turns to avoid holding the lock during analysis.
	turns := make([]Turn, len(sess.Turns))
	copy(turns, sess.Turns)
	t.mu.RUnlock()

	analysis := t.analyzer.Analyze(turns)

	// Persist the analysis result.
	t.mu.Lock()
	if s, ok := t.sessions[sessionID]; ok {
		s.Analysis = analysis
	}
	t.mu.Unlock()

	return analysis, nil
}

// EscalationScore computes the escalation risk score (0-1) for the given
// session without performing the full analysis suite. This is a cheaper
// check suitable for real-time gating.
func (t *SessionTracker) EscalationScore(sessionID string) (float64, error) {
	t.mu.RLock()
	sess, ok := t.sessions[sessionID]
	if !ok {
		t.mu.RUnlock()
		return 0, fmt.Errorf("stateful: session %q not found", sessionID)
	}
	turns := make([]Turn, len(sess.Turns))
	copy(turns, sess.Turns)
	t.mu.RUnlock()

	return t.analyzer.escalationDetector.Score(turns), nil
}

// ReassemblePayload concatenates the most recent N user turns and returns
// the result. This is used for split-payload detection: a malicious
// instruction spread across multiple messages will appear in the combined
// text.
func (t *SessionTracker) ReassemblePayload(sessionID string, lastNTurns int) (string, error) {
	if lastNTurns <= 0 {
		lastNTurns = t.cfg.ReassembleWindow
	}

	t.mu.RLock()
	sess, ok := t.sessions[sessionID]
	if !ok {
		t.mu.RUnlock()
		return "", fmt.Errorf("stateful: session %q not found", sessionID)
	}
	turns := make([]Turn, len(sess.Turns))
	copy(turns, sess.Turns)
	t.mu.RUnlock()

	return reassembleUserTurns(turns, lastNTurns), nil
}

// reassembleUserTurns concatenates the last N user turns.
func reassembleUserTurns(turns []Turn, n int) string {
	// Collect user turns.
	userTurns := make([]Turn, 0, len(turns))
	for _, t := range turns {
		if t.Role == RoleUser {
			userTurns = append(userTurns, t)
		}
	}

	start := len(userTurns) - n
	if start < 0 {
		start = 0
	}

	var sb strings.Builder
	for i := start; i < len(userTurns); i++ {
		if sb.Len() > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(userTurns[i].Content)
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

// CleanupExpiredSessions removes all sessions that have been inactive
// longer than the configured timeout. Returns the count removed.
func (t *SessionTracker) CleanupExpiredSessions() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	removed := 0
	for id, sess := range t.sessions {
		if now.Sub(sess.LastActivityAt) > t.cfg.SessionTimeout {
			delete(t.sessions, id)
			removed++
		}
	}
	return removed
}

// ---------------------------------------------------------------------------
// Keyword extraction (simple tokenizer for topic drift)
// ---------------------------------------------------------------------------

// extractKeywords performs a naive keyword extraction: lowercase, split on
// whitespace/punctuation, remove stopwords, and return unique words of
// length >= 3.
func extractKeywords(text string) []string {
	text = strings.ToLower(text)

	// Replace common punctuation with spaces.
	replacer := strings.NewReplacer(
		".", " ", ",", " ", "!", " ", "?", " ", ";", " ", ":", " ",
		"(", " ", ")", " ", "[", " ", "]", " ", "{", " ", "}", " ",
		"\"", " ", "'", " ", "`", " ", "\n", " ", "\r", " ", "\t", " ",
	)
	text = replacer.Replace(text)

	words := strings.Fields(text)
	seen := make(map[string]bool, len(words))
	result := make([]string, 0, len(words)/2)

	for _, w := range words {
		if len(w) < 3 {
			continue
		}
		if stopwords[w] {
			continue
		}
		if seen[w] {
			continue
		}
		seen[w] = true
		result = append(result, w)
	}
	return result
}

// stopwords is a minimal English stopword set for keyword extraction.
var stopwords = map[string]bool{
	"the": true, "and": true, "for": true, "are": true, "but": true,
	"not": true, "you": true, "all": true, "can": true, "had": true,
	"her": true, "was": true, "one": true, "our": true, "out": true,
	"has": true, "his": true, "how": true, "its": true, "may": true,
	"new": true, "now": true, "old": true, "see": true, "way": true,
	"who": true, "did": true, "get": true, "let": true, "say": true,
	"she": true, "too": true, "use": true, "this": true, "that": true,
	"with": true, "have": true, "from": true, "they": true, "been": true,
	"said": true, "each": true, "which": true, "their": true, "will": true,
	"other": true, "about": true, "many": true, "then": true, "them": true,
	"these": true, "some": true, "would": true, "make": true, "like": true,
	"into": true, "just": true, "over": true, "such": true, "also": true,
	"than": true, "very": true, "when": true, "what": true, "your": true,
	"there": true, "could": true, "more": true, "after": true, "those": true,
}
