// Package anonymizer provides PII anonymization and deanonymization with
// session-scoped, thread-safe token mappings.
package anonymizer

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// tokenPrefix maps PII types to their placeholder label.
var tokenPrefix = map[models.PIIType]string{
	models.PIIEmail:         "EMAIL",
	models.PIIPhone:         "PHONE",
	models.PIISSN:           "SSN",
	models.PIICreditCard:    "CREDIT_CARD",
	models.PIIName:          "PERSON",
	models.PIIAddress:       "ADDRESS",
	models.PIIDOB:           "DOB",
	models.PIIPassport:      "PASSPORT",
	models.PIIMedicalID:     "MEDICAL_ID",
	models.PIIBankAccount:   "BANK_ACCOUNT",
	models.PIIDriverLicense: "DRIVERS_LICENSE",
	models.PIIIPAddress:     "IP_ADDRESS",
	models.PIIEmployeeID:    "EMPLOYEE_ID",
}

// Finding represents a detected PII occurrence in text. This mirrors
// models.Finding but is focused on the fields the anonymizer needs.
type Finding struct {
	// Type is the PII type (must be a valid models.PIIType value).
	Type models.PIIType

	// Value is the original PII text that was detected.
	Value string

	// StartPos is the byte offset of the first character.
	StartPos int

	// EndPos is the byte offset one past the last character.
	EndPos int
}

// sessionState holds the mappings for a single session.
type sessionState struct {
	// forward maps original PII values to their placeholder tokens.
	forward map[string]string

	// reverse maps placeholder tokens back to original values.
	reverse map[string]string

	// counters tracks how many of each PII type have been seen so that
	// tokens can be numbered (<PERSON_1>, <PERSON_2>, ...).
	counters map[string]int

	// createdAt is when the session was first used.
	createdAt time.Time

	// lastUsed is the most recent access time.
	lastUsed time.Time
}

// Anonymizer replaces PII in text with deterministic, numbered tokens
// (<PERSON_1>, <EMAIL_1>, etc.) and supports reversing the replacement
// within the same session.
//
// All methods are safe for concurrent use.
type Anonymizer struct {
	mu       sync.RWMutex
	sessions map[string]*sessionState
}

// New creates a new Anonymizer.
func New() *Anonymizer {
	return &Anonymizer{
		sessions: make(map[string]*sessionState),
	}
}

// getOrCreateSession returns the session state, creating it if necessary.
// Caller must NOT hold a.mu.
func (a *Anonymizer) getOrCreateSession(sessionID string) *sessionState {
	a.mu.Lock()
	defer a.mu.Unlock()

	s, ok := a.sessions[sessionID]
	if !ok {
		s = &sessionState{
			forward:   make(map[string]string),
			reverse:   make(map[string]string),
			counters:  make(map[string]int),
			createdAt: time.Now().UTC(),
		}
		a.sessions[sessionID] = s
	}
	s.lastUsed = time.Now().UTC()
	return s
}

// Anonymize replaces all PII findings in text with numbered placeholder
// tokens. Findings must be sorted by StartPos ascending for correct
// positional replacement. If the same PII value was already seen in the
// session, the same token is reused.
//
// Returns the anonymized text and a map from original values to their
// placeholder tokens.
func (a *Anonymizer) Anonymize(sessionID, text string, findings []Finding) (string, map[string]string) {
	if len(findings) == 0 {
		return text, nil
	}

	sess := a.getOrCreateSession(sessionID)

	// Sort findings by StartPos descending so we can replace from the
	// end of the string without invalidating earlier offsets.
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sortFindingsDesc(sorted)

	applied := make(map[string]string)
	result := text

	for _, f := range sorted {
		token := a.tokenFor(sess, f.Type, f.Value)
		applied[f.Value] = token

		// Guard against out-of-range positions.
		start := f.StartPos
		end := f.EndPos
		if start < 0 {
			start = 0
		}
		if end > len(result) {
			end = len(result)
		}
		if start >= end {
			continue
		}

		result = result[:start] + token + result[end:]
	}

	return result, applied
}

// tokenFor returns a deterministic placeholder for the given PII value,
// creating a new numbered token if this value hasn't been seen before.
// Caller must have obtained sess from getOrCreateSession.
func (a *Anonymizer) tokenFor(sess *sessionState, piiType models.PIIType, value string) string {
	a.mu.Lock()
	defer a.mu.Unlock()

	if existing, ok := sess.forward[value]; ok {
		return existing
	}

	prefix, ok := tokenPrefix[piiType]
	if !ok {
		prefix = strings.ToUpper(string(piiType))
	}

	sess.counters[prefix]++
	token := fmt.Sprintf("<%s_%d>", prefix, sess.counters[prefix])

	sess.forward[value] = token
	sess.reverse[token] = value
	return token
}

// Deanonymize reverses all placeholder tokens in text back to their
// original PII values using the session mapping.
func (a *Anonymizer) Deanonymize(sessionID, text string) string {
	a.mu.RLock()
	sess, ok := a.sessions[sessionID]
	if !ok {
		a.mu.RUnlock()
		return text
	}

	// Copy the reverse map under read lock to avoid holding the lock
	// during replacement.
	reverse := make(map[string]string, len(sess.reverse))
	for k, v := range sess.reverse {
		reverse[k] = v
	}
	a.mu.RUnlock()

	result := text
	for token, original := range reverse {
		result = strings.ReplaceAll(result, token, original)
	}
	return result
}

// CleanupSession removes all mappings for the given session, freeing
// memory.
func (a *Anonymizer) CleanupSession(sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, sessionID)
}

// CleanupStaleSessions removes all sessions that have not been used for
// longer than maxAge.
func (a *Anonymizer) CleanupStaleSessions(maxAge time.Duration) int {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := time.Now().UTC().Add(-maxAge)
	removed := 0

	for id, sess := range a.sessions {
		if sess.lastUsed.Before(cutoff) {
			delete(a.sessions, id)
			removed++
		}
	}
	return removed
}

// SessionCount returns the number of active sessions.
func (a *Anonymizer) SessionCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.sessions)
}

// GetSessionMappings returns a copy of the forward mapping (original ->
// token) for a given session. Returns nil if the session doesn't exist.
func (a *Anonymizer) GetSessionMappings(sessionID string) map[string]string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	sess, ok := a.sessions[sessionID]
	if !ok {
		return nil
	}

	out := make(map[string]string, len(sess.forward))
	for k, v := range sess.forward {
		out[k] = v
	}
	return out
}

// sortFindingsDesc sorts findings by StartPos in descending order using
// insertion sort (findings slices are typically small).
func sortFindingsDesc(findings []Finding) {
	for i := 1; i < len(findings); i++ {
		key := findings[i]
		j := i - 1
		for j >= 0 && findings[j].StartPos < key.StartPos {
			findings[j+1] = findings[j]
			j--
		}
		findings[j+1] = key
	}
}
