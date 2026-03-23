// Package correlator provides cross-sensor event correlation for the AI
// security platform. It links related events from different sources (eBPF,
// gateway, browser) to build richer security context and escalate severity
// when patterns emerge.
package correlator

import (
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

const (
	// defaultWindowDuration is the sliding window for correlation.
	defaultWindowDuration = 10 * time.Minute
	// maxBufferSize is the maximum number of events in the buffer.
	maxBufferSize = 1000
	// sessionLinkWindow is the time window for linking events into a session.
	sessionLinkWindow = 5 * time.Minute
	// escalationWindow is the time window for detecting burst patterns.
	escalationWindow = 1 * time.Minute
)

// CorrelationType classifies how events are related.
type CorrelationType string

const (
	CorrelationSession      CorrelationType = "session"
	CorrelationEnriched     CorrelationType = "enriched"
	CorrelationEscalated    CorrelationType = "escalated"
	CorrelationUnprotected  CorrelationType = "unprotected_ai"
)

// CorrelatedEvent bundles a primary event with its related events and
// correlation metadata.
type CorrelatedEvent struct {
	Primary          models.Event    `json:"primary"`
	RelatedEvents    []models.Event  `json:"related_events"`
	CorrelationType  CorrelationType `json:"correlation_type"`
	CombinedSeverity models.Severity `json:"combined_severity"`
	Reason           string          `json:"reason"`
	CorrelatedAt     time.Time       `json:"correlated_at"`
}

// Correlator processes events from multiple sensors and finds correlations
// within a sliding time window. It is safe for concurrent use.
type Correlator struct {
	mu             sync.RWMutex
	events         []models.Event
	correlations   []CorrelatedEvent
	windowDuration time.Duration
	maxBuffer      int
}

// New creates a Correlator with default settings.
func New() *Correlator {
	return &Correlator{
		windowDuration: defaultWindowDuration,
		maxBuffer:      maxBufferSize,
	}
}

// ProcessEvent adds an event to the correlation buffer and triggers
// correlation analysis.
func (c *Correlator) ProcessEvent(event models.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict old events outside the window.
	c.pruneOldEvents()

	// Evict oldest if at capacity.
	if len(c.events) >= c.maxBuffer {
		c.events = c.events[1:]
	}
	c.events = append(c.events, event)

	// Run correlation checks against the new event.
	c.correlateLocked(event)
}

// Correlate runs correlation analysis across all events in the current window.
// Call this periodically or after a batch of events.
func (c *Correlator) Correlate() []CorrelatedEvent {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneOldEvents()

	// Clear previous correlations and rebuild.
	c.correlations = nil

	// Session linking: same actor + same provider within sessionLinkWindow.
	c.correlateSessionsLocked()

	// Enrichment: eBPF + gateway event pairing.
	c.correlateEnrichmentLocked()

	// Escalation: burst detection.
	c.correlateEscalationLocked()

	// Shadow AI detection.
	c.correlateShadowAILocked()

	out := make([]CorrelatedEvent, len(c.correlations))
	copy(out, c.correlations)
	return out
}

// GetCorrelatedEvents returns correlated events for a specific actor within
// a given time window.
func (c *Correlator) GetCorrelatedEvents(actorID string, timeWindow time.Duration) []CorrelatedEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cutoff := time.Now().Add(-timeWindow)
	var out []CorrelatedEvent
	for _, ce := range c.correlations {
		if ce.Primary.Actor.ID == actorID && ce.CorrelatedAt.After(cutoff) {
			out = append(out, ce)
		}
	}
	return out
}

// EventCount returns the number of events in the buffer.
func (c *Correlator) EventCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.events)
}

// ---------------------------------------------------------------------------
// Internal correlation logic (must be called with lock held)
// ---------------------------------------------------------------------------

// correlateLocked runs correlation for a single newly added event.
func (c *Correlator) correlateLocked(event models.Event) {
	c.checkSessionLink(event)
	c.checkEnrichment(event)
	c.checkEscalation(event)
	c.checkShadowAI(event)
}

// checkSessionLink links events from the same actor and provider within
// the session window.
func (c *Correlator) checkSessionLink(event models.Event) {
	cutoff := event.Timestamp.Add(-sessionLinkWindow)
	var related []models.Event

	for i := range c.events {
		ev := &c.events[i]
		if ev.ID == event.ID {
			continue
		}
		if ev.Actor.ID == event.Actor.ID &&
			ev.Target.Provider == event.Target.Provider &&
			ev.Timestamp.After(cutoff) {
			related = append(related, *ev)
		}
	}

	if len(related) > 0 {
		c.correlations = append(c.correlations, CorrelatedEvent{
			Primary:          event,
			RelatedEvents:    related,
			CorrelationType:  CorrelationSession,
			CombinedSeverity: event.Severity,
			Reason:           "events linked as session: same actor and provider within 5 minutes",
			CorrelatedAt:     time.Now(),
		})
	}
}

// checkEnrichment pairs eBPF network events with gateway guardrail events.
func (c *Correlator) checkEnrichment(event models.Event) {
	if event.Source != models.SourceKernelObserver {
		return
	}

	cutoff := event.Timestamp.Add(-sessionLinkWindow)
	for i := range c.events {
		ev := &c.events[i]
		if ev.Source != models.SourceInlineGateway {
			continue
		}
		if ev.Actor.ID != event.Actor.ID {
			continue
		}
		if !ev.Timestamp.After(cutoff) {
			continue
		}
		if ev.Content.Blocked {
			c.correlations = append(c.correlations, CorrelatedEvent{
				Primary:          event,
				RelatedEvents:    []models.Event{*ev},
				CorrelationType:  CorrelationEnriched,
				CombinedSeverity: higherSeverity(event.Severity, ev.Severity),
				Reason:           "eBPF network event enriched with gateway guardrail block details",
				CorrelatedAt:     time.Now(),
			})
			break
		}
	}
}

// checkEscalation detects multiple blocked events from the same actor within
// the escalation window and escalates severity to critical.
func (c *Correlator) checkEscalation(event models.Event) {
	if !event.Content.Blocked {
		return
	}

	cutoff := event.Timestamp.Add(-escalationWindow)
	blockedCount := 0
	var blockedEvents []models.Event

	for i := range c.events {
		ev := &c.events[i]
		if ev.ID == event.ID {
			continue
		}
		if ev.Actor.ID == event.Actor.ID &&
			ev.Content.Blocked &&
			ev.Timestamp.After(cutoff) {
			blockedCount++
			blockedEvents = append(blockedEvents, *ev)
		}
	}

	// Escalate if 2+ other blocked events in the window (3+ total including current).
	if blockedCount >= 2 {
		c.correlations = append(c.correlations, CorrelatedEvent{
			Primary:          event,
			RelatedEvents:    blockedEvents,
			CorrelationType:  CorrelationEscalated,
			CombinedSeverity: models.SeverityCritical,
			Reason:           "multiple blocked events from same actor within 1 minute; escalated to critical",
			CorrelatedAt:     time.Now(),
		})
	}
}

// checkShadowAI detects eBPF-discovered AI usage with no corresponding
// gateway enrollment.
func (c *Correlator) checkShadowAI(event models.Event) {
	if event.Source != models.SourceKernelObserver {
		return
	}

	// Look for any gateway event from the same actor.
	hasGatewayEvent := false
	for i := range c.events {
		ev := &c.events[i]
		if ev.Actor.ID == event.Actor.ID && ev.Source == models.SourceInlineGateway {
			hasGatewayEvent = true
			break
		}
	}

	if !hasGatewayEvent {
		c.correlations = append(c.correlations, CorrelatedEvent{
			Primary:          event,
			CorrelationType:  CorrelationUnprotected,
			CombinedSeverity: models.SeverityHigh,
			Reason:           "shadow AI detected: eBPF observed AI usage with no gateway enrollment",
			CorrelatedAt:     time.Now(),
		})
	}
}

// correlateSessionsLocked runs session correlation across all events.
func (c *Correlator) correlateSessionsLocked() {
	type sessionKey struct {
		actorID  string
		provider string
	}
	sessions := make(map[sessionKey][]int) // indices into c.events

	for i := range c.events {
		key := sessionKey{
			actorID:  c.events[i].Actor.ID,
			provider: c.events[i].Target.Provider,
		}
		sessions[key] = append(sessions[key], i)
	}

	for _, indices := range sessions {
		if len(indices) < 2 {
			continue
		}
		// Check if events fall within the session window.
		for i := 1; i < len(indices); i++ {
			ev := c.events[indices[i]]
			prevEv := c.events[indices[i-1]]
			if ev.Timestamp.Sub(prevEv.Timestamp) <= sessionLinkWindow {
				c.correlations = append(c.correlations, CorrelatedEvent{
					Primary:          ev,
					RelatedEvents:    []models.Event{prevEv},
					CorrelationType:  CorrelationSession,
					CombinedSeverity: higherSeverity(ev.Severity, prevEv.Severity),
					Reason:           "session linkage: same actor and provider within 5 minutes",
					CorrelatedAt:     time.Now(),
				})
			}
		}
	}
}

// correlateEnrichmentLocked pairs eBPF events with gateway events.
func (c *Correlator) correlateEnrichmentLocked() {
	for i := range c.events {
		if c.events[i].Source == models.SourceKernelObserver {
			c.checkEnrichment(c.events[i])
		}
	}
}

// correlateEscalationLocked detects burst blocked events.
func (c *Correlator) correlateEscalationLocked() {
	for i := range c.events {
		if c.events[i].Content.Blocked {
			c.checkEscalation(c.events[i])
		}
	}
}

// correlateShadowAILocked detects unprotected AI usage across all events.
func (c *Correlator) correlateShadowAILocked() {
	for i := range c.events {
		if c.events[i].Source == models.SourceKernelObserver {
			c.checkShadowAI(c.events[i])
		}
	}
}

// pruneOldEvents removes events outside the sliding window.
func (c *Correlator) pruneOldEvents() {
	cutoff := time.Now().Add(-c.windowDuration)
	start := 0
	for start < len(c.events) && c.events[start].Timestamp.Before(cutoff) {
		start++
	}
	if start > 0 {
		c.events = c.events[start:]
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// severityRank maps severities to numeric ranks for comparison.
var severityRank = map[models.Severity]int{
	models.SeverityInfo:     0,
	models.SeverityLow:      1,
	models.SeverityMedium:   2,
	models.SeverityHigh:     3,
	models.SeverityCritical: 4,
}

func higherSeverity(a, b models.Severity) models.Severity {
	if severityRank[a] >= severityRank[b] {
		return a
	}
	return b
}
