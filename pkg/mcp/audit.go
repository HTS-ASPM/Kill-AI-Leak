package mcp

import (
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/events"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// AuditDecision records whether a tool call or server connection was permitted.
type AuditDecision string

const (
	AuditAllow   AuditDecision = "allow"
	AuditDeny    AuditDecision = "deny"
	AuditPending AuditDecision = "pending_approval"
)

// MCPAuditEntry is a single audit log record for an MCP interaction.
type MCPAuditEntry struct {
	ID        string        `json:"id"`
	Timestamp time.Time     `json:"timestamp"`
	EntryType string        `json:"entry_type"` // "tool_call" or "server_connection"
	User      string        `json:"user"`
	Server    string        `json:"server"`
	Tool      string        `json:"tool,omitempty"`
	Arguments string        `json:"arguments,omitempty"`
	Result    string        `json:"result,omitempty"`
	Decision  AuditDecision `json:"decision"`
	Reason    string        `json:"reason,omitempty"`
	LatencyMs int64         `json:"latency_ms,omitempty"`
	RiskScore float64       `json:"risk_score,omitempty"`
	Method    string        `json:"method,omitempty"`
	RequestID string        `json:"request_id,omitempty"`
}

// AuditFilter provides criteria for searching the audit log.
type AuditFilter struct {
	User      string
	Server    string
	Tool      string
	Decision  AuditDecision
	Since     time.Time
	Until     time.Time
	EntryType string
	Limit     int
}

// MCPAuditLog provides structured audit logging for MCP gateway decisions.
// It stores entries in memory for searching and optionally exports them to
// the platform event bus.
type MCPAuditLog struct {
	mu        sync.RWMutex
	entries   []MCPAuditEntry
	maxSize   int
	logger    *slog.Logger
	publisher *events.Publisher
}

// AuditLogConfig controls audit log behavior.
type AuditLogConfig struct {
	// MaxEntries is the maximum number of entries retained in memory.
	// Oldest entries are evicted when the limit is reached.
	MaxEntries int

	// Publisher, if non-nil, causes each audit entry to also be emitted as
	// a platform event through the event bus.
	Publisher *events.Publisher
}

// DefaultAuditLogConfig returns a configuration with sensible defaults.
func DefaultAuditLogConfig() AuditLogConfig {
	return AuditLogConfig{
		MaxEntries: 10000,
	}
}

// NewMCPAuditLog creates a new audit log with the given configuration.
func NewMCPAuditLog(cfg AuditLogConfig, logger *slog.Logger) *MCPAuditLog {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultAuditLogConfig().MaxEntries
	}

	return &MCPAuditLog{
		entries:   make([]MCPAuditEntry, 0, 256),
		maxSize:   cfg.MaxEntries,
		logger:    logger,
		publisher: cfg.Publisher,
	}
}

// LogToolCall records a tool invocation decision in the audit log.
func (a *MCPAuditLog) LogToolCall(user, server, tool string, args json.RawMessage, result string, decision AuditDecision, reason string, latencyMs int64) {
	entry := MCPAuditEntry{
		ID:        events.GenerateEventID(),
		Timestamp: time.Now().UTC(),
		EntryType: "tool_call",
		User:      user,
		Server:    server,
		Tool:      tool,
		Arguments: truncate(string(args), 4096),
		Result:    truncate(result, 4096),
		Decision:  decision,
		Reason:    reason,
		LatencyMs: latencyMs,
		Method:    MethodToolsCall,
	}

	a.append(entry)

	a.logger.Info("mcp audit: tool call",
		"user", user,
		"server", server,
		"tool", tool,
		"decision", decision,
		"reason", reason,
		"latency_ms", latencyMs,
	)
}

// LogServerConnection records a server connection decision in the audit log.
func (a *MCPAuditLog) LogServerConnection(user, server string, decision AuditDecision, reason string) {
	entry := MCPAuditEntry{
		ID:        events.GenerateEventID(),
		Timestamp: time.Now().UTC(),
		EntryType: "server_connection",
		User:      user,
		Server:    server,
		Decision:  decision,
		Reason:    reason,
		Method:    MethodInitialize,
	}

	a.append(entry)

	a.logger.Info("mcp audit: server connection",
		"user", user,
		"server", server,
		"decision", decision,
		"reason", reason,
	)
}

// Search returns audit entries matching the given filter, ordered from newest
// to oldest.
func (a *MCPAuditLog) Search(filter AuditFilter) []MCPAuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	var results []MCPAuditEntry

	// Iterate backwards for newest-first ordering.
	for i := len(a.entries) - 1; i >= 0 && len(results) < limit; i-- {
		e := a.entries[i]

		if filter.User != "" && !strings.EqualFold(e.User, filter.User) {
			continue
		}
		if filter.Server != "" && !strings.EqualFold(e.Server, filter.Server) {
			continue
		}
		if filter.Tool != "" && !strings.EqualFold(e.Tool, filter.Tool) {
			continue
		}
		if filter.Decision != "" && e.Decision != filter.Decision {
			continue
		}
		if filter.EntryType != "" && e.EntryType != filter.EntryType {
			continue
		}
		if !filter.Since.IsZero() && e.Timestamp.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && e.Timestamp.After(filter.Until) {
			continue
		}

		results = append(results, e)
	}

	return results
}

// Entries returns all audit entries in chronological order.
func (a *MCPAuditLog) Entries() []MCPAuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := make([]MCPAuditEntry, len(a.entries))
	copy(out, a.entries)
	return out
}

// Len returns the current number of audit entries.
func (a *MCPAuditLog) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries)
}

// append adds an entry to the log, evicting the oldest entry if at capacity,
// and optionally publishing an event to the platform event bus.
func (a *MCPAuditLog) append(entry MCPAuditEntry) {
	a.mu.Lock()

	if len(a.entries) >= a.maxSize {
		// Evict the oldest 10% to amortize shift cost.
		evict := a.maxSize / 10
		if evict < 1 {
			evict = 1
		}
		a.entries = a.entries[evict:]
	}

	a.entries = append(a.entries, entry)
	a.mu.Unlock()

	// Export to event bus if configured.
	if a.publisher != nil {
		a.exportToEventBus(entry)
	}
}

// exportToEventBus converts an audit entry to a platform Event and publishes
// it asynchronously.
func (a *MCPAuditLog) exportToEventBus(entry MCPAuditEntry) {
	severity := models.SeverityInfo
	if entry.Decision == AuditDeny {
		severity = models.SeverityMedium
	}

	event := &models.Event{
		ID:        entry.ID,
		Timestamp: entry.Timestamp,
		Source:    models.SourceMCPGateway,
		Severity:  severity,
		Actor: models.Actor{
			Type: models.ActorAgent,
			ID:   entry.User,
			Name: entry.User,
		},
		Target: models.Target{
			Type: models.TargetMCPServer,
			ID:   entry.Server,
		},
		Action: models.Action{
			Type:      models.ActionToolExec,
			Direction: models.DirectionOutbound,
			Protocol:  "mcp",
			Method:    entry.Method,
		},
		Content: models.ContentMeta{
			Blocked: entry.Decision == AuditDeny,
		},
		Metadata: map[string]string{
			"tool":       entry.Tool,
			"decision":   string(entry.Decision),
			"reason":     entry.Reason,
			"entry_type": entry.EntryType,
		},
	}

	if err := a.publisher.PublishGuardrailEvent(event); err != nil {
		a.logger.Warn("failed to publish MCP audit event",
			"entry_id", entry.ID,
			"error", err,
		)
	}
}

// truncate shortens a string to at most maxLen bytes.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
