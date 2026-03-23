// Package storage defines the Store interface and shared types for pluggable
// storage backends (in-memory, PostgreSQL, etc.).
package storage

import (
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Store is the interface that all storage backends must implement.
// The gateway selects a concrete implementation at startup based on
// configuration (e.g. "memory" or "postgres").
type Store interface {
	// --- Events ---

	// RecordEvent persists a new event.
	RecordEvent(event models.Event) error

	// GetEvents returns events matching the filter, paginated.
	GetEvents(filter EventFilter) (*PaginatedEvents, error)

	// GetEvent returns a single event by ID, or nil if not found.
	GetEvent(id string) (*models.Event, error)

	// GetStats computes dashboard statistics from current data.
	GetStats(activeGuardrails int) (*DashboardStats, error)

	// GetThreatActivity aggregates events by day over the given number of days.
	GetThreatActivity(days int) ([]ThreatActivityPoint, error)

	// GetRiskBreakdown counts events by guardrail category.
	GetRiskBreakdown() ([]RiskBreakdown, error)

	// GetTopServices returns the top N services by event count.
	GetTopServices(limit int) ([]TopService, error)

	// --- Services / Inventory ---

	// RecordService upserts a service entry.
	RecordService(svc models.AIService) error

	// GetServices returns services matching the filter, paginated.
	GetServices(filter ServiceFilter) (*PaginatedServices, error)

	// GetService returns a single service by ID, or nil.
	GetService(id string) (*models.AIService, error)

	// GetAIBOM generates a bill of materials from current data.
	GetAIBOM() (*models.AIBOM, error)

	// --- Policies ---

	// GetPolicies returns all stored policies.
	GetPolicies() ([]models.AISecurityPolicy, error)

	// GetPolicy returns a single policy by name, or nil.
	GetPolicy(name string) (*models.AISecurityPolicy, error)

	// CreatePolicy adds a new policy.
	CreatePolicy(policy models.AISecurityPolicy) error

	// UpdatePolicy replaces a policy by name. Returns false if not found.
	UpdatePolicy(name string, policy models.AISecurityPolicy) (bool, error)

	// DeletePolicy removes a policy by name. Returns false if not found.
	DeletePolicy(name string) (bool, error)

	// --- Lifecycle ---

	// Close releases any resources held by the store (e.g. DB connections).
	Close() error
}

// EventFilter controls which events are returned by GetEvents.
type EventFilter struct {
	Severity string
	Source   string
	Decision string // "blocked" or "allowed"
	From     time.Time
	To       time.Time
	Search   string
	Page     int
	PerPage  int
}

// ServiceFilter controls which services are returned by GetServices.
type ServiceFilter struct {
	Namespace string
	Provider  string
	RiskLevel string // "low", "medium", "high", "critical"
	Search    string
	Page      int
	PerPage   int
}

// DashboardStats holds top-level dashboard numbers.
type DashboardStats struct {
	TotalServices     int     `json:"total_services"`
	ActiveGuardrails  int     `json:"active_guardrails"`
	BlockedThreats24h int     `json:"blocked_threats_24h"`
	ShadowAIDetected  int     `json:"shadow_ai_detected"`
	MonthlyCostUSD    float64 `json:"monthly_cost_usd"`
	Events24h         int     `json:"events_24h"`
	AvgLatencyMs      float64 `json:"avg_latency_ms"`
}

// ThreatActivityPoint is one day's worth of threat activity.
type ThreatActivityPoint struct {
	Date    string `json:"date"`
	Blocked int    `json:"blocked"`
	Allowed int    `json:"allowed"`
}

// RiskBreakdown is a category count for the risk breakdown chart.
type RiskBreakdown struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
	Color    string `json:"color"`
}

// TopService summarises a high-activity service.
type TopService struct {
	Name      string  `json:"name"`
	Namespace string  `json:"namespace"`
	Calls7d   int     `json:"calls_7d"`
	Cost7dUSD float64 `json:"cost_7d_usd"`
	RiskScore float64 `json:"risk_score"`
}

// PaginatedEvents wraps a page of events with metadata.
type PaginatedEvents struct {
	Data []models.Event `json:"data"`
	Meta *PageMeta      `json:"meta,omitempty"`
}

// PaginatedServices wraps a page of services with metadata.
type PaginatedServices struct {
	Data []models.AIService `json:"data"`
	Meta *PageMeta          `json:"meta,omitempty"`
}

// PageMeta carries pagination info.
type PageMeta struct {
	Total   int `json:"total"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
}

// NormalizePagination ensures page and perPage are within sane bounds.
func NormalizePagination(page, perPage int) (int, int) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}
	return page, perPage
}
