// Package memory provides a storage.Store adapter for the existing in-memory
// store in pkg/store. It delegates all operations to *store.Store and
// translates between the storage.* types and the store.* types.
package memory

import (
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/storage"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/store"
)

// MemoryStore wraps a *store.Store and implements the storage.Store interface.
type MemoryStore struct {
	inner *store.Store
}

// New creates a new MemoryStore wrapping the given in-memory store.
func New(s *store.Store) *MemoryStore {
	return &MemoryStore{inner: s}
}

// Inner returns the underlying *store.Store for direct access where needed
// (e.g. seeding, or API handlers that still reference the concrete type).
func (m *MemoryStore) Inner() *store.Store {
	return m.inner
}

// --- Events ---

func (m *MemoryStore) RecordEvent(event models.Event) error {
	m.inner.RecordEvent(event)
	return nil
}

func (m *MemoryStore) GetEvents(filter storage.EventFilter) (*storage.PaginatedEvents, error) {
	sf := store.EventFilter{
		Severity: filter.Severity,
		Source:   filter.Source,
		Decision: filter.Decision,
		From:     filter.From,
		To:       filter.To,
		Search:   filter.Search,
		Page:     filter.Page,
		PerPage:  filter.PerPage,
	}
	result := m.inner.GetEvents(sf)
	return &storage.PaginatedEvents{
		Data: result.Data,
		Meta: convertPageMeta(result.Meta),
	}, nil
}

func (m *MemoryStore) GetEvent(id string) (*models.Event, error) {
	return m.inner.GetEvent(id), nil
}

func (m *MemoryStore) GetStats(activeGuardrails int) (*storage.DashboardStats, error) {
	s := m.inner.GetStats(activeGuardrails)
	return &storage.DashboardStats{
		TotalServices:     s.TotalServices,
		ActiveGuardrails:  s.ActiveGuardrails,
		BlockedThreats24h: s.BlockedThreats24h,
		ShadowAIDetected:  s.ShadowAIDetected,
		MonthlyCostUSD:    s.MonthlyCostUSD,
		Events24h:         s.Events24h,
		AvgLatencyMs:      s.AvgLatencyMs,
	}, nil
}

func (m *MemoryStore) GetThreatActivity(days int) ([]storage.ThreatActivityPoint, error) {
	points := m.inner.GetThreatActivity(days)
	out := make([]storage.ThreatActivityPoint, len(points))
	for i, p := range points {
		out[i] = storage.ThreatActivityPoint{
			Date:    p.Date,
			Blocked: p.Blocked,
			Allowed: p.Allowed,
		}
	}
	return out, nil
}

func (m *MemoryStore) GetRiskBreakdown() ([]storage.RiskBreakdown, error) {
	breakdown := m.inner.GetRiskBreakdown()
	out := make([]storage.RiskBreakdown, len(breakdown))
	for i, b := range breakdown {
		out[i] = storage.RiskBreakdown{
			Category: b.Category,
			Count:    b.Count,
			Color:    b.Color,
		}
	}
	return out, nil
}

func (m *MemoryStore) GetTopServices(limit int) ([]storage.TopService, error) {
	services := m.inner.GetTopServices(limit)
	out := make([]storage.TopService, len(services))
	for i, s := range services {
		out[i] = storage.TopService{
			Name:      s.Name,
			Namespace: s.Namespace,
			Calls7d:   s.Calls7d,
			Cost7dUSD: s.Cost7dUSD,
			RiskScore: s.RiskScore,
		}
	}
	return out, nil
}

// --- Services / Inventory ---

func (m *MemoryStore) RecordService(svc models.AIService) error {
	m.inner.RecordService(svc)
	return nil
}

func (m *MemoryStore) GetServices(filter storage.ServiceFilter) (*storage.PaginatedServices, error) {
	sf := store.ServiceFilter{
		Namespace: filter.Namespace,
		Provider:  filter.Provider,
		RiskLevel: filter.RiskLevel,
		Search:    filter.Search,
		Page:      filter.Page,
		PerPage:   filter.PerPage,
	}
	result := m.inner.GetServices(sf)
	return &storage.PaginatedServices{
		Data: result.Data,
		Meta: convertPageMeta(result.Meta),
	}, nil
}

func (m *MemoryStore) GetService(id string) (*models.AIService, error) {
	return m.inner.GetService(id), nil
}

func (m *MemoryStore) GetAIBOM() (*models.AIBOM, error) {
	bom := m.inner.GetAIBOM()
	return &bom, nil
}

// --- Policies ---

func (m *MemoryStore) GetPolicies() ([]models.AISecurityPolicy, error) {
	return m.inner.GetPolicies(), nil
}

func (m *MemoryStore) GetPolicy(name string) (*models.AISecurityPolicy, error) {
	return m.inner.GetPolicy(name), nil
}

func (m *MemoryStore) CreatePolicy(policy models.AISecurityPolicy) error {
	m.inner.AddPolicy(policy)
	return nil
}

func (m *MemoryStore) UpdatePolicy(name string, policy models.AISecurityPolicy) (bool, error) {
	return m.inner.UpdatePolicy(name, policy), nil
}

func (m *MemoryStore) DeletePolicy(name string) (bool, error) {
	return m.inner.DeletePolicy(name), nil
}

// --- Lifecycle ---

func (m *MemoryStore) Close() error {
	return nil
}

// convertPageMeta converts a *store.PageMeta to a *storage.PageMeta.
func convertPageMeta(pm *store.PageMeta) *storage.PageMeta {
	if pm == nil {
		return nil
	}
	return &storage.PageMeta{
		Total:   pm.Total,
		Page:    pm.Page,
		PerPage: pm.PerPage,
	}
}
