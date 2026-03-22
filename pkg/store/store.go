package store

import (
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

const maxEvents = 10000

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

// Store is a thread-safe in-memory store for events, services, and policies.
type Store struct {
	mu       sync.RWMutex
	events   []models.Event
	services map[string]*models.AIService
	policies []models.AISecurityPolicy
}

// New creates an empty Store.
func New() *Store {
	return &Store{
		services: make(map[string]*models.AIService),
	}
}

// RecordEvent appends an event to the ring buffer, evicting the oldest when
// the buffer reaches its capacity.
func (s *Store) RecordEvent(event models.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= maxEvents {
		// Drop the oldest event.
		s.events = s.events[1:]
	}
	s.events = append(s.events, event)
}

// GetEvents returns events matching the filter, paginated.
func (s *Store) GetEvents(f EventFilter) PaginatedEvents {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []models.Event
	for i := len(s.events) - 1; i >= 0; i-- {
		ev := s.events[i]
		if f.Severity != "" && string(ev.Severity) != f.Severity {
			continue
		}
		if f.Source != "" && string(ev.Source) != f.Source {
			continue
		}
		if f.Decision == "blocked" && !ev.Content.Blocked {
			continue
		}
		if f.Decision == "allowed" && ev.Content.Blocked {
			continue
		}
		if !f.From.IsZero() && ev.Timestamp.Before(f.From) {
			continue
		}
		if !f.To.IsZero() && ev.Timestamp.After(f.To) {
			continue
		}
		if f.Search != "" {
			needle := strings.ToLower(f.Search)
			haystack := strings.ToLower(ev.Actor.ID + " " + ev.Target.Provider + " " + ev.Target.Model + " " + ev.ID)
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		filtered = append(filtered, ev)
	}

	total := len(filtered)
	page, perPage := normalizePagination(f.Page, f.PerPage)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	return PaginatedEvents{
		Data: filtered[start:end],
		Meta: &PageMeta{Total: total, Page: page, PerPage: perPage},
	}
}

// GetEvent returns a single event by ID, or nil if not found.
func (s *Store) GetEvent(id string) *models.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.events {
		if s.events[i].ID == id {
			ev := s.events[i]
			return &ev
		}
	}
	return nil
}

// GetStats computes dashboard stats from current data.
func (s *Store) GetStats(activeGuardrails int) DashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	cutoff24h := now.Add(-24 * time.Hour)

	var (
		blocked24h int
		events24h  int
		totalLat   int64
		latCount   int
		totalCost  float64
		shadowAI   int
	)

	for i := range s.events {
		ev := &s.events[i]
		if ev.Timestamp.After(cutoff24h) {
			events24h++
			if ev.Content.Blocked {
				blocked24h++
			}
			if ev.LatencyMs > 0 {
				totalLat += ev.LatencyMs
				latCount++
			}
		}
		totalCost += ev.CostUSD
	}

	for _, svc := range s.services {
		if !svc.GatewayEnrolled {
			shadowAI++
		}
	}

	var avgLat float64
	if latCount > 0 {
		avgLat = float64(totalLat) / float64(latCount)
	}

	return DashboardStats{
		TotalServices:     len(s.services),
		ActiveGuardrails:  activeGuardrails,
		BlockedThreats24h: blocked24h,
		ShadowAIDetected:  shadowAI,
		MonthlyCostUSD:    totalCost * 4, // rough monthly estimate from current data
		Events24h:         events24h,
		AvgLatencyMs:      avgLat,
	}
}

// GetThreatActivity aggregates events by day over the given number of days.
func (s *Store) GetThreatActivity(days int) []ThreatActivityPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if days <= 0 {
		days = 7
	}

	now := time.Now()
	points := make([]ThreatActivityPoint, days)
	for i := 0; i < days; i++ {
		d := now.AddDate(0, 0, -(days - 1 - i))
		points[i] = ThreatActivityPoint{
			Date: d.Format("2006-01-02"),
		}
	}

	cutoff := now.AddDate(0, 0, -(days - 1)).Truncate(24 * time.Hour)
	for i := range s.events {
		ev := &s.events[i]
		if ev.Timestamp.Before(cutoff) {
			continue
		}
		dayKey := ev.Timestamp.Format("2006-01-02")
		for j := range points {
			if points[j].Date == dayKey {
				if ev.Content.Blocked {
					points[j].Blocked++
				} else {
					points[j].Allowed++
				}
				break
			}
		}
	}

	return points
}

// categoryColors maps guardrail categories to chart colours.
var categoryColors = map[string]string{
	"injection":   "#ef4444",
	"jailbreak":   "#f97316",
	"pii":         "#eab308",
	"secrets":     "#22c55e",
	"toxicity":    "#3b82f6",
	"code_safety": "#8b5cf6",
	"rate_limit":  "#ec4899",
	"exfiltration": "#14b8a6",
}

// GetRiskBreakdown counts events by guardrail category.
func (s *Store) GetRiskBreakdown() []RiskBreakdown {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := make(map[string]int)
	for i := range s.events {
		for _, gr := range s.events[i].Guardrails {
			if gr.Decision != string(models.DecisionAllow) {
				// Use the rule_id prefix as a rough category, or fall back to
				// a simple mapping from common rule IDs.
				cat := ruleIDToCategory(gr.RuleID)
				counts[cat]++
			}
		}
	}

	out := make([]RiskBreakdown, 0, len(counts))
	for cat, cnt := range counts {
		color := categoryColors[cat]
		if color == "" {
			color = "#6b7280"
		}
		out = append(out, RiskBreakdown{
			Category: cat,
			Count:    cnt,
			Color:    color,
		})
	}
	return out
}

// GetTopServices returns the top N services by event count.
func (s *Store) GetTopServices(limit int) []TopService {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 10
	}

	type svcAcc struct {
		name      string
		namespace string
		calls     int
		cost      float64
		risk      float64
	}
	acc := make(map[string]*svcAcc)

	for i := range s.events {
		ev := &s.events[i]
		sid := ev.Actor.ID
		if sid == "" {
			continue
		}
		a, ok := acc[sid]
		if !ok {
			a = &svcAcc{name: ev.Actor.Name, namespace: ev.Actor.Namespace}
			if a.name == "" {
				a.name = sid
			}
			acc[sid] = a
		}
		a.calls++
		a.cost += ev.CostUSD
	}

	// Merge risk scores from services.
	for id, a := range acc {
		if svc, ok := s.services[id]; ok {
			a.risk = svc.RiskScore
			if a.name == id {
				a.name = svc.Name
			}
			a.namespace = svc.Namespace
		}
	}

	// Sort by calls descending.
	type kv struct {
		key string
		val *svcAcc
	}
	sorted := make([]kv, 0, len(acc))
	for k, v := range acc {
		sorted = append(sorted, kv{k, v})
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].val.calls > sorted[i].val.calls {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	if len(sorted) > limit {
		sorted = sorted[:limit]
	}

	out := make([]TopService, len(sorted))
	for i, kv := range sorted {
		out[i] = TopService{
			Name:      kv.val.name,
			Namespace: kv.val.namespace,
			Calls7d:   kv.val.calls,
			Cost7dUSD: kv.val.cost,
			RiskScore: kv.val.risk,
		}
	}
	return out
}

// RecordService upserts a service entry.
func (s *Store) RecordService(svc models.AIService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.services[svc.ID]
	if ok {
		existing.LastSeenAt = svc.LastSeenAt
		// Merge providers.
		for _, p := range svc.Providers {
			found := false
			for j := range existing.Providers {
				if existing.Providers[j].Provider == p.Provider {
					existing.Providers[j].CallCount7d += p.CallCount7d
					existing.Providers[j].LastCallAt = p.LastCallAt
					found = true
					break
				}
			}
			if !found {
				existing.Providers = append(existing.Providers, p)
			}
		}
	} else {
		cp := svc
		s.services[svc.ID] = &cp
	}
}

// GetServices returns services matching the filter, paginated.
func (s *Store) GetServices(f ServiceFilter) PaginatedServices {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []models.AIService
	for _, svc := range s.services {
		if f.Namespace != "" && svc.Namespace != f.Namespace {
			continue
		}
		if f.Provider != "" {
			found := false
			for _, p := range svc.Providers {
				if p.Provider == f.Provider {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if f.RiskLevel != "" {
			level := riskLevel(svc.RiskScore)
			if level != f.RiskLevel {
				continue
			}
		}
		if f.Search != "" {
			needle := strings.ToLower(f.Search)
			haystack := strings.ToLower(svc.Name + " " + svc.Namespace + " " + svc.ID)
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		filtered = append(filtered, *svc)
	}

	total := len(filtered)
	page, perPage := normalizePagination(f.Page, f.PerPage)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	return PaginatedServices{
		Data: filtered[start:end],
		Meta: &PageMeta{Total: total, Page: page, PerPage: perPage},
	}
}

// GetService returns a single service by ID, or nil.
func (s *Store) GetService(id string) *models.AIService {
	s.mu.RLock()
	defer s.mu.RUnlock()
	svc, ok := s.services[id]
	if !ok {
		return nil
	}
	cp := *svc
	return &cp
}

// GetAIBOM generates a bill of materials from current data.
func (s *Store) GetAIBOM() models.AIBOM {
	s.mu.RLock()
	defer s.mu.RUnlock()

	services := make([]models.AIService, 0, len(s.services))
	providerSet := make(map[string]bool)
	modelSet := make(map[string]bool)
	dbCount := 0
	shadowCount := 0
	highRisk := 0
	var totalCost float64

	for _, svc := range s.services {
		services = append(services, *svc)
		for _, p := range svc.Providers {
			providerSet[p.Provider] = true
			for _, m := range p.Models {
				modelSet[m] = true
			}
			totalCost += p.EstCost7dUSD
		}
		dbCount += len(svc.Databases)
		if !svc.GatewayEnrolled {
			shadowCount++
		}
		if svc.RiskScore >= 0.7 {
			highRisk++
		}
	}

	return models.AIBOM{
		GeneratedAt: time.Now(),
		Services:    services,
		Summary: models.ABOMSummary{
			TotalServices:    len(services),
			TotalProviders:   len(providerSet),
			TotalModels:      len(modelSet),
			TotalDatabases:   dbCount,
			ShadowAICount:    shadowCount,
			TotalCost7dUSD:   totalCost,
			HighRiskServices: highRisk,
		},
	}
}

// --- Policies ---

// GetPolicies returns all stored policies.
func (s *Store) GetPolicies() []models.AISecurityPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.AISecurityPolicy, len(s.policies))
	copy(out, s.policies)
	return out
}

// GetPolicy returns a single policy by name.
func (s *Store) GetPolicy(name string) *models.AISecurityPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.policies {
		if s.policies[i].Metadata.Name == name {
			p := s.policies[i]
			return &p
		}
	}
	return nil
}

// AddPolicy appends a policy.
func (s *Store) AddPolicy(p models.AISecurityPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies = append(s.policies, p)
}

// UpdatePolicy replaces a policy by name. Returns false if not found.
func (s *Store) UpdatePolicy(name string, p models.AISecurityPolicy) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.policies {
		if s.policies[i].Metadata.Name == name {
			s.policies[i] = p
			return true
		}
	}
	return false
}

// DeletePolicy removes a policy by name. Returns false if not found.
func (s *Store) DeletePolicy(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.policies {
		if s.policies[i].Metadata.Name == name {
			s.policies = append(s.policies[:i], s.policies[i+1:]...)
			return true
		}
	}
	return false
}

// --- Helpers ---

func normalizePagination(page, perPage int) (int, int) {
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

func riskLevel(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.4:
		return "medium"
	default:
		return "low"
	}
}

func ruleIDToCategory(ruleID string) string {
	// Map known rule IDs to their categories.
	switch {
	case strings.Contains(ruleID, "injection"):
		return "injection"
	case strings.Contains(ruleID, "jailbreak"):
		return "jailbreak"
	case strings.Contains(ruleID, "pii"):
		return "pii"
	case strings.Contains(ruleID, "secret"):
		return "secrets"
	case strings.Contains(ruleID, "toxic"):
		return "toxicity"
	case strings.Contains(ruleID, "code"):
		return "code_safety"
	case strings.Contains(ruleID, "rate"):
		return "rate_limit"
	default:
		return ruleID
	}
}
