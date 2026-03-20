// Package costs provides a cost attribution engine for AI/LLM usage. It
// tracks per-model token consumption, attributes costs to namespaces,
// services, users, and models, supports budget alerts, generates daily
// reports, and detects cost anomalies.
package costs

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Pricing
// ---------------------------------------------------------------------------

// ModelPricing holds the per-token pricing for a specific model.
type ModelPricing struct {
	// Provider is the canonical provider name (e.g., "openai").
	Provider string `json:"provider"`

	// Model is the model identifier.
	Model string `json:"model"`

	// InputPer1KTokens is the cost in USD per 1,000 input tokens.
	InputPer1KTokens float64 `json:"input_per_1k_tokens"`

	// OutputPer1KTokens is the cost in USD per 1,000 output tokens.
	OutputPer1KTokens float64 `json:"output_per_1k_tokens"`
}

// PricingTable maps model names to their pricing. It is safe for
// concurrent read access; writes must hold the CostTracker's mutex.
type PricingTable map[string]ModelPricing

// BuiltinPricingTable returns the default pricing table with major models.
// Prices are approximate and should be updated periodically.
func BuiltinPricingTable() PricingTable {
	return PricingTable{
		// OpenAI
		"gpt-4o": {
			Provider: "openai", Model: "gpt-4o",
			InputPer1KTokens: 0.0025, OutputPer1KTokens: 0.010,
		},
		"gpt-4o-mini": {
			Provider: "openai", Model: "gpt-4o-mini",
			InputPer1KTokens: 0.00015, OutputPer1KTokens: 0.0006,
		},
		"gpt-4-turbo": {
			Provider: "openai", Model: "gpt-4-turbo",
			InputPer1KTokens: 0.01, OutputPer1KTokens: 0.03,
		},
		"gpt-4": {
			Provider: "openai", Model: "gpt-4",
			InputPer1KTokens: 0.03, OutputPer1KTokens: 0.06,
		},
		"gpt-3.5-turbo": {
			Provider: "openai", Model: "gpt-3.5-turbo",
			InputPer1KTokens: 0.0005, OutputPer1KTokens: 0.0015,
		},
		"o1": {
			Provider: "openai", Model: "o1",
			InputPer1KTokens: 0.015, OutputPer1KTokens: 0.06,
		},
		"o1-mini": {
			Provider: "openai", Model: "o1-mini",
			InputPer1KTokens: 0.003, OutputPer1KTokens: 0.012,
		},
		"o3-mini": {
			Provider: "openai", Model: "o3-mini",
			InputPer1KTokens: 0.0011, OutputPer1KTokens: 0.0044,
		},

		// Anthropic
		"claude-sonnet-4-20250514": {
			Provider: "anthropic", Model: "claude-sonnet-4-20250514",
			InputPer1KTokens: 0.003, OutputPer1KTokens: 0.015,
		},
		"claude-3-5-sonnet-20241022": {
			Provider: "anthropic", Model: "claude-3-5-sonnet-20241022",
			InputPer1KTokens: 0.003, OutputPer1KTokens: 0.015,
		},
		"claude-3-5-haiku-20241022": {
			Provider: "anthropic", Model: "claude-3-5-haiku-20241022",
			InputPer1KTokens: 0.0008, OutputPer1KTokens: 0.004,
		},
		"claude-3-opus-20240229": {
			Provider: "anthropic", Model: "claude-3-opus-20240229",
			InputPer1KTokens: 0.015, OutputPer1KTokens: 0.075,
		},
		"claude-3-haiku-20240307": {
			Provider: "anthropic", Model: "claude-3-haiku-20240307",
			InputPer1KTokens: 0.00025, OutputPer1KTokens: 0.00125,
		},

		// Google
		"gemini-1.5-pro": {
			Provider: "google_gemini", Model: "gemini-1.5-pro",
			InputPer1KTokens: 0.00125, OutputPer1KTokens: 0.005,
		},
		"gemini-1.5-flash": {
			Provider: "google_gemini", Model: "gemini-1.5-flash",
			InputPer1KTokens: 0.000075, OutputPer1KTokens: 0.0003,
		},
		"gemini-2.0-flash": {
			Provider: "google_gemini", Model: "gemini-2.0-flash",
			InputPer1KTokens: 0.0001, OutputPer1KTokens: 0.0004,
		},

		// Mistral
		"mistral-large": {
			Provider: "mistral", Model: "mistral-large",
			InputPer1KTokens: 0.002, OutputPer1KTokens: 0.006,
		},
		"mistral-small": {
			Provider: "mistral", Model: "mistral-small",
			InputPer1KTokens: 0.0002, OutputPer1KTokens: 0.0006,
		},

		// DeepSeek
		"deepseek-chat": {
			Provider: "deepseek", Model: "deepseek-chat",
			InputPer1KTokens: 0.00014, OutputPer1KTokens: 0.00028,
		},
		"deepseek-reasoner": {
			Provider: "deepseek", Model: "deepseek-reasoner",
			InputPer1KTokens: 0.00055, OutputPer1KTokens: 0.0022,
		},

		// Groq (using hosted models)
		"llama-3.1-70b": {
			Provider: "groq", Model: "llama-3.1-70b",
			InputPer1KTokens: 0.00059, OutputPer1KTokens: 0.00079,
		},

		// Cohere
		"command-r-plus": {
			Provider: "cohere", Model: "command-r-plus",
			InputPer1KTokens: 0.0025, OutputPer1KTokens: 0.01,
		},
		"command-r": {
			Provider: "cohere", Model: "command-r",
			InputPer1KTokens: 0.00015, OutputPer1KTokens: 0.0006,
		},
	}
}

// ---------------------------------------------------------------------------
// Usage record
// ---------------------------------------------------------------------------

// UsageRecord is a single token consumption event.
type UsageRecord struct {
	// Timestamp is when the usage occurred.
	Timestamp time.Time `json:"timestamp"`

	// Actor identifies who incurred the usage.
	Actor string `json:"actor"`

	// Namespace is the Kubernetes namespace (if applicable).
	Namespace string `json:"namespace,omitempty"`

	// Service is the service name (if applicable).
	Service string `json:"service,omitempty"`

	// Provider is the LLM provider.
	Provider string `json:"provider"`

	// Model is the model identifier.
	Model string `json:"model"`

	// TokensIn is the number of input tokens.
	TokensIn int `json:"tokens_in"`

	// TokensOut is the number of output tokens.
	TokensOut int `json:"tokens_out"`

	// CostUSD is the computed cost in USD.
	CostUSD float64 `json:"cost_usd"`
}

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

// Budget defines a spending limit for a scope (namespace, service, user).
type Budget struct {
	// Scope identifies what this budget applies to ("namespace:X",
	// "service:X", "user:X").
	Scope string `json:"scope"`

	// LimitUSD is the budget limit in USD.
	LimitUSD float64 `json:"limit_usd"`

	// Period is the budget period (daily, weekly, monthly).
	Period string `json:"period"`

	// AlertThresholdPct triggers an alert when usage reaches this
	// percentage of the limit. Default: 80%.
	AlertThresholdPct float64 `json:"alert_threshold_pct"`
}

// BudgetAlert is generated when a scope approaches or exceeds its budget.
type BudgetAlert struct {
	Scope      string    `json:"scope"`
	LimitUSD   float64   `json:"limit_usd"`
	CurrentUSD float64   `json:"current_usd"`
	Percentage float64   `json:"percentage"`
	Period     string    `json:"period"`
	Exceeded   bool      `json:"exceeded"`
	Timestamp  time.Time `json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Cost report
// ---------------------------------------------------------------------------

// CostBreakdown holds an aggregated cost for a single dimension.
type CostBreakdown struct {
	Key       string  `json:"key"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	Count     int64   `json:"count"` // number of requests
}

// DailyReport is the daily cost summary.
type DailyReport struct {
	Date          string          `json:"date"` // YYYY-MM-DD
	TotalCostUSD  float64         `json:"total_cost_usd"`
	TotalTokensIn int64           `json:"total_tokens_in"`
	TotalTokensOut int64          `json:"total_tokens_out"`
	TotalRequests int64           `json:"total_requests"`
	ByNamespace   []CostBreakdown `json:"by_namespace"`
	ByService     []CostBreakdown `json:"by_service"`
	ByModel       []CostBreakdown `json:"by_model"`
	ByUser        []CostBreakdown `json:"by_user"`
	Anomalies     []CostAnomaly   `json:"anomalies,omitempty"`
}

// CostAnomaly represents a detected cost spike.
type CostAnomaly struct {
	Scope         string    `json:"scope"`
	CurrentCost   float64   `json:"current_cost"`
	BaselineCost  float64   `json:"baseline_cost"`
	Multiplier    float64   `json:"multiplier"`
	Description   string    `json:"description"`
	DetectedAt    time.Time `json:"detected_at"`
}

// ---------------------------------------------------------------------------
// TimeRange
// ---------------------------------------------------------------------------

// TimeRange specifies a time window for queries.
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// Last24Hours returns a TimeRange covering the past 24 hours.
func Last24Hours() TimeRange {
	now := time.Now()
	return TimeRange{Start: now.Add(-24 * time.Hour), End: now}
}

// Last7Days returns a TimeRange covering the past 7 days.
func Last7Days() TimeRange {
	now := time.Now()
	return TimeRange{Start: now.Add(-7 * 24 * time.Hour), End: now}
}

// Last30Days returns a TimeRange covering the past 30 days.
func Last30Days() TimeRange {
	now := time.Now()
	return TimeRange{Start: now.Add(-30 * 24 * time.Hour), End: now}
}

// Today returns a TimeRange covering the current calendar day (UTC).
func Today() TimeRange {
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return TimeRange{Start: start, End: now}
}

// ---------------------------------------------------------------------------
// CostTracker
// ---------------------------------------------------------------------------

// CostTracker records AI/LLM usage and provides cost attribution,
// budgeting, and anomaly detection. All public methods are safe for
// concurrent use.
type CostTracker struct {
	mu       sync.RWMutex
	records  []UsageRecord
	pricing  PricingTable
	budgets  map[string]Budget // keyed by scope string

	// dailyCosts caches per-day costs for anomaly baseline computation.
	// Key: "YYYY-MM-DD:<scope>", value: total USD.
	dailyCosts map[string]float64

	// anomalyMultiplier is the factor above baseline that triggers an
	// anomaly. Default: 3.0.
	anomalyMultiplier float64
}

// NewCostTracker creates a CostTracker with the built-in pricing table.
func NewCostTracker() *CostTracker {
	return &CostTracker{
		records:           make([]UsageRecord, 0, 4096),
		pricing:           BuiltinPricingTable(),
		budgets:           make(map[string]Budget),
		dailyCosts:        make(map[string]float64),
		anomalyMultiplier: 3.0,
	}
}

// NewCostTrackerWithPricing creates a CostTracker with a custom pricing
// table.
func NewCostTrackerWithPricing(pricing PricingTable) *CostTracker {
	ct := NewCostTracker()
	ct.pricing = pricing
	return ct
}

// SetAnomalyMultiplier changes the anomaly detection threshold. A value
// of 3.0 means costs must exceed 3x the baseline to trigger an anomaly.
func (ct *CostTracker) SetAnomalyMultiplier(m float64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.anomalyMultiplier = m
}

// UpdatePricing adds or updates a model's pricing.
func (ct *CostTracker) UpdatePricing(model string, pricing ModelPricing) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.pricing[model] = pricing
}

// SetBudget configures a budget for a scope.
func (ct *CostTracker) SetBudget(budget Budget) {
	if budget.AlertThresholdPct <= 0 {
		budget.AlertThresholdPct = 80.0
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.budgets[budget.Scope] = budget
}

// ---------------------------------------------------------------------------
// Usage tracking
// ---------------------------------------------------------------------------

// TrackUsage records a token consumption event and computes the cost.
// Returns the computed cost in USD.
func (ct *CostTracker) TrackUsage(actor, namespace, service, provider, model string, tokensIn, tokensOut int) float64 {
	costUSD := ct.computeCost(model, tokensIn, tokensOut)

	record := UsageRecord{
		Timestamp: time.Now(),
		Actor:     actor,
		Namespace: namespace,
		Service:   service,
		Provider:  provider,
		Model:     model,
		TokensIn:  tokensIn,
		TokensOut: tokensOut,
		CostUSD:   costUSD,
	}

	ct.mu.Lock()
	ct.records = append(ct.records, record)

	// Update daily cost cache.
	day := record.Timestamp.UTC().Format("2006-01-02")
	scopes := []string{"all"}
	if namespace != "" {
		scopes = append(scopes, "namespace:"+namespace)
	}
	if service != "" {
		scopes = append(scopes, "service:"+service)
	}
	if actor != "" {
		scopes = append(scopes, "user:"+actor)
	}
	if model != "" {
		scopes = append(scopes, "model:"+model)
	}
	for _, scope := range scopes {
		key := day + ":" + scope
		ct.dailyCosts[key] += costUSD
	}
	ct.mu.Unlock()

	return costUSD
}

// computeCost calculates the USD cost for a given model and token counts.
func (ct *CostTracker) computeCost(model string, tokensIn, tokensOut int) float64 {
	ct.mu.RLock()
	p, ok := ct.pricing[model]
	ct.mu.RUnlock()

	if !ok {
		// Try a case-insensitive match.
		ct.mu.RLock()
		for name, pricing := range ct.pricing {
			if strings.EqualFold(name, model) {
				p = pricing
				ok = true
				break
			}
		}
		ct.mu.RUnlock()
	}

	if !ok {
		return 0 // Unknown model, cannot price.
	}

	inputCost := (float64(tokensIn) / 1000.0) * p.InputPer1KTokens
	outputCost := (float64(tokensOut) / 1000.0) * p.OutputPer1KTokens
	return inputCost + outputCost
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// GetCostByNamespace returns costs aggregated by namespace within the time range.
func (ct *CostTracker) GetCostByNamespace(namespace string, tr TimeRange) CostBreakdown {
	return ct.aggregateByField(tr, func(r UsageRecord) bool {
		return r.Namespace == namespace
	}, namespace)
}

// GetCostByService returns costs aggregated by service within the time range.
func (ct *CostTracker) GetCostByService(service string, tr TimeRange) CostBreakdown {
	return ct.aggregateByField(tr, func(r UsageRecord) bool {
		return r.Service == service
	}, service)
}

// GetCostByUser returns costs aggregated by user/actor within the time range.
func (ct *CostTracker) GetCostByUser(user string, tr TimeRange) CostBreakdown {
	return ct.aggregateByField(tr, func(r UsageRecord) bool {
		return r.Actor == user
	}, user)
}

// GetCostByModel returns costs aggregated by model within the time range.
func (ct *CostTracker) GetCostByModel(model string, tr TimeRange) CostBreakdown {
	return ct.aggregateByField(tr, func(r UsageRecord) bool {
		return r.Model == model
	}, model)
}

// aggregateByField filters records and computes an aggregate.
func (ct *CostTracker) aggregateByField(tr TimeRange, filter func(UsageRecord) bool, key string) CostBreakdown {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	bd := CostBreakdown{Key: key}
	for _, r := range ct.records {
		if r.Timestamp.Before(tr.Start) || r.Timestamp.After(tr.End) {
			continue
		}
		if !filter(r) {
			continue
		}
		bd.TokensIn += int64(r.TokensIn)
		bd.TokensOut += int64(r.TokensOut)
		bd.CostUSD += r.CostUSD
		bd.Count++
	}
	return bd
}

// GetAllCostsByDimension returns cost breakdowns grouped by a dimension
// within the time range.
func (ct *CostTracker) GetAllCostsByDimension(dimension string, tr TimeRange) []CostBreakdown {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	groups := make(map[string]*CostBreakdown)

	for _, r := range ct.records {
		if r.Timestamp.Before(tr.Start) || r.Timestamp.After(tr.End) {
			continue
		}

		var key string
		switch dimension {
		case "namespace":
			key = r.Namespace
		case "service":
			key = r.Service
		case "user":
			key = r.Actor
		case "model":
			key = r.Model
		case "provider":
			key = r.Provider
		default:
			key = "all"
		}

		if key == "" {
			key = "(unknown)"
		}

		bd, ok := groups[key]
		if !ok {
			bd = &CostBreakdown{Key: key}
			groups[key] = bd
		}
		bd.TokensIn += int64(r.TokensIn)
		bd.TokensOut += int64(r.TokensOut)
		bd.CostUSD += r.CostUSD
		bd.Count++
	}

	result := make([]CostBreakdown, 0, len(groups))
	for _, bd := range groups {
		result = append(result, *bd)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CostUSD > result[j].CostUSD
	})

	return result
}

// ---------------------------------------------------------------------------
// Budget alerts
// ---------------------------------------------------------------------------

// CheckBudget evaluates whether the given scope is approaching or
// exceeding its budget for the current period. Returns nil if no budget
// is configured or usage is within limits.
func (ct *CostTracker) CheckBudget(scope string) *BudgetAlert {
	ct.mu.RLock()
	budget, ok := ct.budgets[scope]
	ct.mu.RUnlock()

	if !ok {
		return nil
	}

	tr := ct.budgetTimeRange(budget.Period)
	current := ct.currentSpend(scope, tr)

	pct := (current / budget.LimitUSD) * 100.0
	if pct < budget.AlertThresholdPct {
		return nil // Within limits.
	}

	return &BudgetAlert{
		Scope:      scope,
		LimitUSD:   budget.LimitUSD,
		CurrentUSD: current,
		Percentage: pct,
		Period:     budget.Period,
		Exceeded:   current >= budget.LimitUSD,
		Timestamp:  time.Now(),
	}
}

// CheckAllBudgets evaluates all configured budgets and returns any alerts.
func (ct *CostTracker) CheckAllBudgets() []BudgetAlert {
	ct.mu.RLock()
	budgetScopes := make([]string, 0, len(ct.budgets))
	for scope := range ct.budgets {
		budgetScopes = append(budgetScopes, scope)
	}
	ct.mu.RUnlock()

	var alerts []BudgetAlert
	for _, scope := range budgetScopes {
		if alert := ct.CheckBudget(scope); alert != nil {
			alerts = append(alerts, *alert)
		}
	}
	return alerts
}

// currentSpend computes the total USD spend for a scope within a time range.
func (ct *CostTracker) currentSpend(scope string, tr TimeRange) float64 {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	total := 0.0
	for _, r := range ct.records {
		if r.Timestamp.Before(tr.Start) || r.Timestamp.After(tr.End) {
			continue
		}
		if matchesScope(r, scope) {
			total += r.CostUSD
		}
	}
	return total
}

// matchesScope checks whether a record belongs to the given scope.
func matchesScope(r UsageRecord, scope string) bool {
	parts := strings.SplitN(scope, ":", 2)
	if len(parts) != 2 {
		return true // "all" scope
	}

	switch parts[0] {
	case "namespace":
		return r.Namespace == parts[1]
	case "service":
		return r.Service == parts[1]
	case "user":
		return r.Actor == parts[1]
	case "model":
		return r.Model == parts[1]
	default:
		return false
	}
}

// budgetTimeRange returns the appropriate time range for a budget period.
func (ct *CostTracker) budgetTimeRange(period string) TimeRange {
	now := time.Now().UTC()
	switch period {
	case "daily":
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		return TimeRange{Start: start, End: now}
	case "weekly":
		// Start of current ISO week (Monday).
		weekday := int(now.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		start := time.Date(now.Year(), now.Month(), now.Day()-(weekday-1), 0, 0, 0, 0, time.UTC)
		return TimeRange{Start: start, End: now}
	case "monthly":
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		return TimeRange{Start: start, End: now}
	default:
		return Last24Hours()
	}
}

// ---------------------------------------------------------------------------
// Daily report
// ---------------------------------------------------------------------------

// DailyCostReport generates a comprehensive daily cost breakdown for the
// current day.
func (ct *CostTracker) DailyCostReport() DailyReport {
	tr := Today()
	day := tr.Start.Format("2006-01-02")

	report := DailyReport{
		Date:        day,
		ByNamespace: ct.GetAllCostsByDimension("namespace", tr),
		ByService:   ct.GetAllCostsByDimension("service", tr),
		ByModel:     ct.GetAllCostsByDimension("model", tr),
		ByUser:      ct.GetAllCostsByDimension("user", tr),
	}

	// Compute totals.
	ct.mu.RLock()
	for _, r := range ct.records {
		if r.Timestamp.Before(tr.Start) || r.Timestamp.After(tr.End) {
			continue
		}
		report.TotalCostUSD += r.CostUSD
		report.TotalTokensIn += int64(r.TokensIn)
		report.TotalTokensOut += int64(r.TokensOut)
		report.TotalRequests++
	}
	ct.mu.RUnlock()

	// Detect anomalies.
	report.Anomalies = ct.DetectAnomalies()

	return report
}

// ---------------------------------------------------------------------------
// Anomaly detection
// ---------------------------------------------------------------------------

// DetectAnomalies checks whether today's costs for any scope exceed the
// baseline (average of the previous 7 days) by more than the anomaly
// multiplier.
func (ct *CostTracker) DetectAnomalies() []CostAnomaly {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	today := time.Now().UTC().Format("2006-01-02")
	multiplier := ct.anomalyMultiplier

	// Collect all scope prefixes seen in daily costs.
	scopes := make(map[string]bool)
	for key := range ct.dailyCosts {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) == 2 {
			scopes[parts[1]] = true
		}
	}

	var anomalies []CostAnomaly
	for scope := range scopes {
		todayCost := ct.dailyCosts[today+":"+scope]
		if todayCost == 0 {
			continue
		}

		// Compute baseline from previous 7 days.
		baseline := ct.computeBaseline(scope, today, 7)
		if baseline == 0 {
			continue // No historical data.
		}

		if todayCost > baseline*multiplier {
			anomalies = append(anomalies, CostAnomaly{
				Scope:        scope,
				CurrentCost:  todayCost,
				BaselineCost: baseline,
				Multiplier:   todayCost / baseline,
				Description: fmt.Sprintf(
					"Cost for %s is $%.2f, which is %.1fx the 7-day baseline of $%.2f",
					scope, todayCost, todayCost/baseline, baseline,
				),
				DetectedAt: time.Now(),
			})
		}
	}

	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].Multiplier > anomalies[j].Multiplier
	})

	return anomalies
}

// computeBaseline returns the average daily cost for a scope over the
// given number of previous days. Must be called with ct.mu held.
func (ct *CostTracker) computeBaseline(scope, todayStr string, days int) float64 {
	today, err := time.Parse("2006-01-02", todayStr)
	if err != nil {
		return 0
	}

	total := 0.0
	count := 0
	for i := 1; i <= days; i++ {
		day := today.AddDate(0, 0, -i).Format("2006-01-02")
		key := day + ":" + scope
		if cost, ok := ct.dailyCosts[key]; ok {
			total += cost
			count++
		}
	}

	if count == 0 {
		return 0
	}
	return total / float64(count)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// FormatCostReport generates a human-readable text report from a DailyReport.
func FormatCostReport(report DailyReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Daily Cost Report: %s\n\n", report.Date))
	sb.WriteString(fmt.Sprintf("**Total Cost:** $%.4f\n", report.TotalCostUSD))
	sb.WriteString(fmt.Sprintf("**Total Requests:** %d\n", report.TotalRequests))
	sb.WriteString(fmt.Sprintf("**Total Input Tokens:** %d\n", report.TotalTokensIn))
	sb.WriteString(fmt.Sprintf("**Total Output Tokens:** %d\n\n", report.TotalTokensOut))

	writeBreakdownTable := func(title string, items []CostBreakdown) {
		if len(items) == 0 {
			return
		}
		sb.WriteString(fmt.Sprintf("## %s\n\n", title))
		sb.WriteString("| Key | Cost (USD) | Requests | Input Tokens | Output Tokens |\n")
		sb.WriteString("|-----|-----------|----------|--------------|---------------|\n")
		for _, bd := range items {
			sb.WriteString(fmt.Sprintf("| %s | $%.4f | %d | %d | %d |\n",
				bd.Key, bd.CostUSD, bd.Count, bd.TokensIn, bd.TokensOut))
		}
		sb.WriteString("\n")
	}

	writeBreakdownTable("By Namespace", report.ByNamespace)
	writeBreakdownTable("By Service", report.ByService)
	writeBreakdownTable("By Model", report.ByModel)
	writeBreakdownTable("By User", report.ByUser)

	if len(report.Anomalies) > 0 {
		sb.WriteString("## Cost Anomalies\n\n")
		for _, a := range report.Anomalies {
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", a.Scope, a.Description))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// RoundCost rounds a USD cost to 6 decimal places.
func RoundCost(cost float64) float64 {
	return math.Round(cost*1e6) / 1e6
}
