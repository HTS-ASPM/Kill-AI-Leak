package postgres

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/storage"
)

// RecordEvent inserts a new event into the events table.
func (s *PostgresStore) RecordEvent(event models.Event) error {
	rawJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("postgres: marshal event: %w", err)
	}

	// Determine the decision and rule triggered from guardrail results.
	decision := "allow"
	ruleTriggered := ""
	if event.Content.Blocked {
		decision = "blocked"
	}
	for _, gr := range event.Guardrails {
		if gr.Decision == string(models.DecisionBlock) {
			ruleTriggered = gr.RuleID
			break
		}
	}

	_, err = s.db.Exec(
		`INSERT INTO events (id, timestamp, source, severity, actor_id, actor_name,
			actor_namespace, provider, model, decision, blocked, rule_triggered,
			latency_ms, cost_usd, session_id, raw_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())`,
		event.ID,
		event.Timestamp,
		string(event.Source),
		string(event.Severity),
		event.Actor.ID,
		event.Actor.Name,
		event.Actor.Namespace,
		event.Target.Provider,
		event.Target.Model,
		decision,
		event.Content.Blocked,
		ruleTriggered,
		event.LatencyMs,
		event.CostUSD,
		event.SessionID,
		rawJSON,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert event: %w", err)
	}
	return nil
}

// GetEvents returns events matching the filter, paginated.
func (s *PostgresStore) GetEvents(filter storage.EventFilter) (*storage.PaginatedEvents, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	if filter.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, filter.Severity)
		argIdx++
	}
	if filter.Source != "" {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argIdx))
		args = append(args, filter.Source)
		argIdx++
	}
	if filter.Decision == "blocked" {
		conditions = append(conditions, "blocked = TRUE")
	} else if filter.Decision == "allowed" {
		conditions = append(conditions, "blocked = FALSE")
	}
	if !filter.From.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, filter.From)
		argIdx++
	}
	if !filter.To.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, filter.To)
		argIdx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(LOWER(actor_id) LIKE $%d OR LOWER(provider) LIKE $%d OR LOWER(model) LIKE $%d OR LOWER(id) LIKE $%d)",
			argIdx, argIdx, argIdx, argIdx,
		))
		args = append(args, "%"+strings.ToLower(filter.Search)+"%")
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching rows.
	countQuery := "SELECT COUNT(*) FROM events " + whereClause
	var total int
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("postgres: count events: %w", err)
	}

	page, perPage := storage.NormalizePagination(filter.Page, filter.PerPage)
	offset := (page - 1) * perPage

	// Fetch the page of events.
	dataQuery := fmt.Sprintf(
		"SELECT raw_json FROM events %s ORDER BY timestamp DESC LIMIT $%d OFFSET $%d",
		whereClause, argIdx, argIdx+1,
	)
	args = append(args, perPage, offset)

	rows, err := s.db.Query(dataQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: query events: %w", err)
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var rawJSON []byte
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, fmt.Errorf("postgres: scan event: %w", err)
		}
		var ev models.Event
		if err := json.Unmarshal(rawJSON, &ev); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal event: %w", err)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows error: %w", err)
	}

	if events == nil {
		events = []models.Event{}
	}

	return &storage.PaginatedEvents{
		Data: events,
		Meta: &storage.PageMeta{Total: total, Page: page, PerPage: perPage},
	}, nil
}

// GetEvent returns a single event by ID, or nil if not found.
func (s *PostgresStore) GetEvent(id string) (*models.Event, error) {
	var rawJSON []byte
	err := s.db.QueryRow("SELECT raw_json FROM events WHERE id = $1", id).Scan(&rawJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get event: %w", err)
	}

	var ev models.Event
	if err := json.Unmarshal(rawJSON, &ev); err != nil {
		return nil, fmt.Errorf("postgres: unmarshal event: %w", err)
	}
	return &ev, nil
}

// GetStats computes dashboard statistics from current data.
func (s *PostgresStore) GetStats(activeGuardrails int) (*storage.DashboardStats, error) {
	stats := &storage.DashboardStats{
		ActiveGuardrails: activeGuardrails,
	}

	cutoff24h := time.Now().Add(-24 * time.Hour)

	// Events and blocked in last 24h.
	err := s.db.QueryRow(
		`SELECT
			COALESCE(COUNT(*), 0),
			COALESCE(SUM(CASE WHEN blocked THEN 1 ELSE 0 END), 0),
			COALESCE(AVG(CASE WHEN latency_ms > 0 THEN latency_ms END), 0)
		FROM events WHERE timestamp > $1`,
		cutoff24h,
	).Scan(&stats.Events24h, &stats.BlockedThreats24h, &stats.AvgLatencyMs)
	if err != nil {
		return nil, fmt.Errorf("postgres: event stats: %w", err)
	}

	// Total cost.
	var totalCost float64
	if err := s.db.QueryRow("SELECT COALESCE(SUM(cost_usd), 0) FROM events").Scan(&totalCost); err != nil {
		return nil, fmt.Errorf("postgres: cost sum: %w", err)
	}
	stats.MonthlyCostUSD = totalCost * 4

	// Service counts.
	if err := s.db.QueryRow("SELECT COUNT(*) FROM services").Scan(&stats.TotalServices); err != nil {
		return nil, fmt.Errorf("postgres: service count: %w", err)
	}

	// Shadow AI (not gateway enrolled).
	if err := s.db.QueryRow("SELECT COUNT(*) FROM services WHERE NOT gateway_enrolled").Scan(&stats.ShadowAIDetected); err != nil {
		return nil, fmt.Errorf("postgres: shadow ai count: %w", err)
	}

	return stats, nil
}

// GetThreatActivity aggregates events by day over the given number of days.
func (s *PostgresStore) GetThreatActivity(days int) ([]storage.ThreatActivityPoint, error) {
	if days <= 0 {
		days = 7
	}

	now := time.Now()

	// Pre-populate the output with zero values for each day.
	points := make([]storage.ThreatActivityPoint, days)
	dateIndex := make(map[string]int, days)
	for i := 0; i < days; i++ {
		d := now.AddDate(0, 0, -(days - 1 - i))
		dateStr := d.Format("2006-01-02")
		points[i] = storage.ThreatActivityPoint{Date: dateStr}
		dateIndex[dateStr] = i
	}

	cutoff := now.AddDate(0, 0, -(days - 1)).Truncate(24 * time.Hour)

	rows, err := s.db.Query(
		`SELECT
			TO_CHAR(timestamp, 'YYYY-MM-DD') AS day,
			COALESCE(SUM(CASE WHEN blocked THEN 1 ELSE 0 END), 0) AS blocked_count,
			COALESCE(SUM(CASE WHEN NOT blocked THEN 1 ELSE 0 END), 0) AS allowed_count
		FROM events
		WHERE timestamp >= $1
		GROUP BY day
		ORDER BY day`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: threat activity query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var day string
		var blocked, allowed int
		if err := rows.Scan(&day, &blocked, &allowed); err != nil {
			return nil, fmt.Errorf("postgres: scan threat activity: %w", err)
		}
		if idx, ok := dateIndex[day]; ok {
			points[idx].Blocked = blocked
			points[idx].Allowed = allowed
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows error: %w", err)
	}

	return points, nil
}

// categoryColors maps guardrail categories to chart colours.
var categoryColors = map[string]string{
	"injection":    "#ef4444",
	"jailbreak":    "#f97316",
	"pii":          "#eab308",
	"secrets":      "#22c55e",
	"toxicity":     "#3b82f6",
	"code_safety":  "#8b5cf6",
	"rate_limit":   "#ec4899",
	"exfiltration": "#14b8a6",
}

// GetRiskBreakdown counts events by guardrail category.
func (s *PostgresStore) GetRiskBreakdown() ([]storage.RiskBreakdown, error) {
	// Since guardrail results are stored inside raw_json, we use JSONB
	// queries to extract them. We count each non-allow guardrail result
	// and group by a category derived from the rule_id.
	rows, err := s.db.Query(
		`SELECT
			gr->>'rule_id' AS rule_id,
			COUNT(*) AS cnt
		FROM events,
			jsonb_array_elements(COALESCE(raw_json->'guardrails', '[]'::jsonb)) AS gr
		WHERE gr->>'decision' != 'allow'
		GROUP BY rule_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: risk breakdown query: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var ruleID string
		var cnt int
		if err := rows.Scan(&ruleID, &cnt); err != nil {
			return nil, fmt.Errorf("postgres: scan risk breakdown: %w", err)
		}
		cat := ruleIDToCategory(ruleID)
		counts[cat] += cnt
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows error: %w", err)
	}

	out := make([]storage.RiskBreakdown, 0, len(counts))
	for cat, cnt := range counts {
		color := categoryColors[cat]
		if color == "" {
			color = "#6b7280"
		}
		out = append(out, storage.RiskBreakdown{
			Category: cat,
			Count:    cnt,
			Color:    color,
		})
	}
	return out, nil
}

// GetTopServices returns the top N services by event count.
func (s *PostgresStore) GetTopServices(limit int) ([]storage.TopService, error) {
	if limit <= 0 {
		limit = 10
	}

	rows, err := s.db.Query(
		`SELECT
			e.actor_id,
			e.actor_name,
			e.actor_namespace,
			COUNT(*) AS calls,
			COALESCE(SUM(e.cost_usd), 0) AS total_cost,
			COALESCE(s.risk_score, 0) AS risk_score
		FROM events e
		LEFT JOIN services s ON e.actor_id = s.id
		WHERE e.actor_id != ''
		GROUP BY e.actor_id, e.actor_name, e.actor_namespace, s.risk_score
		ORDER BY calls DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: top services query: %w", err)
	}
	defer rows.Close()

	var out []storage.TopService
	for rows.Next() {
		var ts storage.TopService
		var actorID string
		if err := rows.Scan(&actorID, &ts.Name, &ts.Namespace, &ts.Calls7d, &ts.Cost7dUSD, &ts.RiskScore); err != nil {
			return nil, fmt.Errorf("postgres: scan top service: %w", err)
		}
		if ts.Name == "" {
			ts.Name = actorID
		}
		out = append(out, ts)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows error: %w", err)
	}

	if out == nil {
		out = []storage.TopService{}
	}
	return out, nil
}

// ruleIDToCategory maps known rule IDs to their categories.
func ruleIDToCategory(ruleID string) string {
	lower := strings.ToLower(ruleID)
	switch {
	case strings.Contains(lower, "injection"):
		return "injection"
	case strings.Contains(lower, "jailbreak"):
		return "jailbreak"
	case strings.Contains(lower, "pii"):
		return "pii"
	case strings.Contains(lower, "secret"):
		return "secrets"
	case strings.Contains(lower, "toxic"):
		return "toxicity"
	case strings.Contains(lower, "code"):
		return "code_safety"
	case strings.Contains(lower, "rate"):
		return "rate_limit"
	default:
		return ruleID
	}
}
