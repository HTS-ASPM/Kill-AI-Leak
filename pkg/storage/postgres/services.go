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

// RecordService upserts a service entry. If the service already exists,
// its last_seen_at is updated and provider usage is merged.
func (s *PostgresStore) RecordService(svc models.AIService) error {
	rawJSON, err := json.Marshal(svc)
	if err != nil {
		return fmt.Errorf("postgres: marshal service: %w", err)
	}

	providersJSON, err := json.Marshal(svc.Providers)
	if err != nil {
		return fmt.Errorf("postgres: marshal providers: %w", err)
	}

	discoveredAt := svc.DiscoveredAt
	if discoveredAt.IsZero() {
		discoveredAt = time.Now()
	}
	lastSeenAt := svc.LastSeenAt
	if lastSeenAt.IsZero() {
		lastSeenAt = time.Now()
	}

	// UPSERT: insert or update on conflict.
	_, err = s.db.Exec(
		`INSERT INTO services (id, name, namespace, providers, risk_score, discovered_at, last_seen_at, gateway_enrolled, raw_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			namespace = EXCLUDED.namespace,
			providers = EXCLUDED.providers,
			risk_score = EXCLUDED.risk_score,
			last_seen_at = EXCLUDED.last_seen_at,
			gateway_enrolled = EXCLUDED.gateway_enrolled,
			raw_json = EXCLUDED.raw_json`,
		svc.ID,
		svc.Name,
		svc.Namespace,
		providersJSON,
		svc.RiskScore,
		discoveredAt,
		lastSeenAt,
		svc.GatewayEnrolled,
		rawJSON,
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert service: %w", err)
	}
	return nil
}

// GetServices returns services matching the filter, paginated.
func (s *PostgresStore) GetServices(filter storage.ServiceFilter) (*storage.PaginatedServices, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	if filter.Namespace != "" {
		conditions = append(conditions, fmt.Sprintf("namespace = $%d", argIdx))
		args = append(args, filter.Namespace)
		argIdx++
	}
	if filter.Provider != "" {
		// Check if the providers JSONB array contains an element with the matching provider.
		conditions = append(conditions, fmt.Sprintf("providers @> $%d::jsonb", argIdx))
		provJSON, _ := json.Marshal([]map[string]string{{"provider": filter.Provider}})
		args = append(args, string(provJSON))
		argIdx++
	}
	if filter.RiskLevel != "" {
		switch filter.RiskLevel {
		case "critical":
			conditions = append(conditions, "risk_score >= 0.9")
		case "high":
			conditions = append(conditions, "risk_score >= 0.7 AND risk_score < 0.9")
		case "medium":
			conditions = append(conditions, "risk_score >= 0.4 AND risk_score < 0.7")
		case "low":
			conditions = append(conditions, "risk_score < 0.4")
		}
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(LOWER(name) LIKE $%d OR LOWER(namespace) LIKE $%d OR LOWER(id) LIKE $%d)",
			argIdx, argIdx, argIdx,
		))
		args = append(args, "%"+strings.ToLower(filter.Search)+"%")
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total.
	var total int
	countQuery := "SELECT COUNT(*) FROM services " + whereClause
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("postgres: count services: %w", err)
	}

	page, perPage := storage.NormalizePagination(filter.Page, filter.PerPage)
	offset := (page - 1) * perPage

	dataQuery := fmt.Sprintf(
		"SELECT raw_json FROM services %s ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d",
		whereClause, argIdx, argIdx+1,
	)
	args = append(args, perPage, offset)

	rows, err := s.db.Query(dataQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: query services: %w", err)
	}
	defer rows.Close()

	var services []models.AIService
	for rows.Next() {
		var rawJSON []byte
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, fmt.Errorf("postgres: scan service: %w", err)
		}
		var svc models.AIService
		if err := json.Unmarshal(rawJSON, &svc); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal service: %w", err)
		}
		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows error: %w", err)
	}

	if services == nil {
		services = []models.AIService{}
	}

	return &storage.PaginatedServices{
		Data: services,
		Meta: &storage.PageMeta{Total: total, Page: page, PerPage: perPage},
	}, nil
}

// GetService returns a single service by ID, or nil.
func (s *PostgresStore) GetService(id string) (*models.AIService, error) {
	var rawJSON []byte
	err := s.db.QueryRow("SELECT raw_json FROM services WHERE id = $1", id).Scan(&rawJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get service: %w", err)
	}

	var svc models.AIService
	if err := json.Unmarshal(rawJSON, &svc); err != nil {
		return nil, fmt.Errorf("postgres: unmarshal service: %w", err)
	}
	return &svc, nil
}

// GetAIBOM generates a bill of materials from current service data.
func (s *PostgresStore) GetAIBOM() (*models.AIBOM, error) {
	rows, err := s.db.Query("SELECT raw_json FROM services ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("postgres: query services for bom: %w", err)
	}
	defer rows.Close()

	var services []models.AIService
	providerSet := make(map[string]bool)
	modelSet := make(map[string]bool)
	dbCount := 0
	shadowCount := 0
	highRisk := 0
	var totalCost float64

	for rows.Next() {
		var rawJSON []byte
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, fmt.Errorf("postgres: scan bom service: %w", err)
		}
		var svc models.AIService
		if err := json.Unmarshal(rawJSON, &svc); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal bom service: %w", err)
		}

		services = append(services, svc)
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows error: %w", err)
	}

	if services == nil {
		services = []models.AIService{}
	}

	return &models.AIBOM{
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
	}, nil
}
