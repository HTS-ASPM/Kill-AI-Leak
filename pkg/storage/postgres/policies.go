package postgres

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// GetPolicies returns all stored policies.
func (s *PostgresStore) GetPolicies() ([]models.AISecurityPolicy, error) {
	rows, err := s.db.Query(
		`SELECT name, namespace, spec, mode, created_at, updated_at FROM policies ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: query policies: %w", err)
	}
	defer rows.Close()

	var policies []models.AISecurityPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows error: %w", err)
	}

	if policies == nil {
		policies = []models.AISecurityPolicy{}
	}
	return policies, nil
}

// GetPolicy returns a single policy by name, or nil if not found.
func (s *PostgresStore) GetPolicy(name string) (*models.AISecurityPolicy, error) {
	row := s.db.QueryRow(
		`SELECT name, namespace, spec, mode, created_at, updated_at FROM policies WHERE name = $1`,
		name,
	)

	var (
		pName     string
		namespace string
		specJSON  []byte
		mode      string
		createdAt time.Time
		updatedAt time.Time
	)

	err := row.Scan(&pName, &namespace, &specJSON, &mode, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get policy: %w", err)
	}

	var spec models.PolicySpec
	if len(specJSON) > 0 {
		if err := json.Unmarshal(specJSON, &spec); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal policy spec: %w", err)
		}
	}

	return &models.AISecurityPolicy{
		APIVersion: "killaileak.io/v1",
		Kind:       "AISecurityPolicy",
		Metadata: models.PolicyMetadata{
			Name:      pName,
			Namespace: namespace,
		},
		Spec: spec,
	}, nil
}

// CreatePolicy adds a new policy.
func (s *PostgresStore) CreatePolicy(policy models.AISecurityPolicy) error {
	specJSON, err := json.Marshal(policy.Spec)
	if err != nil {
		return fmt.Errorf("postgres: marshal policy spec: %w", err)
	}

	now := time.Now()
	_, err = s.db.Exec(
		`INSERT INTO policies (name, namespace, spec, mode, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		policy.Metadata.Name,
		policy.Metadata.Namespace,
		specJSON,
		string(policy.Spec.Mode),
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert policy: %w", err)
	}

	// Record in audit log.
	s.auditLog("policy_created", policy.Metadata.Name, map[string]any{
		"name":      policy.Metadata.Name,
		"namespace": policy.Metadata.Namespace,
		"mode":      string(policy.Spec.Mode),
	})

	return nil
}

// UpdatePolicy replaces a policy by name. Returns false if not found.
func (s *PostgresStore) UpdatePolicy(name string, policy models.AISecurityPolicy) (bool, error) {
	specJSON, err := json.Marshal(policy.Spec)
	if err != nil {
		return false, fmt.Errorf("postgres: marshal policy spec: %w", err)
	}

	result, err := s.db.Exec(
		`UPDATE policies SET namespace = $1, spec = $2, mode = $3, updated_at = $4 WHERE name = $5`,
		policy.Metadata.Namespace,
		specJSON,
		string(policy.Spec.Mode),
		time.Now(),
		name,
	)
	if err != nil {
		return false, fmt.Errorf("postgres: update policy: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("postgres: rows affected: %w", err)
	}

	if affected > 0 {
		s.auditLog("policy_updated", name, map[string]any{
			"name":      policy.Metadata.Name,
			"namespace": policy.Metadata.Namespace,
			"mode":      string(policy.Spec.Mode),
		})
	}

	return affected > 0, nil
}

// DeletePolicy removes a policy by name. Returns false if not found.
func (s *PostgresStore) DeletePolicy(name string) (bool, error) {
	result, err := s.db.Exec(`DELETE FROM policies WHERE name = $1`, name)
	if err != nil {
		return false, fmt.Errorf("postgres: delete policy: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("postgres: rows affected: %w", err)
	}

	if affected > 0 {
		s.auditLog("policy_deleted", name, map[string]any{"name": name})
	}

	return affected > 0, nil
}

// auditLog records an entry in the audit_log table. Errors are silently
// ignored to avoid disrupting the caller's flow.
func (s *PostgresStore) auditLog(eventType, actor string, details map[string]any) {
	detailsJSON, _ := json.Marshal(details)
	_, _ = s.db.Exec(
		`INSERT INTO audit_log (event_type, actor, details) VALUES ($1, $2, $3)`,
		eventType, actor, detailsJSON,
	)
}

// scanPolicy scans a single policy row.
func scanPolicy(rows *sql.Rows) (*models.AISecurityPolicy, error) {
	var (
		name      string
		namespace string
		specJSON  []byte
		mode      string
		createdAt time.Time
		updatedAt time.Time
	)

	if err := rows.Scan(&name, &namespace, &specJSON, &mode, &createdAt, &updatedAt); err != nil {
		return nil, fmt.Errorf("postgres: scan policy: %w", err)
	}

	var spec models.PolicySpec
	if len(specJSON) > 0 {
		if err := json.Unmarshal(specJSON, &spec); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal policy spec: %w", err)
		}
	}

	return &models.AISecurityPolicy{
		APIVersion: "killaileak.io/v1",
		Kind:       "AISecurityPolicy",
		Metadata: models.PolicyMetadata{
			Name:      name,
			Namespace: namespace,
		},
		Spec: spec,
	}, nil
}
