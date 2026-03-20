package models

import "time"

// AIService represents a discovered AI-using service in the inventory.
type AIService struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	ServiceAccount  string            `json:"service_account,omitempty"`
	Team            string            `json:"team,omitempty"`
	Providers       []ProviderUsage   `json:"providers"`
	Libraries       []LibraryUsage    `json:"libraries,omitempty"`
	Databases       []DatabaseUsage   `json:"databases,omitempty"`
	ExposureType    string            `json:"exposure_type"` // internal, external
	RiskScore       float64           `json:"risk_score"`
	DiscoveredAt    time.Time         `json:"discovered_at"`
	LastSeenAt      time.Time         `json:"last_seen_at"`
	DiscoveredBy    EventSource       `json:"discovered_by"`
	PolicyApplied   string            `json:"policy_applied,omitempty"`
	GatewayEnrolled bool              `json:"gateway_enrolled"`
	Labels          map[string]string `json:"labels,omitempty"`
}

// ProviderUsage tracks usage of a specific LLM provider by a service.
type ProviderUsage struct {
	Provider        string    `json:"provider"`
	Models          []string  `json:"models"`
	CallCount7d     int64     `json:"call_count_7d"`
	TokensUsed7d    int64     `json:"tokens_used_7d"`
	DataTransferred7d int64   `json:"data_transferred_7d"`
	EstCost7dUSD    float64   `json:"est_cost_7d_usd"`
	LastCallAt      time.Time `json:"last_call_at"`
}

// LibraryUsage tracks AI/ML library usage.
type LibraryUsage struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Language string `json:"language"`
}

// DatabaseUsage tracks database connections from AI services.
type DatabaseUsage struct {
	Type     string `json:"type"` // postgresql, mysql, mongodb, redis, milvus, etc.
	Host     string `json:"host"`
	Database string `json:"database,omitempty"`
}

// AIBOM is the AI Bill of Materials for the organization.
type AIBOM struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Services    []AIService   `json:"services"`
	Summary     ABOMSummary   `json:"summary"`
}

// ABOMSummary aggregates AIBOM statistics.
type ABOMSummary struct {
	TotalServices     int     `json:"total_services"`
	TotalProviders    int     `json:"total_providers"`
	TotalModels       int     `json:"total_models"`
	TotalDatabases    int     `json:"total_databases"`
	ShadowAICount     int     `json:"shadow_ai_count"`
	TotalCost7dUSD    float64 `json:"total_cost_7d_usd"`
	HighRiskServices  int     `json:"high_risk_services"`
}
