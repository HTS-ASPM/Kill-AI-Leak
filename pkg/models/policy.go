package models

// PolicyScope defines where a policy applies.
type PolicyScope struct {
	Namespaces      []string `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	Services        []string `json:"services,omitempty" yaml:"services,omitempty"`
	ServiceAccounts []string `json:"service_accounts,omitempty" yaml:"service_accounts,omitempty"`
	Users           []string `json:"users,omitempty" yaml:"users,omitempty"`
	Teams           []string `json:"teams,omitempty" yaml:"teams,omitempty"`
}

// ProviderPolicy controls which LLM providers are allowed.
type ProviderPolicy struct {
	Allow              []string                    `json:"allow" yaml:"allow"`
	Deny               []string                    `json:"deny" yaml:"deny"`
	NamespaceOverrides map[string]ProviderPolicy    `json:"namespace_overrides,omitempty" yaml:"namespace_overrides,omitempty"`
}

// ModelPolicy controls which specific models are allowed.
type ModelPolicy struct {
	Allow []string `json:"allow" yaml:"allow"`
	Deny  []string `json:"deny" yaml:"deny"`
}

// RateLimitPolicy defines rate limiting rules.
type RateLimitPolicy struct {
	PerUser      *RateLimit `json:"per_user,omitempty" yaml:"per_user,omitempty"`
	PerService   *RateLimit `json:"per_service,omitempty" yaml:"per_service,omitempty"`
	PerNamespace *RateLimit `json:"per_namespace,omitempty" yaml:"per_namespace,omitempty"`
}

// RateLimit defines specific rate limits.
type RateLimit struct {
	RequestsPerMinute int     `json:"requests_per_minute,omitempty" yaml:"requests_per_minute,omitempty"`
	RequestsPerHour   int     `json:"requests_per_hour,omitempty" yaml:"requests_per_hour,omitempty"`
	RequestsPerDay    int     `json:"requests_per_day,omitempty" yaml:"requests_per_day,omitempty"`
	TokensPerDay      int64   `json:"tokens_per_day,omitempty" yaml:"tokens_per_day,omitempty"`
	CostPerDayUSD     float64 `json:"cost_per_day_usd,omitempty" yaml:"cost_per_day_usd,omitempty"`
	CostPerMonthUSD   float64 `json:"cost_per_month_usd,omitempty" yaml:"cost_per_month_usd,omitempty"`
}

// InputPolicy controls what can be sent to LLMs.
type InputPolicy struct {
	BlockPII              bool     `json:"block_pii" yaml:"block_pii"`
	AnonymizePII          bool     `json:"anonymize_pii" yaml:"anonymize_pii"`
	PIITypes              []string `json:"pii_types,omitempty" yaml:"pii_types,omitempty"`
	BlockSecrets          bool     `json:"block_secrets" yaml:"block_secrets"`
	BlockInjectionAbove   float64  `json:"block_injection_score_above" yaml:"block_injection_score_above"`
	MaxTokensPerRequest   int      `json:"max_tokens_per_request,omitempty" yaml:"max_tokens_per_request,omitempty"`
	BlockedTopics         []string `json:"blocked_topics,omitempty" yaml:"blocked_topics,omitempty"`
	AllowedTopics         []string `json:"allowed_topics,omitempty" yaml:"allowed_topics,omitempty"`
}

// OutputPolicy controls what LLM responses are allowed.
type OutputPolicy struct {
	BlockToxicAbove     float64 `json:"block_toxic_score_above" yaml:"block_toxic_score_above"`
	ScanGeneratedCode   bool    `json:"scan_generated_code" yaml:"scan_generated_code"`
	BlockVulnerableCode bool    `json:"block_vulnerable_code" yaml:"block_vulnerable_code"`
	CheckPIILeakage     bool    `json:"check_pii_leakage" yaml:"check_pii_leakage"`
	CheckPromptLeakage  bool    `json:"check_prompt_leakage" yaml:"check_prompt_leakage"`
}

// AgentPolicy controls what AI agents can do.
type AgentPolicy struct {
	Filesystem *FilesystemPolicy `json:"filesystem,omitempty" yaml:"filesystem,omitempty"`
	Commands   *CommandPolicy    `json:"commands,omitempty" yaml:"commands,omitempty"`
	Network    *NetworkPolicy    `json:"network,omitempty" yaml:"network,omitempty"`
	Database   *DatabasePolicy   `json:"database,omitempty" yaml:"database,omitempty"`
}

// FilesystemPolicy controls file access for agents.
type FilesystemPolicy struct {
	AllowRead  []string `json:"allow_read" yaml:"allow_read"`
	DenyRead   []string `json:"deny_read" yaml:"deny_read"`
	AllowWrite []string `json:"allow_write" yaml:"allow_write"`
	DenyWrite  []string `json:"deny_write" yaml:"deny_write"`
	DenyDelete []string `json:"deny_delete" yaml:"deny_delete"`
}

// CommandPolicy controls command execution for agents.
type CommandPolicy struct {
	Allow           []string `json:"allow" yaml:"allow"`
	Deny            []string `json:"deny" yaml:"deny"`
	RequireApproval []string `json:"require_approval" yaml:"require_approval"`
}

// NetworkPolicy controls outbound network access for agents.
type NetworkPolicy struct {
	AllowOutbound []string `json:"allow_outbound" yaml:"allow_outbound"`
	DenyOutbound  []string `json:"deny_outbound" yaml:"deny_outbound"`
}

// DatabasePolicy controls database operations for agents.
type DatabasePolicy struct {
	Allow           []string `json:"allow" yaml:"allow"`
	Deny            []string `json:"deny" yaml:"deny"`
	RequireApproval []string `json:"require_approval" yaml:"require_approval"`
}

// DataResidencyPolicy controls where data can be processed.
type DataResidencyPolicy struct {
	Rules []DataResidencyRule `json:"rules" yaml:"rules"`
}

// DataResidencyRule is a single data residency routing rule.
type DataResidencyRule struct {
	Name      string   `json:"name" yaml:"name"`
	Condition string   `json:"condition" yaml:"condition"`
	RouteTo   []RouteTarget `json:"route_to" yaml:"route_to"`
	DenyRouting []string `json:"deny_routing_to,omitempty" yaml:"deny_routing_to,omitempty"`
}

// RouteTarget specifies a provider+region to route requests to.
type RouteTarget struct {
	Provider string `json:"provider" yaml:"provider"`
	Region   string `json:"region,omitempty" yaml:"region,omitempty"`
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
}

// AISecurityPolicy is the top-level policy resource (like a K8s CRD).
type AISecurityPolicy struct {
	APIVersion string         `json:"apiVersion" yaml:"apiVersion"`
	Kind       string         `json:"kind" yaml:"kind"`
	Metadata   PolicyMetadata `json:"metadata" yaml:"metadata"`
	Spec       PolicySpec     `json:"spec" yaml:"spec"`
}

// PolicyMetadata holds policy identification info.
type PolicyMetadata struct {
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// PolicySpec is the full policy specification.
type PolicySpec struct {
	Scope         PolicyScope          `json:"scope" yaml:"scope"`
	Providers     *ProviderPolicy      `json:"providers,omitempty" yaml:"providers,omitempty"`
	Models        *ModelPolicy         `json:"models,omitempty" yaml:"models,omitempty"`
	RateLimits    *RateLimitPolicy     `json:"rate_limits,omitempty" yaml:"rate_limits,omitempty"`
	Input         *InputPolicy         `json:"input,omitempty" yaml:"input,omitempty"`
	Output        *OutputPolicy        `json:"output,omitempty" yaml:"output,omitempty"`
	Agent         *AgentPolicy         `json:"agent,omitempty" yaml:"agent,omitempty"`
	DataResidency *DataResidencyPolicy `json:"data_residency,omitempty" yaml:"data_residency,omitempty"`
	Mode          EnforcementMode      `json:"mode" yaml:"mode"`
	Alerts        *AlertConfig         `json:"alerts,omitempty" yaml:"alerts,omitempty"`
}

// AlertConfig defines where to send alerts.
type AlertConfig struct {
	Slack     string `json:"slack,omitempty" yaml:"slack,omitempty"`
	PagerDuty string `json:"pagerduty,omitempty" yaml:"pagerduty,omitempty"`
	Email     string `json:"email,omitempty" yaml:"email,omitempty"`
	Webhook   string `json:"webhook,omitempty" yaml:"webhook,omitempty"`
}
