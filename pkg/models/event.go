package models

import "time"

// EventSource identifies where the event originated.
type EventSource string

const (
	SourceKernelObserver EventSource = "kernel_observer"
	SourceInlineGateway  EventSource = "inline_gateway"
	SourceBrowser        EventSource = "browser"
	SourceIDE            EventSource = "ide"
	SourceMCPGateway     EventSource = "mcp_gateway"
	SourceCICD           EventSource = "cicd"
)

// Severity levels for events.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Direction of the AI interaction.
type Direction string

const (
	DirectionOutbound Direction = "outbound"
	DirectionInbound  Direction = "inbound"
)

// ActorType identifies what kind of entity initiated the interaction.
type ActorType string

const (
	ActorPod            ActorType = "pod"
	ActorUser           ActorType = "user"
	ActorServiceAccount ActorType = "service_account"
	ActorBrowserUser    ActorType = "browser_user"
	ActorAgent          ActorType = "agent"
)

// Actor is the entity that initiated the AI interaction.
type Actor struct {
	Type           ActorType         `json:"type"`
	ID             string            `json:"id"`
	Name           string            `json:"name,omitempty"`
	Namespace      string            `json:"namespace,omitempty"`
	Node           string            `json:"node,omitempty"`
	ServiceAccount string            `json:"service_account,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Team           string            `json:"team,omitempty"`
}

// TargetType identifies what kind of resource is being accessed.
type TargetType string

const (
	TargetLLMProvider TargetType = "llm_provider"
	TargetMCPServer   TargetType = "mcp_server"
	TargetDatabase    TargetType = "database"
	TargetFilesystem  TargetType = "filesystem"
	TargetAPI         TargetType = "api"
)

// Target is the resource being accessed in the AI interaction.
type Target struct {
	Type     TargetType `json:"type"`
	ID       string     `json:"id"`
	Provider string     `json:"provider,omitempty"`
	Endpoint string     `json:"endpoint,omitempty"`
	Model    string     `json:"model,omitempty"`
	Region   string     `json:"region,omitempty"`
}

// ActionType classifies the kind of action.
type ActionType string

const (
	ActionAPICall      ActionType = "api_call"
	ActionToolExec     ActionType = "tool_exec"
	ActionFileAccess   ActionType = "file_access"
	ActionProcessSpawn ActionType = "process_spawn"
	ActionDBQuery      ActionType = "db_query"
)

// Action describes what happened.
type Action struct {
	Type      ActionType `json:"type"`
	Direction Direction  `json:"direction"`
	Protocol  string     `json:"protocol,omitempty"`
	Method    string     `json:"method,omitempty"`
}

// ContentMeta holds metadata about the prompt/response content.
type ContentMeta struct {
	HasPrompt      bool     `json:"has_prompt"`
	PromptHash     string   `json:"prompt_hash,omitempty"`
	PromptText     string   `json:"prompt_text,omitempty"`
	ResponseHash   string   `json:"response_hash,omitempty"`
	ResponseText   string   `json:"response_text,omitempty"`
	TokensInput    int      `json:"tokens_input,omitempty"`
	TokensOutput   int      `json:"tokens_output,omitempty"`
	Model          string   `json:"model,omitempty"`
	PIIDetected    []string `json:"pii_detected,omitempty"`
	InjectionScore float64  `json:"injection_score,omitempty"`
	Blocked        bool     `json:"blocked"`
	Anonymized     bool     `json:"anonymized"`
}

// GuardrailResult records which guardrails were triggered for this event.
type GuardrailResult struct {
	RuleID     string   `json:"rule_id"`
	RuleName   string   `json:"rule_name"`
	Stage      string   `json:"stage"`
	Decision   string   `json:"decision"`
	Confidence float64  `json:"confidence"`
	Reason     string   `json:"reason,omitempty"`
	Details    []string `json:"details,omitempty"`
	LatencyMs  int64    `json:"latency_ms"`
}

// Event is the unified event schema for all sensors.
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Source    EventSource `json:"source"`
	Severity Severity    `json:"severity"`

	Actor   Actor       `json:"actor"`
	Target  Target      `json:"target"`
	Action  Action      `json:"action"`
	Content ContentMeta `json:"content"`

	Guardrails []GuardrailResult `json:"guardrails,omitempty"`

	Metadata    map[string]string `json:"metadata,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	TraceID     string            `json:"trace_id,omitempty"`
	CostUSD     float64           `json:"cost_usd,omitempty"`
	LatencyMs   int64             `json:"latency_ms,omitempty"`
}
