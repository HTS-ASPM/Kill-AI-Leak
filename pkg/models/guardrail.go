package models

// GuardrailStage represents when in the pipeline a guardrail executes.
type GuardrailStage string

const (
	StagePreInput   GuardrailStage = "pre_input"
	StageInput      GuardrailStage = "input"
	StageRouting    GuardrailStage = "routing"
	StageOutput     GuardrailStage = "output"
	StagePostOutput GuardrailStage = "post_output"
	StageBehavioral GuardrailStage = "behavioral"
)

// Decision is the action a guardrail takes.
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionBlock     Decision = "block"
	DecisionAnonymize Decision = "anonymize"
	DecisionModify    Decision = "modify"
	DecisionAlert     Decision = "alert"
	DecisionCoach     Decision = "coach"
	DecisionThrottle  Decision = "throttle"
	DecisionLog       Decision = "log"
)

// EnforcementMode controls how a guardrail behaves.
type EnforcementMode string

const (
	ModeOff     EnforcementMode = "off"
	ModeDiscover EnforcementMode = "discover"
	ModeMonitor EnforcementMode = "monitor"
	ModeEnforce EnforcementMode = "enforce"
)

// RuleCategory groups guardrail rules.
type RuleCategory string

const (
	CategoryAuth         RuleCategory = "auth"
	CategoryRateLimit    RuleCategory = "rate_limit"
	CategoryAllowlist    RuleCategory = "allowlist"
	CategoryPII          RuleCategory = "pii"
	CategorySecrets      RuleCategory = "secrets"
	CategoryInjection    RuleCategory = "injection"
	CategoryJailbreak    RuleCategory = "jailbreak"
	CategoryToxicity     RuleCategory = "toxicity"
	CategoryCodeSafety   RuleCategory = "code_safety"
	CategoryDataResidency RuleCategory = "data_residency"
	CategoryBrandSafety  RuleCategory = "brand_safety"
	CategoryExfiltration RuleCategory = "exfiltration"
	CategoryShadowAI     RuleCategory = "shadow_ai"
	CategoryAgentControl RuleCategory = "agent_control"
	CategoryCompliance   RuleCategory = "compliance"
)

// PIIType classifies types of personally identifiable information.
type PIIType string

const (
	PIIEmail        PIIType = "email"
	PIIPhone        PIIType = "phone"
	PIISSN          PIIType = "ssn"
	PIICreditCard   PIIType = "credit_card"
	PIIName         PIIType = "full_name"
	PIIAddress      PIIType = "address"
	PIIDOB          PIIType = "dob"
	PIIPassport     PIIType = "passport"
	PIIMedicalID    PIIType = "medical_id"
	PIIBankAccount  PIIType = "bank_account"
	PIIDriverLicense PIIType = "drivers_license"
	PIIIPAddress    PIIType = "ip_address"
	PIIEmployeeID   PIIType = "employee_id"
)

// PIISeverity classifies how sensitive a PII type is.
type PIISeverity string

const (
	PIISeverityCritical PIISeverity = "critical"
	PIISeverityHigh     PIISeverity = "high"
	PIISeverityMedium   PIISeverity = "medium"
	PIISeverityLow      PIISeverity = "low"
)

// GuardrailRuleConfig is the configuration for a single guardrail rule.
type GuardrailRuleConfig struct {
	ID          string          `json:"id" yaml:"id"`
	Name        string          `json:"name" yaml:"name"`
	Description string          `json:"description" yaml:"description"`
	Stage       GuardrailStage  `json:"stage" yaml:"stage"`
	Category    RuleCategory    `json:"category" yaml:"category"`
	Mode        EnforcementMode `json:"mode" yaml:"mode"`
	Priority    int             `json:"priority" yaml:"priority"`
	Enabled     bool            `json:"enabled" yaml:"enabled"`
	Config      map[string]any  `json:"config,omitempty" yaml:"config,omitempty"`
}

// GuardrailEvaluation is the result of evaluating a single guardrail rule.
type GuardrailEvaluation struct {
	RuleID     string     `json:"rule_id"`
	RuleName   string     `json:"rule_name"`
	Stage      GuardrailStage `json:"stage"`
	Decision   Decision   `json:"decision"`
	Confidence float64    `json:"confidence"`
	Reason     string     `json:"reason,omitempty"`
	Findings   []Finding  `json:"findings,omitempty"`
	LatencyMs  int64      `json:"latency_ms"`
}

// Finding is a specific item found by a guardrail rule.
type Finding struct {
	Type       string  `json:"type"`
	Value      string  `json:"value,omitempty"`
	Location   string  `json:"location,omitempty"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	StartPos   int     `json:"start_pos,omitempty"`
	EndPos     int     `json:"end_pos,omitempty"`
}

// PipelineResult is the aggregate result after all guardrails have run.
type PipelineResult struct {
	FinalDecision Decision              `json:"final_decision"`
	Evaluations   []GuardrailEvaluation `json:"evaluations"`
	ModifiedInput string                `json:"modified_input,omitempty"`
	ModifiedOutput string               `json:"modified_output,omitempty"`
	TotalLatencyMs int64               `json:"total_latency_ms"`
	Blocked       bool                  `json:"blocked"`
	BlockedBy     string                `json:"blocked_by,omitempty"`
}
