// ============================================================================
// TypeScript types matching the Go models in pkg/models/
// ============================================================================

// --- Event types ---

export type EventSource =
  | "kernel_observer"
  | "inline_gateway"
  | "browser"
  | "ide"
  | "mcp_gateway"
  | "cicd";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Direction = "outbound" | "inbound";

export type ActorType =
  | "pod"
  | "user"
  | "service_account"
  | "browser_user"
  | "agent";

export interface Actor {
  type: ActorType;
  id: string;
  name?: string;
  namespace?: string;
  node?: string;
  service_account?: string;
  labels?: Record<string, string>;
  team?: string;
}

export type TargetType =
  | "llm_provider"
  | "mcp_server"
  | "database"
  | "filesystem"
  | "api";

export interface Target {
  type: TargetType;
  id: string;
  provider?: string;
  endpoint?: string;
  model?: string;
  region?: string;
}

export type ActionType =
  | "api_call"
  | "tool_exec"
  | "file_access"
  | "process_spawn"
  | "db_query";

export interface Action {
  type: ActionType;
  direction: Direction;
  protocol?: string;
  method?: string;
}

export interface ContentMeta {
  has_prompt: boolean;
  prompt_hash?: string;
  prompt_text?: string;
  response_hash?: string;
  response_text?: string;
  tokens_input?: number;
  tokens_output?: number;
  model?: string;
  pii_detected?: string[];
  injection_score?: number;
  blocked: boolean;
  anonymized: boolean;
}

export interface GuardrailResult {
  rule_id: string;
  rule_name: string;
  stage: GuardrailStage;
  decision: Decision;
  confidence: number;
  reason?: string;
  details?: string[];
  latency_ms: number;
}

export interface Event {
  id: string;
  timestamp: string;
  source: EventSource;
  severity: Severity;
  actor: Actor;
  target: Target;
  action: Action;
  content: ContentMeta;
  guardrails?: GuardrailResult[];
  metadata?: Record<string, string>;
  session_id?: string;
  trace_id?: string;
  cost_usd?: number;
  latency_ms?: number;
}

// --- Inventory types ---

export interface ProviderUsage {
  provider: string;
  models: string[];
  call_count_7d: number;
  tokens_used_7d: number;
  data_transferred_7d: number;
  est_cost_7d_usd: number;
  last_call_at: string;
}

export interface LibraryUsage {
  name: string;
  version?: string;
  language: string;
}

export interface DatabaseUsage {
  type: string;
  host: string;
  database?: string;
}

export interface AIService {
  id: string;
  name: string;
  namespace: string;
  service_account?: string;
  team?: string;
  providers: ProviderUsage[];
  libraries?: LibraryUsage[];
  databases?: DatabaseUsage[];
  exposure_type: string;
  risk_score: number;
  discovered_at: string;
  last_seen_at: string;
  discovered_by: EventSource;
  policy_applied?: string;
  gateway_enrolled: boolean;
  labels?: Record<string, string>;
}

export interface ABOMSummary {
  total_services: number;
  total_providers: number;
  total_models: number;
  total_databases: number;
  shadow_ai_count: number;
  total_cost_7d_usd: number;
  high_risk_services: number;
}

export interface AIBOM {
  generated_at: string;
  services: AIService[];
  summary: ABOMSummary;
}

// --- Guardrail types ---

export type GuardrailStage =
  | "pre_input"
  | "input"
  | "routing"
  | "output"
  | "post_output"
  | "behavioral";

export type Decision =
  | "allow"
  | "block"
  | "anonymize"
  | "modify"
  | "alert"
  | "coach"
  | "throttle"
  | "log";

export type EnforcementMode = "off" | "discover" | "monitor" | "enforce";

export type RuleCategory =
  | "auth"
  | "rate_limit"
  | "allowlist"
  | "pii"
  | "secrets"
  | "injection"
  | "jailbreak"
  | "toxicity"
  | "code_safety"
  | "data_residency"
  | "brand_safety"
  | "exfiltration"
  | "shadow_ai"
  | "agent_control"
  | "compliance";

export interface GuardrailRuleConfig {
  id: string;
  name: string;
  description: string;
  stage: GuardrailStage;
  category: RuleCategory;
  mode: EnforcementMode;
  priority: number;
  enabled: boolean;
  config?: Record<string, unknown>;
}

export interface Finding {
  type: string;
  value?: string;
  location?: string;
  severity: string;
  confidence: number;
  start_pos?: number;
  end_pos?: number;
}

export interface GuardrailEvaluation {
  rule_id: string;
  rule_name: string;
  stage: GuardrailStage;
  decision: Decision;
  confidence: number;
  reason?: string;
  findings?: Finding[];
  latency_ms: number;
}

export interface PipelineResult {
  final_decision: Decision;
  evaluations: GuardrailEvaluation[];
  modified_input?: string;
  modified_output?: string;
  total_latency_ms: number;
  blocked: boolean;
  blocked_by?: string;
}

// --- Policy types ---

export interface PolicyScope {
  namespaces?: string[];
  services?: string[];
  service_accounts?: string[];
  users?: string[];
  teams?: string[];
}

export interface ProviderPolicy {
  allow: string[];
  deny: string[];
  namespace_overrides?: Record<string, ProviderPolicy>;
}

export interface ModelPolicy {
  allow: string[];
  deny: string[];
}

export interface RateLimit {
  requests_per_minute?: number;
  requests_per_hour?: number;
  requests_per_day?: number;
  tokens_per_day?: number;
  cost_per_day_usd?: number;
  cost_per_month_usd?: number;
}

export interface RateLimitPolicy {
  per_user?: RateLimit;
  per_service?: RateLimit;
  per_namespace?: RateLimit;
}

export interface InputPolicy {
  block_pii: boolean;
  anonymize_pii: boolean;
  pii_types?: string[];
  block_secrets: boolean;
  block_injection_score_above: number;
  max_tokens_per_request?: number;
  blocked_topics?: string[];
  allowed_topics?: string[];
}

export interface OutputPolicy {
  block_toxic_score_above: number;
  scan_generated_code: boolean;
  block_vulnerable_code: boolean;
  check_pii_leakage: boolean;
  check_prompt_leakage: boolean;
}

export interface AlertConfig {
  slack?: string;
  pagerduty?: string;
  email?: string;
  webhook?: string;
}

export interface PolicySpec {
  scope: PolicyScope;
  providers?: ProviderPolicy;
  models?: ModelPolicy;
  rate_limits?: RateLimitPolicy;
  input?: InputPolicy;
  output?: OutputPolicy;
  data_residency?: unknown;
  agent?: unknown;
  mode: EnforcementMode;
  alerts?: AlertConfig;
}

export interface PolicyMetadata {
  name: string;
  namespace?: string;
}

export interface AISecurityPolicy {
  apiVersion: string;
  kind: string;
  metadata: PolicyMetadata;
  spec: PolicySpec;
}

// --- Dashboard-specific types ---

export interface DashboardStats {
  total_services: number;
  active_guardrails: number;
  blocked_threats_24h: number;
  shadow_ai_detected: number;
  monthly_cost_usd: number;
  events_24h: number;
  avg_latency_ms: number;
}

export interface ThreatActivityPoint {
  date: string;
  blocked: number;
  allowed: number;
}

export interface RiskBreakdown {
  category: string;
  count: number;
  color: string;
}

export interface TopService {
  name: string;
  namespace: string;
  calls_7d: number;
  cost_7d_usd: number;
  risk_score: number;
}

// --- Lineage types ---

export interface LineageNode {
  id: string;
  label: string;
  type: "database" | "service" | "llm_provider" | "user";
  risk: "safe" | "warning" | "critical";
  details?: Record<string, string>;
  x: number;
  y: number;
}

export interface LineageEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  has_pii: boolean;
  data_volume?: string;
}

export interface LineageGraph {
  nodes: LineageNode[];
  edges: LineageEdge[];
}

// --- API response wrappers ---

export interface APIResponse<T> {
  data: T;
  meta?: {
    total: number;
    page: number;
    per_page: number;
  };
}

export interface APIError {
  error: string;
  code: number;
  details?: string;
}
