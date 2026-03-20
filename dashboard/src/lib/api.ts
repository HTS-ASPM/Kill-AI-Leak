import type {
  AIService,
  AIBOM,
  AISecurityPolicy,
  APIError,
  APIResponse,
  DashboardStats,
  Event,
  GuardrailRuleConfig,
  LineageGraph,
  RiskBreakdown,
  ThreatActivityPoint,
  TopService,
} from "./types";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080/api/v1";

let authToken: string | null = null;

export function setAuthToken(token: string) {
  authToken = token;
}

export function clearAuthToken() {
  authToken = null;
}

// ---------------------------------------------------------------------------
// Fetch helper
// ---------------------------------------------------------------------------

class APIClientError extends Error {
  code: number;
  details?: string;

  constructor(message: string, code: number, details?: string) {
    super(message);
    this.name = "APIClientError";
    this.code = code;
    this.details = details;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> | undefined),
  };

  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let apiError: APIError | null = null;
    try {
      apiError = (await res.json()) as APIError;
    } catch {
      // response body wasn't valid JSON
    }
    throw new APIClientError(
      apiError?.error ?? `Request failed: ${res.status} ${res.statusText}`,
      res.status,
      apiError?.details,
    );
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Dashboard stats
// ---------------------------------------------------------------------------

export async function fetchStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/stats");
}

export async function fetchThreatActivity(
  days: number = 7,
): Promise<ThreatActivityPoint[]> {
  return request<ThreatActivityPoint[]>(`/stats/threat-activity?days=${days}`);
}

export async function fetchRiskBreakdown(): Promise<RiskBreakdown[]> {
  return request<RiskBreakdown[]>("/stats/risk-breakdown");
}

export async function fetchTopServices(
  limit: number = 10,
): Promise<TopService[]> {
  return request<TopService[]>(`/stats/top-services?limit=${limit}`);
}

// ---------------------------------------------------------------------------
// Inventory / AIBOM
// ---------------------------------------------------------------------------

export interface InventoryFilters {
  namespace?: string;
  provider?: string;
  risk_level?: "low" | "medium" | "high" | "critical";
  search?: string;
  page?: number;
  per_page?: number;
}

export async function fetchInventory(
  filters?: InventoryFilters,
): Promise<APIResponse<AIService[]>> {
  const params = new URLSearchParams();
  if (filters?.namespace) params.set("namespace", filters.namespace);
  if (filters?.provider) params.set("provider", filters.provider);
  if (filters?.risk_level) params.set("risk_level", filters.risk_level);
  if (filters?.search) params.set("search", filters.search);
  if (filters?.page) params.set("page", String(filters.page));
  if (filters?.per_page) params.set("per_page", String(filters.per_page));

  const qs = params.toString();
  return request<APIResponse<AIService[]>>(`/inventory${qs ? `?${qs}` : ""}`);
}

export async function fetchServiceDetail(id: string): Promise<AIService> {
  return request<AIService>(`/inventory/${id}`);
}

export async function fetchAIBOM(): Promise<AIBOM> {
  return request<AIBOM>("/inventory/aibom");
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export interface EventFilters {
  severity?: string;
  source?: string;
  decision?: "blocked" | "allowed";
  from?: string;
  to?: string;
  search?: string;
  page?: number;
  per_page?: number;
}

export async function fetchEvents(
  filters?: EventFilters,
): Promise<APIResponse<Event[]>> {
  const params = new URLSearchParams();
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.source) params.set("source", filters.source);
  if (filters?.decision) params.set("decision", filters.decision);
  if (filters?.from) params.set("from", filters.from);
  if (filters?.to) params.set("to", filters.to);
  if (filters?.search) params.set("search", filters.search);
  if (filters?.page) params.set("page", String(filters.page));
  if (filters?.per_page) params.set("per_page", String(filters.per_page));

  const qs = params.toString();
  return request<APIResponse<Event[]>>(`/events${qs ? `?${qs}` : ""}`);
}

export async function fetchEventDetail(id: string): Promise<Event> {
  return request<Event>(`/events/${id}`);
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

export async function fetchPolicies(): Promise<AISecurityPolicy[]> {
  return request<AISecurityPolicy[]>("/policies");
}

export async function fetchPolicy(name: string): Promise<AISecurityPolicy> {
  return request<AISecurityPolicy>(`/policies/${name}`);
}

export async function createPolicy(
  policy: AISecurityPolicy,
): Promise<AISecurityPolicy> {
  return request<AISecurityPolicy>("/policies", {
    method: "POST",
    body: JSON.stringify(policy),
  });
}

export async function updatePolicy(
  name: string,
  policy: AISecurityPolicy,
): Promise<AISecurityPolicy> {
  return request<AISecurityPolicy>(`/policies/${name}`, {
    method: "PUT",
    body: JSON.stringify(policy),
  });
}

export async function deletePolicy(name: string): Promise<void> {
  return request<void>(`/policies/${name}`, { method: "DELETE" });
}

export interface DryRunRequest {
  prompt: string;
  policy_name?: string;
}

export interface DryRunResponse {
  decision: string;
  evaluations: Array<{
    rule_id: string;
    rule_name: string;
    decision: string;
    reason?: string;
  }>;
  blocked: boolean;
  modified_prompt?: string;
}

export async function dryRunPolicy(
  req: DryRunRequest,
): Promise<DryRunResponse> {
  return request<DryRunResponse>("/policies/dry-run", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

// ---------------------------------------------------------------------------
// Guardrails
// ---------------------------------------------------------------------------

export async function fetchGuardrails(): Promise<GuardrailRuleConfig[]> {
  return request<GuardrailRuleConfig[]>("/guardrails");
}

export async function updateGuardrail(
  id: string,
  update: Partial<GuardrailRuleConfig>,
): Promise<GuardrailRuleConfig> {
  return request<GuardrailRuleConfig>(`/guardrails/${id}`, {
    method: "PATCH",
    body: JSON.stringify(update),
  });
}

// ---------------------------------------------------------------------------
// Data lineage
// ---------------------------------------------------------------------------

export async function fetchLineage(): Promise<LineageGraph> {
  return request<LineageGraph>("/lineage");
}

// ---------------------------------------------------------------------------
// Recent alerts (convenience)
// ---------------------------------------------------------------------------

export async function fetchRecentAlerts(
  limit: number = 10,
): Promise<Event[]> {
  const res = await fetchEvents({
    per_page: limit,
    severity: "high",
  });
  return res.data;
}
