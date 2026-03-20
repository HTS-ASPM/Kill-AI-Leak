// ---------------------------------------------------------------------------
// PolicyManager — fetches, caches, and evaluates AI security policies
//
// Policies are pulled from the Kill-AI-Leak REST API and cached locally via
// chrome.storage.local so the extension can continue to function offline.
// ---------------------------------------------------------------------------

import { getAIProvider } from "./domains";

// ---------------------------------------------------------------------------
// Types — mirrors the backend Go models (pkg/models/policy.go)
// ---------------------------------------------------------------------------

export type EnforcementMode = "off" | "discover" | "monitor" | "enforce";

export type PolicyDecision =
  | "allow"
  | "block"
  | "anonymize"
  | "coach"
  | "throttle"
  | "log";

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

export interface ProviderPolicy {
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
}

export interface PolicyScope {
  namespaces?: string[];
  services?: string[];
  users?: string[];
  teams?: string[];
}

export interface PolicySpec {
  scope: PolicyScope;
  providers?: ProviderPolicy;
  rate_limits?: RateLimitPolicy;
  input?: InputPolicy;
  output?: OutputPolicy;
  mode: EnforcementMode;
}

export interface AISecurityPolicy {
  apiVersion: string;
  kind: string;
  metadata: { name: string; namespace?: string };
  spec: PolicySpec;
}

/** The result of a policy evaluation for a specific request context. */
export interface PolicyEvaluation {
  decision: PolicyDecision;
  reason: string;
  policyName: string;
  mode: EnforcementMode;
  inputPolicy?: InputPolicy;
  outputPolicy?: OutputPolicy;
  rateLimit?: RateLimit;
}

// ---------------------------------------------------------------------------
// Cache keys
// ---------------------------------------------------------------------------

const STORAGE_KEY_POLICIES = "kail_policies";
const STORAGE_KEY_POLICIES_ETAG = "kail_policies_etag";
const STORAGE_KEY_POLICIES_FETCHED_AT = "kail_policies_fetched_at";

/** How long cached policies remain valid when the API is unreachable (ms). */
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes

// ---------------------------------------------------------------------------
// PolicyManager
// ---------------------------------------------------------------------------

export class PolicyManager {
  private policies: AISecurityPolicy[] = [];
  private apiBaseUrl: string;
  private authToken: string;
  private loaded = false;

  constructor(apiBaseUrl: string, authToken: string) {
    this.apiBaseUrl = apiBaseUrl.replace(/\/+$/, "");
    this.authToken = authToken;
  }

  // -----------------------------------------------------------------------
  // Initialization
  // -----------------------------------------------------------------------

  /** Load policies from local cache, then attempt a fresh fetch. */
  async initialize(): Promise<void> {
    await this.loadFromCache();
    // Fire-and-forget a refresh; errors are swallowed (we use cached data).
    this.fetchPolicies().catch(() => {
      /* offline — use cache */
    });
  }

  // -----------------------------------------------------------------------
  // Fetch & cache
  // -----------------------------------------------------------------------

  /** Fetch policies from the Kill-AI-Leak API and persist to cache. */
  async fetchPolicies(): Promise<void> {
    const cachedEtag = await this.getCachedEtag();

    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${this.authToken}`,
    };
    if (cachedEtag) {
      headers["If-None-Match"] = cachedEtag;
    }

    const res = await fetch(`${this.apiBaseUrl}/api/v1/policies?page_size=500`, {
      method: "GET",
      headers,
    });

    if (res.status === 304) {
      // Not modified — cache is still fresh.
      await this.touchCacheTimestamp();
      return;
    }

    if (!res.ok) {
      throw new Error(`Policy fetch failed: ${res.status} ${res.statusText}`);
    }

    const body = (await res.json()) as { policies: AISecurityPolicy[] };
    this.policies = body.policies ?? [];
    this.loaded = true;

    const etag = res.headers.get("ETag") ?? "";
    await this.saveToCache(this.policies, etag);
  }

  // -----------------------------------------------------------------------
  // Evaluation
  // -----------------------------------------------------------------------

  /**
   * Evaluate the effective policy for a given user and target AI domain.
   *
   * Resolution order:
   *   1. Find policies whose scope includes the user/team.
   *   2. Among those, pick the most specific match (user > team > wildcard).
   *   3. Check provider allow/deny lists.
   *   4. Return the aggregated decision.
   */
  evaluate(
    userId: string,
    team: string | undefined,
    targetUrl: string,
  ): PolicyEvaluation {
    // Default: allow (no policy loaded yet or nothing matches).
    const fallback: PolicyEvaluation = {
      decision: "allow",
      reason: "no matching policy",
      policyName: "",
      mode: "discover",
    };

    if (!this.loaded || this.policies.length === 0) {
      return fallback;
    }

    const provider = getAIProvider(targetUrl);
    // Category available via getAICategory(targetUrl) for topic-based rules.

    // Find the best matching policy for this user.
    const matched = this.findMatchingPolicy(userId, team);
    if (!matched) {
      return fallback;
    }

    const spec = matched.spec;
    const eval_: PolicyEvaluation = {
      decision: "allow",
      reason: "policy matched",
      policyName: matched.metadata.name,
      mode: spec.mode,
      inputPolicy: spec.input,
      outputPolicy: spec.output,
      rateLimit: spec.rate_limits?.per_user,
    };

    // Mode check — if mode is "off", everything is allowed.
    if (spec.mode === "off") {
      eval_.decision = "allow";
      eval_.reason = "enforcement mode is off";
      return eval_;
    }

    // Provider allow/deny.
    if (provider && spec.providers) {
      const providerLower = provider.toLowerCase();
      if (spec.providers.deny.length > 0) {
        const denied = spec.providers.deny.some(
          (d) => d === "*" || d.toLowerCase() === providerLower,
        );
        if (denied) {
          eval_.decision = "block";
          eval_.reason = `provider "${provider}" is denied by policy`;
          return eval_;
        }
      }
      if (spec.providers.allow.length > 0) {
        const allowed = spec.providers.allow.some(
          (a) => a === "*" || a.toLowerCase() === providerLower,
        );
        if (!allowed) {
          eval_.decision = "block";
          eval_.reason = `provider "${provider}" is not in allow list`;
          return eval_;
        }
      }
    }

    // If input policy says block secrets or PII, communicate that as "anonymize"
    // or "block" so the content script can act.
    if (spec.input) {
      if (spec.input.block_pii) {
        eval_.decision = "block";
        eval_.reason = "PII blocking is active";
      } else if (spec.input.anonymize_pii) {
        eval_.decision = "anonymize";
        eval_.reason = "PII anonymization is active";
      }
      if (spec.input.block_secrets) {
        eval_.decision = "block";
        eval_.reason = "secrets blocking is active";
      }
    }

    // In monitor/discover modes, downgrade blocking to coaching.
    if (spec.mode === "monitor" || spec.mode === "discover") {
      if (eval_.decision === "block") {
        eval_.decision = "coach";
        eval_.reason += " (monitor mode — coaching only)";
      }
    }

    return eval_;
  }

  // -----------------------------------------------------------------------
  // Policy matching
  // -----------------------------------------------------------------------

  private findMatchingPolicy(
    userId: string,
    team: string | undefined,
  ): AISecurityPolicy | null {
    let bestMatch: AISecurityPolicy | null = null;
    let bestSpecificity = -1;

    for (const policy of this.policies) {
      const specificity = this.scopeSpecificity(policy.spec.scope, userId, team);
      if (specificity > bestSpecificity) {
        bestSpecificity = specificity;
        bestMatch = policy;
      }
    }

    return bestMatch;
  }

  /**
   * Returns a specificity score for how well a scope matches the given user.
   * Higher = more specific. -1 means no match.
   *
   *   user match:  100
   *   team match:   50
   *   wildcard:     10
   *   no scope:      1  (applies to everyone)
   */
  private scopeSpecificity(
    scope: PolicyScope,
    userId: string,
    team: string | undefined,
  ): number {
    const hasUsers = scope.users && scope.users.length > 0;
    const hasTeams = scope.teams && scope.teams.length > 0;

    // If the scope specifies users, the user must be in the list.
    if (hasUsers) {
      if (scope.users!.includes(userId) || scope.users!.includes("*")) {
        return 100;
      }
      return -1;
    }

    // If the scope specifies teams, the user's team must match.
    if (hasTeams && team) {
      if (scope.teams!.includes(team) || scope.teams!.includes("*")) {
        return 50;
      }
      return -1;
    }

    // No user/team scope — applies globally.
    return 1;
  }

  // -----------------------------------------------------------------------
  // Cache helpers
  // -----------------------------------------------------------------------

  private async loadFromCache(): Promise<void> {
    try {
      const result = await chrome.storage.local.get([
        STORAGE_KEY_POLICIES,
        STORAGE_KEY_POLICIES_FETCHED_AT,
      ]);
      const raw = result[STORAGE_KEY_POLICIES];
      if (Array.isArray(raw) && raw.length > 0) {
        this.policies = raw as AISecurityPolicy[];
        this.loaded = true;
      }
    } catch {
      // Storage unavailable — proceed without cache.
    }
  }

  private async saveToCache(
    policies: AISecurityPolicy[],
    etag: string,
  ): Promise<void> {
    try {
      await chrome.storage.local.set({
        [STORAGE_KEY_POLICIES]: policies,
        [STORAGE_KEY_POLICIES_ETAG]: etag,
        [STORAGE_KEY_POLICIES_FETCHED_AT]: Date.now(),
      });
    } catch {
      // Storage full or unavailable.
    }
  }

  private async getCachedEtag(): Promise<string | null> {
    try {
      const result = await chrome.storage.local.get(STORAGE_KEY_POLICIES_ETAG);
      return (result[STORAGE_KEY_POLICIES_ETAG] as string) ?? null;
    } catch {
      return null;
    }
  }

  private async touchCacheTimestamp(): Promise<void> {
    try {
      await chrome.storage.local.set({
        [STORAGE_KEY_POLICIES_FETCHED_AT]: Date.now(),
      });
    } catch {
      /* ignore */
    }
  }

  /** Returns true if the cached policies are stale. */
  async isCacheStale(): Promise<boolean> {
    try {
      const result = await chrome.storage.local.get(STORAGE_KEY_POLICIES_FETCHED_AT);
      const fetchedAt = result[STORAGE_KEY_POLICIES_FETCHED_AT] as number | undefined;
      if (!fetchedAt) return true;
      return Date.now() - fetchedAt > CACHE_TTL_MS;
    } catch {
      return true;
    }
  }

  // -----------------------------------------------------------------------
  // Accessors
  // -----------------------------------------------------------------------

  getPolicies(): readonly AISecurityPolicy[] {
    return this.policies;
  }

  isLoaded(): boolean {
    return this.loaded;
  }

  updateCredentials(apiBaseUrl: string, authToken: string): void {
    this.apiBaseUrl = apiBaseUrl.replace(/\/+$/, "");
    this.authToken = authToken;
  }
}
