package policy

import (
	"strings"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Provider evaluation
// ---------------------------------------------------------------------------

// IsProviderAllowed determines whether the given provider is permitted by the
// policy. The logic is:
//
//  1. If the deny list is non-empty and the provider matches, it is blocked.
//  2. If the allow list is non-empty, the provider must appear in it.
//  3. An empty allow list with no deny match means allow by default.
//
// Matching is case-insensitive. The wildcard "*" matches everything.
func IsProviderAllowed(policy *models.AISecurityPolicy, provider string) bool {
	if policy == nil || policy.Spec.Providers == nil {
		return true // no provider policy means allow all
	}
	pp := policy.Spec.Providers

	// Deny takes precedence.
	if matchesList(pp.Deny, provider) {
		return false
	}

	// If an explicit allow list exists the provider must appear in it.
	if len(pp.Allow) > 0 {
		return matchesList(pp.Allow, provider)
	}

	return true
}

// IsProviderAllowedInNamespace checks the provider against namespace-specific
// overrides first, falling back to the top-level provider policy.
func IsProviderAllowedInNamespace(policy *models.AISecurityPolicy, provider, namespace string) bool {
	if policy == nil || policy.Spec.Providers == nil {
		return true
	}
	pp := policy.Spec.Providers

	// Check namespace override first.
	if ns, ok := pp.NamespaceOverrides[namespace]; ok {
		if matchesList(ns.Deny, provider) {
			return false
		}
		if len(ns.Allow) > 0 {
			return matchesList(ns.Allow, provider)
		}
	}

	// Fall back to the top-level rule.
	return IsProviderAllowed(policy, provider)
}

// ---------------------------------------------------------------------------
// Model evaluation
// ---------------------------------------------------------------------------

// IsModelAllowed determines whether the given model identifier is permitted.
// The semantics mirror IsProviderAllowed: deny list checked first, then the
// allow list, and default-allow when neither list is populated.
//
// Model matching supports a prefix wildcard: "gpt-4*" matches "gpt-4",
// "gpt-4-turbo", etc.
func IsModelAllowed(policy *models.AISecurityPolicy, model string) bool {
	if policy == nil || policy.Spec.Models == nil {
		return true
	}
	mp := policy.Spec.Models

	if matchesListWithPrefix(mp.Deny, model) {
		return false
	}
	if len(mp.Allow) > 0 {
		return matchesListWithPrefix(mp.Allow, model)
	}
	return true
}

// ---------------------------------------------------------------------------
// Rate limit evaluation
// ---------------------------------------------------------------------------

// RateLimitResult holds the outcome of a rate-limit check.
type RateLimitResult struct {
	Allowed   bool
	Remaining int
}

// CheckRateLimit evaluates whether the given current usage is within the
// limits defined in the policy for the specified actor scope. This is a
// stateless check -- the caller provides the current count.
//
// Returns allowed=true when the actor has capacity left, and remaining is
// the number of requests remaining in the smallest applicable window. A
// remaining value of -1 means the dimension is unconstrained.
func CheckRateLimit(policy *models.AISecurityPolicy, actor models.Actor, currentUsage int) RateLimitResult {
	if policy == nil || policy.Spec.RateLimits == nil {
		return RateLimitResult{Allowed: true, Remaining: -1}
	}
	rl := policy.Spec.RateLimits

	var limit *models.RateLimit
	switch {
	case rl.PerUser != nil && actor.ID != "":
		limit = rl.PerUser
	case rl.PerService != nil && actor.Name != "":
		limit = rl.PerService
	case rl.PerNamespace != nil && actor.Namespace != "":
		limit = rl.PerNamespace
	default:
		return RateLimitResult{Allowed: true, Remaining: -1}
	}

	allowed := true
	remaining := -1

	if limit.RequestsPerMinute > 0 {
		rem := limit.RequestsPerMinute - currentUsage
		if rem <= 0 {
			allowed = false
			rem = 0
		}
		if remaining < 0 || rem < remaining {
			remaining = rem
		}
	}
	if limit.RequestsPerHour > 0 {
		rem := limit.RequestsPerHour - currentUsage
		if rem <= 0 {
			allowed = false
			rem = 0
		}
		if remaining < 0 || rem < remaining {
			remaining = rem
		}
	}
	if limit.RequestsPerDay > 0 {
		rem := limit.RequestsPerDay - currentUsage
		if rem <= 0 {
			allowed = false
			rem = 0
		}
		if remaining < 0 || rem < remaining {
			remaining = rem
		}
	}

	return RateLimitResult{Allowed: allowed, Remaining: remaining}
}

// ---------------------------------------------------------------------------
// Enforcement mode
// ---------------------------------------------------------------------------

// GetEnforcementMode returns the enforcement mode set in the policy. If the
// mode is unset or empty, ModeEnforce is returned as the safe default.
func GetEnforcementMode(policy *models.AISecurityPolicy) models.EnforcementMode {
	if policy == nil || policy.Spec.Mode == "" {
		return models.ModeEnforce
	}
	return policy.Spec.Mode
}

// ---------------------------------------------------------------------------
// Policy merging
// ---------------------------------------------------------------------------

// MergePolicy produces a new policy by overlaying `override` on top of
// `base`. Fields present in override replace the corresponding base fields;
// fields absent in override are kept from base. This enables layering a
// namespace-level policy on top of a global one.
//
// Both inputs are left unmodified; the returned policy is a new allocation.
func MergePolicy(base, override *models.AISecurityPolicy) *models.AISecurityPolicy {
	if base == nil {
		return override
	}
	if override == nil {
		return base
	}

	merged := &models.AISecurityPolicy{
		APIVersion: override.APIVersion,
		Kind:       override.Kind,
		Metadata: models.PolicyMetadata{
			Name:      override.Metadata.Name,
			Namespace: coalesceStr(override.Metadata.Namespace, base.Metadata.Namespace),
		},
	}

	// Start with base spec, then overlay override fields.
	merged.Spec = base.Spec

	// Enforcement mode: override wins if set.
	if override.Spec.Mode != "" {
		merged.Spec.Mode = override.Spec.Mode
	}

	// Scope: override replaces entirely.
	if !isEmptyScope(override.Spec.Scope) {
		merged.Spec.Scope = override.Spec.Scope
	}

	// Providers.
	if override.Spec.Providers != nil {
		merged.Spec.Providers = mergeProviderPolicy(base.Spec.Providers, override.Spec.Providers)
	}

	// Models.
	if override.Spec.Models != nil {
		merged.Spec.Models = mergeModelPolicy(base.Spec.Models, override.Spec.Models)
	}

	// Rate limits: override replaces entirely.
	if override.Spec.RateLimits != nil {
		merged.Spec.RateLimits = override.Spec.RateLimits
	}

	// Input policy.
	if override.Spec.Input != nil {
		merged.Spec.Input = override.Spec.Input
	}

	// Output policy.
	if override.Spec.Output != nil {
		merged.Spec.Output = override.Spec.Output
	}

	// Agent policy.
	if override.Spec.Agent != nil {
		merged.Spec.Agent = override.Spec.Agent
	}

	// Data residency.
	if override.Spec.DataResidency != nil {
		merged.Spec.DataResidency = override.Spec.DataResidency
	}

	// Alerts.
	if override.Spec.Alerts != nil {
		merged.Spec.Alerts = override.Spec.Alerts
	}

	return merged
}

// ---------------------------------------------------------------------------
// Merge helpers
// ---------------------------------------------------------------------------

func mergeProviderPolicy(base, override *models.ProviderPolicy) *models.ProviderPolicy {
	if base == nil {
		return override
	}
	merged := &models.ProviderPolicy{
		Allow: coalesceStrSlice(override.Allow, base.Allow),
		Deny:  coalesceStrSlice(override.Deny, base.Deny),
	}
	// Merge namespace overrides.
	merged.NamespaceOverrides = make(map[string]models.ProviderPolicy)
	for k, v := range base.NamespaceOverrides {
		merged.NamespaceOverrides[k] = v
	}
	for k, v := range override.NamespaceOverrides {
		merged.NamespaceOverrides[k] = v
	}
	if len(merged.NamespaceOverrides) == 0 {
		merged.NamespaceOverrides = nil
	}
	return merged
}

func mergeModelPolicy(base, override *models.ModelPolicy) *models.ModelPolicy {
	if base == nil {
		return override
	}
	return &models.ModelPolicy{
		Allow: coalesceStrSlice(override.Allow, base.Allow),
		Deny:  coalesceStrSlice(override.Deny, base.Deny),
	}
}

// ---------------------------------------------------------------------------
// Matching helpers
// ---------------------------------------------------------------------------

// matchesList checks whether value matches any entry in the list (case-insensitive).
// The wildcard "*" matches everything.
func matchesList(list []string, value string) bool {
	lower := strings.ToLower(value)
	for _, entry := range list {
		if entry == "*" || strings.ToLower(entry) == lower {
			return true
		}
	}
	return false
}

// matchesListWithPrefix is like matchesList but also supports trailing
// wildcard patterns (e.g., "gpt-4*" matches "gpt-4-turbo").
func matchesListWithPrefix(list []string, value string) bool {
	lower := strings.ToLower(value)
	for _, entry := range list {
		e := strings.ToLower(entry)
		if e == "*" || e == lower {
			return true
		}
		if strings.HasSuffix(e, "*") {
			prefix := strings.TrimSuffix(e, "*")
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

func coalesceStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func coalesceStrSlice(a, b []string) []string {
	if len(a) > 0 {
		return a
	}
	return b
}
