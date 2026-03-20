// Package policy implements the Kill AI Leak policy engine. It loads
// AISecurityPolicy resources from YAML files, matches them to actors using
// a specificity hierarchy (service > namespace > team > global), and
// evaluates provider/model allowlists and rate limits at request time.
package policy

import (
	"fmt"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Sliding-window rate limiter (in-memory)
// ---------------------------------------------------------------------------

// rateBucket stores timestamped request counts for a single actor key.
type rateBucket struct {
	mu       sync.Mutex
	requests []time.Time
}

// countInWindow returns how many requests occurred within the last `window`
// duration and prunes expired entries.
func (b *rateBucket) countInWindow(window time.Duration) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-window)
	// Prune entries older than cutoff.
	idx := 0
	for idx < len(b.requests) && b.requests[idx].Before(cutoff) {
		idx++
	}
	b.requests = b.requests[idx:]
	return len(b.requests)
}

// record appends the current timestamp to the bucket.
func (b *rateBucket) record() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.requests = append(b.requests, time.Now())
}

// ---------------------------------------------------------------------------
// PolicyEngine
// ---------------------------------------------------------------------------

// PolicyEngine holds all loaded AISecurityPolicy resources and provides
// thread-safe lookups by actor identity. Rate-limit state is kept in memory
// using a sliding-window counter per actor key.
type PolicyEngine struct {
	mu       sync.RWMutex
	policies []*models.AISecurityPolicy

	// rateMu protects the buckets map.
	rateMu  sync.Mutex
	buckets map[string]*rateBucket

	// loader is used for hot-reload; nil when not watching.
	loader *Loader
}

// NewPolicyEngine creates an empty engine ready for use.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		buckets: make(map[string]*rateBucket),
	}
}

// LoadPolicies reads all YAML policy files from the given path. If the path
// is a directory every .yaml/.yml file inside it is loaded; if it points to
// a single file only that file is loaded. Existing policies are replaced
// atomically.
func (e *PolicyEngine) LoadPolicies(path string) error {
	loader := NewLoader()
	policies, err := loader.LoadPath(path)
	if err != nil {
		return fmt.Errorf("policy engine: load: %w", err)
	}
	e.mu.Lock()
	e.policies = policies
	e.loader = loader
	e.mu.Unlock()
	return nil
}

// SetPolicies replaces the loaded policies atomically. This is used by the
// hot-reload watcher to swap in a new set without downtime.
func (e *PolicyEngine) SetPolicies(policies []*models.AISecurityPolicy) {
	e.mu.Lock()
	e.policies = policies
	e.mu.Unlock()
}

// Policies returns a snapshot of all loaded policies.
func (e *PolicyEngine) Policies() []*models.AISecurityPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*models.AISecurityPolicy, len(e.policies))
	copy(out, e.policies)
	return out
}

// ---------------------------------------------------------------------------
// Policy resolution (most-specific-match)
// ---------------------------------------------------------------------------

// scopeSpecificity scores how specific a policy's scope is for the given
// actor. Higher is more specific. Returns -1 when the policy does not apply
// to the actor at all.
func scopeSpecificity(scope models.PolicyScope, actor models.Actor) int {
	score := 0
	matched := false

	// Service-level match (most specific).
	if len(scope.Services) > 0 {
		if containsOrWild(scope.Services, actor.Name) {
			score += 1000
			matched = true
		} else {
			return -1 // scope lists services and actor is not among them
		}
	}

	// ServiceAccount match.
	if len(scope.ServiceAccounts) > 0 {
		if containsOrWild(scope.ServiceAccounts, actor.ServiceAccount) {
			score += 500
			matched = true
		} else {
			return -1
		}
	}

	// Namespace match.
	if len(scope.Namespaces) > 0 {
		if containsOrWild(scope.Namespaces, actor.Namespace) {
			score += 100
			matched = true
		} else {
			return -1
		}
	}

	// Team match.
	if len(scope.Teams) > 0 {
		if containsOrWild(scope.Teams, actor.Team) {
			score += 50
			matched = true
		} else {
			return -1
		}
	}

	// User match.
	if len(scope.Users) > 0 {
		if containsOrWild(scope.Users, actor.ID) || containsOrWild(scope.Users, actor.Name) {
			score += 200
			matched = true
		} else {
			return -1
		}
	}

	// A completely empty scope matches everything (global policy) with the
	// lowest specificity.
	if !matched && isEmptyScope(scope) {
		return 0
	}
	if !matched {
		return -1
	}
	return score
}

// containsOrWild returns true if the slice contains the value or a wildcard "*".
func containsOrWild(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == "*" || v == needle {
			return true
		}
	}
	return false
}

// isEmptyScope returns true when no scope fields are set. Such a policy is
// considered global.
func isEmptyScope(s models.PolicyScope) bool {
	return len(s.Namespaces) == 0 &&
		len(s.Services) == 0 &&
		len(s.ServiceAccounts) == 0 &&
		len(s.Users) == 0 &&
		len(s.Teams) == 0
}

// GetPolicyForActor returns the most specific policy that matches the given
// actor. When no policy matches, nil is returned.
func (e *PolicyEngine) GetPolicyForActor(actor models.Actor) *models.AISecurityPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var best *models.AISecurityPolicy
	bestScore := -1

	for _, p := range e.policies {
		score := scopeSpecificity(p.Spec.Scope, actor)
		if score > bestScore {
			bestScore = score
			best = p
		}
	}
	return best
}

// GetAllPoliciesForActor returns every policy that matches the actor, ordered
// from least to most specific. This is useful when you need to merge policies.
func (e *PolicyEngine) GetAllPoliciesForActor(actor models.Actor) []*models.AISecurityPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	type scored struct {
		policy *models.AISecurityPolicy
		score  int
	}
	var matches []scored
	for _, p := range e.policies {
		s := scopeSpecificity(p.Spec.Scope, actor)
		if s >= 0 {
			matches = append(matches, scored{policy: p, score: s})
		}
	}
	// Sort ascending (least specific first).
	for i := 1; i < len(matches); i++ {
		for j := i; j > 0 && matches[j].score < matches[j-1].score; j-- {
			matches[j], matches[j-1] = matches[j-1], matches[j]
		}
	}
	out := make([]*models.AISecurityPolicy, len(matches))
	for i, m := range matches {
		out[i] = m.policy
	}
	return out
}

// ---------------------------------------------------------------------------
// Provider / model / rate-limit convenience wrappers
// ---------------------------------------------------------------------------

// IsProviderAllowed checks whether the given provider string is allowed by
// the most specific policy matching the actor.
func (e *PolicyEngine) IsProviderAllowed(actor models.Actor, provider string) bool {
	policy := e.GetPolicyForActor(actor)
	if policy == nil {
		return true // no policy means allow
	}
	return IsProviderAllowed(policy, provider)
}

// IsModelAllowed checks whether the given model string is allowed by the most
// specific policy matching the actor.
func (e *PolicyEngine) IsModelAllowed(actor models.Actor, model string) bool {
	policy := e.GetPolicyForActor(actor)
	if policy == nil {
		return true
	}
	return IsModelAllowed(policy, model)
}

// CheckRateLimit verifies that the actor has not exceeded the rate limits
// defined in its matching policy. It uses a sliding-window counter stored in
// memory. Returns whether the request is allowed and the number of remaining
// requests in the smallest window.
func (e *PolicyEngine) CheckRateLimit(actor models.Actor) (allowed bool, remaining int) {
	policy := e.GetPolicyForActor(actor)
	if policy == nil || policy.Spec.RateLimits == nil {
		return true, -1 // unlimited
	}

	rl := policy.Spec.RateLimits
	var limit *models.RateLimit

	// Select the most specific rate limit for the actor.
	switch {
	case rl.PerUser != nil && actor.ID != "":
		limit = rl.PerUser
	case rl.PerService != nil && actor.Name != "":
		limit = rl.PerService
	case rl.PerNamespace != nil && actor.Namespace != "":
		limit = rl.PerNamespace
	default:
		return true, -1
	}

	key := rateLimitKey(actor)
	bucket := e.getOrCreateBucket(key)

	// Check each configured window. All must pass.
	allowed = true
	remaining = -1

	if limit.RequestsPerMinute > 0 {
		count := bucket.countInWindow(time.Minute)
		rem := limit.RequestsPerMinute - count
		if rem <= 0 {
			allowed = false
			rem = 0
		}
		if remaining < 0 || rem < remaining {
			remaining = rem
		}
	}
	if limit.RequestsPerHour > 0 {
		count := bucket.countInWindow(time.Hour)
		rem := limit.RequestsPerHour - count
		if rem <= 0 {
			allowed = false
			rem = 0
		}
		if remaining < 0 || rem < remaining {
			remaining = rem
		}
	}
	if limit.RequestsPerDay > 0 {
		count := bucket.countInWindow(24 * time.Hour)
		rem := limit.RequestsPerDay - count
		if rem <= 0 {
			allowed = false
			rem = 0
		}
		if remaining < 0 || rem < remaining {
			remaining = rem
		}
	}

	if allowed {
		bucket.record()
	}
	return allowed, remaining
}

// rateLimitKey builds a unique key for an actor's rate-limit bucket.
func rateLimitKey(actor models.Actor) string {
	return fmt.Sprintf("%s:%s:%s:%s", actor.Type, actor.Namespace, actor.Name, actor.ID)
}

// getOrCreateBucket retrieves or lazily creates a rate bucket for the key.
func (e *PolicyEngine) getOrCreateBucket(key string) *rateBucket {
	e.rateMu.Lock()
	defer e.rateMu.Unlock()
	b, ok := e.buckets[key]
	if !ok {
		b = &rateBucket{}
		e.buckets[key] = b
	}
	return b
}

// ResetRateLimits clears all in-memory rate-limit state. Useful in tests.
func (e *PolicyEngine) ResetRateLimits() {
	e.rateMu.Lock()
	e.buckets = make(map[string]*rateBucket)
	e.rateMu.Unlock()
}
