package guardrails

import (
	"fmt"
	"sort"
	"sync"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Registry is a thread-safe store for guardrail rules. It supports
// registration, lookup by stage or category, enable/disable toggling,
// and dynamic configuration.
type Registry struct {
	mu       sync.RWMutex
	rules    map[string]Rule                      // keyed by rule ID
	configs  map[string]*models.GuardrailRuleConfig // keyed by rule ID
	disabled map[string]bool                      // keyed by rule ID
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		rules:    make(map[string]Rule),
		configs:  make(map[string]*models.GuardrailRuleConfig),
		disabled: make(map[string]bool),
	}
}

// Register adds a rule to the registry. If a rule with the same ID already
// exists it is replaced. An optional GuardrailRuleConfig can be provided;
// if nil a default config is generated from the rule's own metadata.
func (r *Registry) Register(rule Rule, cfg *models.GuardrailRuleConfig) error {
	if rule == nil {
		return fmt.Errorf("guardrails: cannot register nil rule")
	}
	if rule.ID() == "" {
		return fmt.Errorf("guardrails: rule ID must not be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.rules[rule.ID()] = rule

	if cfg != nil {
		r.configs[rule.ID()] = cfg
	} else {
		r.configs[rule.ID()] = &models.GuardrailRuleConfig{
			ID:       rule.ID(),
			Name:     rule.Name(),
			Stage:    rule.Stage(),
			Category: rule.Category(),
			Mode:     models.ModeEnforce,
			Enabled:  true,
		}
	}

	// If the rule accepts configuration and config values are present,
	// apply them immediately.
	if configurable, ok := rule.(ConfigurableRule); ok && cfg != nil && len(cfg.Config) > 0 {
		if err := configurable.Configure(cfg.Config); err != nil {
			return fmt.Errorf("guardrails: configure rule %s: %w", rule.ID(), err)
		}
	}

	return nil
}

// Get returns a rule by ID, or nil if not found.
func (r *Registry) Get(id string) Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rules[id]
}

// GetConfig returns the configuration for a rule by ID.
func (r *Registry) GetConfig(id string) (*models.GuardrailRuleConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.configs[id]
	return cfg, ok
}

// GetByStage returns all enabled rules that execute in the given stage,
// sorted by priority (lower priority number = runs first).
func (r *Registry) GetByStage(stage models.GuardrailStage) []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []Rule
	for id, rule := range r.rules {
		if rule.Stage() == stage && !r.disabled[id] && r.isEnabledInConfig(id) {
			out = append(out, rule)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		pi := r.priority(out[i].ID())
		pj := r.priority(out[j].ID())
		return pi < pj
	})
	return out
}

// GetByCategory returns all enabled rules in the given category,
// sorted by priority.
func (r *Registry) GetByCategory(category models.RuleCategory) []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []Rule
	for id, rule := range r.rules {
		if rule.Category() == category && !r.disabled[id] && r.isEnabledInConfig(id) {
			out = append(out, rule)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		pi := r.priority(out[i].ID())
		pj := r.priority(out[j].ID())
		return pi < pj
	})
	return out
}

// Enable enables a previously disabled rule. Returns an error if the rule
// is not registered.
func (r *Registry) Enable(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rules[id]; !ok {
		return fmt.Errorf("guardrails: rule %q not registered", id)
	}
	delete(r.disabled, id)
	if cfg, ok := r.configs[id]; ok {
		cfg.Enabled = true
	}
	return nil
}

// Disable disables a rule so it is skipped during evaluation. Returns an
// error if the rule is not registered.
func (r *Registry) Disable(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rules[id]; !ok {
		return fmt.Errorf("guardrails: rule %q not registered", id)
	}
	r.disabled[id] = true
	if cfg, ok := r.configs[id]; ok {
		cfg.Enabled = false
	}
	return nil
}

// IsEnabled reports whether a rule is currently enabled.
func (r *Registry) IsEnabled(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.rules[id]; !ok {
		return false
	}
	return !r.disabled[id] && r.isEnabledInConfig(id)
}

// Configure applies new configuration to a registered rule. The rule must
// implement ConfigurableRule; otherwise an error is returned.
func (r *Registry) Configure(id string, cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rule, ok := r.rules[id]
	if !ok {
		return fmt.Errorf("guardrails: rule %q not registered", id)
	}
	configurable, ok := rule.(ConfigurableRule)
	if !ok {
		return fmt.Errorf("guardrails: rule %q does not support configuration", id)
	}
	if err := configurable.Configure(cfg); err != nil {
		return fmt.Errorf("guardrails: configure rule %s: %w", id, err)
	}
	if c, ok := r.configs[id]; ok {
		c.Config = cfg
	}
	return nil
}

// All returns every registered rule, regardless of enabled state.
func (r *Registry) All() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule)
	}
	return out
}

// Unregister removes a rule from the registry. It is a no-op if the ID
// is not registered.
func (r *Registry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rules, id)
	delete(r.configs, id)
	delete(r.disabled, id)
}

// isEnabledInConfig checks the config-level enabled flag. Must be called
// with at least a read lock held.
func (r *Registry) isEnabledInConfig(id string) bool {
	cfg, ok := r.configs[id]
	if !ok {
		return true // no config means enabled by default
	}
	return cfg.Enabled
}

// priority returns the configured priority for a rule. Must be called with
// at least a read lock held.
func (r *Registry) priority(id string) int {
	cfg, ok := r.configs[id]
	if !ok {
		return 1000 // default priority: low
	}
	return cfg.Priority
}
