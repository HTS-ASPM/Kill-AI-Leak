package mcp

import (
	"strings"
	"sync"
)

// ApprovalRequirement indicates whether a human must approve an action.
type ApprovalRequirement string

const (
	ApprovalNone     ApprovalRequirement = "none"
	ApprovalRequired ApprovalRequirement = "required"
	ApprovalOptional ApprovalRequirement = "optional"
)

// MCPPolicy holds the complete set of tool-use, server-level, and user-level
// rules for the MCP gateway.
type MCPPolicy struct {
	mu sync.RWMutex

	// ServerRules controls which MCP servers are allowed or denied globally.
	ServerRules ServerPolicySet `json:"server_rules" yaml:"server_rules"`

	// ToolRules controls which tools are allowed or denied, potentially
	// scoped to specific servers and users.
	ToolRules []ToolRule `json:"tool_rules" yaml:"tool_rules"`

	// UserRules sets per-user restrictions on servers and tools.
	UserRules map[string]UserPolicy `json:"user_rules,omitempty" yaml:"user_rules,omitempty"`

	// ActionPolicies define which MCP methods require human approval.
	ActionPolicies map[string]ApprovalRequirement `json:"action_policies,omitempty" yaml:"action_policies,omitempty"`

	// DefaultDeny when true blocks all tool calls and server connections
	// unless explicitly allowed. When false, everything is allowed unless
	// explicitly denied.
	DefaultDeny bool `json:"default_deny" yaml:"default_deny"`
}

// ServerPolicySet tracks allowed/denied servers and their risk scores.
type ServerPolicySet struct {
	// Allow is a list of server IDs or patterns that are explicitly approved.
	Allow []string `json:"allow,omitempty" yaml:"allow,omitempty"`

	// Deny is a list of server IDs or patterns that are explicitly blocked.
	Deny []string `json:"deny,omitempty" yaml:"deny,omitempty"`

	// RiskScores maps server IDs to a risk score [0.0, 1.0].
	// Servers above MaxRiskScore are automatically denied.
	RiskScores map[string]float64 `json:"risk_scores,omitempty" yaml:"risk_scores,omitempty"`

	// MaxRiskScore is the threshold above which a server is auto-denied.
	// Zero means risk-based blocking is disabled.
	MaxRiskScore float64 `json:"max_risk_score" yaml:"max_risk_score"`
}

// ToolRule defines a single tool allow/deny rule, optionally scoped to a
// server and/or user.
type ToolRule struct {
	// Tool is the tool name or glob pattern (e.g. "file_*", "exec_command").
	Tool string `json:"tool" yaml:"tool"`

	// Server is an optional server scope. Empty means "any server".
	Server string `json:"server,omitempty" yaml:"server,omitempty"`

	// User is an optional user scope. Empty means "any user".
	User string `json:"user,omitempty" yaml:"user,omitempty"`

	// Allow determines whether the rule permits or denies the tool.
	Allow bool `json:"allow" yaml:"allow"`

	// RequireApproval controls whether this tool invocation needs a human
	// in the loop before proceeding.
	RequireApproval ApprovalRequirement `json:"require_approval,omitempty" yaml:"require_approval,omitempty"`
}

// UserPolicy sets per-user overrides for server and tool access.
type UserPolicy struct {
	// AllowedServers restricts the user to only these servers. Empty means
	// "governed by global server rules".
	AllowedServers []string `json:"allowed_servers,omitempty" yaml:"allowed_servers,omitempty"`

	// DeniedServers explicitly blocks these servers for this user.
	DeniedServers []string `json:"denied_servers,omitempty" yaml:"denied_servers,omitempty"`

	// AllowedTools restricts the user to only these tools. Empty means
	// "governed by global/server tool rules".
	AllowedTools []string `json:"allowed_tools,omitempty" yaml:"allowed_tools,omitempty"`

	// DeniedTools explicitly blocks these tools for this user.
	DeniedTools []string `json:"denied_tools,omitempty" yaml:"denied_tools,omitempty"`

	// MaxRiskScore overrides the global MaxRiskScore for this user.
	// Zero means use global default.
	MaxRiskScore float64 `json:"max_risk_score,omitempty" yaml:"max_risk_score,omitempty"`
}

// NewMCPPolicy creates an MCPPolicy with initialized maps.
func NewMCPPolicy() *MCPPolicy {
	return &MCPPolicy{
		UserRules:      make(map[string]UserPolicy),
		ActionPolicies: make(map[string]ApprovalRequirement),
		ServerRules: ServerPolicySet{
			RiskScores: make(map[string]float64),
		},
	}
}

// IsServerAllowed checks whether the given MCP server is permitted based on
// server-level rules and risk scores. The optional user parameter refines the
// check against user-specific overrides.
func (p *MCPPolicy) IsServerAllowed(server string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	serverNorm := NormalizeServerID(server)

	// Explicit deny takes precedence.
	for _, pattern := range p.ServerRules.Deny {
		if matchPattern(NormalizeServerID(pattern), serverNorm) {
			return false
		}
	}

	// Risk score check.
	if p.ServerRules.MaxRiskScore > 0 {
		if score, ok := p.ServerRules.RiskScores[serverNorm]; ok {
			if score > p.ServerRules.MaxRiskScore {
				return false
			}
		}
	}

	// If default-deny, the server must appear in the allow list.
	if p.DefaultDeny {
		for _, pattern := range p.ServerRules.Allow {
			if matchPattern(NormalizeServerID(pattern), serverNorm) {
				return true
			}
		}
		return false
	}

	// Default allow: server is permitted unless explicitly denied.
	return true
}

// IsToolAllowed checks whether a specific tool call is permitted for the given
// user on the given server.
func (p *MCPPolicy) IsToolAllowed(user, server, tool string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	serverNorm := NormalizeServerID(server)
	toolNorm := strings.TrimSpace(strings.ToLower(tool))
	userNorm := strings.TrimSpace(strings.ToLower(user))

	// Check user-level denials first.
	if userNorm != "" {
		if up, ok := p.UserRules[userNorm]; ok {
			// User-level denied tools.
			for _, dt := range up.DeniedTools {
				if matchPattern(strings.ToLower(dt), toolNorm) {
					return false
				}
			}

			// User-level denied servers.
			for _, ds := range up.DeniedServers {
				if matchPattern(NormalizeServerID(ds), serverNorm) {
					return false
				}
			}

			// If user has an explicit allow-list, enforce it.
			if len(up.AllowedTools) > 0 {
				found := false
				for _, at := range up.AllowedTools {
					if matchPattern(strings.ToLower(at), toolNorm) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}

			// User-level server allow-list.
			if len(up.AllowedServers) > 0 && serverNorm != "" {
				found := false
				for _, as := range up.AllowedServers {
					if matchPattern(NormalizeServerID(as), serverNorm) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}

			// User-level risk score override.
			if up.MaxRiskScore > 0 && serverNorm != "" {
				if score, ok := p.ServerRules.RiskScores[serverNorm]; ok {
					if score > up.MaxRiskScore {
						return false
					}
				}
			}
		}
	}

	// Check explicit tool rules (most specific match wins).
	var bestMatch *ToolRule
	bestSpecificity := -1

	for i := range p.ToolRules {
		r := &p.ToolRules[i]
		rTool := strings.ToLower(r.Tool)
		rServer := NormalizeServerID(r.Server)
		rUser := strings.TrimSpace(strings.ToLower(r.User))

		// Does this rule match the request?
		if !matchPattern(rTool, toolNorm) {
			continue
		}
		if rServer != "" && !matchPattern(rServer, serverNorm) {
			continue
		}
		if rUser != "" && rUser != userNorm {
			continue
		}

		// Calculate specificity: more constraints = more specific.
		specificity := 0
		if rServer != "" {
			specificity++
		}
		if rUser != "" {
			specificity++
		}
		if !strings.ContainsAny(rTool, "*?") {
			specificity++ // exact tool name is more specific than a glob
		}

		if specificity > bestSpecificity {
			bestSpecificity = specificity
			bestMatch = r
		}
	}

	if bestMatch != nil {
		return bestMatch.Allow
	}

	// No matching rule found: fall back to default policy.
	return !p.DefaultDeny
}

// RequiresApproval returns the approval requirement for a given MCP method.
func (p *MCPPolicy) RequiresApproval(method string) ApprovalRequirement {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if req, ok := p.ActionPolicies[method]; ok {
		return req
	}
	return ApprovalNone
}

// RiskScore returns the configured risk score for a server, or 0.0 if unknown.
func (p *MCPPolicy) RiskScore(server string) float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	serverNorm := NormalizeServerID(server)
	if score, ok := p.ServerRules.RiskScores[serverNorm]; ok {
		return score
	}
	return 0.0
}

// SetRiskScore sets the risk score for an MCP server.
func (p *MCPPolicy) SetRiskScore(server string, score float64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	serverNorm := NormalizeServerID(server)
	if p.ServerRules.RiskScores == nil {
		p.ServerRules.RiskScores = make(map[string]float64)
	}
	p.ServerRules.RiskScores[serverNorm] = score
}

// matchPattern performs a simple glob match supporting '*' (match any
// sequence) and '?' (match single character). Both pattern and value should
// be pre-normalized to lowercase.
func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == value
	}
	return globMatch(pattern, value)
}

// globMatch is a non-recursive glob matching implementation.
func globMatch(pattern, str string) bool {
	px, sx := 0, 0
	nextPx, nextSx := 0, -1

	for sx < len(str) {
		if px < len(pattern) {
			switch pattern[px] {
			case '?':
				px++
				sx++
				continue
			case '*':
				nextPx = px
				nextSx = sx
				px++
				continue
			default:
				if pattern[px] == str[sx] {
					px++
					sx++
					continue
				}
			}
		}
		if nextSx >= 0 {
			nextSx++
			sx = nextSx
			px = nextPx + 1
			continue
		}
		return false
	}

	// Consume trailing '*'.
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
