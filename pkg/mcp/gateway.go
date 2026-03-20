package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GatewayConfig holds configuration for the MCPGateway.
type GatewayConfig struct {
	// UpstreamURL is the base URL of the real MCP server to proxy to.
	UpstreamURL string

	// MaxBodyBytes limits the size of incoming request bodies.
	// Zero means 10 MiB.
	MaxBodyBytes int64

	// RequestTimeout is the timeout for upstream requests.
	// Zero means 30 seconds.
	RequestTimeout time.Duration

	// EnableShadowDetection controls whether the gateway checks for
	// unauthorized MCP servers in initialize handshakes.
	EnableShadowDetection bool
}

// DefaultGatewayConfig returns a GatewayConfig with sensible defaults.
func DefaultGatewayConfig() GatewayConfig {
	return GatewayConfig{
		MaxBodyBytes:          10 << 20, // 10 MiB
		RequestTimeout:        30 * time.Second,
		EnableShadowDetection: true,
	}
}

// ShadowServerEntry tracks a suspected unauthorized MCP server.
type ShadowServerEntry struct {
	ServerID     string    `json:"server_id"`
	ClientInfo   string    `json:"client_info"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	RequestCount int       `json:"request_count"`
}

// MCPGateway intercepts Model Context Protocol JSON-RPC traffic, enforces
// tool-use policies, logs all decisions, and forwards permitted requests to
// the upstream MCP server.
type MCPGateway struct {
	cfg        GatewayConfig
	policy     *MCPPolicy
	audit      *MCPAuditLog
	logger     *slog.Logger
	httpClient *http.Client

	// knownServers tracks MCP servers seen through initialize handshakes.
	// Access protected by shadowMu.
	shadowMu     sync.RWMutex
	knownServers map[string]*ShadowServerEntry

	// approvedServers is the set of server IDs that have been approved
	// through policy. Any server not in this set during initialize is
	// flagged as a potential shadow server.
	approvedServers map[string]bool
}

// NewMCPGateway creates a new MCP gateway with the given configuration,
// policy, and audit log.
func NewMCPGateway(cfg GatewayConfig, policy *MCPPolicy, audit *MCPAuditLog, logger *slog.Logger) *MCPGateway {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultGatewayConfig().MaxBodyBytes
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultGatewayConfig().RequestTimeout
	}

	approved := make(map[string]bool)
	if policy != nil {
		for _, s := range policy.ServerRules.Allow {
			approved[NormalizeServerID(s)] = true
		}
	}

	return &MCPGateway{
		cfg:    cfg,
		policy: policy,
		audit:  audit,
		logger: logger,
		httpClient: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
		knownServers:    make(map[string]*ShadowServerEntry),
		approvedServers: approved,
	}
}

// ServeHTTP implements http.Handler. It intercepts MCP JSON-RPC requests,
// applies policies, logs decisions, and either blocks or forwards the request.
func (g *MCPGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Extract user identity from headers (set by upstream auth middleware).
	user := r.Header.Get("X-MCP-User")
	if user == "" {
		user = r.Header.Get("X-Forwarded-User")
	}
	if user == "" {
		user = "anonymous"
	}

	server := r.Header.Get("X-MCP-Server")

	// Read body.
	body, err := io.ReadAll(io.LimitReader(r.Body, g.cfg.MaxBodyBytes))
	if err != nil {
		g.writeError(w, nil, ErrCodeParse, "failed to read request body")
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		g.writeError(w, nil, ErrCodeInvalidRequest, "empty request body")
		return
	}

	// Parse the MCP message.
	msg, err := ParseMCPMessage(body)
	if err != nil {
		g.logger.Warn("failed to parse MCP message",
			"error", err,
			"user", user,
			"server", server,
		)
		g.writeError(w, nil, ErrCodeParse, err.Error())
		return
	}

	g.logger.Debug("MCP request received",
		"method", msg.Raw.Method,
		"user", user,
		"server", server,
		"notification", msg.IsNotification,
	)

	// Apply policy decisions based on method type.
	switch msg.Raw.Method {
	case MethodInitialize:
		g.handleInitialize(w, r, msg, user, server, body, start)
	case MethodToolsCall:
		g.handleToolCall(w, r, msg, user, server, body, start)
	default:
		// For listing, ping, and other read-only methods, check server
		// allowance and then forward.
		if server != "" && g.policy != nil && !g.policy.IsServerAllowed(server) {
			g.audit.LogServerConnection(user, server, AuditDeny, "server blocked by policy")
			g.writeError(w, msg.Raw.ID, ErrCodeServerBlocked,
				fmt.Sprintf("MCP server %q is not permitted", server))
			return
		}
		g.forwardToUpstream(w, r, body, start)
	}
}

// handleInitialize processes MCP initialize handshakes. It checks server
// approval and detects shadow MCP servers.
func (g *MCPGateway) handleInitialize(w http.ResponseWriter, r *http.Request, msg *ParsedMessage, user, server string, body []byte, start time.Time) {
	// Detect shadow servers.
	if g.cfg.EnableShadowDetection && server != "" {
		g.recordServerSighting(server, msg)
	}

	// Check server policy.
	if server != "" && g.policy != nil && !g.policy.IsServerAllowed(server) {
		g.audit.LogServerConnection(user, server, AuditDeny, "server blocked by policy")
		g.writeError(w, msg.Raw.ID, ErrCodeServerBlocked,
			fmt.Sprintf("MCP server %q is not permitted", server))
		return
	}

	// Check approval requirement.
	if g.policy != nil {
		if req := g.policy.RequiresApproval(MethodInitialize); req == ApprovalRequired {
			g.audit.LogServerConnection(user, server, AuditPending, "requires human approval")
			g.writeError(w, msg.Raw.ID, ErrCodeApprovalNeeded,
				"server connection requires human approval")
			return
		}
	}

	g.audit.LogServerConnection(user, server, AuditAllow, "permitted")
	g.forwardToUpstream(w, r, body, start)
}

// handleToolCall processes MCP tools/call requests. It enforces tool-level
// policies and logs the decision.
func (g *MCPGateway) handleToolCall(w http.ResponseWriter, r *http.Request, msg *ParsedMessage, user, server string, body []byte, start time.Time) {
	if msg.ToolCall == nil {
		g.writeError(w, msg.Raw.ID, ErrCodeInvalidParams, "missing tool call parameters")
		return
	}

	toolName := msg.ToolCall.Name

	// Check server-level access first.
	if server != "" && g.policy != nil && !g.policy.IsServerAllowed(server) {
		latency := time.Since(start).Milliseconds()
		g.audit.LogToolCall(user, server, toolName, msg.ToolCall.Arguments, "", AuditDeny, "server blocked", latency)
		g.writeError(w, msg.Raw.ID, ErrCodeServerBlocked,
			fmt.Sprintf("MCP server %q is not permitted", server))
		return
	}

	// Check tool-level policy.
	if g.policy != nil && !g.policy.IsToolAllowed(user, server, toolName) {
		latency := time.Since(start).Milliseconds()
		g.audit.LogToolCall(user, server, toolName, msg.ToolCall.Arguments, "", AuditDeny, "tool blocked by policy", latency)
		g.writeError(w, msg.Raw.ID, ErrCodePolicyDenied,
			fmt.Sprintf("tool %q is not permitted for user %q on server %q", toolName, user, server))
		return
	}

	// Check approval requirement for tools/call.
	if g.policy != nil {
		if req := g.policy.RequiresApproval(MethodToolsCall); req == ApprovalRequired {
			latency := time.Since(start).Milliseconds()
			g.audit.LogToolCall(user, server, toolName, msg.ToolCall.Arguments, "", AuditPending, "requires human approval", latency)
			g.writeError(w, msg.Raw.ID, ErrCodeApprovalNeeded,
				"tool call requires human approval")
			return
		}
	}

	// Forward permitted request to upstream.
	respBody, err := g.doForward(r, body)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		g.audit.LogToolCall(user, server, toolName, msg.ToolCall.Arguments, "", AuditAllow, "forwarded (upstream error)", latency)
		g.writeError(w, msg.Raw.ID, ErrCodeInternal, "upstream error: "+err.Error())
		return
	}

	// Log successful forward with response.
	resultStr := truncate(string(respBody), 4096)
	g.audit.LogToolCall(user, server, toolName, msg.ToolCall.Arguments, resultStr, AuditAllow, "permitted", latency)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

// forwardToUpstream forwards the raw request body to the upstream MCP server
// and writes the response back to the client.
func (g *MCPGateway) forwardToUpstream(w http.ResponseWriter, r *http.Request, body []byte, start time.Time) {
	respBody, err := g.doForward(r, body)
	if err != nil {
		g.logger.Error("upstream forward failed",
			"error", err,
			"latency_ms", time.Since(start).Milliseconds(),
		)
		g.writeError(w, nil, ErrCodeInternal, "upstream error: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

// doForward sends the request body to the upstream MCP server and returns
// the response body.
func (g *MCPGateway) doForward(r *http.Request, body []byte) ([]byte, error) {
	if g.cfg.UpstreamURL == "" {
		return nil, fmt.Errorf("no upstream URL configured")
	}

	ctx, cancel := context.WithTimeout(r.Context(), g.cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.UpstreamURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Forward relevant headers.
	for _, hdr := range []string{"Authorization", "X-MCP-User", "X-MCP-Server", "X-Request-ID"} {
		if v := r.Header.Get(hdr); v != "" {
			req.Header.Set(hdr, v)
		}
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, g.cfg.MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read upstream response: %w", err)
	}

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, truncate(string(respBody), 256))
	}

	return respBody, nil
}

// writeError sends a JSON-RPC 2.0 error response.
func (g *MCPGateway) writeError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	resp := NewErrorResponse(id, code, message)
	data, err := json.Marshal(resp)
	if err != nil {
		g.logger.Error("failed to marshal error response", "error", err)
		http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"}}`, http.StatusInternalServerError)
		return
	}

	status := http.StatusOK
	switch code {
	case ErrCodePolicyDenied, ErrCodeServerBlocked:
		status = http.StatusForbidden
	case ErrCodeApprovalNeeded:
		status = http.StatusConflict
	case ErrCodeParse, ErrCodeInvalidRequest, ErrCodeInvalidParams:
		status = http.StatusBadRequest
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

// recordServerSighting records an MCP server observed during an initialize
// handshake. Unknown servers are flagged as potential shadow servers.
func (g *MCPGateway) recordServerSighting(server string, msg *ParsedMessage) {
	serverNorm := NormalizeServerID(server)
	now := time.Now().UTC()

	clientInfo := ""
	if msg.Initialize != nil {
		clientInfo = msg.Initialize.ClientInfo.Name
		if msg.Initialize.ClientInfo.Version != "" {
			clientInfo += "/" + msg.Initialize.ClientInfo.Version
		}
	}

	g.shadowMu.Lock()
	defer g.shadowMu.Unlock()

	entry, exists := g.knownServers[serverNorm]
	if !exists {
		entry = &ShadowServerEntry{
			ServerID:   serverNorm,
			ClientInfo: clientInfo,
			FirstSeen:  now,
		}
		g.knownServers[serverNorm] = entry
	}

	entry.LastSeen = now
	entry.RequestCount++
	if clientInfo != "" {
		entry.ClientInfo = clientInfo
	}

	// Check if this is a shadow server.
	if !g.approvedServers[serverNorm] {
		g.logger.Warn("potential shadow MCP server detected",
			"server", server,
			"client_info", clientInfo,
			"request_count", entry.RequestCount,
		)
	}
}

// ShadowServers returns all MCP servers that are not in the approved list.
func (g *MCPGateway) ShadowServers() []ShadowServerEntry {
	g.shadowMu.RLock()
	defer g.shadowMu.RUnlock()

	var shadows []ShadowServerEntry
	for id, entry := range g.knownServers {
		if !g.approvedServers[id] {
			shadows = append(shadows, *entry)
		}
	}
	return shadows
}

// KnownServers returns all MCP servers observed through the gateway.
func (g *MCPGateway) KnownServers() []ShadowServerEntry {
	g.shadowMu.RLock()
	defer g.shadowMu.RUnlock()

	entries := make([]ShadowServerEntry, 0, len(g.knownServers))
	for _, entry := range g.knownServers {
		entries = append(entries, *entry)
	}
	return entries
}

// HealthCheck returns nil if the gateway is operational. It verifies upstream
// connectivity when an upstream URL is configured.
func (g *MCPGateway) HealthCheck(ctx context.Context) error {
	if g.cfg.UpstreamURL == "" {
		return nil // no upstream configured, running in intercept-only mode
	}

	healthURL := strings.TrimRight(g.cfg.UpstreamURL, "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("create health check request: %w", err)
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upstream unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("upstream unhealthy: status %d", resp.StatusCode)
	}

	return nil
}

// Stats returns operational statistics for the gateway.
type GatewayStats struct {
	AuditEntries   int `json:"audit_entries"`
	KnownServers   int `json:"known_servers"`
	ShadowServers  int `json:"shadow_servers"`
	PolicyRules    int `json:"policy_rules"`
}

// Stats returns current gateway statistics.
func (g *MCPGateway) Stats() GatewayStats {
	g.shadowMu.RLock()
	shadowCount := 0
	for id := range g.knownServers {
		if !g.approvedServers[id] {
			shadowCount++
		}
	}
	serverCount := len(g.knownServers)
	g.shadowMu.RUnlock()

	policyRules := 0
	if g.policy != nil {
		g.policy.mu.RLock()
		policyRules = len(g.policy.ToolRules)
		g.policy.mu.RUnlock()
	}

	return GatewayStats{
		AuditEntries:  g.audit.Len(),
		KnownServers:  serverCount,
		ShadowServers: shadowCount,
		PolicyRules:   policyRules,
	}
}
