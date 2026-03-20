// Package mcp provides an MCP (Model Context Protocol) security gateway that
// intercepts JSON-RPC 2.0 traffic between AI agents and MCP servers, enforcing
// tool-use policies, audit logging, and shadow server detection.
package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JSON-RPC 2.0 version constant.
const jsonRPCVersion = "2.0"

// Well-known MCP method names.
const (
	MethodToolsCall     = "tools/call"
	MethodToolsList     = "tools/list"
	MethodResourcesRead = "resources/read"
	MethodResourcesList = "resources/list"
	MethodPromptsList   = "prompts/list"
	MethodPromptsGet    = "prompts/get"
	MethodInitialize    = "initialize"
	MethodPing          = "ping"
)

// MCPRequest represents a JSON-RPC 2.0 request from an MCP client.
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// MCPResponse represents a JSON-RPC 2.0 response to an MCP client.
type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
}

// MCPError represents a JSON-RPC 2.0 error object.
type MCPError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	ErrCodeParse          = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603

	// Application-level error codes for policy enforcement.
	ErrCodePolicyDenied   = -32000
	ErrCodeServerBlocked  = -32001
	ErrCodeApprovalNeeded = -32002
)

func (e *MCPError) Error() string {
	return fmt.Sprintf("MCP error %d: %s", e.Code, e.Message)
}

// ToolCallParams holds the parsed parameters from a tools/call request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ResourceReadParams holds the parsed parameters from a resources/read request.
type ResourceReadParams struct {
	URI string `json:"uri"`
}

// PromptsGetParams holds the parsed parameters from a prompts/get request.
type PromptsGetParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// InitializeParams holds the parsed parameters from an initialize request.
type InitializeParams struct {
	ProtocolVersion string     `json:"protocolVersion"`
	Capabilities    Capability `json:"capabilities,omitempty"`
	ClientInfo      ClientInfo `json:"clientInfo,omitempty"`
}

// Capability describes protocol capabilities advertised by the client or server.
type Capability struct {
	Tools     *ToolCapability     `json:"tools,omitempty"`
	Resources *ResourceCapability `json:"resources,omitempty"`
	Prompts   *PromptCapability   `json:"prompts,omitempty"`
}

// ToolCapability describes tool-related capabilities.
type ToolCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourceCapability describes resource-related capabilities.
type ResourceCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptCapability describes prompt-related capabilities.
type PromptCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ClientInfo identifies the MCP client.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ParsedMessage is the result of parsing raw MCP traffic. It provides typed
// access to the request details regardless of the JSON-RPC method.
type ParsedMessage struct {
	// Raw is the original parsed request.
	Raw MCPRequest

	// IsNotification is true when the request has no ID (fire-and-forget).
	IsNotification bool

	// ToolCall is populated when the method is tools/call.
	ToolCall *ToolCallParams

	// ResourceRead is populated when the method is resources/read.
	ResourceRead *ResourceReadParams

	// PromptsGet is populated when the method is prompts/get.
	PromptsGet *PromptsGetParams

	// Initialize is populated when the method is initialize.
	Initialize *InitializeParams
}

// ParseMCPMessage parses a raw JSON body into a structured ParsedMessage.
// It validates the JSON-RPC envelope and extracts method-specific parameters.
func ParseMCPMessage(body []byte) (*ParsedMessage, error) {
	var req MCPRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if req.JSONRPC != jsonRPCVersion {
		return nil, fmt.Errorf("unsupported jsonrpc version %q, expected %q", req.JSONRPC, jsonRPCVersion)
	}
	if req.Method == "" {
		return nil, fmt.Errorf("missing method field")
	}

	pm := &ParsedMessage{
		Raw:            req,
		IsNotification: len(req.ID) == 0 || string(req.ID) == "null",
	}

	// Parse method-specific parameters.
	switch req.Method {
	case MethodToolsCall:
		var params ToolCallParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return nil, fmt.Errorf("invalid tools/call params: %w", err)
			}
		}
		if params.Name == "" {
			return nil, fmt.Errorf("tools/call: missing tool name")
		}
		pm.ToolCall = &params

	case MethodResourcesRead:
		var params ResourceReadParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return nil, fmt.Errorf("invalid resources/read params: %w", err)
			}
		}
		if params.URI == "" {
			return nil, fmt.Errorf("resources/read: missing uri")
		}
		pm.ResourceRead = &params

	case MethodPromptsGet:
		var params PromptsGetParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return nil, fmt.Errorf("invalid prompts/get params: %w", err)
			}
		}
		if params.Name == "" {
			return nil, fmt.Errorf("prompts/get: missing prompt name")
		}
		pm.PromptsGet = &params

	case MethodInitialize:
		var params InitializeParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return nil, fmt.Errorf("invalid initialize params: %w", err)
			}
		}
		pm.Initialize = &params
	}

	return pm, nil
}

// NewErrorResponse creates a JSON-RPC 2.0 error response.
func NewErrorResponse(id json.RawMessage, code int, message string) *MCPResponse {
	return &MCPResponse{
		JSONRPC: jsonRPCVersion,
		ID:      id,
		Error: &MCPError{
			Code:    code,
			Message: message,
		},
	}
}

// NewResultResponse creates a JSON-RPC 2.0 success response.
func NewResultResponse(id json.RawMessage, result any) (*MCPResponse, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	return &MCPResponse{
		JSONRPC: jsonRPCVersion,
		ID:      id,
		Result:  data,
	}, nil
}

// IsMCPMethod returns true if the method string is a recognized MCP method.
func IsMCPMethod(method string) bool {
	switch method {
	case MethodToolsCall, MethodToolsList, MethodResourcesRead,
		MethodResourcesList, MethodPromptsList, MethodPromptsGet,
		MethodInitialize, MethodPing:
		return true
	default:
		return false
	}
}

// IsWriteMethod returns true if the method could modify state (tools/call).
func IsWriteMethod(method string) bool {
	return method == MethodToolsCall
}

// NormalizeServerID normalizes an MCP server identifier to a canonical form
// by lowercasing and trimming whitespace. This prevents policy bypasses via
// casing differences.
func NormalizeServerID(server string) string {
	return strings.TrimSpace(strings.ToLower(server))
}
