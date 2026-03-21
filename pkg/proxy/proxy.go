package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/internal/logger"
	"github.com/kill-ai-leak/kill-ai-leak/internal/middleware"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/anonymizer"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/config"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// GuardrailEngine is the interface the proxy uses to evaluate requests and
// responses through the guardrail pipeline.
type GuardrailEngine interface {
	EvaluateInput(ctx context.Context, evalCtx *guardrails.EvalContext) (*models.PipelineResult, error)
	EvaluateOutput(ctx context.Context, evalCtx *guardrails.EvalContext) (*models.PipelineResult, error)
}

// wellKnownProviders maps canonical provider names to their upstream base URLs.
var wellKnownProviders = map[string]string{
	"openai":    "https://api.openai.com",
	"anthropic": "https://api.anthropic.com",
	"google":    "https://generativelanguage.googleapis.com",
	"cohere":    "https://api.cohere.ai",
	"mistral":   "https://api.mistral.ai",
	"azure":     "https://openai.azure.com",
}

// LLMProxy is the core reverse proxy that sits between callers and upstream
// LLM providers. It intercepts requests and responses, runs guardrail
// evaluations, and enforces security policy.
type LLMProxy struct {
	config     *config.AppConfig
	engine     GuardrailEngine
	log        *logger.Logger
	targets    map[string]*url.URL
	transports map[string]*http.Transport
	anonymizer *anonymizer.Anonymizer

	mu sync.RWMutex
}

// NewLLMProxy constructs an LLMProxy from configuration and a guardrail engine.
func NewLLMProxy(cfg *config.AppConfig, engine GuardrailEngine, log *logger.Logger) (*LLMProxy, error) {
	p := &LLMProxy{
		config:     cfg,
		engine:     engine,
		log:        log,
		targets:    make(map[string]*url.URL),
		transports: make(map[string]*http.Transport),
		anonymizer: anonymizer.New(),
	}

	// Build the target map from configuration + well-known defaults.
	providers := make(map[string]string, len(wellKnownProviders))
	for k, v := range wellKnownProviders {
		providers[k] = v
	}
	for _, entry := range cfg.Providers.Entries {
		providers[entry.Name] = entry.BaseURL
	}
	for name, override := range cfg.Proxy.ProviderOverrides {
		providers[name] = override
	}

	for name, rawURL := range providers {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid upstream URL for %s: %w", name, err)
		}
		p.targets[name] = u
		p.transports[name] = &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		}
	}

	return p, nil
}

// ServeHTTP implements http.Handler. It is the main request flow:
//  1. Extract APP-ID and provider
//  2. Read + parse request body to extract prompt
//  3. Run input guardrails
//  4. Forward to upstream if allowed
//  5. Run output guardrails on the response
//  6. Return (possibly modified) response to the caller
func (p *LLMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// --- 1. Extract service identity and provider ---
	actor := middleware.ActorFromContext(ctx)
	if actor == nil {
		actor = &models.Actor{Type: models.ActorServiceAccount, ID: "unknown"}
	}

	provider := extractProvider(r)
	if provider == "" {
		p.log.Warn(ctx, "no provider specified in request")
		respondJSON(w, http.StatusBadRequest, errorResponse{
			Error:   "missing_provider",
			Message: "Specify the target provider via X-LLM-Provider header or URL path",
		})
		return
	}

	target := p.resolveTarget(provider)
	if target == nil {
		p.log.Warn(ctx, "unknown provider", map[string]any{"provider": provider})
		respondJSON(w, http.StatusBadRequest, errorResponse{
			Error:   "unknown_provider",
			Message: fmt.Sprintf("Provider %q is not configured", provider),
		})
		return
	}

	// --- 2. Read the request body ---
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, int64(p.config.Server.MaxRequestBodyMB)*1024*1024))
	if err != nil {
		p.log.Error(ctx, "failed to read request body", map[string]any{"error": err.Error()})
		respondJSON(w, http.StatusBadRequest, errorResponse{
			Error:   "read_body_failed",
			Message: "Could not read request body",
		})
		return
	}
	defer r.Body.Close()

	promptText := extractPrompt(bodyBytes, provider)

	// --- 3. Build EvalContext and run input guardrails ---
	evalCtx := guardrails.NewEvalContext(ctx).
		WithPrompt(promptText).
		WithActor(actor).
		WithProvider(provider)

	// Copy select headers into the eval context.
	headers := make(map[string]string, 4)
	for _, h := range []string{"Content-Type", "X-APP-ID", "X-Request-ID", "X-Session-ID"} {
		if v := r.Header.Get(h); v != "" {
			headers[h] = v
		}
	}
	evalCtx.WithHeaders(headers)

	if sid := r.Header.Get("X-Session-ID"); sid != "" {
		evalCtx.WithSessionID(sid)
	}

	var inputResult *models.PipelineResult
	if p.engine != nil && p.config.Guardrails.Enabled {
		inputResult, err = p.engine.EvaluateInput(ctx, evalCtx)
		if err != nil {
			p.log.Error(ctx, "input guardrail evaluation failed", map[string]any{"error": err.Error()})
			respondJSON(w, http.StatusInternalServerError, errorResponse{
				Error:   "guardrail_error",
				Message: "Failed to evaluate input guardrails",
			})
			return
		}

		// --- 4. Blocked → 403 ---
		if inputResult.Blocked {
			p.log.Warn(ctx, "request blocked by input guardrail", map[string]any{
				"blocked_by": inputResult.BlockedBy,
				"decision":   string(inputResult.FinalDecision),
				"app_id":     actor.ID,
			})
			respondJSON(w, http.StatusForbidden, blockedResponse{
				Error:     "request_blocked",
				Message:   "Your request was blocked by security policy",
				BlockedBy: inputResult.BlockedBy,
				Decision:  string(inputResult.FinalDecision),
				Details:   formatEvaluationDetails(inputResult),
			})
			return
		}

		// --- 5. Anonymized → replace body ---
		if inputResult.FinalDecision == models.DecisionAnonymize && inputResult.ModifiedInput != "" {
			bodyBytes = replacePromptInBody(bodyBytes, provider, inputResult.ModifiedInput)
		}

		// --- 5b. PII anonymization via the anonymizer ---
		// If the decision is Anonymize and there are PII findings, run them
		// through the session-scoped anonymizer for deterministic replacement.
		if inputResult.FinalDecision == models.DecisionAnonymize {
			piiFindings := extractPIIFindings(inputResult)
			if len(piiFindings) > 0 {
				sessionID := evalCtx.SessionID
				if sessionID == "" {
					sessionID = actor.ID // fall back to actor ID
				}
				anonFindings := convertToAnonymizerFindings(piiFindings)
				anonText, _ := p.anonymizer.Anonymize(sessionID, promptText, anonFindings)
				bodyBytes = replacePromptInBody(bodyBytes, provider, anonText)
				// Mark that we anonymized so we can deanonymize the response.
				evalCtx.SetMetadata("_anonymizer_session", sessionID)
			}
		}
	}

	// --- 6. Forward to upstream ---
	upstreamReq, err := p.buildUpstreamRequest(ctx, r, target, provider, bodyBytes)
	if err != nil {
		p.log.Error(ctx, "failed to build upstream request", map[string]any{"error": err.Error()})
		respondJSON(w, http.StatusInternalServerError, errorResponse{
			Error:   "proxy_error",
			Message: "Failed to construct upstream request",
		})
		return
	}

	transport := p.transports[provider]
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport)
	}

	resp, err := transport.RoundTrip(upstreamReq)
	if err != nil {
		p.log.Error(ctx, "upstream request failed", map[string]any{
			"error":    err.Error(),
			"provider": provider,
			"target":   target.String(),
		})
		respondJSON(w, http.StatusBadGateway, errorResponse{
			Error:   "upstream_error",
			Message: fmt.Sprintf("Upstream provider %q returned an error", provider),
		})
		return
	}
	defer resp.Body.Close()

	// --- 7. Read upstream response body ---
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.log.Error(ctx, "failed to read upstream response", map[string]any{"error": err.Error()})
		respondJSON(w, http.StatusBadGateway, errorResponse{
			Error:   "upstream_read_error",
			Message: "Failed to read upstream response body",
		})
		return
	}

	// --- 8. Run output guardrails ---
	if p.engine != nil && p.config.Guardrails.Enabled {
		responseText := extractResponseText(respBody, provider)
		evalCtx.WithResponse(responseText)

		outputResult, outErr := p.engine.EvaluateOutput(ctx, evalCtx)
		if outErr != nil {
			p.log.Error(ctx, "output guardrail evaluation failed", map[string]any{"error": outErr.Error()})
			// Return a safe fallback rather than leaking potentially dangerous content.
			respondJSON(w, http.StatusOK, safeFallbackResponse(provider))
			return
		}

		if outputResult.Blocked {
			p.log.Warn(ctx, "response blocked by output guardrail", map[string]any{
				"blocked_by": outputResult.BlockedBy,
				"decision":   string(outputResult.FinalDecision),
				"app_id":     actor.ID,
			})
			respondJSON(w, http.StatusOK, safeFallbackResponse(provider))
			return
		}

		// If the output was modified (e.g., de-anonymized), use the modified version.
		if outputResult.ModifiedOutput != "" {
			respBody = replaceResponseInBody(respBody, provider, outputResult.ModifiedOutput)
		}
	}

	// --- 8b. Deanonymize response if PII anonymization was applied ---
	if anonSessRaw, ok := evalCtx.GetMetadata("_anonymizer_session"); ok {
		if anonSessID, ok := anonSessRaw.(string); ok && anonSessID != "" {
			responseText := extractResponseText(respBody, provider)
			deanonText := p.anonymizer.Deanonymize(anonSessID, responseText)
			if deanonText != responseText {
				respBody = replaceResponseInBody(respBody, provider, deanonText)
			}
		}
	}

	// --- 9. Return response to caller ---
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// resolveTarget returns the parsed URL for a provider, or nil.
func (p *LLMProxy) resolveTarget(provider string) *url.URL {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.targets[provider]
}

// buildUpstreamRequest creates the HTTP request to send to the LLM provider.
func (p *LLMProxy) buildUpstreamRequest(ctx context.Context, orig *http.Request, target *url.URL, provider string, body []byte) (*http.Request, error) {
	upstreamURL := *target
	upstreamURL.Path = singleJoiningSlash(target.Path, orig.URL.Path)
	upstreamURL.RawQuery = orig.URL.RawQuery

	req, err := http.NewRequestWithContext(ctx, orig.Method, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	// Copy original headers, stripping internal ones.
	for key, vals := range orig.Header {
		if isInternalHeader(key) {
			continue
		}
		for _, v := range vals {
			req.Header.Add(key, v)
		}
	}

	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	req.Host = target.Host

	return req, nil
}

// ---- Request Parsing ----

// openAIRequest is a minimal representation of an OpenAI chat completion request.
type openAIRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"`
	} `json:"messages"`
}

// anthropicRequest is a minimal representation of an Anthropic messages request.
type anthropicRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"`
	} `json:"messages"`
	System string `json:"system,omitempty"`
}

// extractPrompt pulls the user-facing text out of the request body.
func extractPrompt(body []byte, provider string) string {
	switch provider {
	case "anthropic":
		return extractAnthropicPrompt(body)
	default:
		// OpenAI-compatible format is the most common; used by openai, azure, mistral, etc.
		return extractOpenAIPrompt(body)
	}
}

func extractOpenAIPrompt(body []byte) string {
	var req openAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return string(body)
	}

	var parts []string
	for _, msg := range req.Messages {
		text := contentToString(msg.Content)
		if text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n")
}

func extractAnthropicPrompt(body []byte) string {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return string(body)
	}

	var parts []string
	if req.System != "" {
		parts = append(parts, req.System)
	}
	for _, msg := range req.Messages {
		text := contentToString(msg.Content)
		if text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n")
}

// contentToString normalises the Content field which can be either a plain
// string or an array of content blocks.
func contentToString(c any) string {
	switch v := c.(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					parts = append(parts, t)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		if b, err := json.Marshal(c); err == nil {
			return string(b)
		}
		return ""
	}
}

// ---- Response Parsing ----

func extractResponseText(body []byte, provider string) string {
	switch provider {
	case "anthropic":
		return extractAnthropicResponse(body)
	default:
		return extractOpenAIResponse(body)
	}
}

func extractOpenAIResponse(body []byte) string {
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Choices) == 0 {
		return string(body)
	}
	return resp.Choices[0].Message.Content
}

func extractAnthropicResponse(body []byte) string {
	var resp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Content) == 0 {
		return string(body)
	}

	var parts []string
	for _, block := range resp.Content {
		if block.Type == "text" {
			parts = append(parts, block.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// ---- Body Replacement ----

// replacePromptInBody swaps the prompt text in the serialised request body
// with the anonymised version.
func replacePromptInBody(body []byte, provider string, newPrompt string) []byte {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}

	messages, ok := raw["messages"].([]any)
	if !ok {
		return body
	}

	// Replace the content of the last user message.
	for i := len(messages) - 1; i >= 0; i-- {
		msg, ok := messages[i].(map[string]any)
		if !ok {
			continue
		}
		if role, _ := msg["role"].(string); role == "user" {
			msg["content"] = newPrompt
			break
		}
	}

	// For Anthropic, also replace the system field if present and the new prompt
	// covers it.
	if provider == "anthropic" {
		if _, hasSys := raw["system"]; hasSys {
			// Keep system as-is; the engine only anonymised user messages.
		}
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

// replaceResponseInBody swaps the assistant text in the serialised response
// body with the modified version.
func replaceResponseInBody(body []byte, provider string, newText string) []byte {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}

	switch provider {
	case "anthropic":
		content, ok := raw["content"].([]any)
		if ok && len(content) > 0 {
			if block, ok := content[0].(map[string]any); ok {
				block["text"] = newText
			}
		}
	default:
		choices, ok := raw["choices"].([]any)
		if ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]any); ok {
				if msg, ok := choice["message"].(map[string]any); ok {
					msg["content"] = newText
				}
			}
		}
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

// ---- Safe Fallback ----

// safeFallbackResponse returns a provider-appropriate "content filtered"
// response so the caller gets a well-formed response even when output is
// blocked.
func safeFallbackResponse(provider string) any {
	msg := "I'm unable to provide a response to this request due to content security policy."
	switch provider {
	case "anthropic":
		return map[string]any{
			"id":    "msg_filtered",
			"type":  "message",
			"role":  "assistant",
			"model": "filtered",
			"content": []map[string]any{
				{"type": "text", "text": msg},
			},
			"stop_reason": "end_turn",
		}
	default:
		return map[string]any{
			"id":      "chatcmpl-filtered",
			"object":  "chat.completion",
			"model":   "filtered",
			"choices": []map[string]any{
				{
					"index":         0,
					"message":       map[string]string{"role": "assistant", "content": msg},
					"finish_reason": "stop",
				},
			},
		}
	}
}

// ---- Utility Helpers ----

// extractProvider determines the target LLM provider from the request.
// It checks the X-LLM-Provider header first, then falls back to the first
// path segment (e.g., /openai/v1/chat/completions).
func extractProvider(r *http.Request) string {
	if p := r.Header.Get("X-LLM-Provider"); p != "" {
		return strings.ToLower(strings.TrimSpace(p))
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/protect/")
	path = strings.TrimPrefix(path, "/")
	if idx := strings.Index(path, "/"); idx > 0 {
		return strings.ToLower(path[:idx])
	}
	if path != "" {
		return strings.ToLower(path)
	}
	return ""
}

func isInternalHeader(key string) bool {
	k := strings.ToLower(key)
	return k == "x-app-id" || k == "x-llm-provider" || k == "x-session-id"
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// formatEvaluationDetails converts pipeline evaluations into a slice of
// human-readable strings for the blocked response.
func formatEvaluationDetails(result *models.PipelineResult) []string {
	var details []string
	for _, eval := range result.Evaluations {
		if eval.Decision == models.DecisionBlock {
			detail := fmt.Sprintf("[%s] %s: %s", eval.Stage, eval.RuleName, eval.Reason)
			details = append(details, detail)
		}
	}
	return details
}

// ---- Response Types ----

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type blockedResponse struct {
	Error     string   `json:"error"`
	Message   string   `json:"message"`
	BlockedBy string   `json:"blocked_by,omitempty"`
	Decision  string   `json:"decision"`
	Details   []string `json:"details,omitempty"`
}

func respondJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ReverseProxy returns a standard library httputil.ReverseProxy configured
// for the given provider. This is an alternative to the full ServeHTTP flow
// when guardrails are not needed (e.g., health check proxying).
func (p *LLMProxy) ReverseProxy(provider string) (*httputil.ReverseProxy, error) {
	target := p.resolveTarget(provider)
	if target == nil {
		return nil, fmt.Errorf("proxy: unknown provider %q", provider)
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
			req.Host = target.Host
		},
		Transport: p.transports[provider],
	}
	return rp, nil
}

// ---- PII Anonymization Helpers ----

// extractPIIFindings collects PII-related findings from the pipeline result.
func extractPIIFindings(result *models.PipelineResult) []models.Finding {
	var out []models.Finding
	for _, eval := range result.Evaluations {
		for _, f := range eval.Findings {
			if isPIIType(f.Type) {
				out = append(out, f)
			}
		}
	}
	return out
}

// isPIIType returns true if the finding type corresponds to a known PII type.
func isPIIType(t string) bool {
	switch models.PIIType(t) {
	case models.PIIEmail, models.PIIPhone, models.PIISSN, models.PIICreditCard,
		models.PIIName, models.PIIAddress, models.PIIDOB, models.PIIPassport,
		models.PIIMedicalID, models.PIIBankAccount, models.PIIDriverLicense,
		models.PIIIPAddress, models.PIIEmployeeID:
		return true
	}
	return false
}

// convertToAnonymizerFindings converts models.Finding slices to the format
// expected by the anonymizer package.
func convertToAnonymizerFindings(findings []models.Finding) []anonymizer.Finding {
	out := make([]anonymizer.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, anonymizer.Finding{
			Type:     models.PIIType(f.Type),
			Value:    f.Value,
			StartPos: f.StartPos,
			EndPos:   f.EndPos,
		})
	}
	return out
}
