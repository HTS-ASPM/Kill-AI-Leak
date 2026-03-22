package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/internal/health"
	"github.com/kill-ai-leak/kill-ai-leak/internal/logger"
	"github.com/kill-ai-leak/kill-ai-leak/internal/middleware"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/config"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Handler bundles HTTP handlers for the inline gateway and wires them into a
// single http.ServeMux.
type Handler struct {
	proxy      *LLMProxy
	health     *health.Checker
	log        *logger.Logger
	cfg        *config.AppConfig
	apiHandler *APIHandler

	// Prometheus-style counters (simple atomic counters; a real deployment
	// would use the prometheus client library).
	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	errorCount      atomic.Int64
	upstreamLatency atomic.Int64 // cumulative milliseconds
}

// SetAPIHandler attaches the data API handler so it can be registered.
func (h *Handler) SetAPIHandler(api *APIHandler) {
	h.apiHandler = api
}

// NewHandler constructs the Handler and returns a ready-to-use http.ServeMux.
func NewHandler(proxy *LLMProxy, hc *health.Checker, log *logger.Logger, cfg *config.AppConfig) *Handler {
	return &Handler{
		proxy:  proxy,
		health: hc,
		log:    log,
		cfg:    cfg,
	}
}

// Register mounts all routes onto the provided mux.
func (h *Handler) Register(mux *http.ServeMux) {
	// Data API endpoints for the dashboard (must be registered before the
	// catch-all /api/protect/ route so that /api/v1/* paths match first).
	if h.apiHandler != nil {
		h.apiHandler.Register(mux)
	}

	// Main proxy endpoint -- requests like POST /api/protect/openai/v1/chat/completions.
	mux.Handle("/api/protect/", h.protectHandler())

	// Dry-run evaluation endpoint -- runs the full guardrail pipeline
	// without forwarding to upstream. Returns the PipelineResult as JSON.
	mux.Handle("/api/evaluate", h.evaluateHandler())

	// Health probes.
	mux.HandleFunc("/healthz", h.health.LivenessHandler())
	mux.HandleFunc("/readyz", h.health.ReadinessHandler())
	mux.HandleFunc("/health", h.health.DetailedHandler())

	// Metrics.
	mux.HandleFunc("/metrics", h.metricsHandler())
}

// protectHandler wraps the core proxy with per-request instrumentation.
func (h *Handler) protectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.totalRequests.Add(1)
		start := time.Now()

		sw := &statusCapture{ResponseWriter: w, status: http.StatusOK}
		h.proxy.ServeHTTP(sw, r)

		elapsed := time.Since(start).Milliseconds()
		h.upstreamLatency.Add(elapsed)

		if sw.status == http.StatusForbidden {
			h.blockedRequests.Add(1)
		}
		if sw.status >= 500 {
			h.errorCount.Add(1)
		}

		h.log.Info(r.Context(), "protect request handled", map[string]any{
			"status":      sw.status,
			"duration_ms": elapsed,
			"provider":    extractProvider(r),
		})
	})
}

// evaluateHandler runs the full guardrail pipeline (input + output stages)
// on the request body without forwarding to the upstream provider. This is
// useful for dry-run testing of prompts.
func (h *Handler) evaluateHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondJSON(w, http.StatusMethodNotAllowed, errorResponse{
				Error:   "method_not_allowed",
				Message: "Only POST is accepted",
			})
			return
		}

		ctx := r.Context()

		// Extract actor.
		actor := middleware.ActorFromContext(ctx)
		if actor == nil {
			actor = &models.Actor{Type: models.ActorServiceAccount, ID: "unknown"}
		}

		provider := extractProvider(r)
		if provider == "" {
			// For evaluate, provider may be passed as a query param or header.
			provider = r.URL.Query().Get("provider")
		}
		if provider == "" {
			provider = "openai" // default for dry-run
		}

		// Read body.
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, int64(h.cfg.Server.MaxRequestBodyMB)*1024*1024))
		if err != nil {
			respondJSON(w, http.StatusBadRequest, errorResponse{
				Error:   "read_body_failed",
				Message: "Could not read request body",
			})
			return
		}
		defer r.Body.Close()

		promptText := extractPrompt(bodyBytes, provider)

		// Build EvalContext.
		evalCtx := guardrails.NewEvalContext(ctx).
			WithPrompt(promptText).
			WithActor(actor).
			WithProvider(provider)

		// Copy headers.
		headers := make(map[string]string, 4)
		for _, hdr := range []string{"Content-Type", "X-APP-ID", "X-Request-ID", "X-Session-ID"} {
			if v := r.Header.Get(hdr); v != "" {
				headers[hdr] = v
			}
		}
		evalCtx.WithHeaders(headers)

		if sid := r.Header.Get("X-Session-ID"); sid != "" {
			evalCtx.WithSessionID(sid)
		}

		if h.proxy.engine == nil || !h.cfg.Guardrails.Enabled {
			respondJSON(w, http.StatusOK, map[string]any{
				"message": "guardrails are disabled; nothing to evaluate",
			})
			return
		}

		// Run input guardrails.
		inputResult, err := h.proxy.engine.EvaluateInput(ctx, evalCtx)
		if err != nil {
			h.log.Error(ctx, "evaluate: input guardrail failed", map[string]any{"error": err.Error()})
			respondJSON(w, http.StatusInternalServerError, errorResponse{
				Error:   "guardrail_error",
				Message: "Failed to evaluate input guardrails",
			})
			return
		}

		// Run output guardrails (with empty response, since we do not call upstream).
		evalCtx.WithResponse("")
		outputResult, err := h.proxy.engine.EvaluateOutput(ctx, evalCtx)
		if err != nil {
			h.log.Error(ctx, "evaluate: output guardrail failed", map[string]any{"error": err.Error()})
			respondJSON(w, http.StatusInternalServerError, errorResponse{
				Error:   "guardrail_error",
				Message: "Failed to evaluate output guardrails",
			})
			return
		}

		// Merge evaluations from both stages.
		allEvals := make([]models.GuardrailEvaluation, 0, len(inputResult.Evaluations)+len(outputResult.Evaluations))
		allEvals = append(allEvals, inputResult.Evaluations...)
		allEvals = append(allEvals, outputResult.Evaluations...)

		totalLatency := inputResult.TotalLatencyMs + outputResult.TotalLatencyMs

		// Build a combined result.
		combined := &models.PipelineResult{
			FinalDecision:  inputResult.FinalDecision,
			Evaluations:    allEvals,
			TotalLatencyMs: totalLatency,
			Blocked:        inputResult.Blocked || outputResult.Blocked,
			BlockedBy:      inputResult.BlockedBy,
		}
		if !inputResult.Blocked && outputResult.Blocked {
			combined.FinalDecision = outputResult.FinalDecision
			combined.BlockedBy = outputResult.BlockedBy
		}

		h.log.Info(ctx, "evaluate (dry-run) completed", map[string]any{
			"decision":   string(combined.FinalDecision),
			"blocked":    combined.Blocked,
			"latency_ms": totalLatency,
			"provider":   provider,
		})

		respondJSON(w, http.StatusOK, combined)
	})
}

// metricsHandler exposes basic counters in a Prometheus-compatible text format.
func (h *Handler) metricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")

		total := h.totalRequests.Load()
		blocked := h.blockedRequests.Load()
		errors := h.errorCount.Load()
		latency := h.upstreamLatency.Load()

		// If the caller wants JSON, return JSON.
		if accept == "application/json" || r.URL.Query().Get("format") == "json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_requests":          total,
				"blocked_requests":        blocked,
				"error_count":             errors,
				"cumulative_latency_ms":   latency,
			})
			return
		}

		// Default: Prometheus text exposition format.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		lines := []string{
			"# HELP killaileak_requests_total Total proxy requests.",
			"# TYPE killaileak_requests_total counter",
			formatMetric("killaileak_requests_total", total),
			"# HELP killaileak_requests_blocked_total Requests blocked by guardrails.",
			"# TYPE killaileak_requests_blocked_total counter",
			formatMetric("killaileak_requests_blocked_total", blocked),
			"# HELP killaileak_errors_total Upstream and internal errors.",
			"# TYPE killaileak_errors_total counter",
			formatMetric("killaileak_errors_total", errors),
			"# HELP killaileak_upstream_latency_ms_total Cumulative upstream latency.",
			"# TYPE killaileak_upstream_latency_ms_total counter",
			formatMetric("killaileak_upstream_latency_ms_total", latency),
		}
		for _, line := range lines {
			_, _ = w.Write([]byte(line + "\n"))
		}
	}
}

func formatMetric(name string, value int64) string {
	return name + " " + intToString(value)
}

func intToString(v int64) string {
	buf := make([]byte, 0, 20)
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	for v > 0 {
		buf = append(buf, byte('0'+v%10))
		v /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	// Reverse.
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

// statusCapture wraps ResponseWriter to capture the status code.
type statusCapture struct {
	http.ResponseWriter
	status int
}

func (sc *statusCapture) WriteHeader(code int) {
	sc.status = code
	sc.ResponseWriter.WriteHeader(code)
}
