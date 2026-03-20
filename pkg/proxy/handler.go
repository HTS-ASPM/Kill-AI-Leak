package proxy

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/internal/health"
	"github.com/kill-ai-leak/kill-ai-leak/internal/logger"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/config"
)

// Handler bundles HTTP handlers for the inline gateway and wires them into a
// single http.ServeMux.
type Handler struct {
	proxy   *LLMProxy
	health  *health.Checker
	log     *logger.Logger
	cfg     *config.AppConfig

	// Prometheus-style counters (simple atomic counters; a real deployment
	// would use the prometheus client library).
	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	errorCount      atomic.Int64
	upstreamLatency atomic.Int64 // cumulative milliseconds
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
	// Main proxy endpoint -- requests like POST /api/protect/openai/v1/chat/completions.
	mux.Handle("/api/protect/", h.protectHandler())

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
