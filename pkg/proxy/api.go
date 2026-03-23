package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/compliance"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/store"
)

// APIHandler serves the /api/v1/ data endpoints consumed by the dashboard.
type APIHandler struct {
	store    *store.Store
	registry *guardrails.Registry
}

// NewAPIHandler creates an APIHandler.
func NewAPIHandler(s *store.Store, registry *guardrails.Registry) *APIHandler {
	return &APIHandler{store: s, registry: registry}
}

// Register mounts all /api/v1/ routes onto the provided mux.
func (a *APIHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/stats", a.handleStats)
	mux.HandleFunc("/api/v1/stats/threat-activity", a.handleThreatActivity)
	mux.HandleFunc("/api/v1/stats/risk-breakdown", a.handleRiskBreakdown)
	mux.HandleFunc("/api/v1/stats/top-services", a.handleTopServices)

	mux.HandleFunc("/api/v1/inventory/aibom", a.handleAIBOM)
	mux.HandleFunc("/api/v1/inventory/", a.handleInventoryByID)
	mux.HandleFunc("/api/v1/inventory", a.handleInventory)

	mux.HandleFunc("/api/v1/events/", a.handleEventByID)
	mux.HandleFunc("/api/v1/events", a.handleEvents)

	mux.HandleFunc("/api/v1/guardrails/", a.handleGuardrailByID)
	mux.HandleFunc("/api/v1/guardrails", a.handleGuardrails)

	mux.HandleFunc("/api/v1/policies/", a.handlePolicyByName)
	mux.HandleFunc("/api/v1/policies", a.handlePolicies)

	mux.HandleFunc("/api/v1/lineage", a.handleLineage)

	mux.HandleFunc("/api/v1/compliance/", a.handleCompliance)
}

// --- Stats ---

func (a *APIHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	activeGuardrails := 0
	if a.registry != nil {
		for _, rule := range a.registry.All() {
			if a.registry.IsEnabled(rule.ID()) {
				activeGuardrails++
			}
		}
	}
	stats := a.store.GetStats(activeGuardrails)
	a.respondJSON(w, http.StatusOK, stats)
}

func (a *APIHandler) handleThreatActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	days := queryInt(r, "days", 7)
	points := a.store.GetThreatActivity(days)
	a.respondJSON(w, http.StatusOK, points)
}

func (a *APIHandler) handleRiskBreakdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	breakdown := a.store.GetRiskBreakdown()
	a.respondJSON(w, http.StatusOK, breakdown)
}

func (a *APIHandler) handleTopServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 10)
	services := a.store.GetTopServices(limit)
	a.respondJSON(w, http.StatusOK, services)
}

// --- Inventory ---

func (a *APIHandler) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	f := store.ServiceFilter{
		Namespace: r.URL.Query().Get("namespace"),
		Provider:  r.URL.Query().Get("provider"),
		RiskLevel: r.URL.Query().Get("risk_level"),
		Search:    r.URL.Query().Get("search"),
		Page:      queryInt(r, "page", 1),
		PerPage:   queryInt(r, "per_page", 20),
	}
	result := a.store.GetServices(f)
	a.respondJSON(w, http.StatusOK, result)
}

func (a *APIHandler) handleInventoryByID(w http.ResponseWriter, r *http.Request) {
	// /api/v1/inventory/aibom is handled by its own handler due to mux
	// ordering, but guard here just in case.
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/inventory/")
	if id == "" || id == "aibom" {
		a.handleAIBOM(w, r)
		return
	}

	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}

	svc := a.store.GetService(id)
	if svc == nil {
		a.respondJSON(w, http.StatusNotFound, apiErrorBody{
			Error:   "not_found",
			Message: "Service not found",
		})
		return
	}
	a.respondJSON(w, http.StatusOK, svc)
}

func (a *APIHandler) handleAIBOM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	bom := a.store.GetAIBOM()
	a.respondJSON(w, http.StatusOK, bom)
}

// --- Events ---

func (a *APIHandler) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	f := store.EventFilter{
		Severity: r.URL.Query().Get("severity"),
		Source:   r.URL.Query().Get("source"),
		Decision: r.URL.Query().Get("decision"),
		Search:   r.URL.Query().Get("search"),
		Page:     queryInt(r, "page", 1),
		PerPage:  queryInt(r, "per_page", 20),
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = t
		}
	}
	result := a.store.GetEvents(f)
	a.respondJSON(w, http.StatusOK, result)
}

func (a *APIHandler) handleEventByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/events/")
	if id == "" {
		a.handleEvents(w, r)
		return
	}
	ev := a.store.GetEvent(id)
	if ev == nil {
		a.respondJSON(w, http.StatusNotFound, apiErrorBody{
			Error:   "not_found",
			Message: "Event not found",
		})
		return
	}
	a.respondJSON(w, http.StatusOK, ev)
}

// --- Guardrails ---

func (a *APIHandler) handleGuardrails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	if a.registry == nil {
		a.respondJSON(w, http.StatusOK, []models.GuardrailRuleConfig{})
		return
	}
	var configs []models.GuardrailRuleConfig
	for _, rule := range a.registry.All() {
		cfg, ok := a.registry.GetConfig(rule.ID())
		if ok {
			configs = append(configs, *cfg)
		}
	}
	if configs == nil {
		configs = []models.GuardrailRuleConfig{}
	}
	a.respondJSON(w, http.StatusOK, configs)
}

func (a *APIHandler) handleGuardrailByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/guardrails/")
	if id == "" {
		a.handleGuardrails(w, r)
		return
	}

	switch r.Method {
	case http.MethodPatch:
		a.patchGuardrail(w, r, id)
	default:
		a.methodNotAllowed(w)
	}
}

func (a *APIHandler) patchGuardrail(w http.ResponseWriter, r *http.Request, id string) {
	if a.registry == nil {
		a.respondJSON(w, http.StatusNotFound, apiErrorBody{
			Error:   "not_found",
			Message: "Guardrail not found",
		})
		return
	}

	cfg, ok := a.registry.GetConfig(id)
	if !ok {
		a.respondJSON(w, http.StatusNotFound, apiErrorBody{
			Error:   "not_found",
			Message: "Guardrail not found",
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		a.respondJSON(w, http.StatusBadRequest, apiErrorBody{
			Error:   "bad_request",
			Message: "Could not read request body",
		})
		return
	}
	defer r.Body.Close()

	var update struct {
		Enabled *bool                   `json:"enabled,omitempty"`
		Mode    *models.EnforcementMode `json:"mode,omitempty"`
	}
	if err := json.Unmarshal(body, &update); err != nil {
		a.respondJSON(w, http.StatusBadRequest, apiErrorBody{
			Error:   "bad_request",
			Message: "Invalid JSON body",
		})
		return
	}

	if update.Enabled != nil {
		if *update.Enabled {
			_ = a.registry.Enable(id)
		} else {
			_ = a.registry.Disable(id)
		}
	}
	if update.Mode != nil {
		cfg.Mode = *update.Mode
	}

	// Re-read in case Enable/Disable mutated it.
	cfg, _ = a.registry.GetConfig(id)
	a.respondJSON(w, http.StatusOK, cfg)
}

// --- Policies ---

func (a *APIHandler) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policies := a.store.GetPolicies()
		if policies == nil {
			policies = []models.AISecurityPolicy{}
		}
		a.respondJSON(w, http.StatusOK, policies)

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			a.respondJSON(w, http.StatusBadRequest, apiErrorBody{
				Error:   "bad_request",
				Message: "Could not read request body",
			})
			return
		}
		defer r.Body.Close()

		var policy models.AISecurityPolicy
		if err := json.Unmarshal(body, &policy); err != nil {
			a.respondJSON(w, http.StatusBadRequest, apiErrorBody{
				Error:   "bad_request",
				Message: "Invalid JSON body",
			})
			return
		}
		a.store.AddPolicy(policy)
		a.respondJSON(w, http.StatusCreated, policy)

	default:
		a.methodNotAllowed(w)
	}
}

func (a *APIHandler) handlePolicyByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")

	// Handle dry-run sub-path.
	if name == "dry-run" {
		a.handlePolicyDryRun(w, r)
		return
	}

	if name == "" {
		a.handlePolicies(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		p := a.store.GetPolicy(name)
		if p == nil {
			a.respondJSON(w, http.StatusNotFound, apiErrorBody{
				Error:   "not_found",
				Message: "Policy not found",
			})
			return
		}
		a.respondJSON(w, http.StatusOK, p)

	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			a.respondJSON(w, http.StatusBadRequest, apiErrorBody{
				Error:   "bad_request",
				Message: "Could not read request body",
			})
			return
		}
		defer r.Body.Close()

		var policy models.AISecurityPolicy
		if err := json.Unmarshal(body, &policy); err != nil {
			a.respondJSON(w, http.StatusBadRequest, apiErrorBody{
				Error:   "bad_request",
				Message: "Invalid JSON body",
			})
			return
		}

		if !a.store.UpdatePolicy(name, policy) {
			a.respondJSON(w, http.StatusNotFound, apiErrorBody{
				Error:   "not_found",
				Message: "Policy not found",
			})
			return
		}
		a.respondJSON(w, http.StatusOK, policy)

	case http.MethodDelete:
		if !a.store.DeletePolicy(name) {
			a.respondJSON(w, http.StatusNotFound, apiErrorBody{
				Error:   "not_found",
				Message: "Policy not found",
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		a.methodNotAllowed(w)
	}
}

func (a *APIHandler) handlePolicyDryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w)
		return
	}
	// Placeholder for dry-run; return a minimal response.
	a.respondJSON(w, http.StatusOK, map[string]any{
		"decision":    "allow",
		"evaluations": []any{},
		"blocked":     false,
	})
}

// --- Lineage ---

func (a *APIHandler) handleLineage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}
	// Build a simple lineage graph from current services.
	type node struct {
		ID      string            `json:"id"`
		Label   string            `json:"label"`
		Type    string            `json:"type"`
		Risk    string            `json:"risk"`
		Details map[string]string `json:"details,omitempty"`
		X       float64           `json:"x"`
		Y       float64           `json:"y"`
	}
	type edge struct {
		ID         string `json:"id"`
		Source     string `json:"source"`
		Target     string `json:"target"`
		Label      string `json:"label,omitempty"`
		HasPII     bool   `json:"has_pii"`
		DataVolume string `json:"data_volume,omitempty"`
	}

	nodes := []node{}
	edges := []edge{}

	a.respondJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes,
		"edges": edges,
	})
}

// --- Compliance ---

func (a *APIHandler) handleCompliance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w)
		return
	}

	standard := strings.TrimPrefix(r.URL.Path, "/api/v1/compliance/")
	if standard == "" {
		a.respondJSON(w, http.StatusBadRequest, apiErrorBody{
			Error:   "bad_request",
			Message: "Missing compliance standard. Use: gdpr, soc2, or eu-ai-act",
		})
		return
	}

	// Parse time range from query params, defaulting to last 30 days.
	now := time.Now()
	tr := compliance.TimeRange{
		From: now.AddDate(0, 0, -30),
		To:   now,
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tr.From = t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tr.To = t
		}
	}

	gen := compliance.NewReportGenerator(a.store, a.registry)

	var (
		report *compliance.ComplianceReport
		err    error
	)

	switch standard {
	case "gdpr":
		report, err = gen.GenerateGDPR(tr)
	case "soc2":
		report, err = gen.GenerateSOC2(tr)
	case "eu-ai-act":
		report, err = gen.GenerateEUAIAct(tr)
	default:
		a.respondJSON(w, http.StatusBadRequest, apiErrorBody{
			Error:   "bad_request",
			Message: "Unknown compliance standard. Use: gdpr, soc2, or eu-ai-act",
		})
		return
	}

	if err != nil {
		a.respondJSON(w, http.StatusInternalServerError, apiErrorBody{
			Error:   "internal_error",
			Message: "Failed to generate compliance report",
		})
		return
	}

	// Return markdown or JSON based on Accept header or format param.
	format := r.URL.Query().Get("format")
	if format == "" {
		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "text/markdown") {
			format = "markdown"
		} else {
			format = "json"
		}
	}

	switch format {
	case "markdown":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(compliance.ExportMarkdown(report)))
	default:
		a.respondJSON(w, http.StatusOK, report)
	}
}

// --- Helpers ---

type apiErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (a *APIHandler) respondJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *APIHandler) methodNotAllowed(w http.ResponseWriter) {
	a.respondJSON(w, http.StatusMethodNotAllowed, apiErrorBody{
		Error:   "method_not_allowed",
		Message: "Method not allowed",
	})
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
