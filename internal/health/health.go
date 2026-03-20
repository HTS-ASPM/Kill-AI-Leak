package health

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Status represents the health status of a component.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

// ComponentHealth describes the health of a single subsystem.
type ComponentHealth struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message,omitempty"`
	// LastCheck records when this component was last evaluated.
	LastCheck time.Time `json:"last_check"`
}

// Report is the aggregated health report returned by the health endpoint.
type Report struct {
	Status     Status            `json:"status"`
	Components []ComponentHealth `json:"components"`
	Timestamp  time.Time         `json:"timestamp"`
	Version    string            `json:"version,omitempty"`
}

// Checker maintains component health state and serves liveness/readiness
// probes.
type Checker struct {
	mu         sync.RWMutex
	components map[string]*ComponentHealth
	version    string
	ready      bool
}

// NewChecker creates a Checker for health reporting.
func NewChecker(version string) *Checker {
	return &Checker{
		components: make(map[string]*ComponentHealth),
		version:    version,
	}
}

// RegisterComponent adds a named component to the health registry. It starts
// in an unhealthy state until the first SetComponentHealth call.
func (c *Checker) RegisterComponent(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.components[name] = &ComponentHealth{
		Name:      name,
		Status:    StatusUnhealthy,
		Message:   "not yet checked",
		LastCheck: time.Now().UTC(),
	}
}

// SetComponentHealth updates the health state for a named component.
func (c *Checker) SetComponentHealth(name string, status Status, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	comp, ok := c.components[name]
	if !ok {
		comp = &ComponentHealth{Name: name}
		c.components[name] = comp
	}
	comp.Status = status
	comp.Message = msg
	comp.LastCheck = time.Now().UTC()
}

// SetReady marks the service as ready to serve traffic.
func (c *Checker) SetReady(ready bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ready = ready
}

// IsReady returns whether the service is ready.
func (c *Checker) IsReady() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ready
}

// report builds the current health report.
func (c *Checker) report() Report {
	c.mu.RLock()
	defer c.mu.RUnlock()

	r := Report{
		Status:    StatusHealthy,
		Timestamp: time.Now().UTC(),
		Version:   c.version,
	}

	for _, comp := range c.components {
		r.Components = append(r.Components, *comp)
		if comp.Status == StatusUnhealthy {
			r.Status = StatusUnhealthy
		} else if comp.Status == StatusDegraded && r.Status != StatusUnhealthy {
			r.Status = StatusDegraded
		}
	}

	return r
}

// LivenessHandler returns an http.HandlerFunc for the /healthz liveness
// probe. A running server is always live.
func (c *Checker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]string{"status": "alive"}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// ReadinessHandler returns an http.HandlerFunc for the /readyz readiness
// probe. It reports 200 when ready and 503 when not.
func (c *Checker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		report := c.report()
		if !c.IsReady() || report.Status == StatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(report)
	}
}

// DetailedHandler returns an http.HandlerFunc that renders the full health
// report including per-component status. Suitable for operators.
func (c *Checker) DetailedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		report := c.report()
		code := http.StatusOK
		if report.Status == StatusUnhealthy {
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(report)
	}
}
