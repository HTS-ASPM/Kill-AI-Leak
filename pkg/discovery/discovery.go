// Package discovery provides automatic AI service detection based on eBPF
// events.  It maintains an in-memory inventory of all discovered AI-using
// services and flags shadow AI (services calling AI APIs without being in
// an approved inventory).
package discovery

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// DiscoveryConfig holds tuning parameters for the discovery engine.
type DiscoveryConfig struct {
	// ShadowAIEnabled enables flagging of unapproved AI usage.
	ShadowAIEnabled bool

	// ApprovedServices is the set of service names that are approved to
	// use AI.  Any service not in this set is flagged as shadow AI.
	// Empty means no approved list (all services are flagged).
	ApprovedServices map[string]bool

	// StaleTimeout is the duration after which a service that has not
	// been seen is considered stale and can be evicted.
	StaleTimeout time.Duration

	// DeduplicationWindow is the minimum time between duplicate service
	// discovery callbacks for the same service.
	DeduplicationWindow time.Duration
}

// DefaultDiscoveryConfig returns a DiscoveryConfig with sensible defaults.
func DefaultDiscoveryConfig() DiscoveryConfig {
	return DiscoveryConfig{
		ShadowAIEnabled:     true,
		ApprovedServices:    make(map[string]bool),
		StaleTimeout:        24 * time.Hour,
		DeduplicationWindow: 5 * time.Minute,
	}
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

// NewServiceCallback is invoked when a previously unseen AI service is
// detected.
type NewServiceCallback func(svc *models.AIService)

// ShadowAICallback is invoked when a service is flagged as shadow AI.
type ShadowAICallback func(svc *models.AIService, reason string)

// ---------------------------------------------------------------------------
// ServiceDiscovery
// ---------------------------------------------------------------------------

// serviceEntry is the internal bookkeeping record for a discovered service.
type serviceEntry struct {
	service  *models.AIService
	lastSeen time.Time
	// providers tracks unique provider names for deduplication.
	providers map[string]bool
	// libraries tracks unique library names.
	libraries map[string]bool
	// shadowFlagged indicates whether this service has been flagged.
	shadowFlagged bool
}

// ServiceDiscovery analyses eBPF events to discover AI-using services.
// It is safe for concurrent use.
type ServiceDiscovery struct {
	cfg    DiscoveryConfig
	logger *slog.Logger

	mu       sync.RWMutex
	services map[string]*serviceEntry // keyed by service ID (typically "pid:<pid>" or pod name)

	// Callbacks.
	onNewService []NewServiceCallback
	onShadowAI   []ShadowAICallback

	// Provider domain map for matching.
	providerDomains map[string]string
}

// NewServiceDiscovery creates a new discovery engine with default config.
func NewServiceDiscovery(logger *slog.Logger) *ServiceDiscovery {
	return NewServiceDiscoveryWithConfig(DefaultDiscoveryConfig(), logger)
}

// NewServiceDiscoveryWithConfig creates a discovery engine with the given
// configuration.
func NewServiceDiscoveryWithConfig(cfg DiscoveryConfig, logger *slog.Logger) *ServiceDiscovery {
	if logger == nil {
		logger = slog.Default()
	}
	return &ServiceDiscovery{
		cfg:             cfg,
		logger:          logger,
		services:        make(map[string]*serviceEntry),
		providerDomains: buildProviderDomainMap(),
	}
}

// OnNewService registers a callback for new service discovery events.
func (d *ServiceDiscovery) OnNewService(cb NewServiceCallback) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onNewService = append(d.onNewService, cb)
}

// OnShadowAI registers a callback for shadow AI detection events.
func (d *ServiceDiscovery) OnShadowAI(cb ShadowAICallback) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onShadowAI = append(d.onShadowAI, cb)
}

// ProcessEvent analyses an incoming eBPF event and updates the service
// inventory.  It detects new services and shadow AI usage.
func (d *ServiceDiscovery) ProcessEvent(evt *models.Event) {
	if evt == nil {
		return
	}

	switch evt.Action.Type {
	case models.ActionAPICall:
		d.processAPICallEvent(evt)
	case models.ActionProcessSpawn:
		d.processExecEvent(evt)
	case models.ActionFileAccess:
		d.processFileEvent(evt)
	default:
		// Other event types are not relevant for discovery.
	}
}

// processAPICallEvent handles TCP/SSL events that indicate an AI API call.
func (d *ServiceDiscovery) processAPICallEvent(evt *models.Event) {
	provider := evt.Target.Provider
	if provider == "" {
		// Try to identify from metadata.
		if host, ok := evt.Metadata["http_host"]; ok {
			provider = d.identifyProviderByHost(host)
		}
		if provider == "" && evt.Target.Endpoint != "" {
			provider = d.identifyProviderByHost(evt.Target.Endpoint)
		}
	}

	if provider == "" {
		// Not an AI-related API call.
		return
	}

	serviceID := d.serviceIDFromEvent(evt)
	serviceName := evt.Actor.Name
	namespace := evt.Actor.Namespace

	d.mu.Lock()
	entry, exists := d.services[serviceID]

	if !exists {
		// New service discovered.
		svc := &models.AIService{
			ID:           serviceID,
			Name:         serviceName,
			Namespace:    namespace,
			Providers:    []models.ProviderUsage{},
			Libraries:    []models.LibraryUsage{},
			DiscoveredAt: time.Now().UTC(),
			LastSeenAt:   time.Now().UTC(),
			DiscoveredBy: models.SourceKernelObserver,
			Labels:       make(map[string]string),
		}

		entry = &serviceEntry{
			service:   svc,
			lastSeen:  time.Now(),
			providers: make(map[string]bool),
			libraries: make(map[string]bool),
		}
		d.services[serviceID] = entry
	}

	entry.lastSeen = time.Now()
	entry.service.LastSeenAt = time.Now().UTC()

	isNewProvider := !entry.providers[provider]
	if isNewProvider {
		entry.providers[provider] = true
		entry.service.Providers = append(entry.service.Providers, models.ProviderUsage{
			Provider:   provider,
			LastCallAt: time.Now().UTC(),
		})
	}

	// Update model if available.
	if evt.Target.Model != "" {
		for i, pu := range entry.service.Providers {
			if pu.Provider == provider {
				found := false
				for _, m := range pu.Models {
					if m == evt.Target.Model {
						found = true
						break
					}
				}
				if !found {
					entry.service.Providers[i].Models = append(
						entry.service.Providers[i].Models, evt.Target.Model)
				}
				entry.service.Providers[i].CallCount7d++
				entry.service.Providers[i].LastCallAt = time.Now().UTC()
				break
			}
		}
	}

	// Copy the service for callbacks (release lock before calling).
	svcCopy := copyService(entry.service)
	isNew := !exists
	isShadow := d.cfg.ShadowAIEnabled && !d.isApproved(serviceName) && !entry.shadowFlagged

	if isShadow {
		entry.shadowFlagged = true
		entry.service.RiskScore = 0.8
		entry.service.Labels["shadow_ai"] = "true"
	}
	d.mu.Unlock()

	// Fire callbacks outside the lock.
	if isNew || isNewProvider {
		for _, cb := range d.onNewService {
			cb(svcCopy)
		}
	}

	if isShadow {
		reason := fmt.Sprintf("service %q is calling %s API but is not in the approved inventory",
			serviceName, provider)
		for _, cb := range d.onShadowAI {
			cb(svcCopy, reason)
		}
	}
}

// processExecEvent handles process spawn events for AI library detection.
func (d *ServiceDiscovery) processExecEvent(evt *models.Event) {
	aiLib := evt.Metadata["ai_library"]
	if aiLib == "" {
		// Check argv for AI library patterns.
		aiLib = detectAILibFromMetadata(evt.Metadata)
	}

	if aiLib == "" {
		return
	}

	serviceID := d.serviceIDFromEvent(evt)
	serviceName := evt.Actor.Name

	d.mu.Lock()
	entry, exists := d.services[serviceID]

	if !exists {
		svc := &models.AIService{
			ID:           serviceID,
			Name:         serviceName,
			Namespace:    evt.Actor.Namespace,
			Providers:    []models.ProviderUsage{},
			Libraries:    []models.LibraryUsage{},
			DiscoveredAt: time.Now().UTC(),
			LastSeenAt:   time.Now().UTC(),
			DiscoveredBy: models.SourceKernelObserver,
			Labels:       make(map[string]string),
		}
		entry = &serviceEntry{
			service:   svc,
			lastSeen:  time.Now(),
			providers: make(map[string]bool),
			libraries: make(map[string]bool),
		}
		d.services[serviceID] = entry
	}

	entry.lastSeen = time.Now()

	isNewLib := !entry.libraries[aiLib]
	if isNewLib {
		entry.libraries[aiLib] = true

		// Determine the language from the process name.
		lang := detectLanguage(evt.Metadata["comm"], evt.Metadata["filename"])

		entry.service.Libraries = append(entry.service.Libraries, models.LibraryUsage{
			Name:     aiLib,
			Language: lang,
		})
	}

	svcCopy := copyService(entry.service)
	isNew := !exists
	d.mu.Unlock()

	if isNew || isNewLib {
		for _, cb := range d.onNewService {
			cb(svcCopy)
		}
	}
}

// processFileEvent handles file access events for AI model file detection.
func (d *ServiceDiscovery) processFileEvent(evt *models.Event) {
	fileClass := evt.Metadata["file_class"]

	// We're interested in model files and credential files.
	if fileClass != "model_file" && fileClass != "credential_file" {
		return
	}

	serviceID := d.serviceIDFromEvent(evt)
	serviceName := evt.Actor.Name

	d.mu.Lock()
	entry, exists := d.services[serviceID]

	if !exists {
		svc := &models.AIService{
			ID:           serviceID,
			Name:         serviceName,
			Namespace:    evt.Actor.Namespace,
			Providers:    []models.ProviderUsage{},
			Libraries:    []models.LibraryUsage{},
			DiscoveredAt: time.Now().UTC(),
			LastSeenAt:   time.Now().UTC(),
			DiscoveredBy: models.SourceKernelObserver,
			Labels:       make(map[string]string),
		}
		entry = &serviceEntry{
			service:   svc,
			lastSeen:  time.Now(),
			providers: make(map[string]bool),
			libraries: make(map[string]bool),
		}
		d.services[serviceID] = entry
	}

	entry.lastSeen = time.Now()

	if fileClass == "model_file" {
		filename := evt.Metadata["filename"]
		modelFormat := evt.Metadata["model_format"]
		entry.service.Labels["uses_local_models"] = "true"
		entry.service.Labels["model_format"] = modelFormat
		entry.service.Labels["model_file"] = filename

		// If accessing local models, add "local" as a provider.
		if !entry.providers["local_model"] {
			entry.providers["local_model"] = true
			entry.service.Providers = append(entry.service.Providers, models.ProviderUsage{
				Provider:   "local_model",
				LastCallAt: time.Now().UTC(),
			})
		}
	}

	if fileClass == "credential_file" {
		entry.service.Labels["accesses_credentials"] = "true"
		entry.service.RiskScore += 0.2
		if entry.service.RiskScore > 1.0 {
			entry.service.RiskScore = 1.0
		}
	}

	svcCopy := copyService(entry.service)
	isNew := !exists
	d.mu.Unlock()

	if isNew {
		for _, cb := range d.onNewService {
			cb(svcCopy)
		}
	}
}

// ---------------------------------------------------------------------------
// Inventory access
// ---------------------------------------------------------------------------

// ServiceCount returns the number of discovered services.
func (d *ServiceDiscovery) ServiceCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.services)
}

// GetService returns a copy of the discovered service, or nil if not found.
func (d *ServiceDiscovery) GetService(id string) *models.AIService {
	d.mu.RLock()
	defer d.mu.RUnlock()
	entry, ok := d.services[id]
	if !ok {
		return nil
	}
	return copyService(entry.service)
}

// ListServices returns a snapshot of all discovered services.
func (d *ServiceDiscovery) ListServices() []*models.AIService {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*models.AIService, 0, len(d.services))
	for _, entry := range d.services {
		result = append(result, copyService(entry.service))
	}
	return result
}

// GenerateAIBOM produces an AI Bill of Materials from the current inventory.
func (d *ServiceDiscovery) GenerateAIBOM() *models.AIBOM {
	ptrServices := d.ListServices()

	// Dereference pointers for the AIBOM value slice.
	services := make([]models.AIService, 0, len(ptrServices))
	for _, svc := range ptrServices {
		if svc != nil {
			services = append(services, *svc)
		}
	}

	providerSet := make(map[string]bool)
	modelSet := make(map[string]bool)
	dbCount := 0
	shadowCount := 0
	highRisk := 0
	totalCost := 0.0

	for _, svc := range services {
		for _, p := range svc.Providers {
			providerSet[p.Provider] = true
			for _, m := range p.Models {
				modelSet[m] = true
			}
			totalCost += p.EstCost7dUSD
		}
		dbCount += len(svc.Databases)
		if svc.Labels["shadow_ai"] == "true" {
			shadowCount++
		}
		if svc.RiskScore >= 0.7 {
			highRisk++
		}
	}

	return &models.AIBOM{
		GeneratedAt: time.Now().UTC(),
		Services:    services,
		Summary: models.ABOMSummary{
			TotalServices:    len(services),
			TotalProviders:   len(providerSet),
			TotalModels:      len(modelSet),
			TotalDatabases:   dbCount,
			ShadowAICount:    shadowCount,
			TotalCost7dUSD:   totalCost,
			HighRiskServices: highRisk,
		},
	}
}

// EvictStale removes services that have not been seen within the configured
// stale timeout.  Returns the number of evicted services.
func (d *ServiceDiscovery) EvictStale() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-d.cfg.StaleTimeout)
	evicted := 0

	for id, entry := range d.services {
		if entry.lastSeen.Before(cutoff) {
			delete(d.services, id)
			evicted++
		}
	}

	if evicted > 0 {
		d.logger.Info("evicted stale services", "count", evicted)
	}
	return evicted
}

// IsShadowAI returns true if the given service is flagged as shadow AI.
func (d *ServiceDiscovery) IsShadowAI(serviceID string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	entry, ok := d.services[serviceID]
	if !ok {
		return false
	}
	return entry.shadowFlagged
}

// SetApprovedServices updates the approved service list.
func (d *ServiceDiscovery) SetApprovedServices(approved []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg.ApprovedServices = make(map[string]bool, len(approved))
	for _, name := range approved {
		d.cfg.ApprovedServices[name] = true
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// serviceIDFromEvent derives a unique service identifier from the event.
// In a K8s environment this would be the pod name; otherwise we use the
// PID + process name.
func (d *ServiceDiscovery) serviceIDFromEvent(evt *models.Event) string {
	// Prefer K8s identity if available.
	if evt.Actor.Namespace != "" && evt.Actor.Name != "" {
		return fmt.Sprintf("%s/%s", evt.Actor.Namespace, evt.Actor.Name)
	}
	return evt.Actor.ID
}

// isApproved checks if a service name is in the approved list.
func (d *ServiceDiscovery) isApproved(name string) bool {
	if len(d.cfg.ApprovedServices) == 0 {
		return false // no approved list means everything is flagged
	}
	return d.cfg.ApprovedServices[name]
}

// identifyProviderByHost looks up the AI provider from a hostname.
func (d *ServiceDiscovery) identifyProviderByHost(host string) string {
	host = strings.ToLower(host)
	for domain, provider := range d.providerDomains {
		if strings.Contains(host, domain) {
			return provider
		}
	}
	return ""
}

// buildProviderDomainMap returns a map of domain substrings to provider names.
func buildProviderDomainMap() map[string]string {
	return map[string]string{
		"api.openai.com":                    "openai",
		"openai.azure.com":                  "azure_openai",
		"api.anthropic.com":                 "anthropic",
		"generativelanguage.googleapis.com": "google_gemini",
		"aiplatform.googleapis.com":         "google_vertex",
		"api.cohere.ai":                     "cohere",
		"api.cohere.com":                    "cohere",
		"api-inference.huggingface.co":      "huggingface",
		"api.together.xyz":                  "together_ai",
		"api.together.ai":                   "together_ai",
		"api.fireworks.ai":                  "fireworks_ai",
		"api.groq.com":                      "groq",
		"api.mistral.ai":                    "mistral",
		"api.deepseek.com":                  "deepseek",
		"bedrock-runtime":                   "aws_bedrock",
		"api.replicate.com":                 "replicate",
		"api.perplexity.ai":                 "perplexity",
		"localhost:11434":                    "ollama",
		"127.0.0.1:11434":                   "ollama",
	}
}

// detectAILibFromMetadata checks event metadata argv fields for AI library
// patterns.
func detectAILibFromMetadata(meta map[string]string) string {
	// Collect all argv fields.
	var allArgs strings.Builder
	for key, val := range meta {
		if strings.HasPrefix(key, "argv") || key == "filename" || key == "comm" {
			allArgs.WriteString(val)
			allArgs.WriteByte(' ')
		}
	}

	lower := strings.ToLower(allArgs.String())

	patterns := map[string]string{
		"openai":        "openai",
		"anthropic":     "anthropic",
		"langchain":     "langchain",
		"llama_index":   "llama_index",
		"llamaindex":    "llama_index",
		"transformers":  "transformers",
		"torch":         "pytorch",
		"tensorflow":    "tensorflow",
		"keras":         "keras",
		"ollama":        "ollama",
		"vllm":          "vllm",
		"huggingface":   "huggingface",
		"cohere":        "cohere",
		"groq":          "groq",
		"mistralai":     "mistral",
		"google.generativeai": "google_genai",
		"autogen":       "autogen",
		"crewai":        "crewai",
		"dspy":          "dspy",
		"litellm":       "litellm",
		"semantic_kernel": "semantic_kernel",
	}

	for pattern, lib := range patterns {
		if strings.Contains(lower, pattern) {
			return lib
		}
	}

	return ""
}

// detectLanguage guesses the programming language from process name/path.
func detectLanguage(comm, filename string) string {
	lower := strings.ToLower(comm + " " + filename)

	switch {
	case strings.Contains(lower, "python"):
		return "python"
	case strings.Contains(lower, "node") || strings.Contains(lower, "npm") ||
		strings.Contains(lower, "bun") || strings.Contains(lower, "deno"):
		return "javascript"
	case strings.Contains(lower, "java"):
		return "java"
	case strings.Contains(lower, "ruby"):
		return "ruby"
	case strings.Contains(lower, "go"):
		return "go"
	case strings.Contains(lower, "dotnet") || strings.Contains(lower, "csharp"):
		return "csharp"
	case strings.Contains(lower, "php"):
		return "php"
	case strings.Contains(lower, "rust"):
		return "rust"
	default:
		return "unknown"
	}
}

// copyService creates a deep-ish copy of an AIService for safe use outside
// the lock.
func copyService(src *models.AIService) *models.AIService {
	if src == nil {
		return nil
	}

	dst := *src // shallow copy

	// Deep copy slices.
	if len(src.Providers) > 0 {
		dst.Providers = make([]models.ProviderUsage, len(src.Providers))
		for i, p := range src.Providers {
			dst.Providers[i] = p
			if len(p.Models) > 0 {
				dst.Providers[i].Models = make([]string, len(p.Models))
				copy(dst.Providers[i].Models, p.Models)
			}
		}
	}

	if len(src.Libraries) > 0 {
		dst.Libraries = make([]models.LibraryUsage, len(src.Libraries))
		copy(dst.Libraries, src.Libraries)
	}

	if len(src.Databases) > 0 {
		dst.Databases = make([]models.DatabaseUsage, len(src.Databases))
		copy(dst.Databases, src.Databases)
	}

	if len(src.Labels) > 0 {
		dst.Labels = make(map[string]string, len(src.Labels))
		for k, v := range src.Labels {
			dst.Labels[k] = v
		}
	}

	return &dst
}
