// Package compliance provides report generators for GDPR, SOC2, and EU AI Act
// compliance evidence. Reports aggregate data from the platform's event store,
// service inventory, and guardrail registry to produce structured compliance
// documentation.
package compliance

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/store"
)

// ComplianceReport is the top-level report structure.
type ComplianceReport struct {
	Title       string          `json:"title"`
	Standard    string          `json:"standard"`
	GeneratedAt time.Time       `json:"generated_at"`
	TimeRange   TimeRange       `json:"time_range"`
	Sections    []ReportSection `json:"sections"`
}

// TimeRange defines the report's temporal scope.
type TimeRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ReportSection is a titled grouping within the report.
type ReportSection struct {
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Items       []ReportItem `json:"items"`
	Status      string       `json:"status"` // "compliant", "non_compliant", "partial"
}

// ReportItem is a single piece of evidence or finding within a section.
type ReportItem struct {
	Label       string `json:"label"`
	Value       string `json:"value"`
	Status      string `json:"status,omitempty"` // "ok", "warning", "fail"
	Description string `json:"description,omitempty"`
}

// ReportGenerator produces compliance reports from platform data.
type ReportGenerator struct {
	store    *store.Store
	registry *guardrails.Registry
}

// NewReportGenerator creates a ReportGenerator.
func NewReportGenerator(s *store.Store, registry *guardrails.Registry) *ReportGenerator {
	return &ReportGenerator{store: s, registry: registry}
}

// ---------------------------------------------------------------------------
// GDPR Report
// ---------------------------------------------------------------------------

// GenerateGDPR produces a GDPR compliance report covering data inventory,
// legal basis, data flows, protection measures, and retention policies.
func (g *ReportGenerator) GenerateGDPR(tr TimeRange) (*ComplianceReport, error) {
	report := &ComplianceReport{
		Title:       "GDPR Compliance Report",
		Standard:    "gdpr",
		GeneratedAt: time.Now(),
		TimeRange:   tr,
	}

	services := g.getServicesSnapshot()
	events := g.getEventsInRange(tr)

	// Section 1: Data Inventory
	report.Sections = append(report.Sections, g.gdprDataInventory(services))

	// Section 2: Legal Basis
	report.Sections = append(report.Sections, g.gdprLegalBasis(services))

	// Section 3: Data Flows
	report.Sections = append(report.Sections, g.gdprDataFlows(services, events))

	// Section 4: Protection Measures
	report.Sections = append(report.Sections, g.gdprProtectionMeasures())

	// Section 5: Retention
	report.Sections = append(report.Sections, g.gdprRetention())

	return report, nil
}

func (g *ReportGenerator) gdprDataInventory(services []models.AIService) ReportSection {
	section := ReportSection{
		Title:       "Data Inventory",
		Description: "AI services processing personal data and their associated LLM providers.",
		Status:      "compliant",
	}

	for _, svc := range services {
		providers := make([]string, 0, len(svc.Providers))
		for _, p := range svc.Providers {
			providers = append(providers, fmt.Sprintf("%s (%s)", p.Provider, strings.Join(p.Models, ", ")))
		}
		section.Items = append(section.Items, ReportItem{
			Label:       svc.Name,
			Value:       fmt.Sprintf("Namespace: %s | Providers: %s | Enrolled: %v", svc.Namespace, strings.Join(providers, "; "), svc.GatewayEnrolled),
			Status:      boolStatus(svc.GatewayEnrolled),
			Description: fmt.Sprintf("Discovered by %s on %s", svc.DiscoveredBy, svc.DiscoveredAt.Format(time.DateOnly)),
		})
	}

	if len(section.Items) == 0 {
		section.Items = append(section.Items, ReportItem{
			Label:  "No services",
			Value:  "No AI services discovered in the inventory",
			Status: "warning",
		})
		section.Status = "partial"
	}

	return section
}

func (g *ReportGenerator) gdprLegalBasis(services []models.AIService) ReportSection {
	section := ReportSection{
		Title:       "Legal Basis",
		Description: "Legal basis for processing personal data through AI services.",
		Status:      "partial",
	}

	section.Items = append(section.Items, ReportItem{
		Label:       "Legitimate Interest Assessment",
		Value:       fmt.Sprintf("%d AI services require legal basis review", len(services)),
		Status:      "warning",
		Description: "Ensure each AI service has a documented legal basis (consent, legitimate interest, contractual necessity).",
	})

	section.Items = append(section.Items, ReportItem{
		Label:       "Data Processing Agreements",
		Value:       "DPAs required with all LLM providers processing EU personal data",
		Status:      "warning",
		Description: "Verify data processing agreements are in place with each external LLM provider.",
	})

	return section
}

func (g *ReportGenerator) gdprDataFlows(services []models.AIService, events []models.Event) ReportSection {
	section := ReportSection{
		Title:       "Data Flows",
		Description: "PII data flows between services and LLM providers.",
		Status:      "compliant",
	}

	// Count PII events per service.
	piiByService := make(map[string]int)
	for _, ev := range events {
		if len(ev.Content.PIIDetected) > 0 {
			piiByService[ev.Actor.ID]++
		}
		for _, gr := range ev.Guardrails {
			if strings.Contains(gr.RuleID, "pii") {
				piiByService[ev.Actor.ID]++
				break
			}
		}
	}

	for _, svc := range services {
		piiCount := piiByService[svc.ID]
		for _, p := range svc.Providers {
			status := "ok"
			if piiCount > 0 {
				status = "warning"
			}
			section.Items = append(section.Items, ReportItem{
				Label:       fmt.Sprintf("%s -> %s", svc.Name, p.Provider),
				Value:       fmt.Sprintf("Calls: %d | PII events: %d | Tokens: %d", p.CallCount7d, piiCount, p.TokensUsed7d),
				Status:      status,
				Description: fmt.Sprintf("Data flow from %s to %s (models: %s)", svc.Name, p.Provider, strings.Join(p.Models, ", ")),
			})
		}
	}

	for _, item := range section.Items {
		if item.Status == "warning" {
			section.Status = "partial"
			break
		}
	}

	return section
}

func (g *ReportGenerator) gdprProtectionMeasures() ReportSection {
	section := ReportSection{
		Title:       "Protection Measures",
		Description: "Technical measures protecting personal data in AI interactions.",
		Status:      "compliant",
	}

	// Check guardrail rules.
	ruleChecks := []struct {
		id    string
		label string
		desc  string
	}{
		{"GR-010", "PII Detection", "Detects personal data in prompts before sending to LLM providers"},
		{"GR-011", "PII Anonymization", "Anonymizes detected PII with reversible placeholders"},
		{"GR-020", "Data Residency", "Routes EU data only to EU-approved providers"},
	}

	for _, rc := range ruleChecks {
		status := "fail"
		value := "Not configured"
		if g.registry != nil && g.registry.IsEnabled(rc.id) {
			status = "ok"
			value = "Active and enforcing"
		}
		section.Items = append(section.Items, ReportItem{
			Label:       rc.label,
			Value:       value,
			Status:      status,
			Description: rc.desc,
		})
		if status == "fail" {
			section.Status = "partial"
		}
	}

	return section
}

func (g *ReportGenerator) gdprRetention() ReportSection {
	return ReportSection{
		Title:       "Retention",
		Description: "Data retention policies for AI interaction logs.",
		Status:      "partial",
		Items: []ReportItem{
			{
				Label:       "Audit Log Retention",
				Value:       "365 days (configurable)",
				Status:      "ok",
				Description: "Audit logs are retained per GR-046 configuration.",
			},
			{
				Label:       "PII in Logs",
				Value:       "PII is hashed in audit logs",
				Status:      "ok",
				Description: "PII values are hashed before storage in audit records.",
			},
			{
				Label:       "Data Subject Access Requests",
				Value:       "Manual process required",
				Status:      "warning",
				Description: "Automated DSAR handling for AI interaction data is not yet implemented.",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// SOC2 Report
// ---------------------------------------------------------------------------

// GenerateSOC2 produces a SOC2 compliance report covering access control,
// security monitoring, incident response, and change management.
func (g *ReportGenerator) GenerateSOC2(tr TimeRange) (*ComplianceReport, error) {
	report := &ComplianceReport{
		Title:       "SOC2 Type II Compliance Evidence Report",
		Standard:    "soc2",
		GeneratedAt: time.Now(),
		TimeRange:   tr,
	}

	events := g.getEventsInRange(tr)

	// Section 1: Access Control
	report.Sections = append(report.Sections, g.soc2AccessControl())

	// Section 2: Security Monitoring
	report.Sections = append(report.Sections, g.soc2SecurityMonitoring(events))

	// Section 3: Incident Response
	report.Sections = append(report.Sections, g.soc2IncidentResponse(events))

	// Section 4: Change Management
	report.Sections = append(report.Sections, g.soc2ChangeManagement())

	return report, nil
}

func (g *ReportGenerator) soc2AccessControl() ReportSection {
	section := ReportSection{
		Title:       "Access Control",
		Description: "Evidence of access control mechanisms for AI services.",
		Status:      "compliant",
	}

	authRules := []struct {
		id    string
		label string
	}{
		{"GR-001", "API Key Authentication"},
		{"GR-002", "mTLS Client Verification"},
		{"GR-003", "RBAC Policy Check"},
		{"GR-004", "Per-User Rate Limit"},
		{"GR-005", "Per-Service Rate Limit"},
	}

	for _, ar := range authRules {
		status := "fail"
		value := "Not configured"
		if g.registry != nil && g.registry.IsEnabled(ar.id) {
			status = "ok"
			value = "Active"
		}
		section.Items = append(section.Items, ReportItem{
			Label:  ar.label,
			Value:  value,
			Status: status,
		})
		if status == "fail" {
			section.Status = "partial"
		}
	}

	return section
}

func (g *ReportGenerator) soc2SecurityMonitoring(events []models.Event) ReportSection {
	section := ReportSection{
		Title:       "Security Monitoring",
		Description: "Evidence of continuous security monitoring for AI interactions.",
		Status:      "compliant",
	}

	// Count active guardrail rules.
	activeRules := 0
	totalRules := 0
	if g.registry != nil {
		for _, rule := range g.registry.All() {
			totalRules++
			if g.registry.IsEnabled(rule.ID()) {
				activeRules++
			}
		}
	}

	section.Items = append(section.Items, ReportItem{
		Label:  "Active Guardrail Rules",
		Value:  fmt.Sprintf("%d of %d rules active", activeRules, totalRules),
		Status: boolStatus(activeRules > 0),
	})

	// Count detection events.
	detectionCount := 0
	blockedCount := 0
	for _, ev := range events {
		if len(ev.Guardrails) > 0 {
			detectionCount++
		}
		if ev.Content.Blocked {
			blockedCount++
		}
	}

	section.Items = append(section.Items, ReportItem{
		Label:  "Detection Events",
		Value:  fmt.Sprintf("%d events analyzed, %d threats blocked", detectionCount, blockedCount),
		Status: "ok",
	})

	section.Items = append(section.Items, ReportItem{
		Label:  "Total Events in Period",
		Value:  fmt.Sprintf("%d", len(events)),
		Status: "ok",
	})

	return section
}

func (g *ReportGenerator) soc2IncidentResponse(events []models.Event) ReportSection {
	section := ReportSection{
		Title:       "Incident Response",
		Description: "Evidence of incident detection and response for AI security threats.",
		Status:      "compliant",
	}

	// Count events by severity.
	severityCounts := make(map[models.Severity]int)
	for _, ev := range events {
		if ev.Content.Blocked {
			severityCounts[ev.Severity]++
		}
	}

	section.Items = append(section.Items, ReportItem{
		Label:  "Critical Threats Blocked",
		Value:  fmt.Sprintf("%d", severityCounts[models.SeverityCritical]),
		Status: "ok",
	})
	section.Items = append(section.Items, ReportItem{
		Label:  "High Threats Blocked",
		Value:  fmt.Sprintf("%d", severityCounts[models.SeverityHigh]),
		Status: "ok",
	})
	section.Items = append(section.Items, ReportItem{
		Label:  "Medium Threats Blocked",
		Value:  fmt.Sprintf("%d", severityCounts[models.SeverityMedium]),
		Status: "ok",
	})

	section.Items = append(section.Items, ReportItem{
		Label:       "Alert Channels",
		Value:       "Configurable via policy (Slack, PagerDuty, Email, Webhook)",
		Status:      "ok",
		Description: "Alert routing is defined in AISecurityPolicy.Spec.Alerts",
	})

	return section
}

func (g *ReportGenerator) soc2ChangeManagement() ReportSection {
	return ReportSection{
		Title:       "Change Management",
		Description: "Evidence of change management processes for AI security policies.",
		Status:      "partial",
		Items: []ReportItem{
			{
				Label:       "Policy Version Control",
				Value:       "Policies are stored as versioned YAML/JSON resources",
				Status:      "ok",
				Description: "AISecurityPolicy resources follow Kubernetes-style versioning.",
			},
			{
				Label:       "Guardrail Rule Updates",
				Value:       "Rules support dynamic configuration via API",
				Status:      "ok",
				Description: "Rule configurations can be updated via PATCH /api/v1/guardrails/{id}.",
			},
			{
				Label:       "Audit Trail for Changes",
				Value:       "Policy changes logged in event store",
				Status:      "warning",
				Description: "Dedicated change audit trail recommended for SOC2 evidence.",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// EU AI Act Report
// ---------------------------------------------------------------------------

// GenerateEUAIAct produces an EU AI Act compliance report covering AI system
// inventory, risk classification, transparency measures, and human oversight.
func (g *ReportGenerator) GenerateEUAIAct(tr TimeRange) (*ComplianceReport, error) {
	report := &ComplianceReport{
		Title:       "EU AI Act Compliance Report",
		Standard:    "eu-ai-act",
		GeneratedAt: time.Now(),
		TimeRange:   tr,
	}

	services := g.getServicesSnapshot()

	// Section 1: AI System Inventory
	report.Sections = append(report.Sections, g.euaiInventory(services))

	// Section 2: Risk Classification
	report.Sections = append(report.Sections, g.euaiRiskClassification(services))

	// Section 3: Transparency Measures
	report.Sections = append(report.Sections, g.euaiTransparency())

	// Section 4: Human Oversight
	report.Sections = append(report.Sections, g.euaiHumanOversight())

	return report, nil
}

func (g *ReportGenerator) euaiInventory(services []models.AIService) ReportSection {
	section := ReportSection{
		Title:       "AI System Inventory",
		Description: "Complete inventory of all AI systems in use across the organization.",
		Status:      "compliant",
	}

	for _, svc := range services {
		exposure := svc.ExposureType
		if exposure == "" {
			exposure = "unknown"
		}
		section.Items = append(section.Items, ReportItem{
			Label:       svc.Name,
			Value:       fmt.Sprintf("Namespace: %s | Team: %s | Exposure: %s | Risk: %.2f", svc.Namespace, svc.Team, exposure, svc.RiskScore),
			Status:      riskStatus(svc.RiskScore),
			Description: fmt.Sprintf("Gateway enrolled: %v | Discovered: %s", svc.GatewayEnrolled, svc.DiscoveredAt.Format(time.DateOnly)),
		})
	}

	// Flag shadow AI.
	shadowCount := 0
	for _, svc := range services {
		if !svc.GatewayEnrolled {
			shadowCount++
		}
	}
	if shadowCount > 0 {
		section.Items = append(section.Items, ReportItem{
			Label:       "Shadow AI Services",
			Value:       fmt.Sprintf("%d unregistered AI service(s) detected", shadowCount),
			Status:      "warning",
			Description: "These services use AI providers but are not enrolled in the governance gateway.",
		})
		section.Status = "partial"
	}

	return section
}

func (g *ReportGenerator) euaiRiskClassification(services []models.AIService) ReportSection {
	section := ReportSection{
		Title:       "Risk Classification",
		Description: "Risk classification of AI systems per EU AI Act risk categories.",
		Status:      "compliant",
	}

	// Classify services by risk level.
	riskBuckets := map[string]int{
		"minimal":     0,
		"limited":     0,
		"high":        0,
		"unacceptable": 0,
	}

	for _, svc := range services {
		switch {
		case svc.RiskScore >= 0.9:
			riskBuckets["unacceptable"]++
		case svc.RiskScore >= 0.7:
			riskBuckets["high"]++
		case svc.RiskScore >= 0.4:
			riskBuckets["limited"]++
		default:
			riskBuckets["minimal"]++
		}
	}

	for level, count := range riskBuckets {
		status := "ok"
		if level == "unacceptable" && count > 0 {
			status = "fail"
			section.Status = "non_compliant"
		} else if level == "high" && count > 0 {
			status = "warning"
			if section.Status == "compliant" {
				section.Status = "partial"
			}
		}
		section.Items = append(section.Items, ReportItem{
			Label:  fmt.Sprintf("%s risk", strings.Title(level)),
			Value:  fmt.Sprintf("%d service(s)", count),
			Status: status,
		})
	}

	return section
}

func (g *ReportGenerator) euaiTransparency() ReportSection {
	section := ReportSection{
		Title:       "Transparency Measures",
		Description: "Audit logging and transparency measures for AI interactions.",
		Status:      "compliant",
	}

	section.Items = append(section.Items, ReportItem{
		Label:       "Audit Logging",
		Value:       "All AI interactions logged via guardrail pipeline",
		Status:      "ok",
		Description: "Every request/response pair is recorded with guardrail evaluation results.",
	})

	section.Items = append(section.Items, ReportItem{
		Label:       "AI Service Discovery",
		Value:       "Automated discovery via eBPF kernel observer and gateway enrollment",
		Status:      "ok",
		Description: "AI services are automatically discovered and inventoried.",
	})

	section.Items = append(section.Items, ReportItem{
		Label:       "AIBOM Generation",
		Value:       "AI Bill of Materials available via /api/v1/inventory/aibom",
		Status:      "ok",
		Description: "Complete inventory of AI components, providers, and models.",
	})

	return section
}

func (g *ReportGenerator) euaiHumanOversight() ReportSection {
	section := ReportSection{
		Title:       "Human Oversight",
		Description: "Guardrail rules and blocking policies providing human oversight of AI systems.",
		Status:      "compliant",
	}

	if g.registry == nil {
		section.Status = "non_compliant"
		section.Items = append(section.Items, ReportItem{
			Label:  "Guardrail Engine",
			Value:  "Not configured",
			Status: "fail",
		})
		return section
	}

	// List active blocking rules as evidence of human oversight.
	activeBlocking := 0
	for _, rule := range g.registry.All() {
		if !g.registry.IsEnabled(rule.ID()) {
			continue
		}
		cfg, ok := g.registry.GetConfig(rule.ID())
		if ok && cfg.Mode == models.ModeEnforce {
			activeBlocking++
		}
	}

	section.Items = append(section.Items, ReportItem{
		Label:  "Active Enforcement Rules",
		Value:  fmt.Sprintf("%d rules in enforce mode", activeBlocking),
		Status: boolStatus(activeBlocking > 0),
	})

	section.Items = append(section.Items, ReportItem{
		Label:       "Content Filtering",
		Value:       "Input and output content is scanned for safety violations",
		Status:      "ok",
		Description: "Injection detection, toxicity filtering, PII protection, and code safety rules provide automated oversight.",
	})

	section.Items = append(section.Items, ReportItem{
		Label:       "Emergency Override",
		Value:       "Enforcement mode can be toggled via API",
		Status:      "ok",
		Description: "Human operators can disable or enable rules in real-time.",
	})

	return section
}

// ---------------------------------------------------------------------------
// Export Functions
// ---------------------------------------------------------------------------

// ExportMarkdown renders a compliance report as a markdown document.
func ExportMarkdown(report *ComplianceReport) string {
	var b strings.Builder

	b.WriteString("# ")
	b.WriteString(report.Title)
	b.WriteString("\n\n")

	b.WriteString("**Standard:** ")
	b.WriteString(report.Standard)
	b.WriteString("\n")

	b.WriteString("**Generated:** ")
	b.WriteString(report.GeneratedAt.Format(time.RFC3339))
	b.WriteString("\n")

	b.WriteString("**Period:** ")
	b.WriteString(report.TimeRange.From.Format(time.DateOnly))
	b.WriteString(" to ")
	b.WriteString(report.TimeRange.To.Format(time.DateOnly))
	b.WriteString("\n\n")

	b.WriteString("---\n\n")

	for _, section := range report.Sections {
		b.WriteString("## ")
		b.WriteString(section.Title)
		b.WriteString("\n\n")

		b.WriteString("**Status:** ")
		b.WriteString(statusEmoji(section.Status))
		b.WriteString(" ")
		b.WriteString(section.Status)
		b.WriteString("\n\n")

		if section.Description != "" {
			b.WriteString(section.Description)
			b.WriteString("\n\n")
		}

		if len(section.Items) > 0 {
			b.WriteString("| Item | Value | Status |\n")
			b.WriteString("|------|-------|--------|\n")
			for _, item := range section.Items {
				b.WriteString("| ")
				b.WriteString(item.Label)
				b.WriteString(" | ")
				b.WriteString(item.Value)
				b.WriteString(" | ")
				b.WriteString(statusEmoji(item.Status))
				b.WriteString(" |\n")
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

// ExportJSON renders a compliance report as structured JSON.
func ExportJSON(report *ComplianceReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// getServicesSnapshot returns all services from the store.
func (g *ReportGenerator) getServicesSnapshot() []models.AIService {
	if g.store == nil {
		return nil
	}
	// Get all services using a broad filter.
	result := g.store.GetServices(store.ServiceFilter{Page: 1, PerPage: 100})
	return result.Data
}

// getEventsInRange returns events within the given time range.
func (g *ReportGenerator) getEventsInRange(tr TimeRange) []models.Event {
	if g.store == nil {
		return nil
	}
	result := g.store.GetEvents(store.EventFilter{
		From:    tr.From,
		To:      tr.To,
		Page:    1,
		PerPage: 100,
	})
	return result.Data
}

func boolStatus(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

func riskStatus(score float64) string {
	switch {
	case score >= 0.7:
		return "warning"
	case score >= 0.4:
		return "ok"
	default:
		return "ok"
	}
}

func statusEmoji(status string) string {
	switch status {
	case "compliant", "ok":
		return "[PASS]"
	case "partial", "warning":
		return "[WARN]"
	case "non_compliant", "fail":
		return "[FAIL]"
	default:
		return "[----]"
	}
}
