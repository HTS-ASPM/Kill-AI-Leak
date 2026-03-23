// Package alerting provides interfaces and implementations for sending
// security alerts when guardrail rules block requests. Supported backends
// include generic webhooks, Slack (Block Kit), and fan-out via MultiAlerter.
package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Alert contains the details of a security alert to be sent.
type Alert struct {
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	RuleID    string            `json:"rule_id,omitempty"`
	Actor     string            `json:"actor,omitempty"`
	Provider  string            `json:"provider,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Details   map[string]string `json:"details,omitempty"`
}

// Alerter is the interface for sending security alerts.
type Alerter interface {
	// SendAlert delivers an alert to the configured destination.
	SendAlert(alert Alert) error
}

// ---------------------------------------------------------------------------
// WebhookAlerter -- generic JSON webhook
// ---------------------------------------------------------------------------

// WebhookAlerter sends alerts as JSON POST requests to any webhook URL.
type WebhookAlerter struct {
	url    string
	client *http.Client
}

// NewWebhookAlerter creates a WebhookAlerter targeting the given URL.
func NewWebhookAlerter(url string) *WebhookAlerter {
	return &WebhookAlerter{
		url: url,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SendAlert sends the alert as a JSON payload to the webhook URL.
func (w *WebhookAlerter) SendAlert(alert Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("webhook alerter: marshal: %w", err)
	}

	resp, err := w.client.Post(w.url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook alerter: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook alerter: server returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// SlackAlerter -- Slack Block Kit formatted messages
// ---------------------------------------------------------------------------

// SlackAlerter sends alerts formatted as Slack Block Kit messages to a
// Slack Incoming Webhook URL.
type SlackAlerter struct {
	webhookURL string
	client     *http.Client
}

// NewSlackAlerter creates a SlackAlerter targeting the given Slack webhook URL.
func NewSlackAlerter(webhookURL string) *SlackAlerter {
	return &SlackAlerter{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SendAlert formats the alert as a Slack Block Kit message and sends it.
func (s *SlackAlerter) SendAlert(alert Alert) error {
	emoji := severityEmoji(alert.Severity)

	// Build detail fields for the Slack message.
	var fields []map[string]any
	fields = append(fields, slackField("Severity", alert.Severity))
	if alert.RuleID != "" {
		fields = append(fields, slackField("Rule", alert.RuleID))
	}
	if alert.Actor != "" {
		fields = append(fields, slackField("Actor", alert.Actor))
	}
	if alert.Provider != "" {
		fields = append(fields, slackField("Provider", alert.Provider))
	}
	fields = append(fields, slackField("Time", alert.Timestamp.Format(time.RFC3339)))

	for k, v := range alert.Details {
		fields = append(fields, slackField(k, v))
	}

	// Build Slack Block Kit payload.
	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type":  "plain_text",
				"text":  fmt.Sprintf("%s %s", emoji, alert.Title),
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": alert.Message,
			},
		},
		{
			"type":   "section",
			"fields": fields,
		},
		{
			"type": "divider",
		},
		{
			"type": "context",
			"elements": []map[string]any{
				{
					"type": "mrkdwn",
					"text": "Sent by *Kill-AI-Leak* Security Platform",
				},
			},
		},
	}

	payload := map[string]any{
		"blocks": blocks,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack alerter: marshal: %w", err)
	}

	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack alerter: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack alerter: server returned %d", resp.StatusCode)
	}
	return nil
}

// slackField creates a Slack section field.
func slackField(label, value string) map[string]any {
	return map[string]any{
		"type": "mrkdwn",
		"text": fmt.Sprintf("*%s:*\n%s", label, value),
	}
}

// severityEmoji returns a text indicator for the severity level.
func severityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "[CRITICAL]"
	case "high":
		return "[HIGH]"
	case "medium":
		return "[MEDIUM]"
	case "low":
		return "[LOW]"
	default:
		return "[INFO]"
	}
}

// ---------------------------------------------------------------------------
// MultiAlerter -- fan-out to multiple backends
// ---------------------------------------------------------------------------

// MultiAlerter sends alerts to multiple Alerter backends. If any one fails
// the error is collected but delivery continues to the remaining backends.
type MultiAlerter struct {
	alerters []Alerter
}

// NewMultiAlerter creates a MultiAlerter that fans out to all provided alerters.
func NewMultiAlerter(alerters ...Alerter) *MultiAlerter {
	return &MultiAlerter{alerters: alerters}
}

// SendAlert sends the alert to every configured backend, collecting errors.
func (m *MultiAlerter) SendAlert(alert Alert) error {
	var errs []string
	for _, a := range m.alerters {
		if err := a.SendAlert(alert); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("multi alerter: %d/%d backends failed: %s",
			len(errs), len(m.alerters), strings.Join(errs, "; "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// NewAlerterFromConfig creates an Alerter from the alerting configuration.
// It returns nil if alerting is disabled or no backends are configured.
// ---------------------------------------------------------------------------

// AlertConfig holds the alerting configuration. This mirrors the config
// struct but is defined here to avoid import cycles.
type AlertConfig struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	SlackURL    string `json:"slack_url" yaml:"slack_url"`
	WebhookURL  string `json:"webhook_url" yaml:"webhook_url"`
	MinSeverity string `json:"min_severity" yaml:"min_severity"`
}

// NewAlerterFromConfig builds the appropriate Alerter (or nil) from config.
func NewAlerterFromConfig(cfg AlertConfig) Alerter {
	if !cfg.Enabled {
		return nil
	}

	var alerters []Alerter

	if cfg.SlackURL != "" {
		alerters = append(alerters, NewSlackAlerter(cfg.SlackURL))
	}
	if cfg.WebhookURL != "" {
		alerters = append(alerters, NewWebhookAlerter(cfg.WebhookURL))
	}

	switch len(alerters) {
	case 0:
		return nil
	case 1:
		return alerters[0]
	default:
		return NewMultiAlerter(alerters...)
	}
}

// ShouldAlert returns true if the given severity meets or exceeds the minimum
// severity threshold.
func ShouldAlert(eventSeverity, minSeverity string) bool {
	return severityRank(eventSeverity) >= severityRank(minSeverity)
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
