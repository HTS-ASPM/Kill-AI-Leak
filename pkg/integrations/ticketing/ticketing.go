// Package ticketing provides integrations for creating tickets in external
// issue-tracking systems when security events exceed configured severity
// thresholds. Supported providers include Jira, Linear, and generic webhooks.
package ticketing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Ticket / TicketResult — common types
// ---------------------------------------------------------------------------

// Ticket holds the information needed to create a ticket in an external
// issue-tracking system.
type Ticket struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Labels      []string          `json:"labels,omitempty"`
	Assignee    string            `json:"assignee,omitempty"`
	Project     string            `json:"project,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// TicketResult holds the response from creating a ticket.
type TicketResult struct {
	ID     string `json:"id"`
	URL    string `json:"url"`
	Status string `json:"status"`
}

// ---------------------------------------------------------------------------
// TicketingClient interface
// ---------------------------------------------------------------------------

// TicketingClient defines the interface for creating tickets in external
// issue-tracking systems.
type TicketingClient interface {
	// CreateTicket creates a new ticket and returns the result.
	CreateTicket(ticket Ticket) (*TicketResult, error)
}

// TicketingConfig holds configuration for a ticketing provider.
type TicketingConfig struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	Provider    string `json:"provider" yaml:"provider"`         // "jira", "linear", "webhook"
	BaseURL     string `json:"base_url" yaml:"base_url"`         // Jira base URL / webhook URL
	APIKey      string `json:"api_key" yaml:"api_key"`           // API token / key
	Email       string `json:"email" yaml:"email"`               // Jira email (for basic auth)
	ProjectKey  string `json:"project_key" yaml:"project_key"`   // Jira project key / Linear team ID
	IssueType   string `json:"issue_type" yaml:"issue_type"`     // Jira issue type (default: "Bug")
	AutoCreate  bool   `json:"auto_create" yaml:"auto_create"`   // Auto-create on high-severity blocks
	MinSeverity string `json:"min_severity" yaml:"min_severity"` // Min severity for auto-creation
}

// NewTicketingClientFromConfig creates the appropriate TicketingClient from
// configuration. Returns nil if ticketing is disabled or the provider is
// unrecognized.
func NewTicketingClientFromConfig(cfg TicketingConfig) TicketingClient {
	if !cfg.Enabled {
		return nil
	}

	switch strings.ToLower(cfg.Provider) {
	case "jira":
		issueType := cfg.IssueType
		if issueType == "" {
			issueType = "Bug"
		}
		return &JiraClient{
			baseURL:    strings.TrimSuffix(cfg.BaseURL, "/"),
			email:      cfg.Email,
			apiToken:   cfg.APIKey,
			projectKey: cfg.ProjectKey,
			issueType:  issueType,
			client:     &http.Client{Timeout: 15 * time.Second},
		}
	case "linear":
		return &LinearClient{
			apiKey: cfg.APIKey,
			teamID: cfg.ProjectKey,
			client: &http.Client{Timeout: 15 * time.Second},
		}
	case "webhook":
		return &WebhookTicketing{
			endpoint: cfg.BaseURL,
			token:    cfg.APIKey,
			client:   &http.Client{Timeout: 10 * time.Second},
		}
	default:
		return nil
	}
}

// ShouldCreateTicket returns true if the given severity meets or exceeds
// the minimum severity threshold for auto-ticket creation.
func ShouldCreateTicket(eventSeverity, minSeverity string) bool {
	return severityRank(eventSeverity) >= severityRank(minSeverity)
}

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

// ---------------------------------------------------------------------------
// JiraClient — Jira REST API v3
// ---------------------------------------------------------------------------

// JiraClient creates issues in Jira via the REST API v3.
type JiraClient struct {
	baseURL    string
	email      string
	apiToken   string
	projectKey string
	issueType  string
	client     *http.Client
}

// jiraCreateRequest is the JSON body for creating a Jira issue.
type jiraCreateRequest struct {
	Fields jiraFields `json:"fields"`
}

type jiraFields struct {
	Project   jiraProject   `json:"project"`
	Summary   string        `json:"summary"`
	IssueType jiraIssueType `json:"issuetype"`
	Priority  *jiraPriority `json:"priority,omitempty"`
	Labels    []string      `json:"labels,omitempty"`
	Description *jiraADF    `json:"description,omitempty"`
}

type jiraProject struct {
	Key string `json:"key"`
}

type jiraIssueType struct {
	Name string `json:"name"`
}

type jiraPriority struct {
	Name string `json:"name"`
}

// jiraADF is a minimal Atlassian Document Format (ADF) document.
type jiraADF struct {
	Type    string        `json:"type"`
	Version int           `json:"version"`
	Content []jiraADFNode `json:"content"`
}

type jiraADFNode struct {
	Type    string        `json:"type"`
	Content []jiraADFText `json:"content,omitempty"`
}

type jiraADFText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// jiraCreateResponse holds the Jira issue creation response.
type jiraCreateResponse struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Self string `json:"self"`
}

// CreateTicket creates a Jira issue via REST API v3.
func (j *JiraClient) CreateTicket(ticket Ticket) (*TicketResult, error) {
	labels := append([]string{"kill-ai-leak", "security"}, ticket.Labels...)

	reqBody := jiraCreateRequest{
		Fields: jiraFields{
			Project:   jiraProject{Key: j.projectKey},
			Summary:   ticket.Title,
			IssueType: jiraIssueType{Name: j.issueType},
			Priority:  &jiraPriority{Name: jiraPriority_(ticket.Severity)},
			Labels:    labels,
			Description: &jiraADF{
				Type:    "doc",
				Version: 1,
				Content: []jiraADFNode{
					{
						Type: "paragraph",
						Content: []jiraADFText{
							{Type: "text", Text: ticket.Description},
						},
					},
				},
			},
		},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ticketing jira: marshal: %w", err)
	}

	url := j.baseURL + "/rest/api/3/issue"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("ticketing jira: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(j.email, j.apiToken)

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ticketing jira: post: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ticketing jira: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ticketing jira: server returned %d: %s", resp.StatusCode, string(body))
	}

	var result jiraCreateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ticketing jira: parse response: %w", err)
	}

	return &TicketResult{
		ID:     result.Key,
		URL:    fmt.Sprintf("%s/browse/%s", j.baseURL, result.Key),
		Status: "created",
	}, nil
}

// jiraPriority_ maps severity to Jira priority name.
func jiraPriority_(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Medium"
	}
}

// ---------------------------------------------------------------------------
// LinearClient — Linear GraphQL API
// ---------------------------------------------------------------------------

// LinearClient creates issues in Linear via the GraphQL API.
type LinearClient struct {
	apiKey string
	teamID string
	client *http.Client
}

// linearRequest is the GraphQL request body.
type linearRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

// linearResponse is the GraphQL response.
type linearResponse struct {
	Data struct {
		IssueCreate struct {
			Success bool `json:"success"`
			Issue   struct {
				ID         string `json:"id"`
				Identifier string `json:"identifier"`
				URL        string `json:"url"`
			} `json:"issue"`
		} `json:"issueCreate"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// CreateTicket creates a Linear issue via the GraphQL API.
func (l *LinearClient) CreateTicket(ticket Ticket) (*TicketResult, error) {
	mutation := `mutation IssueCreate($input: IssueCreateInput!) {
		issueCreate(input: $input) {
			success
			issue {
				id
				identifier
				url
			}
		}
	}`

	labels := append([]string{"kill-ai-leak"}, ticket.Labels...)

	input := map[string]interface{}{
		"teamId":      l.teamID,
		"title":       ticket.Title,
		"description": ticket.Description,
		"priority":    linearPriority(ticket.Severity),
		"labelIds":    labels,
	}

	if ticket.Assignee != "" {
		input["assigneeId"] = ticket.Assignee
	}

	reqBody := linearRequest{
		Query: mutation,
		Variables: map[string]interface{}{
			"input": input,
		},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ticketing linear: marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.linear.app/graphql", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("ticketing linear: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", l.apiKey)

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ticketing linear: post: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ticketing linear: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ticketing linear: server returned %d: %s", resp.StatusCode, string(body))
	}

	var result linearResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ticketing linear: parse response: %w", err)
	}

	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("ticketing linear: graphql error: %s", result.Errors[0].Message)
	}

	if !result.Data.IssueCreate.Success {
		return nil, fmt.Errorf("ticketing linear: issue creation reported failure")
	}

	return &TicketResult{
		ID:     result.Data.IssueCreate.Issue.Identifier,
		URL:    result.Data.IssueCreate.Issue.URL,
		Status: "created",
	}, nil
}

// linearPriority maps severity to Linear priority (0=no priority, 1=urgent, 2=high, 3=medium, 4=low).
func linearPriority(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// WebhookTicketing — generic webhook POST
// ---------------------------------------------------------------------------

// WebhookTicketing sends ticket creation requests as JSON POST to any
// HTTP endpoint. This allows integration with any ticketing system that
// accepts webhook payloads.
type WebhookTicketing struct {
	endpoint string
	token    string
	client   *http.Client
}

// CreateTicket sends the ticket as a JSON POST to the configured endpoint.
func (w *WebhookTicketing) CreateTicket(ticket Ticket) (*TicketResult, error) {
	payload, err := json.Marshal(ticket)
	if err != nil {
		return nil, fmt.Errorf("ticketing webhook: marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, w.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("ticketing webhook: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ticketing webhook: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ticketing webhook: server returned %d: %s", resp.StatusCode, string(body))
	}

	// Attempt to parse a response with id/url.
	body, _ := io.ReadAll(resp.Body)
	var result TicketResult
	if err := json.Unmarshal(body, &result); err != nil {
		// If the webhook doesn't return structured JSON, return a
		// generic success result.
		return &TicketResult{
			ID:     "webhook-accepted",
			Status: "created",
		}, nil
	}
	if result.Status == "" {
		result.Status = "created"
	}
	return &result, nil
}
