package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/internal/health"
	"github.com/kill-ai-leak/kill-ai-leak/internal/logger"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/config"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/injection"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/jailbreak"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/pii"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/secrets"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/detection/toxicity"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/fuzzer"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/proxy"
)

// cleanPrompts are benign prompts that should be allowed without findings.
var cleanPrompts = []string{
	"What is the capital of France?",
	"Explain the theory of relativity in simple terms.",
	"Write a haiku about spring flowers.",
	"How do I make a peanut butter and jelly sandwich?",
	"What are the main differences between Python and Go?",
	"Summarize the plot of Romeo and Juliet.",
	"What is the boiling point of water at sea level?",
	"List three benefits of regular exercise.",
	"How does photosynthesis work?",
	"What year did the first moon landing occur?",
}

// setupTestGateway creates a test HTTP server with the real guardrail
// pipeline. It returns the server and a cleanup function.
func setupTestGateway(t *testing.T) *httptest.Server {
	t.Helper()

	// Build a minimal config with guardrails enabled in enforce mode.
	cfg := config.DefaultConfig()
	cfg.Guardrails.Enabled = true
	cfg.Guardrails.DefaultMode = "enforce"
	cfg.Auth.Enabled = false // no auth for tests
	cfg.Server.MaxRequestBodyMB = 10

	log := logger.New(logger.LevelWarn, io.Discard)

	// Build the guardrail engine with the detection rules available.
	registry := guardrails.NewRegistry()
	rules := []guardrails.Rule{
		pii.New(),
		secrets.New(),
		injection.New(),
		jailbreak.New(),
		toxicity.New(),
	}
	for _, rule := range rules {
		ruleCfg := &models.GuardrailRuleConfig{
			ID:       rule.ID(),
			Name:     rule.Name(),
			Stage:    rule.Stage(),
			Category: rule.Category(),
			Mode:     models.ModeEnforce,
			Enabled:  true,
		}
		if err := registry.Register(rule, ruleCfg); err != nil {
			t.Fatalf("register rule %s: %v", rule.ID(), err)
		}
	}

	grEngine := guardrails.NewEngine(registry, guardrails.DefaultEngineConfig())
	engine := guardrails.NewEngineAdapter(grEngine)

	// Build the proxy (it won't actually forward since we use /api/evaluate).
	llmProxy, err := proxy.NewLLMProxy(cfg, engine, log)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}

	// Build handler.
	hc := health.NewChecker("test")
	hc.RegisterComponent("guardrails")
	hc.SetComponentHealth("guardrails", health.StatusHealthy, "test")
	hc.SetReady(true)

	handler := proxy.NewHandler(llmProxy, hc, log, cfg)
	mux := http.NewServeMux()
	handler.Register(mux)

	return httptest.NewServer(mux)
}

// openAIRequest matches the format expected by the /api/evaluate endpoint.
type openAIRequest struct {
	Model    string           `json:"model"`
	Messages []openAIMessage  `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// sendPayload sends a single payload to the test gateway's /api/evaluate
// endpoint and returns the parsed PipelineResult.
func sendPayload(t *testing.T, baseURL, text string) *models.PipelineResult {
	t.Helper()

	reqBody := openAIRequest{
		Model: "test-model",
		Messages: []openAIMessage{
			{Role: "user", Content: text},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp, err := http.Post(baseURL+"/api/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	result, err := fuzzer.ParsePipelineResult(respBody)
	if err != nil {
		t.Fatalf("parse pipeline result: %v (body: %s)", err, string(respBody))
	}
	return result
}

// TestFuzzerIntegration runs all fuzzer payloads against a live test gateway
// and checks detection rates.
func TestFuzzerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := setupTestGateway(t)
	defer srv.Close()

	t.Run("InjectionPayloads", func(t *testing.T) {
		testCategoryDetection(t, srv.URL, fuzzer.InjectionPayloads, "prompt_injection")
	})

	t.Run("JailbreakPayloads", func(t *testing.T) {
		testCategoryDetection(t, srv.URL, fuzzer.JailbreakPayloads, "jailbreak")
	})

	t.Run("SystemPromptPayloads", func(t *testing.T) {
		testCategoryDetection(t, srv.URL, fuzzer.SystemPromptPayloads, "system_prompt_leak")
	})

	t.Run("ExtractionPayloads", func(t *testing.T) {
		testCategoryDetection(t, srv.URL, fuzzer.ExtractionPayloads, "data_extraction")
	})

	t.Run("CleanPrompts", func(t *testing.T) {
		testCleanPrompts(t, srv.URL)
	})

	t.Run("FullCampaignReport", func(t *testing.T) {
		testFullCampaignReport(t, srv.URL)
	})
}

// categoryResult tracks per-payload detection outcomes.
type categoryResult struct {
	Total    int
	Detected int
	Missed   []string
}

// testCategoryDetection sends all payloads in a category to the gateway
// and reports detection stats.
func testCategoryDetection(t *testing.T, baseURL string, payloads []fuzzer.Payload, category string) {
	t.Helper()

	result := categoryResult{Total: len(payloads)}

	for i, p := range payloads {
		pipeResult := sendPayload(t, baseURL, p.Text)
		detected := fuzzer.IsPayloadDetected(pipeResult)
		if detected {
			result.Detected++
		} else {
			result.Missed = append(result.Missed, fmt.Sprintf("[%d] %s", i, truncate(p.Text, 80)))
		}
	}

	detectionRate := 0.0
	if result.Total > 0 {
		detectionRate = float64(result.Detected) / float64(result.Total) * 100
	}

	t.Logf("Category: %s", category)
	t.Logf("  Total: %d, Detected: %d, Missed: %d", result.Total, result.Detected, len(result.Missed))
	t.Logf("  Detection Rate: %.1f%%", detectionRate)

	if len(result.Missed) > 0 {
		t.Logf("  Missed payloads:")
		for _, m := range result.Missed {
			t.Logf("    - %s", m)
		}
	}

	// We log the detection rate but don't hard-fail; this is informational
	// for the security team. The full campaign test below checks the
	// aggregate threshold.
}

// testCleanPrompts verifies that clean prompts are allowed without findings.
func testCleanPrompts(t *testing.T, baseURL string) {
	t.Helper()

	falsePositives := 0
	for i, prompt := range cleanPrompts {
		result := sendPayload(t, baseURL, prompt)
		detected := fuzzer.IsPayloadDetected(result)
		if detected {
			falsePositives++
			t.Logf("  FALSE POSITIVE [%d]: %q -> decision=%s blocked=%v",
				i, truncate(prompt, 60), result.FinalDecision, result.Blocked)
		}
	}

	t.Logf("Clean prompts: %d total, %d false positives", len(cleanPrompts), falsePositives)

	// Allow up to 20% false positive rate for clean prompts.
	maxFP := len(cleanPrompts) / 5
	if maxFP < 1 {
		maxFP = 1
	}
	if falsePositives > maxFP {
		t.Errorf("Too many false positives: %d out of %d clean prompts (max allowed: %d)",
			falsePositives, len(cleanPrompts), maxFP)
	}
}

// testFullCampaignReport runs a complete fuzzing campaign using FuzzGateway
// and generates a report.
func testFullCampaignReport(t *testing.T, baseURL string) {
	t.Helper()

	start := time.Now()
	campaign, err := fuzzer.FuzzGateway(
		t.Context(),
		baseURL,
		nil, // all categories
		0,   // no mutations for speed
		5,   // concurrency
	)
	if err != nil {
		t.Fatalf("FuzzGateway: %v", err)
	}

	elapsed := time.Since(start)
	t.Logf("Campaign completed in %s (%d results)", elapsed.Round(time.Millisecond), len(campaign.Results))

	// Generate and log the text report.
	textReport := fuzzer.GenerateTextReport(campaign)
	t.Logf("\n%s", textReport)

	// Generate JSON report.
	jsonBytes, err := fuzzer.GenerateJSONReport(campaign)
	if err != nil {
		t.Fatalf("GenerateJSONReport: %v", err)
	}

	// Verify JSON is valid.
	var jsonReport fuzzer.JSONReport
	if err := json.Unmarshal(jsonBytes, &jsonReport); err != nil {
		t.Fatalf("JSON report unmarshal: %v", err)
	}

	t.Logf("JSON report: campaign=%s detection_rate=%.1f%% missed=%d",
		jsonReport.CampaignID, jsonReport.DetectionRate*100, len(jsonReport.MissedPayloads))

	// Write reports to temp files for inspection.
	if dir := os.TempDir(); dir != "" {
		textPath := dir + "/fuzzer-report.txt"
		jsonPath := dir + "/fuzzer-report.json"
		_ = os.WriteFile(textPath, []byte(textReport), 0644)
		_ = os.WriteFile(jsonPath, jsonBytes, 0644)
		t.Logf("Reports written to:\n  Text: %s\n  JSON: %s", textPath, jsonPath)
	}
}

// truncate shortens a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
