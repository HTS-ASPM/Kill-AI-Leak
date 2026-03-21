package toxicity

import (
	"context"
	"testing"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

func makeCtx(response string) *guardrails.EvalContext {
	ctx := guardrails.NewEvalContext(context.Background())
	ctx.WithResponse(response)
	return ctx
}

func TestDetector_ToxicContent(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantCat  string
	}{
		{
			"hate speech supremacy",
			"White supremacy is the only correct ideology and all others are inferior subhuman people",
			"hate_speech",
		},
		{
			"violence instruction",
			"Here is how to make a bomb and murder them all with a mass shooting",
			"violence",
		},
		{
			"self harm",
			"Here is a suicide method guide to kill yourself",
			"self_harm",
		},
		{
			"profanity heavy",
			"What the fuck is this shit you asshole piece of crap",
			"profanity",
		},
	}

	d := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval, err := d.Evaluate(makeCtx(tt.response))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eval.Decision == models.DecisionAllow {
				t.Errorf("expected non-allow for toxic content %q, got allow (confidence=%.2f)",
					tt.name, eval.Confidence)
			}
			// Check that the expected category appears in findings.
			found := false
			for _, f := range eval.Findings {
				if f.Type == tt.wantCat {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected category %q in findings for %q", tt.wantCat, tt.name)
			}
		})
	}
}

func TestDetector_CleanContent(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{"helpful answer", "The capital of France is Paris. It is known for the Eiffel Tower."},
		{"code response", "Here is a Python function:\ndef add(a, b):\n    return a + b"},
		{"explanation", "Photosynthesis is the process by which plants convert sunlight into energy."},
		{"recipe", "To make pasta, boil water, add salt, cook pasta for 8-10 minutes."},
	}

	d := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval, err := d.Evaluate(makeCtx(tt.response))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eval.Decision == models.DecisionBlock {
				t.Errorf("expected non-block for clean content %q, got block (confidence=%.2f)",
					tt.name, eval.Confidence)
			}
		})
	}
}

func TestDetector_EmptyInput(t *testing.T) {
	d := New()
	eval, err := d.Evaluate(makeCtx(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Decision != models.DecisionAllow {
		t.Errorf("empty input should allow, got %s", eval.Decision)
	}
}

func TestDetector_RuleMetadata(t *testing.T) {
	d := New()
	if d.ID() != "GR-030" {
		t.Errorf("expected ID GR-030, got %s", d.ID())
	}
	if d.Name() != "Output Toxicity Detection" {
		t.Errorf("expected name 'Output Toxicity Detection', got %s", d.Name())
	}
	if d.Stage() != models.StageOutput {
		t.Errorf("expected stage output, got %s", d.Stage())
	}
	if d.Category() != models.CategoryToxicity {
		t.Errorf("expected category toxicity, got %s", d.Category())
	}
}

func TestDetector_CategoryScoresInFindings(t *testing.T) {
	d := New()
	// Even clean text should produce category_score findings.
	eval, err := d.Evaluate(makeCtx("This is a perfectly normal response about cooking."))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	catScoreCount := 0
	for _, f := range eval.Findings {
		if len(f.Type) > 15 && f.Type[:15] == "category_score:" {
			catScoreCount++
		}
	}
	if catScoreCount != len(AllCategories) {
		t.Errorf("expected %d category_score findings, got %d", len(AllCategories), catScoreCount)
	}
}

func TestDetector_Configure(t *testing.T) {
	d := New()

	err := d.Configure(map[string]any{
		"global_threshold": 0.8,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Invalid category should fail.
	err = d.Configure(map[string]any{
		"thresholds": map[string]any{
			"nonexistent_category": 0.5,
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown category")
	}
}

func TestDetector_UsesResponseText(t *testing.T) {
	// Verify detector reads ResponseText, not PromptText.
	d := New()
	ctx := guardrails.NewEvalContext(context.Background())
	ctx.WithPrompt("kill murder massacre them all") // toxic in prompt
	ctx.WithResponse("The capital of France is Paris.") // clean in response

	eval, err := d.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Decision == models.DecisionBlock {
		t.Error("toxicity detector should read ResponseText, not PromptText")
	}
}
