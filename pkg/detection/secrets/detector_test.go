package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

func makeCtx(prompt string) *guardrails.EvalContext {
	ctx := guardrails.NewEvalContext(context.Background())
	ctx.WithPrompt(prompt)
	return ctx
}

func TestDetector_SecretTypes(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantType  string
		wantBlock bool
	}{
		{
			"aws access key",
			"Here is my key: AKIAIOSFODNN7EXAMPLE",
			"aws_access_key",
			true,
		},
		{
			"github token",
			"Use this token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123",
			"github_token",
			true,
		},
		{
			"openai key project",
			"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH",
			"openai_key",
			true,
		},
		{
			"anthropic key",
			"sk-ant-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH",
			"anthropic_key",
			true,
		},
		{
			"private key header",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z...",
			"private_key",
			true,
		},
		{
			"password assignment",
			`password = "SuperSecretP@ssw0rd!"`,
			"password",
			true,
		},
		{
			"connection string postgres",
			"postgresql://admin:secretpass@db.example.com:5432/mydb",
			"connection_string",
			true,
		},
		{
			"connection string mongodb",
			"mongodb://user:p4ssw0rd@mongo.example.com:27017/app",
			"connection_string",
			true,
		},
		{
			"bearer token",
			`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
			"bearer_token",
			true,
		},
	}

	d := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval, err := d.Evaluate(makeCtx(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantBlock && eval.Decision != models.DecisionBlock {
				t.Errorf("expected block for %q, got %s", tt.name, eval.Decision)
			}
			if tt.wantType != "" {
				found := false
				for _, f := range eval.Findings {
					if f.Type == tt.wantType {
						found = true
						break
					}
				}
				if !found {
					types := make([]string, len(eval.Findings))
					for i, f := range eval.Findings {
						types[i] = f.Type
					}
					t.Errorf("expected finding type %q, got %v", tt.wantType, types)
				}
			}
		})
	}
}

func TestDetector_HighEntropyString(t *testing.T) {
	// A high-entropy random-looking string should be flagged.
	d := New()
	input := "Check this token: aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9"
	eval, err := d.Evaluate(makeCtx(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have at least one finding (either pattern or entropy).
	if len(eval.Findings) == 0 {
		t.Error("expected at least one finding for high-entropy string")
	}
}

func TestDetector_CleanText(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"normal prose", "The quick brown fox jumps over the lazy dog"},
		{"code without secrets", "func main() { fmt.Println(\"hello world\") }"},
		{"technical doc", "Kubernetes pods run in namespaces for isolation"},
		{"short text", "Hello"},
		{"numbers only", "The result is 42 and pi is 3.14159"},
	}

	d := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval, err := d.Evaluate(makeCtx(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eval.Decision != models.DecisionAllow {
				t.Errorf("expected allow for clean text %q, got %s (%d findings)",
					tt.input, eval.Decision, len(eval.Findings))
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

func TestDetector_RedactedValues(t *testing.T) {
	d := New()
	input := "AKIAIOSFODNN7EXAMPLE"
	eval, err := d.Evaluate(makeCtx(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range eval.Findings {
		if f.Type == "aws_access_key" {
			if f.Value == input {
				t.Error("finding value should be redacted, but got the full key")
			}
			if !strings.Contains(f.Value, "****") && !strings.Contains(f.Value, "***") {
				t.Errorf("expected redacted value with asterisks, got %q", f.Value)
			}
		}
	}
}

func TestDetector_RuleMetadata(t *testing.T) {
	d := New()
	if d.ID() != "GR-012" {
		t.Errorf("expected ID GR-012, got %s", d.ID())
	}
	if d.Stage() != models.StageInput {
		t.Errorf("expected stage input, got %s", d.Stage())
	}
	if d.Category() != models.CategorySecrets {
		t.Errorf("expected category secrets, got %s", d.Category())
	}
}

func TestDetector_Configure_DisableEntropy(t *testing.T) {
	d := New()
	err := d.Configure(map[string]any{
		"disable_entropy": true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A borderline entropy-only string should be allowed with entropy disabled.
	input := "Check this token: aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9"
	eval, err := d.Evaluate(makeCtx(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With entropy disabled, we should have no high_entropy_string findings.
	for _, f := range eval.Findings {
		if f.Type == "high_entropy_string" {
			t.Error("expected no high_entropy_string findings when entropy is disabled")
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		minEnt float64
		maxEnt float64
	}{
		{"empty", "", 0, 0.01},
		{"single char", "aaaa", 0, 0.01},
		{"low entropy", "aabbccdd", 1.9, 2.1},
		{"high entropy mixed", "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v", 4.0, 6.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := shannonEntropy(tt.input)
			if e < tt.minEnt || e > tt.maxEnt {
				t.Errorf("shannonEntropy(%q) = %.2f, want [%.2f, %.2f]",
					tt.input, e, tt.minEnt, tt.maxEnt)
			}
		})
	}
}
