package pii

import (
	"context"
	"testing"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

func makeCtx(prompt string) *guardrails.EvalContext {
	ctx := guardrails.NewEvalContext(context.Background())
	ctx.WithPrompt(prompt)
	return ctx
}

func TestDetector_PIITypes(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantType    string
		wantDetect  bool
	}{
		// Email
		{"email", "Contact me at john.doe@example.com for details", "email", true},
		// Phone
		{"phone US", "Call me at (555) 123-4567 anytime", "phone", true},
		{"phone intl", "My number is +1-555-123-4567", "phone", true},
		// SSN
		{"ssn", "My SSN is 123-45-6789", "ssn", true},
		// Credit card (no dashes)
		{"credit card visa", "Card: 4111111111111111", "credit_card", true},
		// Credit card (with dashes)
		{"credit card dashes", "Card: 4111-1111-1111-1111", "credit_card", true},
		// Credit card (with spaces)
		{"credit card spaces", "Card: 4111 1111 1111 1111", "credit_card", true},
		// IP address
		{"ip address", "Server is at 192.168.1.100 on the network", "ip_address", true},
		// AWS key
		{"aws access key", "Key: AKIAIOSFODNN7EXAMPLE", "aws_access_key", true},
		// GitHub token
		{"github token", "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123", "github_token", true},
		// JWT
		{"jwt", "Auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "jwt", true},
	}

	d := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval, err := d.Evaluate(makeCtx(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantDetect {
				if eval.Decision == models.DecisionAllow {
					t.Errorf("expected PII detection for %q, but got allow", tt.input)
				}
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
					t.Errorf("expected finding type %q, got types %v", tt.wantType, types)
				}
			}
		})
	}
}

func TestDetector_FalsePositiveResistance(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"date like ssn", "The event is on 12-34-5678 at noon"},
		{"version number", "Use version 3.14.159 of the library"},
		{"normal number", "The answer is 42"},
		{"short number", "Room 101"},
		{"sentence with numbers", "I scored 95 on the test out of 100"},
	}

	d := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval, err := d.Evaluate(makeCtx(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// These inputs should not trigger SSN or credit card findings.
			for _, f := range eval.Findings {
				if f.Type == "ssn" || f.Type == "credit_card" {
					t.Errorf("false positive: detected %s in %q", f.Type, tt.input)
				}
			}
		})
	}
}

func TestDetector_MultiplePII(t *testing.T) {
	input := "Email me at alice@example.com, my SSN is 123-45-6789, and my card is 4111111111111111"

	d := New()
	eval, err := d.Evaluate(makeCtx(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(eval.Findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(eval.Findings))
	}

	typeSet := make(map[string]bool)
	for _, f := range eval.Findings {
		typeSet[f.Type] = true
	}
	for _, want := range []string{"email", "ssn", "credit_card"} {
		if !typeSet[want] {
			t.Errorf("expected finding type %q in multi-PII text", want)
		}
	}
}

func TestDetector_NoPII(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"clean sentence", "The quick brown fox jumps over the lazy dog"},
		{"code snippet", "func main() { fmt.Println(\"hello\") }"},
		{"technical doc", "Kubernetes uses etcd as its backing store for all cluster data"},
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

func TestDetector_RuleMetadata(t *testing.T) {
	d := New()
	if d.ID() != "GR-010" {
		t.Errorf("expected ID GR-010, got %s", d.ID())
	}
	if d.Stage() != models.StageInput {
		t.Errorf("expected stage input, got %s", d.Stage())
	}
	if d.Category() != models.CategoryPII {
		t.Errorf("expected category pii, got %s", d.Category())
	}
}

func TestDetector_MaskedValues(t *testing.T) {
	d := New()
	eval, err := d.Evaluate(makeCtx("my email is test@example.com"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range eval.Findings {
		if f.Type == "email" {
			// The masked value should not contain the full email.
			if f.Value == "test@example.com" {
				t.Error("finding value should be masked, but got the full email")
			}
		}
	}
}
