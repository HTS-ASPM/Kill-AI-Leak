package code

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

func wrapCode(lang, code string) string {
	return "Here is the code:\n```" + lang + "\n" + code + "\n```"
}

func TestScanner_SQLInjection(t *testing.T) {
	tests := []struct {
		name string
		code string
		lang string
	}{
		{
			"string concat sql python",
			`query = "SELECT * FROM users WHERE name = '" + user_input + "'"`,
			"python",
		},
		{
			"format string sql python",
			`query = f"SELECT * FROM users WHERE id = {user_id}"`,
			"python",
		},
		{
			"sprintf sql go",
			`query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)`,
			"go",
		},
	}

	s := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := wrapCode(tt.lang, tt.code)
			eval, err := s.Evaluate(makeCtx(response))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eval.Decision == models.DecisionAllow {
				t.Errorf("expected non-allow for SQL injection in %q, got allow", tt.name)
			}
			found := false
			for _, f := range eval.Findings {
				if len(f.Type) >= 13 && f.Type[:13] == "sql_injection" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected sql_injection finding for %q", tt.name)
			}
		})
	}
}

func TestScanner_CommandInjection(t *testing.T) {
	tests := []struct {
		name string
		code string
		lang string
	}{
		{
			"os.system python",
			`os.system("rm -rf " + user_input)`,
			"python",
		},
		{
			"subprocess.call python",
			`subprocess.call(["sh", "-c", cmd])`,
			"python",
		},
		{
			"exec.Command go",
			`cmd := exec.Command("bash", "-c", userInput)`,
			"go",
		},
	}

	s := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := wrapCode(tt.lang, tt.code)
			eval, err := s.Evaluate(makeCtx(response))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eval.Decision == models.DecisionAllow {
				t.Errorf("expected non-allow for command injection in %q, got allow", tt.name)
			}
			found := false
			for _, f := range eval.Findings {
				if len(f.Type) >= 17 && f.Type[:17] == "command_injection" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected command_injection finding for %q", tt.name)
			}
		})
	}
}

func TestScanner_HardcodedSecrets(t *testing.T) {
	tests := []struct {
		name string
		code string
		lang string
	}{
		{
			"hardcoded password",
			`password = "SuperSecret123!"`,
			"python",
		},
		{
			"hardcoded aws key",
			`AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`,
			"python",
		},
		{
			"private key in code",
			`key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."`,
			"python",
		},
		{
			"connection string",
			`db_url = "postgresql://admin:secret@localhost:5432/mydb"`,
			"python",
		},
	}

	s := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := wrapCode(tt.lang, tt.code)
			eval, err := s.Evaluate(makeCtx(response))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eval.Decision == models.DecisionAllow {
				t.Errorf("expected non-allow for hardcoded secret in %q, got allow", tt.name)
			}
			found := false
			for _, f := range eval.Findings {
				if len(f.Type) >= 16 && f.Type[:16] == "hardcoded_secret" {
					found = true
					break
				}
			}
			if !found {
				types := make([]string, len(eval.Findings))
				for i, f := range eval.Findings {
					types[i] = f.Type
				}
				t.Errorf("expected hardcoded_secret finding for %q, got types %v", tt.name, types)
			}
		})
	}
}

func TestScanner_CleanCode(t *testing.T) {
	tests := []struct {
		name string
		code string
		lang string
	}{
		{
			"safe sql with params",
			`rows, err := db.Query("SELECT * FROM users WHERE id = $1", userID)`,
			"go",
		},
		{
			"simple function",
			"def add(a, b):\n    return a + b",
			"python",
		},
		{
			"http handler",
			"func handler(w http.ResponseWriter, r *http.Request) {\n    w.Write([]byte(\"hello\"))\n}",
			"go",
		},
	}

	s := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := wrapCode(tt.lang, tt.code)
			eval, err := s.Evaluate(makeCtx(response))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eval.Decision == models.DecisionBlock {
				t.Errorf("expected non-block for clean code %q, got block (%d findings)",
					tt.name, len(eval.Findings))
			}
		})
	}
}

func TestScanner_NoCodeBlocks(t *testing.T) {
	s := New()
	eval, err := s.Evaluate(makeCtx("Just a plain text response without any code."))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Decision != models.DecisionAllow {
		t.Errorf("no code blocks should allow, got %s", eval.Decision)
	}
}

func TestScanner_EmptyInput(t *testing.T) {
	s := New()
	eval, err := s.Evaluate(makeCtx(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Decision != models.DecisionAllow {
		t.Errorf("empty input should allow, got %s", eval.Decision)
	}
}

func TestScanner_RuleMetadata(t *testing.T) {
	s := New()
	if s.ID() != "GR-033" {
		t.Errorf("expected ID GR-033, got %s", s.ID())
	}
	if s.Stage() != models.StageOutput {
		t.Errorf("expected stage output, got %s", s.Stage())
	}
	if s.Category() != models.CategoryCodeSafety {
		t.Errorf("expected category code_safety, got %s", s.Category())
	}
}

func TestScanner_UsesResponseText(t *testing.T) {
	s := New()
	ctx := guardrails.NewEvalContext(context.Background())
	// SQL injection in prompt, clean response.
	ctx.WithPrompt(wrapCode("python", `query = "SELECT * FROM users WHERE name = '" + user_input + "'""`))
	ctx.WithResponse("The capital of France is Paris.")

	eval, err := s.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Decision != models.DecisionAllow {
		t.Error("code scanner should read ResponseText, not PromptText")
	}
}

func TestScanner_Configure(t *testing.T) {
	s := New()
	err := s.Configure(map[string]any{
		"block_on_critical": false,
		"block_on_high":     true,
		"max_findings":      5.0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractCodeBlocks(t *testing.T) {
	text := "Some text\n```python\nprint('hello')\n```\nMore text\n```go\nfmt.Println(\"hi\")\n```"
	blocks := extractCodeBlocks(text)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 code blocks, got %d", len(blocks))
	}
	if blocks[0].lang != "python" {
		t.Errorf("expected first block lang=python, got %q", blocks[0].lang)
	}
	if blocks[1].lang != "go" {
		t.Errorf("expected second block lang=go, got %q", blocks[1].lang)
	}
}
