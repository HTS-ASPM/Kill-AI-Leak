// Package fingerprint provides AI service fingerprint matching. It
// maintains a database of known AI/LLM provider signatures and can
// determine whether an HTTP request targets an AI service based on the
// host, path, and headers.
package fingerprint

import (
	"strings"
)

// Signature describes the fingerprint patterns for a single AI provider.
type Signature struct {
	// Provider is the canonical provider name returned on match.
	Provider string

	// Domains are hostname substrings that identify this provider.
	// A match is triggered when the request host contains any entry.
	Domains []string

	// PathPrefixes are URL path prefixes that identify this provider.
	// Matched after a domain match to disambiguate shared infrastructure.
	PathPrefixes []string

	// HeaderPatterns maps header names (lowercased) to substrings. A
	// match requires the header value to contain the substring.
	HeaderPatterns map[string]string
}

// builtinSignatures contains fingerprints for all major AI providers.
var builtinSignatures = []Signature{
	{
		Provider: "openai",
		Domains:  []string{"api.openai.com", "openai.azure.com"},
		PathPrefixes: []string{
			"/v1/chat/completions",
			"/v1/completions",
			"/v1/embeddings",
			"/v1/images",
			"/v1/audio",
			"/v1/moderations",
			"/v1/assistants",
			"/v1/threads",
			"/v1/files",
			"/v1/fine_tuning",
			"/v1/batches",
			"/openai/deployments",
		},
		HeaderPatterns: map[string]string{
			"authorization":       "Bearer sk-",
			"openai-organization": "",
			"openai-project":      "",
		},
	},
	{
		Provider: "anthropic",
		Domains:  []string{"api.anthropic.com"},
		PathPrefixes: []string{
			"/v1/messages",
			"/v1/complete",
		},
		HeaderPatterns: map[string]string{
			"x-api-key":         "sk-ant-",
			"anthropic-version": "",
		},
	},
	{
		Provider: "google_gemini",
		Domains: []string{
			"generativelanguage.googleapis.com",
			"aiplatform.googleapis.com",
			"us-central1-aiplatform.googleapis.com",
		},
		PathPrefixes: []string{
			"/v1/models",
			"/v1beta/models",
			"/v1/projects",
		},
		HeaderPatterns: map[string]string{
			"x-goog-api-key":    "",
			"x-goog-api-client": "",
		},
	},
	{
		Provider: "aws_bedrock",
		Domains: []string{
			"bedrock-runtime.",
			"bedrock.",
			".amazonaws.com",
		},
		PathPrefixes: []string{
			"/model/",
			"/invoke",
			"/converse",
		},
		HeaderPatterns: map[string]string{
			"x-amz-target": "AmazonBedrock",
		},
	},
	{
		Provider: "cohere",
		Domains:  []string{"api.cohere.ai", "api.cohere.com"},
		PathPrefixes: []string{
			"/v1/generate",
			"/v1/embed",
			"/v1/classify",
			"/v1/rerank",
			"/v1/chat",
			"/v2/chat",
		},
		HeaderPatterns: map[string]string{
			"authorization": "Bearer ",
		},
	},
	{
		Provider: "huggingface",
		Domains: []string{
			"api-inference.huggingface.co",
			"huggingface.co",
			"api.huggingface.co",
		},
		PathPrefixes: []string{
			"/models/",
			"/api/models",
			"/pipeline/",
			"/v1/chat/completions",
			"/api/inference",
		},
		HeaderPatterns: map[string]string{
			"authorization": "Bearer hf_",
		},
	},
	{
		Provider: "google_aistudio",
		Domains: []string{
			"aistudio.google.com",
			"makersuite.google.com",
		},
		PathPrefixes: []string{
			"/app/",
			"/api/",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "notebooklm",
		Domains: []string{
			"notebooklm.google.com",
			"notebooklm.google",
		},
		PathPrefixes: []string{
			"/",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "together_ai",
		Domains:  []string{"api.together.xyz", "api.together.ai"},
		PathPrefixes: []string{
			"/v1/chat/completions",
			"/v1/completions",
			"/v1/embeddings",
			"/inference",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "fireworks_ai",
		Domains:  []string{"api.fireworks.ai"},
		PathPrefixes: []string{
			"/inference/v1/chat/completions",
			"/inference/v1/completions",
			"/inference/v1/embeddings",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "groq",
		Domains:  []string{"api.groq.com"},
		PathPrefixes: []string{
			"/openai/v1/chat/completions",
			"/openai/v1/models",
		},
		HeaderPatterns: map[string]string{
			"authorization": "Bearer gsk_",
		},
	},
	{
		Provider: "mistral",
		Domains:  []string{"api.mistral.ai"},
		PathPrefixes: []string{
			"/v1/chat/completions",
			"/v1/embeddings",
			"/v1/models",
			"/v1/fim/completions",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "deepseek",
		Domains:  []string{"api.deepseek.com"},
		PathPrefixes: []string{
			"/chat/completions",
			"/v1/chat/completions",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "grok",
		Domains:  []string{"api.x.ai", "api.grok.com"},
		PathPrefixes: []string{
			"/v1/chat/completions",
			"/v1/completions",
			"/v1/embeddings",
		},
		HeaderPatterns: map[string]string{
			"authorization": "Bearer xai-",
		},
	},
	{
		Provider: "perplexity",
		Domains:  []string{"api.perplexity.ai"},
		PathPrefixes: []string{
			"/chat/completions",
			"/v1/chat/completions",
		},
		HeaderPatterns: map[string]string{
			"authorization": "Bearer pplx-",
		},
	},
	{
		Provider: "openrouter",
		Domains:  []string{"openrouter.ai", "api.openrouter.ai"},
		PathPrefixes: []string{
			"/api/v1/chat/completions",
			"/api/v1/completions",
		},
		HeaderPatterns: map[string]string{
			"authorization":  "Bearer sk-or-",
			"x-title":        "",
			"http-referer":   "",
		},
	},
	{
		Provider: "replicate",
		Domains:  []string{"api.replicate.com"},
		PathPrefixes: []string{
			"/v1/predictions",
			"/v1/models",
			"/v1/deployments",
		},
		HeaderPatterns: map[string]string{
			"authorization": "Bearer r8_",
		},
	},
	{
		Provider: "ai21",
		Domains:  []string{"api.ai21.com"},
		PathPrefixes: []string{
			"/studio/v1/chat/completions",
			"/studio/v1/j2-",
			"/v1/chat/completions",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "cerebras",
		Domains:  []string{"api.cerebras.ai"},
		PathPrefixes: []string{
			"/v1/chat/completions",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "sambanova",
		Domains:  []string{"api.sambanova.ai", "fast-api.snova.ai"},
		PathPrefixes: []string{
			"/v1/chat/completions",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "ollama",
		Domains:  []string{"localhost:11434", "127.0.0.1:11434", "ollama"},
		PathPrefixes: []string{
			"/api/generate",
			"/api/chat",
			"/api/embeddings",
			"/api/pull",
			"/api/tags",
			"/v1/chat/completions",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "vllm",
		Domains:  []string{"localhost:8000", "127.0.0.1:8000"},
		PathPrefixes: []string{
			"/v1/chat/completions",
			"/v1/completions",
			"/v1/models",
		},
		HeaderPatterns: map[string]string{},
	},
	{
		Provider: "llamacpp",
		Domains:  []string{"localhost:8080", "127.0.0.1:8080"},
		PathPrefixes: []string{
			"/completion",
			"/v1/chat/completions",
		},
		HeaderPatterns: map[string]string{},
	},
}

// allAIDomains is a precomputed set of domain substrings from all
// signatures, used for fast domain checks.
var allAIDomains map[string]bool

func init() {
	allAIDomains = make(map[string]bool, 64)
	for _, sig := range builtinSignatures {
		for _, d := range sig.Domains {
			allAIDomains[d] = true
		}
	}
}

// Matcher holds the signature database and provides matching methods.
type Matcher struct {
	signatures []Signature
}

// NewMatcher returns a Matcher initialised with the built-in signatures.
func NewMatcher() *Matcher {
	sigs := make([]Signature, len(builtinSignatures))
	copy(sigs, builtinSignatures)
	return &Matcher{signatures: sigs}
}

// NewMatcherWithSignatures returns a Matcher using the provided
// signatures instead of the built-in set.
func NewMatcherWithSignatures(sigs []Signature) *Matcher {
	return &Matcher{signatures: sigs}
}

// AddSignature appends a custom signature to the matcher.
func (m *Matcher) AddSignature(sig Signature) {
	m.signatures = append(m.signatures, sig)
}

// MatchResult holds the outcome of a match attempt.
type MatchResult struct {
	// Matched is true if a provider was identified.
	Matched bool

	// Provider is the canonical provider name.
	Provider string

	// MatchedDomain is the domain pattern that matched, if any.
	MatchedDomain string

	// MatchedPath is the path prefix that matched, if any.
	MatchedPath string

	// MatchedHeader is the header name that matched, if any.
	MatchedHeader string

	// Confidence is a rough score (0-1) indicating match quality.
	// Domain matches start at 0.6, path matches add 0.2, header
	// matches add 0.2.
	Confidence float64
}

// MatchRequest determines which AI provider, if any, the given request
// targets. It checks the host, path, and headers against all signatures
// and returns the best match.
func (m *Matcher) MatchRequest(host, path string, headers map[string]string) MatchResult {
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.TrimSpace(path)

	var best MatchResult

	for _, sig := range m.signatures {
		result := matchSignature(sig, host, path, headers)
		if result.Confidence > best.Confidence {
			best = result
		}
	}

	return best
}

// matchSignature checks a single signature against the request.
func matchSignature(sig Signature, host, path string, headers map[string]string) MatchResult {
	result := MatchResult{Provider: sig.Provider}

	// --- Domain match ---
	for _, domain := range sig.Domains {
		if strings.Contains(host, strings.ToLower(domain)) {
			result.Matched = true
			result.MatchedDomain = domain
			result.Confidence = 0.6
			break
		}
	}

	// --- Path match ---
	if path != "" {
		for _, prefix := range sig.PathPrefixes {
			if strings.HasPrefix(path, prefix) {
				result.MatchedPath = prefix
				if result.Matched {
					result.Confidence += 0.2
				} else {
					// Path-only match (weaker signal).
					result.Matched = true
					result.Confidence = 0.3
				}
				break
			}
		}
	}

	// --- Header match ---
	if len(sig.HeaderPatterns) > 0 {
		for hName, hSubstr := range sig.HeaderPatterns {
			for rName, rValue := range headers {
				if strings.EqualFold(rName, hName) {
					if hSubstr == "" || strings.Contains(rValue, hSubstr) {
						result.MatchedHeader = hName
						if result.Matched {
							result.Confidence += 0.2
						} else {
							result.Matched = true
							result.Confidence = 0.4
						}
						break
					}
				}
			}
			if result.MatchedHeader != "" {
				break
			}
		}
	}

	// Cap confidence at 1.0.
	if result.Confidence > 1.0 {
		result.Confidence = 1.0
	}

	if !result.Matched {
		result.Confidence = 0
	}

	return result
}

// IsAIRelatedDomain returns true if the given domain matches any known
// AI provider domain pattern.
func IsAIRelatedDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	for d := range allAIDomains {
		if strings.Contains(domain, strings.ToLower(d)) {
			return true
		}
	}
	return false
}

// ProviderForDomain returns the provider name for a known AI domain, or
// an empty string if the domain is not recognised.
func ProviderForDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, sig := range builtinSignatures {
		for _, d := range sig.Domains {
			if strings.Contains(domain, strings.ToLower(d)) {
				return sig.Provider
			}
		}
	}
	return ""
}

// ListProviders returns the canonical names of all providers in the
// built-in signature database.
func ListProviders() []string {
	providers := make([]string, len(builtinSignatures))
	for i, sig := range builtinSignatures {
		providers[i] = sig.Provider
	}
	return providers
}
