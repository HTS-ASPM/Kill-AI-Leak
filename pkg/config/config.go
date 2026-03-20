package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AppConfig is the top-level configuration for the Kill-AI-Leak platform.
type AppConfig struct {
	Server     ServerConfig     `json:"server" yaml:"server"`
	Proxy      ProxyConfig      `json:"proxy" yaml:"proxy"`
	Guardrails GuardrailsConfig `json:"guardrails" yaml:"guardrails"`
	Providers  ProvidersConfig  `json:"providers" yaml:"providers"`
	Storage    StorageConfig    `json:"storage" yaml:"storage"`
	Logging    LoggingConfig    `json:"logging" yaml:"logging"`
	Auth       AuthConfig       `json:"auth" yaml:"auth"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host              string        `json:"host" yaml:"host"`
	Port              int           `json:"port" yaml:"port"`
	ReadTimeout       time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout      time.Duration `json:"write_timeout" yaml:"write_timeout"`
	IdleTimeout       time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
	ShutdownTimeout   time.Duration `json:"shutdown_timeout" yaml:"shutdown_timeout"`
	MaxRequestBodyMB  int           `json:"max_request_body_mb" yaml:"max_request_body_mb"`
	TLSCertFile       string        `json:"tls_cert_file" yaml:"tls_cert_file"`
	TLSKeyFile        string        `json:"tls_key_file" yaml:"tls_key_file"`
}

// ProxyConfig holds reverse proxy settings.
type ProxyConfig struct {
	DefaultTimeout    time.Duration     `json:"default_timeout" yaml:"default_timeout"`
	MaxRetries        int               `json:"max_retries" yaml:"max_retries"`
	RetryBackoff      time.Duration     `json:"retry_backoff" yaml:"retry_backoff"`
	BufferPoolSize    int               `json:"buffer_pool_size" yaml:"buffer_pool_size"`
	StripHeaders      []string          `json:"strip_headers" yaml:"strip_headers"`
	ProviderOverrides map[string]string `json:"provider_overrides" yaml:"provider_overrides"`
}

// GuardrailsConfig holds guardrail engine settings.
type GuardrailsConfig struct {
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	DefaultMode     string        `json:"default_mode" yaml:"default_mode"`
	PipelineTimeout time.Duration `json:"pipeline_timeout" yaml:"pipeline_timeout"`
	PolicyDir       string        `json:"policy_dir" yaml:"policy_dir"`
	RulesDir        string        `json:"rules_dir" yaml:"rules_dir"`
}

// ProviderEntry describes a single upstream LLM provider.
type ProviderEntry struct {
	Name      string `json:"name" yaml:"name"`
	BaseURL   string `json:"base_url" yaml:"base_url"`
	AuthType  string `json:"auth_type" yaml:"auth_type"`
	AuthEnv   string `json:"auth_env" yaml:"auth_env"`
}

// ProvidersConfig holds upstream provider settings.
type ProvidersConfig struct {
	Entries []ProviderEntry `json:"entries" yaml:"entries"`
}

// StorageConfig holds backend storage settings.
type StorageConfig struct {
	EventDriver  string `json:"event_driver" yaml:"event_driver"`
	EventDSN     string `json:"event_dsn" yaml:"event_dsn"`
	PolicyDriver string `json:"policy_driver" yaml:"policy_driver"`
	PolicyDSN    string `json:"policy_dsn" yaml:"policy_dsn"`
}

// LoggingConfig holds structured logging settings.
type LoggingConfig struct {
	Level  string `json:"level" yaml:"level"`
	Format string `json:"format" yaml:"format"`
	Output string `json:"output" yaml:"output"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	Enabled     bool              `json:"enabled" yaml:"enabled"`
	HeaderName  string            `json:"header_name" yaml:"header_name"`
	ServiceKeys map[string]string `json:"service_keys" yaml:"service_keys"`
}

// DefaultConfig returns an AppConfig populated with production-ready defaults.
func DefaultConfig() *AppConfig {
	return &AppConfig{
		Server: ServerConfig{
			Host:             "0.0.0.0",
			Port:             8080,
			ReadTimeout:      30 * time.Second,
			WriteTimeout:     60 * time.Second,
			IdleTimeout:      120 * time.Second,
			ShutdownTimeout:  15 * time.Second,
			MaxRequestBodyMB: 10,
		},
		Proxy: ProxyConfig{
			DefaultTimeout: 30 * time.Second,
			MaxRetries:     2,
			RetryBackoff:   500 * time.Millisecond,
			BufferPoolSize: 32 * 1024,
			StripHeaders:   []string{"X-Internal-Only"},
		},
		Guardrails: GuardrailsConfig{
			Enabled:         true,
			DefaultMode:     "enforce",
			PipelineTimeout: 5 * time.Second,
			PolicyDir:       "/etc/kill-ai-leak/policies",
			RulesDir:        "/etc/kill-ai-leak/rules",
		},
		Providers: ProvidersConfig{
			Entries: []ProviderEntry{
				{Name: "openai", BaseURL: "https://api.openai.com", AuthType: "bearer", AuthEnv: "OPENAI_API_KEY"},
				{Name: "anthropic", BaseURL: "https://api.anthropic.com", AuthType: "header", AuthEnv: "ANTHROPIC_API_KEY"},
				{Name: "google", BaseURL: "https://generativelanguage.googleapis.com", AuthType: "bearer", AuthEnv: "GOOGLE_API_KEY"},
				{Name: "cohere", BaseURL: "https://api.cohere.ai", AuthType: "bearer", AuthEnv: "COHERE_API_KEY"},
				{Name: "mistral", BaseURL: "https://api.mistral.ai", AuthType: "bearer", AuthEnv: "MISTRAL_API_KEY"},
			},
		},
		Storage: StorageConfig{
			EventDriver:  "memory",
			PolicyDriver: "file",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Auth: AuthConfig{
			Enabled:    true,
			HeaderName: "X-APP-ID",
		},
	}
}

// LoadFromFile reads a YAML config file and merges it over the defaults.
func LoadFromFile(path string) (*AppConfig, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse yaml %s: %w", path, err)
	}

	return cfg, nil
}

// ApplyEnvOverrides applies environment variable overrides on top of the
// loaded configuration. Environment variables use the prefix KILLAI_ and
// follow the pattern KILLAI_SECTION_KEY (e.g., KILLAI_SERVER_PORT).
func ApplyEnvOverrides(cfg *AppConfig) {
	if v := os.Getenv("KILLAI_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("KILLAI_SERVER_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = port
		}
	}
	if v := os.Getenv("KILLAI_SERVER_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Server.ReadTimeout = d
		}
	}
	if v := os.Getenv("KILLAI_SERVER_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Server.WriteTimeout = d
		}
	}
	if v := os.Getenv("KILLAI_PROXY_DEFAULT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Proxy.DefaultTimeout = d
		}
	}
	if v := os.Getenv("KILLAI_GUARDRAILS_ENABLED"); v != "" {
		cfg.Guardrails.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("KILLAI_GUARDRAILS_DEFAULT_MODE"); v != "" {
		cfg.Guardrails.DefaultMode = v
	}
	if v := os.Getenv("KILLAI_GUARDRAILS_POLICY_DIR"); v != "" {
		cfg.Guardrails.PolicyDir = v
	}
	if v := os.Getenv("KILLAI_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("KILLAI_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
	if v := os.Getenv("KILLAI_STORAGE_EVENT_DRIVER"); v != "" {
		cfg.Storage.EventDriver = v
	}
	if v := os.Getenv("KILLAI_STORAGE_EVENT_DSN"); v != "" {
		cfg.Storage.EventDSN = v
	}
	if v := os.Getenv("KILLAI_AUTH_ENABLED"); v != "" {
		cfg.Auth.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
}

// Addr returns the listen address as host:port.
func (c *ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// ProviderBaseURL returns the base URL for the given provider name. It checks
// override mappings first, then the configured entries, and finally falls back
// to well-known defaults.
func (c *AppConfig) ProviderBaseURL(provider string) (string, bool) {
	if override, ok := c.Proxy.ProviderOverrides[provider]; ok {
		return override, true
	}
	for _, e := range c.Providers.Entries {
		if strings.EqualFold(e.Name, provider) {
			return e.BaseURL, true
		}
	}
	return "", false
}
