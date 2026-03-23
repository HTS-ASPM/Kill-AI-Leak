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
	Alerting   AlertingConfig   `json:"alerting" yaml:"alerting"`
	SIEM       SIEMConfig       `json:"siem" yaml:"siem"`
	Identity   IdentityConfig   `json:"identity" yaml:"identity"`
	Ticketing  TicketingConfig  `json:"ticketing" yaml:"ticketing"`
}

// SIEMConfig holds configuration for SIEM event export.
type SIEMConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	Type      string `json:"type" yaml:"type"`           // "webhook", "splunk", "elastic", "syslog"
	Endpoint  string `json:"endpoint" yaml:"endpoint"`   // Target URL or host:port
	Token     string `json:"token" yaml:"token"`         // Auth token (HEC token, API key, etc.)
	Index     string `json:"index" yaml:"index"`         // Target index/sourcetype
	BatchSize int    `json:"batch_size" yaml:"batch_size"`
	FlushSecs int    `json:"flush_interval_secs" yaml:"flush_interval_secs"`
}

// IdentityConfig holds configuration for identity provider integration.
type IdentityConfig struct {
	Provider        string   `json:"provider" yaml:"provider"`                   // "apikey", "oidc", "saml"
	IssuerURL       string   `json:"issuer_url" yaml:"issuer_url"`              // OIDC issuer URL
	Audience        string   `json:"audience" yaml:"audience"`                  // Expected audience claim
	RequiredGroups  []string `json:"required_groups" yaml:"required_groups"`    // Required group membership
	SAMLMetadataURL string   `json:"saml_metadata_url" yaml:"saml_metadata_url"` // SAML metadata endpoint
}

// TicketingConfig holds configuration for ticketing system integration.
type TicketingConfig struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	Provider    string `json:"provider" yaml:"provider"`         // "jira", "linear", "webhook"
	BaseURL     string `json:"base_url" yaml:"base_url"`         // Jira base URL / webhook URL
	APIKey      string `json:"api_key" yaml:"api_key"`           // API token / key
	ProjectKey  string `json:"project_key" yaml:"project_key"`   // Jira project key / Linear team ID
	AutoCreate  bool   `json:"auto_create" yaml:"auto_create"`   // Auto-create on high-severity blocks
	MinSeverity string `json:"min_severity" yaml:"min_severity"` // Min severity for auto-creation
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
	PostgresDSN  string `json:"postgres_dsn" yaml:"postgres_dsn"`
	Driver       string `json:"driver" yaml:"driver"` // "memory" or "postgres"
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

// AlertingConfig holds alert dispatch settings.
type AlertingConfig struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	SlackURL    string `json:"slack_url" yaml:"slack_url"`
	WebhookURL  string `json:"webhook_url" yaml:"webhook_url"`
	EmailTo     string `json:"email_to" yaml:"email_to"`
	MinSeverity string `json:"min_severity" yaml:"min_severity"` // "critical", "high", "medium"
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
				{Name: "gemini", BaseURL: "https://generativelanguage.googleapis.com", AuthType: "bearer", AuthEnv: "GEMINI_API_KEY"},
				{Name: "deepseek", BaseURL: "https://api.deepseek.com", AuthType: "bearer", AuthEnv: "DEEPSEEK_API_KEY"},
				{Name: "grok", BaseURL: "https://api.x.ai", AuthType: "bearer", AuthEnv: "XAI_API_KEY"},
				{Name: "perplexity", BaseURL: "https://api.perplexity.ai", AuthType: "bearer", AuthEnv: "PERPLEXITY_API_KEY"},
				{Name: "mistral", BaseURL: "https://api.mistral.ai", AuthType: "bearer", AuthEnv: "MISTRAL_API_KEY"},
				{Name: "cohere", BaseURL: "https://api.cohere.ai", AuthType: "bearer", AuthEnv: "COHERE_API_KEY"},
				{Name: "groq", BaseURL: "https://api.groq.com", AuthType: "bearer", AuthEnv: "GROQ_API_KEY"},
				{Name: "together", BaseURL: "https://api.together.xyz", AuthType: "bearer", AuthEnv: "TOGETHER_API_KEY"},
				{Name: "fireworks", BaseURL: "https://api.fireworks.ai", AuthType: "bearer", AuthEnv: "FIREWORKS_API_KEY"},
				{Name: "openrouter", BaseURL: "https://openrouter.ai", AuthType: "bearer", AuthEnv: "OPENROUTER_API_KEY"},
				{Name: "replicate", BaseURL: "https://api.replicate.com", AuthType: "bearer", AuthEnv: "REPLICATE_API_TOKEN"},
			},
		},
		Storage: StorageConfig{
			EventDriver:  "memory",
			PolicyDriver: "file",
			Driver:       "memory",
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
		Alerting: AlertingConfig{
			Enabled:     false,
			MinSeverity: "high",
		},
		SIEM: SIEMConfig{
			Enabled:   false,
			Type:      "webhook",
			BatchSize: 100,
			FlushSecs: 5,
		},
		Identity: IdentityConfig{
			Provider: "apikey",
		},
		Ticketing: TicketingConfig{
			Enabled:     false,
			Provider:    "jira",
			AutoCreate:  false,
			MinSeverity: "high",
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
	if v := os.Getenv("KILLAI_STORAGE_DRIVER"); v != "" {
		cfg.Storage.Driver = v
	}
	if v := os.Getenv("KILLAI_STORAGE_POSTGRES_DSN"); v != "" {
		cfg.Storage.PostgresDSN = v
	}
	if v := os.Getenv("KILLAI_ALERTING_ENABLED"); v != "" {
		cfg.Alerting.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("KILLAI_ALERTING_SLACK_URL"); v != "" {
		cfg.Alerting.SlackURL = v
	}
	if v := os.Getenv("KILLAI_ALERTING_WEBHOOK_URL"); v != "" {
		cfg.Alerting.WebhookURL = v
	}
	if v := os.Getenv("KILLAI_ALERTING_MIN_SEVERITY"); v != "" {
		cfg.Alerting.MinSeverity = v
	}
	// --- SIEM overrides ---
	if v := os.Getenv("KILLAI_SIEM_ENABLED"); v != "" {
		cfg.SIEM.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("KILLAI_SIEM_TYPE"); v != "" {
		cfg.SIEM.Type = v
	}
	if v := os.Getenv("KILLAI_SIEM_ENDPOINT"); v != "" {
		cfg.SIEM.Endpoint = v
	}
	if v := os.Getenv("KILLAI_SIEM_TOKEN"); v != "" {
		cfg.SIEM.Token = v
	}
	if v := os.Getenv("KILLAI_SIEM_INDEX"); v != "" {
		cfg.SIEM.Index = v
	}
	if v := os.Getenv("KILLAI_SIEM_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SIEM.BatchSize = n
		}
	}
	if v := os.Getenv("KILLAI_SIEM_FLUSH_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SIEM.FlushSecs = n
		}
	}
	// --- Identity overrides ---
	if v := os.Getenv("KILLAI_IDENTITY_PROVIDER"); v != "" {
		cfg.Identity.Provider = v
	}
	if v := os.Getenv("KILLAI_IDENTITY_ISSUER_URL"); v != "" {
		cfg.Identity.IssuerURL = v
	}
	if v := os.Getenv("KILLAI_IDENTITY_AUDIENCE"); v != "" {
		cfg.Identity.Audience = v
	}
	if v := os.Getenv("KILLAI_IDENTITY_SAML_METADATA_URL"); v != "" {
		cfg.Identity.SAMLMetadataURL = v
	}
	// --- Ticketing overrides ---
	if v := os.Getenv("KILLAI_TICKETING_ENABLED"); v != "" {
		cfg.Ticketing.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("KILLAI_TICKETING_PROVIDER"); v != "" {
		cfg.Ticketing.Provider = v
	}
	if v := os.Getenv("KILLAI_TICKETING_BASE_URL"); v != "" {
		cfg.Ticketing.BaseURL = v
	}
	if v := os.Getenv("KILLAI_TICKETING_API_KEY"); v != "" {
		cfg.Ticketing.APIKey = v
	}
	if v := os.Getenv("KILLAI_TICKETING_PROJECT_KEY"); v != "" {
		cfg.Ticketing.ProjectKey = v
	}
	if v := os.Getenv("KILLAI_TICKETING_AUTO_CREATE"); v != "" {
		cfg.Ticketing.AutoCreate = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("KILLAI_TICKETING_MIN_SEVERITY"); v != "" {
		cfg.Ticketing.MinSeverity = v
	}
}

// Validate checks the configuration for invalid or missing values.
func (c *AppConfig) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("config: server.port must be between 1 and 65535, got %d", c.Server.Port)
	}
	if c.Server.ReadTimeout <= 0 {
		return fmt.Errorf("config: server.read_timeout must be > 0")
	}
	if c.Server.WriteTimeout <= 0 {
		return fmt.Errorf("config: server.write_timeout must be > 0")
	}
	if c.Proxy.DefaultTimeout <= 0 {
		return fmt.Errorf("config: proxy.default_timeout must be > 0")
	}
	if c.Server.MaxRequestBodyMB <= 0 || c.Server.MaxRequestBodyMB > 100 {
		return fmt.Errorf("config: server.max_request_body_mb must be between 1 and 100, got %d", c.Server.MaxRequestBodyMB)
	}
	return nil
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
