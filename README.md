# Kill AI Leak

Enterprise security platform that discovers, monitors, and controls all AI/LLM usage across your organization -- from shadow AI detection to real-time guardrails on every prompt and response.

## Quick Start

```bash
# Install the CLI
curl -sSfL https://get.killaileak.dev | bash

# Deploy the gateway (Kubernetes)
killaileak install --namespace kill-ai-leak

# Or run locally with Docker Compose
git clone https://github.com/kill-ai-leak/kill-ai-leak.git
cd kill-ai-leak
docker compose up -d
```

## Architecture

```
                          +------------------+
                          |   Developers /   |
                          |   AI Agents /    |
                          |   Services       |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |   Kill AI Leak   |
                          |     Gateway      |         +-----------------+
                          |                  +-------->| Policy Engine   |
                          | +--pre_input---+ |         | (YAML policies) |
                          | |  auth, rate  | |         +-----------------+
                          | +--input-------+ |
                          | |  PII, inject,| |         +-----------------+
                          | |  secrets     | |         | Guardrail Rules |
                          | +--routing-----+ |         | (54 built-in)   |
                          | |  residency,  | |         +-----------------+
                          | |  failover    | |
                          | +--output------+ |
                          | |  toxicity,   | |
                          | |  code scan   | |
                          | +--post_output-+ |
                          | |  audit, cost | |
                          +---------+--------+
                                    |
                 +------------------+------------------+
                 |                  |                   |
        +--------v-------+ +------v--------+ +--------v--------+
        |    OpenAI       | |  Anthropic    | |  AWS Bedrock    |
        |    Azure OpenAI | |               | |  Google Gemini  |
        +----------------+ +---------------+ +-----------------+
                 |                  |                   |
                 +------------------+------------------+
                                    |
                          +---------v---------+
                          |   Event Bus       |
                          |   (NATS)          |
                          +---------+---------+
                                    |
                    +---------------+---------------+
                    |                               |
           +--------v--------+            +--------v--------+
           |   Processor     |            |   API Server    |
           | (anomaly detect,|            | (dashboard,     |
           |  AIBOM, alerts) |            |  REST API)      |
           +--------+--------+            +-----------------+
                    |
           +--------v--------+
           |   ClickHouse    |
           |   PostgreSQL    |
           |   Redis         |
           +-----------------+
```

## Features

### Discovery and Inventory
- **Shadow AI detection** -- find every service calling LLM providers, even those bypassing the gateway
- **AI Bill of Materials (AIBOM)** -- full inventory of providers, models, libraries, and costs
- **Kernel-level observer** -- eBPF-based network monitoring for zero-instrumentation discovery

### Security Guardrails (54 built-in rules)
- **PII detection and anonymization** -- regex + NER-based scanning with reversible tokenization
- **Secret detection** -- API keys, tokens, credentials blocked before reaching providers
- **Prompt injection defense** -- heuristic + ML classifier to detect injection and jailbreak attempts
- **Output safety** -- toxicity filtering, code vulnerability scanning, prompt leakage detection
- **Agent sandboxing** -- filesystem, command execution, and network egress controls

### Policy Engine
- **Kubernetes-native policies** -- CRD-style YAML with scope targeting (namespace, service, team, user)
- **Hierarchical resolution** -- most-specific policy wins (service > namespace > team > global)
- **Enforcement modes** -- off / discover / monitor / enforce for safe rollouts
- **Hot-reload** -- policies update without gateway restart via file watching

### Compliance and Governance
- **Data residency routing** -- enforce GDPR, HIPAA, and regional data sovereignty requirements
- **Full audit trail** -- every request and response logged with tamper-evident records
- **Cost accounting** -- per-team, per-service token and dollar tracking
- **Rate limiting** -- sliding-window limits per user, service, or namespace

## Configuration

The gateway reads configuration from `configs/default.yaml`. Override with `--config` or environment variables prefixed with `KILLAILEAK_`.

```yaml
server:
  host: 0.0.0.0
  port: 8080

guardrails:
  enabled: true
  default_mode: monitor  # start in monitor mode, promote to enforce

providers:
  openai:
    upstream: https://api.openai.com
  anthropic:
    upstream: https://api.anthropic.com
```

Policies are loaded from YAML files and support hot-reload:

```yaml
apiVersion: killaileak.dev/v1
kind: AISecurityPolicy
metadata:
  name: production-default
spec:
  scope:
    namespaces: ["production"]
  providers:
    allow: [openai, anthropic]
    deny: [gemini]
  models:
    allow: ["gpt-4*", "claude-*"]
  rate_limits:
    per_service:
      requests_per_minute: 100
  input:
    block_pii: true
    block_secrets: true
  mode: enforce
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/proxy/{provider}/**` | Proxy requests to LLM provider |
| `GET` | `/v1/inventory` | List discovered AI services |
| `GET` | `/v1/inventory/{id}` | Get service details |
| `GET` | `/v1/events` | Query event log |
| `GET` | `/v1/policies` | List active policies |
| `POST` | `/v1/policies` | Create or update a policy |
| `GET` | `/v1/policies/{name}` | Get policy by name |
| `DELETE`| `/v1/policies/{name}` | Delete a policy |
| `GET` | `/v1/aibom` | Export AI Bill of Materials |
| `GET` | `/v1/dashboard/summary` | Dashboard summary stats |
| `GET` | `/v1/guardrails/rules` | List guardrail rules and status |
| `PUT` | `/v1/guardrails/rules/{id}` | Update rule configuration |
| `GET` | `/healthz` | Health check |
| `GET` | `/readyz` | Readiness check |
| `GET` | `/metrics` | Prometheus metrics |

## Development Setup

### Prerequisites

- Go 1.22+
- Docker and Docker Compose
- protoc (for protobuf generation)
- golangci-lint

### Build

```bash
# Build all binaries
make build

# Run tests
make test

# Lint
make lint

# Format code
make fmt

# Run go vet
make vet

# Generate protobuf code
make proto

# Build Docker images
make docker-build

# Run gateway locally
make run-gateway

# Run API server locally
make run-api-server

# See all targets
make help
```

### Project Structure

```
kill-ai-leak/
  cmd/
    gateway/          # Reverse proxy + guardrail pipeline
    api-server/       # REST API + dashboard backend
    observer/         # eBPF kernel observer
    processor/        # Event processor + anomaly detection
    cli/              # CLI tool (killaileak)
  pkg/
    models/           # Shared domain types
    policy/           # Policy engine, loader, evaluator
    guardrails/       # Rule interface, registry, pipeline
    detection/        # PII, secret, injection detectors
  internal/
    health/           # Health check handlers
    logger/           # Structured logging
    middleware/       # HTTP middleware
  api/
    proto/            # Protobuf definitions
    openapi/          # OpenAPI specs
  configs/
    default.yaml      # Default application config
    guardrails/       # Guardrail rule catalog
  deploy/
    docker/           # Dockerfiles
  tests/
    integration/      # Integration tests
```

## License

Apache-2.0
