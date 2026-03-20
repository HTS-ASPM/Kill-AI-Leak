# Kill-AI-Leak — Unified AI Security Platform

## Vision

A single platform that **discovers all AI usage** (like Aurva) AND **actively protects it** (like Prompt Security) — covering every attack surface from kernel to browser.

---

## Core Design Principle: Observe → Classify → Enforce

```
Phase 1: DISCOVER          Phase 2: UNDERSTAND         Phase 3: ENFORCE
(eBPF passive)             (Correlate & classify)      (Inline active)

 See everything     →      Know what matters     →     Block what's dangerous
 Zero instrumentation      Risk scoring                Real-time filtering
 Kernel-level              Context enrichment          Policy enforcement
```

Unlike Aurva (observe-only) or Prompt Security (enforce-only), this platform does **both** in a closed loop: eBPF discovers unknown AI usage → auto-routes it through the inline gateway → enforces policy → feeds results back to improve detection.

---

## Architecture Overview

```
                    ┌──────────────────────────────────────────────────────┐
                    │              EDGE SENSORS (Data Plane)               │
                    │                                                      │
  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
  │  Kernel   │  │  Inline  │  │ Browser  │  │   IDE    │  │   MCP    │  │
  │ Observer  │  │ Gateway  │  │ Sentinel │  │ Sentinel │  │ Gateway  │  │
  │ (eBPF)   │  │ (Proxy)  │  │ (Ext)    │  │ (Ext)    │  │ (Proxy)  │  │
  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
       │              │              │              │              │       │
       └──────────────┴──────┬───────┴──────────────┴──────────────┘       │
                             │                                             │
                    ┌────────▼─────────┐                                   │
                    │    Event Bus     │  NATS JetStream / Kafka           │
                    │  (Normalize +    │                                   │
                    │   Fan-out)       │                                   │
                    └────────┬─────────┘                                   │
                             │                                             │
       ┌─────────────────────┼─────────────────────────┐                   │
       │          PROCESSING ENGINE (Control Plane)     │                   │
       │                     │                          │                   │
       │  ┌──────────┐  ┌───▼──────┐  ┌──────────┐    │                   │
       │  │Correlator│  │Detection │  │ Policy   │    │                   │
       │  │          │◄─┤ Engine   │◄─┤ Engine   │    │                   │
       │  │eBPF +    │  │          │  │          │    │                   │
       │  │Proxy join│  │ML + Rules│  │Enforce   │    │                   │
       │  └────┬─────┘  └────┬─────┘  └────┬─────┘    │                   │
       │       │              │              │          │                   │
       │       └──────────────┴──────┬───────┘          │                   │
       │                             │                  │                   │
       └─────────────────────────────┼──────────────────┘                   │
                                     │                                     │
                    ┌────────────────┼────────────────────┐                │
                    │         STORAGE PLANE               │                │
                    │                │                     │                │
                    │  ┌──────────┐  │  ┌──────────────┐  │                │
                    │  │ClickHouse│  │  │ PostgreSQL   │  │                │
                    │  │(Events & │  │  │(Policies,    │  │                │
                    │  │ Analytics)│  │  │ Inventory,   │  │                │
                    │  └──────────┘  │  │ Config)      │  │                │
                    │                │  └──────────────┘  │                │
                    │  ┌──────────┐  │  ┌──────────────┐  │                │
                    │  │  Redis   │  │  │ Object Store │  │                │
                    │  │(Sessions,│  │  │(Audit archive│  │                │
                    │  │ Cache)   │  │  │ S3/MinIO)    │  │                │
                    │  └──────────┘  │  └──────────────┘  │                │
                    └────────────────┼────────────────────┘                │
                                     │                                     │
                    ┌────────────────▼────────────────────┐                │
                    │       PRESENTATION PLANE             │                │
                    │                                      │                │
                    │  Dashboard ─ AIBOM ─ Data Lineage    │                │
                    │  Alert Mgr ─ Policy Editor           │                │
                    │  Compliance Reports ─ Red Team       │                │
                    └──────────────────────────────────────┘                │
                    └──────────────────────────────────────────────────────┘
```

---

## Layer 1: Edge Sensors (Data Plane)

Six collection mechanisms at different interception points. Each sensor is independently deployable.

### 1A. Kernel Observer (eBPF DaemonSet)

**What**: Passive kernel-level tracing on every K8s node. Zero instrumentation.

**From**: Aurva/AIOStack approach

**Deployment**: Kubernetes DaemonSet (privileged container)

**Technology**: BPF CO-RE programs written in C, loaded via Go userspace (cilium/ebpf library)

**Kernel Tracepoints**:

| Tracepoint | What it captures |
|------------|-----------------|
| `tcp_sendmsg` / `tcp_recvmsg` | Network I/O — which pods talk to which LLM provider endpoints |
| `execve` | Process execution — detects AI framework spawning (python, node, java, go) |
| `openat` | File access — model file loads, config reads, credential access |
| `connect` | Outbound connections — new LLM API endpoint discovery |
| DNS hooks | Domain resolution — maps IPs to `api.openai.com`, `api.anthropic.com`, etc. |

**TLS Visibility**: uprobes on `SSL_write`/`SSL_read` (OpenSSL), `gnutls_record_send`/`recv` — captures plaintext at syscall layer before encryption.

**AI Fingerprinting**: Signature database to classify traffic:
- HTTP headers (e.g., `Authorization: Bearer sk-...`, `x-api-key`, `anthropic-version`)
- Endpoint paths (`/v1/chat/completions`, `/v1/messages`, `/api/generate`)
- Library load patterns (`import openai`, `import anthropic`, `torch.load`)
- Model file patterns (`.gguf`, `.safetensors`, `.pt`, `.onnx`)

**Output**: Structured events → Event Bus

```go
type KernelEvent struct {
    Timestamp   time.Time
    NodeID      string
    PodID       string
    Namespace   string
    ProcessName string
    PID         uint32
    Syscall     string      // tcp_sendmsg, execve, openat, etc.
    Direction   string      // ingress/egress
    RemoteAddr  string      // IP:port of LLM provider
    RemoteDNS   string      // resolved domain
    BytesSent   uint64
    BytesRecv   uint64
    TLSVersion  string
    Metadata    map[string]string  // extracted headers, paths, etc.
}
```

**Resource budget**: <2% CPU, <256MB RAM per node

---

### 1B. Inline Gateway (LLM Proxy)

**What**: Active reverse proxy that inspects and can block/modify LLM API calls in real time.

**From**: Prompt Security approach

**Deployment options**:
- **Central gateway** (Deployment) — all LLM traffic routes through it
- **Sidecar** (per-pod injection) — co-located with each AI service
- **External proxy** — for non-K8s workloads

**How apps integrate**:

```python
# Option 1: API base URL redirect (1-line change)
openai.api_base = "https://gateway.kill-ai-leak.internal/v1"

# Option 2: Environment variable (zero code change)
# OPENAI_BASE_URL=https://gateway.kill-ai-leak.internal/v1

# Option 3: K8s network policy (transparent proxy, zero code change)
# All egress to api.openai.com:443 is redirected via iptables/eBPF
```

**Inspection pipeline** (per request):

```
Incoming request
      │
      ▼
┌─────────────┐
│ Authenticate │ → APP-ID / service identity / mTLS
└──────┬──────┘
       ▼
┌─────────────┐
│  INPUT SCAN  │ → PII detection, secrets scanning
│              │ → Prompt injection detection (ML model)
│              │ → Jailbreak detection
│              │ → Policy rule evaluation
└──────┬──────┘
       │
   ┌───▼───┐
   │DECISION│ → ALLOW / BLOCK / ANONYMIZE / ALERT
   └───┬───┘
       │ (if allowed)
       ▼
┌──────────────┐
│ Forward to   │ → api.openai.com / api.anthropic.com / etc.
│ LLM Provider │
└──────┬───────┘
       ▼
┌──────────────┐
│ OUTPUT SCAN  │ → Toxic content filter
│              │ → Hallucination flag
│              │ → Sensitive data in response
│              │ → Code vulnerability scan (for code gen)
└──────┬───────┘
       ▼
  Return to app
```

**Technology**: Go (net/http reverse proxy) with plugin architecture for scan modules

**Latency budget**: <50ms added per request (scan pipeline)

**Key feature — Auto-discovery enrollment**:
When the eBPF Observer discovers a new service calling an LLM API, it can automatically:
1. Alert the security team
2. Suggest routing through the gateway
3. (With policy) auto-inject sidecar or redirect traffic via eBPF

This is the **closed loop** that neither Aurva nor Prompt Security has alone.

---

### 1C. Browser Sentinel (Extension)

**What**: Browser extension for employee AI usage monitoring and DLP.

**From**: Prompt Security approach

**Browsers**: Chrome, Firefox, Edge, Arc (Manifest V3)

**Capabilities**:

| Capability | Mechanism |
|-----------|-----------|
| Shadow AI discovery | Monitor navigation to known AI domains (500+ in database) |
| Prompt capture | Content script intercepts form submissions / fetch calls to AI services |
| PII/secrets scan | Scan prompt content before send, block or anonymize |
| Response scan | Intercept AI responses for harmful content |
| Policy enforcement | Per-user, per-department rules via SAML/SSO identity |
| User coaching | Non-intrusive popup explaining risk when flagged |

**Identity integration**: SAML/SSO, MDM (JumpCloud, Intune, Jamf)

**Architecture**:
```
  Web page (chat.openai.com)
       │
  Content Script (injected)
       │ intercepts fetch/XHR
       ▼
  Service Worker (background)
       │ runs detection logic
       │ phones home for policy
       ▼
  ┌──────────┐
  │ Local ML  │  ← small on-device model for PII/injection detection
  │ (ONNX.js) │  ← works offline, low latency
  └─────┬────┘
        │
   ┌────▼────┐
   │ Decision │ → Allow / Block / Anonymize / Alert
   └────┬────┘
        │
   Cloud API (for logging, policy sync, heavy analysis)
```

---

### 1D. IDE Sentinel (Extension + Local Proxy)

**What**: Protection for AI code assistants (Copilot, Cursor, Cody, etc.)

**From**: Prompt Security approach, enhanced with local proxy

**Components**:

1. **VS Code / JetBrains Extension**
   - Hooks into editor AI features
   - Scans code context being sent as prompt
   - SAST on AI-generated code before insertion

2. **Local Proxy (background daemon)**
   - Binds to `localhost:8443`
   - IDE configured to route AI traffic through it (`HTTPS_PROXY`)
   - Full request/response inspection
   - Works for any tool that respects proxy settings

3. **Process Monitor (lightweight eBPF or ptrace)**
   - For CLI coding agents (Claude Code, Aider) that don't respect proxy
   - Traces `execve` (what commands the agent runs)
   - Traces `openat` (what files the agent reads/writes)
   - Traces `tcp_sendmsg` (what data leaves the machine)

**Capabilities**:

| Capability | How |
|-----------|-----|
| Code exfiltration prevention | Scan outgoing context for secrets, proprietary patterns |
| Generated code safety | SAST scan on AI-generated code before it enters codebase |
| Tool execution audit | Log every bash command, file write, git operation the agent performs |
| Dependency hijack detection | Flag when agent installs unexpected packages |
| Repo injection detection | Scan `.cursorrules`, `AGENTS.md`, `CLAUDE.md` for injection attempts |

**Technology**: TypeScript (extension) + Go (local proxy + process monitor)

---

### 1E. MCP Gateway

**What**: Security gateway for Model Context Protocol (agentic AI).

**From**: Prompt Security approach

**Deployment**: Reverse proxy or lightweight agent

**Capabilities**:
- Intercept every MCP request/response
- Tool use authorization (allow/deny specific tools per agent)
- Shadow MCP discovery (unauthorized MCP servers)
- Risk scoring for 13,000+ known MCP servers
- Granular policies: user-based, server-based, action-based
- Full audit log of every agent interaction

**Architecture**:
```
  AI Agent (Claude, GPT, custom)
       │
       │ MCP protocol
       ▼
  ┌──────────────┐
  │  MCP Gateway  │
  │               │
  │ ┌───────────┐ │
  │ │Tool Policy│ │ → Which tools can this agent use?
  │ │Server Auth│ │ → Is this MCP server approved?
  │ │Data Filter│ │ → Is the tool response safe?
  │ │Audit Log  │ │ → Record everything
  │ └───────────┘ │
  └───────┬───────┘
          │
          ▼
    MCP Server (filesystem, database, API, etc.)
```

---

### 1F. CI/CD Scanner

**What**: Pre-merge and pre-deploy security checks.

**New addition** (neither Aurva nor Prompt Security has this)

**Capabilities**:
- Scan PRs for AI-generated code vulnerabilities
- Detect prompt injection payloads committed to repo (`.cursorrules`, `AGENTS.md`, etc.)
- Validate AI service configurations before deploy
- Block deployments that introduce unapproved AI dependencies

**Integration**: GitHub Actions, GitLab CI, Jenkins, ArgoCD

---

## Layer 2: Event Bus (Transport)

All sensors emit normalized events to a central event bus.

**Technology**: NATS JetStream (lightweight, K8s-native) for most deployments. Kafka for high-scale (>10K events/sec).

**Event Schema** (unified across all sensors):

```json
{
  "event_id": "uuid",
  "timestamp": "2026-03-20T10:30:00Z",
  "source": "kernel_observer | inline_gateway | browser | ide | mcp | cicd",
  "severity": "info | warning | critical",
  "actor": {
    "type": "pod | user | service_account | browser_user | agent",
    "id": "pod-xyz / user@corp.com / sa-default",
    "namespace": "prod-finance",
    "node": "node-1"
  },
  "target": {
    "type": "llm_provider | mcp_server | database | filesystem",
    "id": "api.openai.com / mcp-filesystem / postgres-prod",
    "endpoint": "/v1/chat/completions"
  },
  "action": {
    "type": "api_call | tool_exec | file_access | process_spawn",
    "direction": "outbound | inbound",
    "protocol": "https | grpc | mcp",
    "method": "POST"
  },
  "content": {
    "has_prompt": true,
    "prompt_hash": "sha256:...",
    "token_count": 1500,
    "model": "gpt-4",
    "pii_detected": ["email", "ssn"],
    "injection_score": 0.02,
    "blocked": false,
    "anonymized": true
  },
  "metadata": {
    "k8s_labels": {},
    "service_mesh": "istio",
    "tls_version": "1.3"
  }
}
```

**Fan-out**: Events are delivered to multiple consumers in parallel:
- Detection Engine (real-time analysis)
- ClickHouse (storage)
- Alert Manager (if severity ≥ threshold)
- External SIEM (Splunk, Elastic, Sentinel — optional)

---

## Layer 3: Processing Engine (Control Plane)

### 3A. Correlator

Joins events from different sensors into a unified view.

**Key correlations**:
- eBPF kernel event (pod X connected to api.openai.com) + Inline Gateway event (request body contained PII) → single enriched event
- Browser event (user@corp.com used ChatGPT) + Identity (user is in finance dept) → policy evaluation with full context
- IDE event (Copilot sent code) + eBPF event (same code patterns in production repo) → proprietary code leak alert

**K8s enrichment**:
- Socket inode → pod (via `/proc/net/tcp` + cgroup)
- Pod → Deployment/DaemonSet → Namespace → Team
- ServiceAccount → IAM role → permissions

### 3B. Detection Engine

Multiple detection layers running in parallel:

```
┌─────────────────────────────────────────────┐
│              Detection Engine                 │
│                                               │
│  ┌────────────┐  ┌─────────────────────────┐ │
│  │ Rule Engine │  │    ML Models            │ │
│  │ (Go)       │  │    (Python/ONNX)        │ │
│  │            │  │                         │ │
│  │ • Regex    │  │ • Prompt injection      │ │
│  │   patterns │  │   classifier            │ │
│  │ • PII      │  │ • Jailbreak detector    │ │
│  │   matchers │  │ • Toxicity scorer       │ │
│  │ • Secret   │  │ • Anomaly detector      │ │
│  │   scanners │  │   (baseline deviation)  │ │
│  │ • Domain   │  │ • PII NER model         │ │
│  │   blocklist│  │ • Code vuln classifier  │ │
│  └────────────┘  └─────────────────────────┘ │
│                                               │
│  ┌──────────────────────────────────────────┐ │
│  │ Stateful Context Analyzer                │ │
│  │                                          │ │
│  │ Tracks conversation sessions (Redis)     │ │
│  │ Detects multi-turn jailbreak attempts    │ │
│  │ Identifies gradual escalation patterns   │ │
│  │ Conversation trajectory scoring          │ │
│  └──────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

**Detection capabilities**:

| Threat | Detection Method | Action |
|--------|-----------------|--------|
| Prompt injection | ML classifier + signature rules | Block request |
| Indirect injection (RAG poisoning) | Embedding analysis + anomaly detection | Alert + quarantine |
| Jailbreak | Multi-model ensemble classifier | Block request |
| PII/secrets in prompt | NER model + regex (emails, SSNs, API keys, etc.) | Anonymize or block |
| Toxic/biased output | Content classifier on LLM response | Filter response |
| Shadow AI (unknown services) | eBPF discovers new AI API calls not in inventory | Alert + auto-enroll |
| Denial of wallet | Rate limiting + cost anomaly detection | Throttle/block |
| Code exfiltration | Proprietary code fingerprinting + secret scanning | Block in IDE/proxy |
| Vulnerable generated code | SAST on AI-generated code | Block insertion |
| Repo prompt injection | Scan `.cursorrules`, `AGENTS.md` for payloads | Block + alert |
| Multi-turn escalation | Stateful session analysis | Block at threshold |
| Agent tool abuse | MCP gateway policy + process exec monitoring | Block action |
| Model file exfiltration | eBPF file access monitoring (`.gguf`, `.safetensors`) | Alert |

### 3C. Policy Engine

Granular, hierarchical policy enforcement.

```yaml
# Example policy definition
apiVersion: kill-ai-leak/v1
kind: AISecurityPolicy
metadata:
  name: prod-finance-policy
  namespace: prod-finance
spec:
  # Who
  scope:
    namespaces: ["prod-finance"]
    serviceAccounts: ["invoice-ai-sa"]
    users: ["finance-team@corp.com"]

  # What LLM providers are allowed
  providers:
    allow: ["openai", "anthropic"]
    deny: ["*"]  # deny all others

  # Content rules
  input:
    block_pii: true
    anonymize_pii: true  # anonymize instead of hard block
    pii_types: ["ssn", "credit_card", "email"]
    block_secrets: true
    block_injection_score_above: 0.8
    max_tokens_per_request: 4096

  output:
    block_toxic_score_above: 0.7
    scan_generated_code: true
    block_vulnerable_code: true

  # Rate limits
  limits:
    max_requests_per_hour: 1000
    max_cost_per_day_usd: 100

  # Enforcement mode
  mode: enforce  # discover | monitor | enforce

  # Notifications
  alerts:
    slack: "#ai-security-alerts"
    pagerduty: "ai-security-oncall"
```

**Enforcement modes** (graduated rollout):

| Mode | Behavior |
|------|----------|
| `discover` | eBPF only. Log everything, block nothing. Build inventory. |
| `monitor` | eBPF + inline gateway in log-only mode. See what *would* be blocked. |
| `enforce` | Active blocking, anonymization, rate limiting. |

---

## Layer 4: Storage

| Store | Purpose | Technology |
|-------|---------|------------|
| **Event analytics** | High-throughput event storage, time-series queries, dashboards | ClickHouse |
| **Relational data** | Policies, inventory, service catalog, user config, teams | PostgreSQL |
| **Real-time state** | Session tracking, policy cache, rate limit counters | Redis |
| **Audit archive** | Long-term compliance storage, immutable audit trail | S3 / MinIO |
| **Prompt embeddings** (optional) | Semantic similarity search for injection detection | pgvector or Milvus |

---

## Layer 5: Presentation

### Dashboard (Next.js + React)

**Views**:

1. **AI Inventory / AIBOM** — complete bill of materials of all AI usage
   - Every service, provider, model, library, vector DB
   - Auto-discovered via eBPF + enriched via inline gateway
   - Per-service: call volume, token usage, cost estimate, data transferred

2. **Data Lineage** — visual graph showing data flow
   - Source (database/API) → Service → LLM Provider
   - Highlights PII exposure paths
   - Click-through to specific events

3. **Threat Feed** — real-time stream of security events
   - Prompt injections, jailbreak attempts, PII leaks
   - Severity-colored, filterable, searchable

4. **Policy Manager** — YAML editor + visual policy builder
   - Per-namespace, per-team, per-service policies
   - Dry-run mode (see impact before enforcing)

5. **Compliance Center** — pre-built reports
   - GDPR: data flow documentation, PII handling audit trail
   - SOC2: access controls, monitoring evidence
   - EU AI Act: AI system inventory, risk classification
   - Custom: exportable audit logs

6. **Red Team / Fuzzer** — built-in vulnerability testing
   - Mutation-based prompt fuzzing against your own services
   - Automated jailbreak / injection / exfiltration testing
   - Risk scoring with remediation recommendations
   - Continuous regression testing

---

## Layer 6: Integrations

| Category | Integrations |
|----------|-------------|
| **Identity** | Okta, Azure AD, Google Workspace, JumpCloud, SAML/OIDC |
| **SIEM** | Splunk, Elastic, Microsoft Sentinel, Sumo Logic |
| **Alerting** | PagerDuty, OpsGenie, Slack, Teams, email |
| **Ticketing** | Jira, Linear, GitHub Issues |
| **CI/CD** | GitHub Actions, GitLab CI, Jenkins, ArgoCD |
| **Service Mesh** | Istio, Linkerd (for transparent traffic redirect) |
| **Cloud** | AWS (EKS, Bedrock), GCP (GKE, Vertex), Azure (AKS, OpenAI) |
| **LLM Providers** | OpenAI, Anthropic, Google, Cohere, AWS Bedrock, self-hosted |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis, Milvus, Weaviate, Pinecone |

---

## Technology Stack

| Component | Language | Why |
|-----------|----------|-----|
| eBPF programs | C (BPF CO-RE) | Required for kernel programs |
| eBPF userspace loader | Go (cilium/ebpf) | Best Go library for eBPF lifecycle |
| Inline Gateway / Proxy | Go | High performance, low latency, stdlib net/http |
| Detection Engine — rules | Go | Fast rule evaluation, same binary as gateway |
| Detection Engine — ML | Python + ONNX Runtime | ML ecosystem, exportable models |
| Event Bus | NATS JetStream | Lightweight, K8s-native, sufficient for most scale |
| API Server | Go (gRPC + REST) | Consistent with data plane, high throughput |
| Dashboard | Next.js + React + TypeScript | Modern, SSR for performance |
| Browser Extension | TypeScript (Manifest V3) | Required for Chrome/Firefox |
| IDE Extension | TypeScript (VS Code API) | Required for VS Code |
| Local Proxy (dev machines) | Go | Cross-platform single binary |
| CLI Tool | Go (Cobra) | Cross-platform, install via brew/curl |
| Helm Charts | Go Template | K8s standard |
| Policy CRDs | Go (controller-runtime) | K8s-native policy management |

---

## Deployment Topologies

### Topology A: Full K8s (Recommended)

```
K8s Cluster
├── Namespace: kill-ai-leak-system
│   ├── DaemonSet: kernel-observer (eBPF, privileged)
│   ├── Deployment: inline-gateway (replicas: 3, HPA)
│   ├── Deployment: mcp-gateway (replicas: 2)
│   ├── Deployment: event-processor (replicas: 3, HPA)
│   ├── Deployment: detection-engine (replicas: 2, GPU optional)
│   ├── Deployment: api-server (replicas: 2)
│   ├── Deployment: dashboard (replicas: 2)
│   ├── StatefulSet: clickhouse (3 nodes)
│   ├── StatefulSet: postgresql (primary + replica)
│   ├── StatefulSet: redis (sentinel mode)
│   ├── StatefulSet: nats (3 nodes, JetStream)
│   └── CRDs: AISecurityPolicy, AIServiceInventory
│
│── Developer Machines (optional)
│   ├── IDE Extension (VS Code / JetBrains)
│   ├── Browser Extension (Chrome / Firefox)
│   └── Local Agent (Go binary: proxy + process monitor)
```

### Topology B: Hybrid (Self-hosted data plane, SaaS control plane)

```
Customer K8s Cluster              SaaS (hosted by us)
├── kernel-observer               ├── event-processor
├── inline-gateway         ──►    ├── detection-engine
├── mcp-gateway                   ├── dashboard
└── nats (local buffer)           ├── clickhouse
                                  ├── postgresql
                                  └── redis
```

Data plane stays in customer cluster (data sovereignty). Control plane is managed SaaS.

### Topology C: Lightweight (Observation only)

Just the eBPF observer + dashboard. No inline gateway. Discovery and visibility without enforcement. Good for initial rollout.

```
K8s Cluster
├── DaemonSet: kernel-observer
└── Sends events to SaaS dashboard
```

---

## Phased Build Plan

### Phase 1: Foundation (Months 1-3)
- [ ] eBPF Observer — tcp_sendmsg/recvmsg, SSL_write/read uprobes
- [ ] AI service fingerprinting (signature DB for LLM providers)
- [ ] K8s metadata enrichment (pod → service → namespace → team)
- [ ] Event Bus (NATS JetStream)
- [ ] ClickHouse + PostgreSQL setup
- [ ] Basic dashboard: AI inventory / AIBOM
- [ ] Helm chart for one-command install
- [ ] `curl | bash` installer

**Deliverable**: "Deploy and see all AI usage in your cluster in 60 seconds"

### Phase 2: Inline Enforcement (Months 3-5)
- [ ] Inline Gateway (Go reverse proxy)
- [ ] PII/secrets detection (regex + NER model)
- [ ] Prompt injection detection (ML classifier)
- [ ] Policy engine (YAML CRDs)
- [ ] Enforcement modes: discover → monitor → enforce
- [ ] eBPF → Gateway auto-enrollment loop
- [ ] Dashboard: threat feed, policy editor

**Deliverable**: "Discover unknown AI, then enforce policy on it"

### Phase 3: Edge Protection (Months 5-7)
- [ ] Browser extension (Chrome + Firefox)
- [ ] Shadow AI detection (employee AI usage monitoring)
- [ ] Employee DLP (PII anonymization in prompts)
- [ ] SSO/SAML integration
- [ ] IDE extension (VS Code)
- [ ] Local proxy for code assistants
- [ ] Generated code SAST scanning

**Deliverable**: "Protect employees and developers, not just infrastructure"

### Phase 4: Agentic AI (Months 7-9)
- [ ] MCP Gateway
- [ ] Tool use authorization policies
- [ ] Shadow MCP discovery
- [ ] MCP server risk scoring database
- [ ] CLI Agent for coding agents (Claude Code, Aider)
- [ ] Process execution monitoring on dev machines
- [ ] Repo injection scanner (`.cursorrules`, `AGENTS.md`)

**Deliverable**: "Full visibility and control over AI agents"

### Phase 5: Advanced (Months 9-12)
- [ ] Red Team Fuzzer (automated vulnerability testing)
- [ ] Multi-turn stateful detection
- [ ] RAG poisoning detection
- [ ] Cost management / denial-of-wallet protection
- [ ] Compliance reports (GDPR, SOC2, EU AI Act)
- [ ] SIEM integrations (Splunk, Elastic, Sentinel)
- [ ] Data lineage visualization
- [ ] Self-hosted / on-prem deployment option

**Deliverable**: "Enterprise-ready AI security platform"

---

## What This Platform Does That Neither Aurva Nor Prompt Security Does Alone

| Capability | Aurva | Prompt Security | Kill-AI-Leak |
|-----------|-------|-----------------|--------------|
| Zero-instrumentation discovery | Yes | No | Yes (eBPF) |
| Active blocking / filtering | No | Yes | Yes (Gateway) |
| Auto-discovery → auto-enforcement loop | No | No | **Yes** |
| Kernel-level process monitoring | Yes | No | Yes (eBPF) |
| Browser employee protection | No | Yes | Yes (Extension) |
| Coding agent tool execution monitoring | Partial | No | **Yes** (eBPF + process monitor) |
| MCP gateway | No | Yes | Yes |
| Repo injection scanning | No | No | **Yes** (CI/CD + IDE) |
| AI-generated code SAST | No | Partial | **Yes** |
| Graduated enforcement (discover → enforce) | No | No | **Yes** |
| Red team fuzzer | No | Yes (open source) | Yes (built-in) |
| Data lineage (source → LLM) | Yes | No | **Yes** |
| Multi-turn stateful detection | No | Yes | Yes |
| TLS visibility without MITM proxy | Yes (uprobes) | No (must proxy) | **Both** |
| Open source core | Yes | Fuzzer only | Yes (observer) |

---

## Repo Structure

```
kill-ai-leak/
├── cmd/
│   ├── observer/          # eBPF observer binary
│   ├── gateway/           # Inline gateway binary
│   ├── mcp-gateway/       # MCP gateway binary
│   ├── processor/         # Event processor binary
│   ├── api-server/        # API server binary
│   ├── agent/             # Local dev machine agent
│   └── cli/               # CLI tool (kalctl)
├── pkg/
│   ├── ebpf/              # eBPF programs (C) + Go loaders
│   │   ├── probes/        # BPF CO-RE C programs
│   │   └── loader/        # Go userspace loader
│   ├── proxy/             # Reverse proxy core
│   ├── detection/         # Detection engine
│   │   ├── rules/         # Rule-based detectors
│   │   ├── ml/            # ML model inference (ONNX)
│   │   └── stateful/      # Multi-turn session tracking
│   ├── policy/            # Policy engine + CRD types
│   ├── enrichment/        # K8s metadata enrichment
│   ├── fingerprint/       # AI service signature DB
│   ├── events/            # Event schema + bus client
│   └── common/            # Shared utilities
├── ml/
│   ├── injection/         # Prompt injection classifier
│   ├── pii/               # PII NER model
│   ├── toxicity/          # Toxicity classifier
│   └── training/          # Training pipelines
├── extensions/
│   ├── browser/           # Chrome/Firefox extension
│   ├── vscode/            # VS Code extension
│   └── jetbrains/         # JetBrains plugin
├── dashboard/
│   ├── src/               # Next.js app
│   └── public/
├── charts/
│   └── kill-ai-leak/      # Helm chart
├── deploy/
│   ├── install.sh
│   ├── uninstall.sh
│   └── docker/            # Dockerfiles
├── tests/
│   ├── e2e/
│   ├── integration/
│   └── fuzzer/            # Red team fuzzer
├── docs/
├── ARCHITECTURE.md         # This file
├── LICENSE                 # Apache 2.0
└── README.md
```
