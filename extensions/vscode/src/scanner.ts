// ---------------------------------------------------------------------------
// Kill-AI-Leak — VS Code Code Scanner
//
// Provides three scanning modes:
//   1. Secret detection (API keys, tokens, passwords, connection strings)
//   2. Vulnerability detection (SAST-lite: SQLi, CMDi, XSS, path traversal, ...)
//   3. Prompt injection detection (in agent config files)
//
// Integrates with VS Code Diagnostics to surface findings as warnings/errors.
// Pattern sets mirror the backend Go detectors to maintain consistency.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScannerConfig {
  sensitivityLevel: "low" | "medium" | "high";
  serverUrl: string;
  authToken: string;
}

export interface ScanFinding {
  ruleId: string;
  category: string;
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  startPos: number;
  endPos: number;
  line: number;
  value?: string;
}

export interface ScanResult {
  fileName: string;
  findings: ScanFinding[];
  scannedAt: string;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

interface ScanPattern {
  ruleId: string;
  category: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  regex: RegExp;
  message: string;
  /** If set, only apply to these language IDs. */
  languages?: string[];
}

// ---- Secrets ----

const SECRET_PATTERNS: ScanPattern[] = [
  {
    ruleId: "KAIL-S001",
    category: "secrets",
    label: "aws_access_key",
    severity: "critical",
    confidence: 0.97,
    regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    message: "AWS Access Key ID detected",
  },
  {
    ruleId: "KAIL-S002",
    category: "secrets",
    label: "aws_secret_key",
    severity: "critical",
    confidence: 0.95,
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    message: "AWS Secret Access Key detected",
  },
  {
    ruleId: "KAIL-S003",
    category: "secrets",
    label: "github_token",
    severity: "critical",
    confidence: 0.97,
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g,
    message: "GitHub personal access token detected",
  },
  {
    ruleId: "KAIL-S004",
    category: "secrets",
    label: "openai_key",
    severity: "critical",
    confidence: 0.97,
    regex: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g,
    message: "OpenAI API key detected",
  },
  {
    ruleId: "KAIL-S005",
    category: "secrets",
    label: "openai_key",
    severity: "critical",
    confidence: 0.95,
    regex: /\bsk-proj-[A-Za-z0-9_-]{40,200}\b/g,
    message: "OpenAI project API key detected",
  },
  {
    ruleId: "KAIL-S006",
    category: "secrets",
    label: "anthropic_key",
    severity: "critical",
    confidence: 0.97,
    regex: /\bsk-ant-[A-Za-z0-9_-]{40,200}\b/g,
    message: "Anthropic API key detected",
  },
  {
    ruleId: "KAIL-S007",
    category: "secrets",
    label: "slack_token",
    severity: "high",
    confidence: 0.95,
    regex: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b/g,
    message: "Slack bot token detected",
  },
  {
    ruleId: "KAIL-S008",
    category: "secrets",
    label: "private_key",
    severity: "critical",
    confidence: 0.99,
    regex: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    message: "Private key detected in source code",
  },
  {
    ruleId: "KAIL-S009",
    category: "secrets",
    label: "password",
    severity: "high",
    confidence: 0.85,
    regex: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{8,})["']/gi,
    message: "Hardcoded password detected",
  },
  {
    ruleId: "KAIL-S010",
    category: "secrets",
    label: "connection_string",
    severity: "critical",
    confidence: 0.95,
    regex: /(?:mongodb|postgres(?:ql)?|mysql|redis|amqp|mssql):\/\/[^\s]+:[^\s]+@[^\s]+/gi,
    message: "Database connection string with credentials detected",
  },
  {
    ruleId: "KAIL-S011",
    category: "secrets",
    label: "bearer_token",
    severity: "high",
    confidence: 0.85,
    regex: /(?:authorization|bearer)\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9_\-.~+/]+=*["']?/gi,
    message: "Bearer token detected in source code",
  },
  {
    ruleId: "KAIL-S012",
    category: "secrets",
    label: "api_key",
    severity: "high",
    confidence: 0.80,
    regex: /(?:api_key|apikey|api[-_]secret)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?/gi,
    message: "API key assignment detected",
  },
  {
    ruleId: "KAIL-S013",
    category: "secrets",
    label: "jwt",
    severity: "high",
    confidence: 0.90,
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    message: "JWT token detected in source code",
  },
];

// ---- Code vulnerabilities (SAST-lite) ----

const VULN_PATTERNS: ScanPattern[] = [
  // SQL Injection
  {
    ruleId: "KAIL-V001",
    category: "sql_injection",
    label: "string_concat_sql",
    severity: "critical",
    confidence: 0.90,
    regex: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\s+.*[+"']\s*\+\s*\w+/gi,
    message: "SQL query built via string concatenation (SQL injection risk)",
  },
  {
    ruleId: "KAIL-V002",
    category: "sql_injection",
    label: "format_string_sql",
    severity: "critical",
    confidence: 0.90,
    regex: /(?:f["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s|\.format\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE|DROP))/gi,
    message: "SQL query built via format string (SQL injection risk)",
    languages: ["python"],
  },
  {
    ruleId: "KAIL-V003",
    category: "sql_injection",
    label: "sprintf_sql",
    severity: "critical",
    confidence: 0.90,
    regex: /(?:fmt\.Sprintf|sprintf|String\.format)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)/gi,
    message: "SQL query built via sprintf (SQL injection risk)",
  },

  // Command Injection
  {
    ruleId: "KAIL-V010",
    category: "command_injection",
    label: "os_system_call",
    severity: "critical",
    confidence: 0.85,
    regex: /(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)|exec\.Command|Runtime\.(?:getRuntime\(\)\.)?exec)\s*\(/gi,
    message: "Command execution function detected (command injection risk)",
  },
  {
    ruleId: "KAIL-V011",
    category: "command_injection",
    label: "shell_exec",
    severity: "critical",
    confidence: 0.80,
    regex: /(?:eval|exec)\s*\(/gi,
    message: "eval/exec call detected (code injection risk)",
  },
  {
    ruleId: "KAIL-V012",
    category: "command_injection",
    label: "child_process",
    severity: "high",
    confidence: 0.85,
    regex: /(?:child_process|shelljs).*(?:exec|spawn)\s*\(/gi,
    message: "Node.js child process execution detected",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
  },

  // Path Traversal
  {
    ruleId: "KAIL-V020",
    category: "path_traversal",
    label: "path_traversal_input",
    severity: "high",
    confidence: 0.80,
    regex: /(?:open|readFile|writeFile|readFileSync|writeFileSync|os\.(?:Open|Create|ReadFile|WriteFile))\s*\(\s*(?:req\.|request\.|params\.|user_?input|filename)/gi,
    message: "File path built from user input (path traversal risk)",
  },

  // XSS
  {
    ruleId: "KAIL-V030",
    category: "xss",
    label: "inner_html",
    severity: "high",
    confidence: 0.85,
    regex: /\.innerHTML\s*=/gi,
    message: "innerHTML assignment detected (XSS risk)",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
  },
  {
    ruleId: "KAIL-V031",
    category: "xss",
    label: "document_write",
    severity: "high",
    confidence: 0.85,
    regex: /document\.write(?:ln)?\s*\(/gi,
    message: "document.write detected (XSS risk)",
    languages: ["javascript", "typescript", "html"],
  },
  {
    ruleId: "KAIL-V032",
    category: "xss",
    label: "dangerously_set_html",
    severity: "high",
    confidence: 0.90,
    regex: /dangerouslySetInnerHTML\s*=\s*\{/gi,
    message: "dangerouslySetInnerHTML usage detected (XSS risk)",
    languages: ["javascriptreact", "typescriptreact", "javascript", "typescript"],
  },

  // Hardcoded credentials in code
  {
    ruleId: "KAIL-V040",
    category: "hardcoded_secret",
    label: "hardcoded_password",
    severity: "critical",
    confidence: 0.85,
    regex: /(?:password|passwd|pwd|secret|api_?key|token|auth)\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
    message: "Hardcoded credential detected in code",
  },

  // Insecure Cryptography
  {
    ruleId: "KAIL-V050",
    category: "insecure_crypto",
    label: "weak_hash_md5",
    severity: "medium",
    confidence: 0.80,
    regex: /(?:md5|MD5)\s*[.(]/g,
    message: "MD5 hash function used (cryptographically broken)",
  },
  {
    ruleId: "KAIL-V051",
    category: "insecure_crypto",
    label: "weak_hash_sha1",
    severity: "medium",
    confidence: 0.80,
    regex: /(?:sha1|SHA1)\s*[.(]/g,
    message: "SHA1 hash function used (deprecated for security)",
  },
  {
    ruleId: "KAIL-V052",
    category: "insecure_crypto",
    label: "disabled_tls_verify",
    severity: "high",
    confidence: 0.90,
    regex: /(?:InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|VERIFY_NONE|SSL_VERIFY_NONE|NODE_TLS_REJECT_UNAUTHORIZED.*0)/gi,
    message: "TLS certificate verification disabled",
  },

  // Deserialization
  {
    ruleId: "KAIL-V060",
    category: "deserialization",
    label: "pickle_load",
    severity: "critical",
    confidence: 0.90,
    regex: /pickle\.(?:loads?|Unpickler)\s*\(/gi,
    message: "Unsafe pickle deserialization (arbitrary code execution risk)",
    languages: ["python"],
  },
  {
    ruleId: "KAIL-V061",
    category: "deserialization",
    label: "yaml_unsafe_load",
    severity: "critical",
    confidence: 0.90,
    regex: /yaml\.(?:unsafe_)?load\s*\(/gi,
    message: "Unsafe YAML load (code execution risk)",
    languages: ["python"],
  },
];

// ---- Prompt injection (for agent config files) ----

const INJECTION_PATTERNS: ScanPattern[] = [
  {
    ruleId: "KAIL-I001",
    category: "prompt_injection",
    label: "ignore_previous",
    severity: "critical",
    confidence: 0.90,
    regex: /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|directives?|rules?)/gi,
    message: "Prompt injection: instruction override attempt detected",
  },
  {
    ruleId: "KAIL-I002",
    category: "prompt_injection",
    label: "disregard_instructions",
    severity: "critical",
    confidence: 0.90,
    regex: /disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|prompts?|guidelines?)/gi,
    message: "Prompt injection: disregard instructions pattern detected",
  },
  {
    ruleId: "KAIL-I003",
    category: "prompt_injection",
    label: "system_prompt_marker",
    severity: "critical",
    confidence: 0.95,
    regex: /system\s*prompt\s*:/gi,
    message: "Prompt injection: system prompt marker detected",
  },
  {
    ruleId: "KAIL-I004",
    category: "prompt_injection",
    label: "chatml_marker",
    severity: "critical",
    confidence: 0.95,
    regex: /<\|im_start\|>|<\|im_end\|>/g,
    message: "Prompt injection: ChatML format marker detected",
  },
  {
    ruleId: "KAIL-I005",
    category: "prompt_injection",
    label: "inst_marker",
    severity: "critical",
    confidence: 0.90,
    regex: /\[INST\]|\[\/INST\]/g,
    message: "Prompt injection: instruction format marker detected",
  },
  {
    ruleId: "KAIL-I006",
    category: "prompt_injection",
    label: "role_reassignment",
    severity: "high",
    confidence: 0.80,
    regex: /you\s+are\s+now\s+(?:a|an|the)\s+/gi,
    message: "Prompt injection: role reassignment attempt detected",
  },
  {
    ruleId: "KAIL-I007",
    category: "prompt_injection",
    label: "prompt_leak",
    severity: "high",
    confidence: 0.85,
    regex: /(?:show|reveal|display|print|output|repeat|echo)\s+(?:your|the|my)?\s*(?:system\s+)?(?:prompt|instructions?|rules?|directives?)/gi,
    message: "Prompt injection: prompt leaking attempt detected",
  },
  {
    ruleId: "KAIL-I008",
    category: "prompt_injection",
    label: "data_exfiltration",
    severity: "critical",
    confidence: 0.85,
    regex: /(?:send|post|fetch|curl|wget|http)\s+.*(?:to|http)/gi,
    message: "Potential data exfiltration command in agent config",
  },
  {
    ruleId: "KAIL-I009",
    category: "prompt_injection",
    label: "hidden_instruction",
    severity: "high",
    confidence: 0.75,
    regex: /(?:from\s+now\s+on|henceforth|starting\s+now)\s*,?\s*(?:you\s+are|act\s+as|behave\s+as|respond\s+as)/gi,
    message: "Prompt injection: hidden instruction override detected",
  },
  {
    ruleId: "KAIL-I010",
    category: "prompt_injection",
    label: "execute_code",
    severity: "critical",
    confidence: 0.85,
    regex: /(?:execute|run|eval)\s+(?:the\s+following|this)\s+(?:code|command|script)/gi,
    message: "Prompt injection: code execution directive detected",
  },
];

// ---------------------------------------------------------------------------
// Sensitivity thresholds
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const SENSITIVITY_THRESHOLD: Record<string, number> = {
  low: 3,    // Only critical
  medium: 2, // High and above
  high: 1,   // Everything
};

// ---------------------------------------------------------------------------
// Scanner class
// ---------------------------------------------------------------------------

export class Scanner {
  private config: ScannerConfig;
  private minSeverityRank: number;

  constructor(config: ScannerConfig) {
    this.config = config;
    this.minSeverityRank =
      SENSITIVITY_THRESHOLD[config.sensitivityLevel] ?? 2;
  }

  /**
   * Scan a file's content for secrets, vulnerabilities, and PII.
   */
  scanFile(
    text: string,
    fileName: string,
    languageId: string,
  ): ScanResult {
    const start = Date.now();
    const findings: ScanFinding[] = [];

    // Run secret patterns.
    findings.push(...this.runPatterns(SECRET_PATTERNS, text, languageId));

    // Run vulnerability patterns.
    findings.push(...this.runPatterns(VULN_PATTERNS, text, languageId));

    // Filter by sensitivity threshold.
    const filtered = findings.filter(
      (f) => (SEVERITY_RANK[f.severity] ?? 0) >= this.minSeverityRank,
    );

    return {
      fileName,
      findings: filtered,
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - start,
    };
  }

  /**
   * Scan an agent configuration file specifically for prompt injection.
   */
  scanAgentConfig(text: string, fileName: string): ScanResult {
    const start = Date.now();
    const findings: ScanFinding[] = [];

    // Run injection patterns.
    findings.push(...this.runPatterns(INJECTION_PATTERNS, text, ""));

    // Also scan for secrets that might be embedded.
    findings.push(...this.runPatterns(SECRET_PATTERNS, text, ""));

    return {
      fileName,
      findings,
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - start,
    };
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private runPatterns(
    patterns: ScanPattern[],
    text: string,
    languageId: string,
  ): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const seen = new Set<string>();

    for (const pattern of patterns) {
      // Language filter.
      if (
        pattern.languages &&
        pattern.languages.length > 0 &&
        languageId &&
        !pattern.languages.includes(languageId)
      ) {
        continue;
      }

      // Reset regex.
      pattern.regex.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = pattern.regex.exec(text)) !== null) {
        const start = match.index;
        const end = start + match[0].length;
        const dedupKey = `${pattern.ruleId}:${start}:${end}`;

        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);

        // Calculate line number.
        const line = countNewlines(text, start);

        findings.push({
          ruleId: pattern.ruleId,
          category: pattern.category,
          message: pattern.message,
          severity: pattern.severity,
          confidence: pattern.confidence,
          startPos: start,
          endPos: end,
          line,
          value: redact(match[0]),
        });
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

function countNewlines(text: string, upTo: number): number {
  let count = 0;
  for (let i = 0; i < upTo && i < text.length; i++) {
    if (text[i] === "\n") count++;
  }
  return count;
}

function redact(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return value.slice(0, 4) + "*".repeat(value.length - 6) + value.slice(-2);
}
