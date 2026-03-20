// ---------------------------------------------------------------------------
// Kill-AI-Leak — Content Script: Prompt & Response Scanner
//
// Injected into AI chat sites. Responsibilities:
//   1. Intercept form submissions and input field content
//   2. Scan for PII (email, phone, SSN, credit card, etc.)
//   3. Scan for secrets (API keys, passwords, tokens)
//   4. Show warning overlay when sensitive data is detected
//   5. Monkey-patch fetch() / XMLHttpRequest to intercept API calls
//   6. Capture AI responses for output scanning
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PII & Secret pattern definitions
// (Mirrors the backend Go patterns from pkg/detection/pii and secrets)
// ---------------------------------------------------------------------------

interface DetectionPattern {
  type: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  regex: RegExp;
}

const PII_PATTERNS: DetectionPattern[] = [
  {
    type: "pii",
    label: "email",
    severity: "medium",
    regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
  },
  {
    type: "pii",
    label: "phone",
    severity: "medium",
    regex: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
  },
  {
    type: "pii",
    label: "ssn",
    severity: "critical",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    type: "pii",
    label: "credit_card",
    severity: "critical",
    regex:
      /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
  },
  {
    type: "pii",
    label: "credit_card",
    severity: "critical",
    regex: /\b(?:\d{4}[-\s]){3}\d{4}\b/g,
  },
  {
    type: "pii",
    label: "ip_address",
    severity: "low",
    regex:
      /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  },
];

const SECRET_PATTERNS: DetectionPattern[] = [
  {
    type: "secret",
    label: "aws_access_key",
    severity: "critical",
    regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    type: "secret",
    label: "aws_secret_key",
    severity: "critical",
    regex:
      /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
  },
  {
    type: "secret",
    label: "github_token",
    severity: "critical",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g,
  },
  {
    type: "secret",
    label: "openai_key",
    severity: "critical",
    regex: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g,
  },
  {
    type: "secret",
    label: "openai_key",
    severity: "critical",
    regex: /\bsk-proj-[A-Za-z0-9_-]{40,200}\b/g,
  },
  {
    type: "secret",
    label: "anthropic_key",
    severity: "critical",
    regex: /\bsk-ant-[A-Za-z0-9_-]{40,200}\b/g,
  },
  {
    type: "secret",
    label: "slack_token",
    severity: "high",
    regex: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b/g,
  },
  {
    type: "secret",
    label: "private_key",
    severity: "critical",
    regex: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    type: "secret",
    label: "password",
    severity: "high",
    regex:
      /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{8,})["']/gi,
  },
  {
    type: "secret",
    label: "connection_string",
    severity: "critical",
    regex:
      /(?:mongodb|postgres(?:ql)?|mysql|redis|amqp|mssql):\/\/[^\s]+:[^\s]+@[^\s]+/gi,
  },
  {
    type: "secret",
    label: "bearer_token",
    severity: "high",
    regex:
      /(?:authorization|bearer)\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9_\-.~+/]+=*["']?/gi,
  },
  {
    type: "secret",
    label: "api_key",
    severity: "high",
    regex:
      /(?:api_key|apikey|api[-_]secret)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?/gi,
  },
  {
    type: "secret",
    label: "jwt",
    severity: "high",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
];

const ALL_PATTERNS: DetectionPattern[] = [...PII_PATTERNS, ...SECRET_PATTERNS];

// ---------------------------------------------------------------------------
// Finding type
// ---------------------------------------------------------------------------

interface ScanFinding {
  type: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  value: string;
  startPos: number;
  endPos: number;
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

function scanText(text: string): ScanFinding[] {
  if (!text || text.length < 5) return [];

  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  for (const pattern of ALL_PATTERNS) {
    // Reset lastIndex for global regexes.
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(text)) !== null) {
      const key = `${pattern.label}:${match.index}:${match.index + match[0].length}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        type: pattern.type,
        label: pattern.label,
        severity: pattern.severity,
        value: match[0],
        startPos: match.index,
        endPos: match.index + match[0].length,
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Warning Overlay
// ---------------------------------------------------------------------------

let overlayEl: HTMLElement | null = null;

function showWarningOverlay(findings: ScanFinding[]): void {
  removeOverlay();

  overlayEl = document.createElement("div");
  overlayEl.id = "kail-warning-overlay";

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;

  const summaryParts: string[] = [];
  if (criticalCount > 0) summaryParts.push(`${criticalCount} critical`);
  if (highCount > 0) summaryParts.push(`${highCount} high`);
  if (mediumCount > 0) summaryParts.push(`${mediumCount} medium`);

  const findingList = findings
    .slice(0, 10)
    .map((f) => {
      const masked = maskValue(f.value);
      return `<li><span class="kail-severity kail-severity-${f.severity}">${f.severity}</span> <strong>${escapeHtml(f.label)}</strong>: ${escapeHtml(masked)}</li>`;
    })
    .join("");

  overlayEl.innerHTML = `
    <div class="kail-overlay-content">
      <div class="kail-overlay-header">
        <span class="kail-shield-icon">&#x1f6e1;</span>
        <strong>Kill-AI-Leak: Sensitive Data Detected</strong>
        <button id="kail-overlay-close" title="Dismiss">&times;</button>
      </div>
      <p>Found ${findings.length} sensitive item(s): ${summaryParts.join(", ")}</p>
      <ul class="kail-finding-list">${findingList}</ul>
      ${findings.length > 10 ? `<p class="kail-more">...and ${findings.length - 10} more</p>` : ""}
      <div class="kail-overlay-actions">
        <button id="kail-btn-anonymize" class="kail-btn kail-btn-primary">Anonymize &amp; Send</button>
        <button id="kail-btn-block" class="kail-btn kail-btn-danger">Block Submission</button>
        <button id="kail-btn-allow" class="kail-btn kail-btn-secondary">Allow Anyway</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlayEl);

  // Bind actions.
  document.getElementById("kail-overlay-close")?.addEventListener("click", removeOverlay);
  document.getElementById("kail-btn-block")?.addEventListener("click", () => {
    pendingAction = "block";
    removeOverlay();
  });
  document.getElementById("kail-btn-anonymize")?.addEventListener("click", () => {
    pendingAction = "anonymize";
    removeOverlay();
  });
  document.getElementById("kail-btn-allow")?.addEventListener("click", () => {
    pendingAction = "allow";
    removeOverlay();
  });
}

function removeOverlay(): void {
  overlayEl?.remove();
  overlayEl = null;
}

// ---------------------------------------------------------------------------
// Pending action state (set by overlay buttons, consumed by interceptors)
// ---------------------------------------------------------------------------

let pendingAction: "block" | "anonymize" | "allow" | null = null;
let pendingResolve: ((action: "block" | "anonymize" | "allow") => void) | null =
  null;

function waitForUserAction(
  findings: ScanFinding[],
): Promise<"block" | "anonymize" | "allow"> {
  pendingAction = null;

  showWarningOverlay(findings);

  return new Promise((resolve) => {
    pendingResolve = resolve;

    const check = setInterval(() => {
      if (pendingAction !== null) {
        clearInterval(check);
        resolve(pendingAction);
        pendingResolve = null;
      }
    }, 100);

    // Auto-block after 30 seconds if no user action.
    setTimeout(() => {
      if (pendingAction === null) {
        clearInterval(check);
        pendingAction = "block";
        removeOverlay();
        resolve("block");
        pendingResolve = null;
      }
    }, 30_000);
  });
}

// ---------------------------------------------------------------------------
// Input field interception
// ---------------------------------------------------------------------------

function findPromptInputs(): Array<HTMLTextAreaElement | HTMLInputElement | HTMLElement> {
  const selectors = [
    'textarea[data-id="root"]',                  // ChatGPT
    'div[contenteditable="true"]',               // Claude, Gemini
    "textarea#prompt-textarea",                  // ChatGPT alternate
    'textarea[placeholder*="message"]',          // Generic chat
    'textarea[placeholder*="Message"]',
    'textarea[placeholder*="Ask"]',
    'div[role="textbox"]',                       // Generic contenteditable
    "textarea.chat-input",
    'textarea[name="q"]',                        // Perplexity
  ];

  const elements: Array<HTMLTextAreaElement | HTMLInputElement | HTMLElement> = [];
  for (const sel of selectors) {
    const found = document.querySelectorAll<HTMLElement>(sel);
    found.forEach((el) => elements.push(el));
  }

  return elements;
}

function getInputText(
  el: HTMLTextAreaElement | HTMLInputElement | HTMLElement,
): string {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    return el.value;
  }
  return el.textContent ?? el.innerText ?? "";
}

// ---------------------------------------------------------------------------
// Form submission interception
// ---------------------------------------------------------------------------

function interceptFormSubmissions(): void {
  // Watch for Enter key on prompt inputs.
  document.addEventListener(
    "keydown",
    async (event) => {
      if (event.key !== "Enter" || event.shiftKey) return;

      const target = event.target as HTMLElement;
      const text = getInputText(target as HTMLTextAreaElement);
      if (!text) return;

      const findings = scanText(text);
      if (findings.length === 0) return;

      event.preventDefault();
      event.stopPropagation();

      reportFindings(findings);

      const action = await waitForUserAction(findings);

      if (action === "block") {
        // Do nothing — submission was blocked.
        return;
      }

      if (action === "anonymize") {
        // Dispatch anonymize event to the anonymizer content script.
        window.dispatchEvent(
          new CustomEvent("kail-anonymize-request", {
            detail: { text, findings },
          }),
        );
        // The anonymizer will set the input value and re-submit.
        return;
      }

      // "allow" — re-fire the enter key.
      const enterEvent = new KeyboardEvent("keydown", {
        key: "Enter",
        code: "Enter",
        keyCode: 13,
        bubbles: true,
        cancelable: true,
      });
      target.dispatchEvent(enterEvent);
    },
    true, // capture phase
  );

  // Watch for click on send buttons.
  document.addEventListener(
    "click",
    async (event) => {
      const target = event.target as HTMLElement;
      const isSendButton = isSendButtonElement(target);
      if (!isSendButton) return;

      const inputs = findPromptInputs();
      for (const input of inputs) {
        const text = getInputText(input);
        if (!text) continue;

        const findings = scanText(text);
        if (findings.length === 0) continue;

        event.preventDefault();
        event.stopPropagation();

        reportFindings(findings);

        const action = await waitForUserAction(findings);

        if (action === "block") return;

        if (action === "anonymize") {
          window.dispatchEvent(
            new CustomEvent("kail-anonymize-request", {
              detail: { text, findings },
            }),
          );
          return;
        }

        // "allow" — re-click the button.
        target.click();
        return;
      }
    },
    true,
  );
}

function isSendButtonElement(el: HTMLElement): boolean {
  if (!el) return false;
  const testEl = el.closest("button") ?? el;
  const ariaLabel = (testEl.getAttribute("aria-label") ?? "").toLowerCase();
  const text = (testEl.textContent ?? "").toLowerCase();
  const dataTestId = testEl.getAttribute("data-testid") ?? "";

  return (
    ariaLabel.includes("send") ||
    text.includes("send") ||
    text === "submit" ||
    dataTestId.includes("send") ||
    testEl.querySelector('svg[data-icon="send"]') !== null ||
    testEl.querySelector('path[d*="M2.01"]') !== null // Common send icon path
  );
}

// ---------------------------------------------------------------------------
// fetch() monkey-patch
// ---------------------------------------------------------------------------

const originalFetch = window.fetch.bind(window);

(window as Record<string, unknown>).fetch = async function patchedFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

  // Only intercept POST requests to known AI API endpoints.
  const method = init?.method?.toUpperCase() ?? "GET";
  if (method !== "POST") {
    return originalFetch(input, init);
  }

  // Scan outbound body.
  if (init?.body) {
    const bodyText = await extractBodyText(init.body);
    if (bodyText) {
      const findings = scanText(bodyText);
      if (findings.length > 0) {
        reportFindings(findings);

        const action = await waitForUserAction(findings);

        if (action === "block") {
          return new Response(
            JSON.stringify({
              error: "blocked_by_kill_ai_leak",
              message: "Request blocked: sensitive data detected",
            }),
            { status: 403, headers: { "Content-Type": "application/json" } },
          );
        }

        if (action === "anonymize") {
          // Anonymize the body in place.
          const anonymizedBody = anonymizeText(bodyText, findings);
          init = { ...init, body: anonymizedBody };
        }
      }
    }
  }

  // Execute the real fetch.
  const response = await originalFetch(input, init);

  // Clone and scan the response for output violations.
  scanResponseAsync(response.clone()).catch(() => {});

  return response;
};

// ---------------------------------------------------------------------------
// XMLHttpRequest monkey-patch
// ---------------------------------------------------------------------------

const OriginalXHR = window.XMLHttpRequest;

class PatchedXHR extends OriginalXHR {
  private _method = "GET";
  private _url = "";

  override open(method: string, url: string | URL, ...args: [boolean?, string?, string?]): void {
    this._method = method.toUpperCase();
    this._url = typeof url === "string" ? url : url.toString();
    return super.open(method, url, ...args);
  }

  override send(body?: Document | XMLHttpRequestBodyInit | null): void {
    if (this._method === "POST" && body) {
      const bodyStr = typeof body === "string" ? body : "";
      if (bodyStr) {
        const findings = scanText(bodyStr);
        if (findings.length > 0) {
          reportFindings(findings);
          // For XHR we can only block synchronously (no await).
          // We block the request and let the user know via overlay.
          showWarningOverlay(findings);
          // Abort the request.
          this.abort();
          return;
        }
      }
    }

    // Scan response on load.
    this.addEventListener("load", () => {
      try {
        const responseText = this.responseText;
        if (responseText) {
          scanResponseText(responseText);
        }
      } catch {
        // Response may not be accessible (CORS).
      }
    });

    return super.send(body);
  }
}

(window as Record<string, unknown>).XMLHttpRequest = PatchedXHR as typeof XMLHttpRequest;

// ---------------------------------------------------------------------------
// Body extraction helpers
// ---------------------------------------------------------------------------

async function extractBodyText(
  body: BodyInit | null | undefined,
): Promise<string | null> {
  if (!body) return null;
  if (typeof body === "string") return body;
  if (body instanceof Blob) return body.text();
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(body);
  if (body instanceof URLSearchParams) return body.toString();
  if (body instanceof FormData) {
    const parts: string[] = [];
    body.forEach((value, key) => {
      if (typeof value === "string") {
        parts.push(`${key}=${value}`);
      }
    });
    return parts.join("&");
  }
  // ReadableStream — consume a clone.
  if (body instanceof ReadableStream) {
    try {
      const reader = body.getReader();
      const chunks: Uint8Array[] = [];
      let done = false;
      while (!done) {
        const result = await reader.read();
        done = result.done;
        if (result.value) chunks.push(result.value);
      }
      const combined = new Uint8Array(
        chunks.reduce((s, c) => s + c.length, 0),
      );
      let offset = 0;
      for (const chunk of chunks) {
        combined.set(chunk, offset);
        offset += chunk.length;
      }
      return new TextDecoder().decode(combined);
    } catch {
      return null;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Response scanning
// ---------------------------------------------------------------------------

async function scanResponseAsync(response: Response): Promise<void> {
  try {
    const text = await response.text();
    scanResponseText(text);
  } catch {
    // Cannot read — e.g. streaming or opaque response.
  }
}

function scanResponseText(text: string): void {
  if (!text || text.length < 10) return;

  // Look for PII leakage in responses (the LLM repeating back PII).
  const findings = scanText(text);
  if (findings.length > 0) {
    // Report to background.
    chrome.runtime.sendMessage({
      type: "SCAN_RESULT",
      findings: findings.map((f) => ({
        type: f.label,
        severity: f.severity,
        direction: "response",
      })),
    });
  }
}

// ---------------------------------------------------------------------------
// Simple inline anonymization (for fetch body replacement)
// ---------------------------------------------------------------------------

function anonymizeText(text: string, findings: ScanFinding[]): string {
  // Sort findings by startPos descending to replace from end.
  const sorted = [...findings].sort((a, b) => b.startPos - a.startPos);
  let result = text;
  const counters = new Map<string, number>();

  for (const f of sorted) {
    const prefix = f.label.toUpperCase();
    const count = (counters.get(prefix) ?? 0) + 1;
    counters.set(prefix, count);
    const token = `<${prefix}_${count}>`;
    result = result.slice(0, f.startPos) + token + result.slice(f.endPos);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Report findings to background service worker
// ---------------------------------------------------------------------------

function reportFindings(findings: ScanFinding[]): void {
  chrome.runtime.sendMessage({
    type: "SCAN_RESULT",
    findings: findings.map((f) => ({
      type: f.label,
      severity: f.severity,
      direction: "request",
    })),
  });
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

function maskValue(s: string): string {
  if (s.length <= 4) return "*".repeat(s.length);
  return s[0] + "*".repeat(s.length - 2) + s[s.length - 1];
}

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

function init(): void {
  interceptFormSubmissions();

  // Inject the overlay CSS.
  const style = document.createElement("style");
  style.textContent = OVERLAY_CSS;
  document.head.appendChild(style);
}

// ---------------------------------------------------------------------------
// Inline CSS for the warning overlay
// ---------------------------------------------------------------------------

const OVERLAY_CSS = `
#kail-warning-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.6);
  z-index: 2147483647;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.kail-overlay-content {
  background: #1a1a2e;
  color: #e0e0e0;
  border: 2px solid #e94560;
  border-radius: 12px;
  padding: 24px 28px;
  max-width: 560px;
  width: 90%;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}
.kail-overlay-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
  font-size: 16px;
}
.kail-overlay-header button {
  margin-left: auto;
  background: none;
  border: none;
  color: #999;
  font-size: 22px;
  cursor: pointer;
  padding: 0 4px;
}
.kail-overlay-header button:hover { color: #fff; }
.kail-shield-icon { font-size: 22px; }
.kail-finding-list {
  list-style: none;
  padding: 0;
  margin: 8px 0;
  max-height: 200px;
  overflow-y: auto;
}
.kail-finding-list li {
  padding: 6px 0;
  border-bottom: 1px solid #2a2a4a;
  font-size: 13px;
}
.kail-severity {
  display: inline-block;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}
.kail-severity-critical { background: #e94560; color: #fff; }
.kail-severity-high { background: #f77f00; color: #fff; }
.kail-severity-medium { background: #eab308; color: #000; }
.kail-severity-low { background: #3b82f6; color: #fff; }
.kail-more { font-size: 12px; color: #888; }
.kail-overlay-actions {
  display: flex;
  gap: 10px;
  margin-top: 16px;
}
.kail-btn {
  flex: 1;
  padding: 10px 16px;
  border: none;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.15s;
}
.kail-btn:hover { opacity: 0.85; }
.kail-btn-primary { background: #16a34a; color: #fff; }
.kail-btn-danger { background: #e94560; color: #fff; }
.kail-btn-secondary { background: #334155; color: #e0e0e0; }
`;

// Run on load.
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
