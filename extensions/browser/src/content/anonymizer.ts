export {};

// ---------------------------------------------------------------------------
// Kill-AI-Leak — Content Script: Client-Side PII Anonymizer
//
// Provides reversible PII anonymization within a browser session.
// Tokens are deterministic per session: "John Smith" always maps to
// <PERSON_1> for the lifetime of the tab.
//
// Mirrors the server-side Go anonymizer (pkg/anonymizer/anonymizer.go).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AnonymizeFinding {
  label: string;
  value: string;
  startPos: number;
  endPos: number;
}

interface AnonymizeRequest {
  text: string;
  findings: AnonymizeFinding[];
}

// ---------------------------------------------------------------------------
// Token prefix mapping (matches backend tokenPrefix map)
// ---------------------------------------------------------------------------

const TOKEN_PREFIX: Record<string, string> = {
  email: "EMAIL",
  phone: "PHONE",
  ssn: "SSN",
  credit_card: "CREDIT_CARD",
  full_name: "PERSON",
  address: "ADDRESS",
  dob: "DOB",
  passport: "PASSPORT",
  medical_id: "MEDICAL_ID",
  bank_account: "BANK_ACCOUNT",
  drivers_license: "DRIVERS_LICENSE",
  ip_address: "IP_ADDRESS",
  employee_id: "EMPLOYEE_ID",
  aws_access_key: "AWS_KEY",
  aws_secret_key: "AWS_SECRET",
  github_token: "GITHUB_TOKEN",
  openai_key: "OPENAI_KEY",
  anthropic_key: "ANTHROPIC_KEY",
  slack_token: "SLACK_TOKEN",
  private_key: "PRIVATE_KEY",
  password: "PASSWORD",
  connection_string: "CONN_STRING",
  bearer_token: "BEARER_TOKEN",
  api_key: "API_KEY",
  jwt: "JWT",
};

// ---------------------------------------------------------------------------
// Session-scoped mapping store
// ---------------------------------------------------------------------------

class AnonymizationSession {
  /** Original value -> token. */
  private forward = new Map<string, string>();
  /** Token -> original value. */
  private reverse = new Map<string, string>();
  /** Prefix -> running counter. */
  private counters = new Map<string, number>();

  /**
   * Get (or create) a deterministic token for the given PII value.
   * Same value always returns the same token within a session.
   */
  tokenFor(label: string, value: string): string {
    const existing = this.forward.get(value);
    if (existing) return existing;

    const prefix = TOKEN_PREFIX[label] ?? label.toUpperCase();
    const count = (this.counters.get(prefix) ?? 0) + 1;
    this.counters.set(prefix, count);

    const token = `<${prefix}_${count}>`;
    this.forward.set(value, token);
    this.reverse.set(token, value);
    return token;
  }

  /**
   * Anonymize all findings in the text, replacing each PII value with its
   * session token. Findings MUST be sorted by startPos ascending.
   */
  anonymize(text: string, findings: AnonymizeFinding[]): string {
    if (findings.length === 0) return text;

    // Replace from end to preserve offsets.
    const sorted = [...findings].sort((a, b) => b.startPos - a.startPos);
    let result = text;

    for (const f of sorted) {
      const token = this.tokenFor(f.label, f.value);
      const start = Math.max(0, f.startPos);
      const end = Math.min(result.length, f.endPos);
      if (start >= end) continue;
      result = result.slice(0, start) + token + result.slice(end);
    }

    return result;
  }

  /**
   * Reverse all tokens in the text back to original values.
   * Used to de-anonymize AI responses so the user sees real data.
   */
  deanonymize(text: string): string {
    let result = text;
    for (const [token, original] of this.reverse) {
      // Use split/join instead of replaceAll for broader compatibility.
      result = result.split(token).join(original);
    }
    return result;
  }

  /** Returns a copy of the forward mapping for debugging / display. */
  getMappings(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [key, val] of this.forward) {
      out[key] = val;
    }
    return out;
  }

  /** Number of unique PII values seen. */
  get size(): number {
    return this.forward.size;
  }

  /** Clear all mappings (e.g. on session reset). */
  clear(): void {
    this.forward.clear();
    this.reverse.clear();
    this.counters.clear();
  }
}

// ---------------------------------------------------------------------------
// Global session instance (one per tab)
// ---------------------------------------------------------------------------

const session = new AnonymizationSession();

// ---------------------------------------------------------------------------
// Visual indicator
// ---------------------------------------------------------------------------

let indicatorEl: HTMLElement | null = null;

function showIndicator(): void {
  if (indicatorEl) return;

  indicatorEl = document.createElement("div");
  indicatorEl.id = "kail-anon-indicator";
  indicatorEl.innerHTML = `
    <span class="kail-anon-dot"></span>
    <span class="kail-anon-label">Anonymization Active</span>
    <span class="kail-anon-count">${session.size} item(s)</span>
  `;
  document.body.appendChild(indicatorEl);

  const style = document.createElement("style");
  style.textContent = INDICATOR_CSS;
  style.id = "kail-anon-indicator-style";
  document.head.appendChild(style);
}

function updateIndicator(): void {
  if (!indicatorEl) return;
  const countEl = indicatorEl.querySelector(".kail-anon-count");
  if (countEl) {
    countEl.textContent = `${session.size} item(s)`;
  }
}

export function hideIndicator(): void {
  indicatorEl?.remove();
  indicatorEl = null;
  document.getElementById("kail-anon-indicator-style")?.remove();
}

const INDICATOR_CSS = `
#kail-anon-indicator {
  position: fixed;
  bottom: 16px;
  right: 16px;
  z-index: 2147483646;
  display: flex;
  align-items: center;
  gap: 8px;
  background: #3b82f6;
  color: #ffffff;
  border: none;
  border-radius: 20px;
  padding: 8px 16px;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 12px;
  box-shadow: 0 4px 16px rgba(59, 130, 246, 0.3);
  cursor: default;
  user-select: none;
}
.kail-anon-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #ffffff;
  animation: kail-pulse 2s ease-in-out infinite;
}
@keyframes kail-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
.kail-anon-label { font-weight: 600; color: #ffffff; }
.kail-anon-count { color: rgba(255, 255, 255, 0.75); }
`;

// ---------------------------------------------------------------------------
// Input field helpers
// ---------------------------------------------------------------------------

function findPromptInputs(): Array<HTMLTextAreaElement | HTMLInputElement | HTMLElement> {
  const selectors = [
    'textarea[data-id="root"]',
    'div[contenteditable="true"]',
    "textarea#prompt-textarea",
    'textarea[placeholder*="message"]',
    'textarea[placeholder*="Message"]',
    'textarea[placeholder*="Ask"]',
    'div[role="textbox"]',
    "textarea.chat-input",
    'textarea[name="q"]',
  ];

  const elements: Array<HTMLTextAreaElement | HTMLInputElement | HTMLElement> = [];
  for (const sel of selectors) {
    document.querySelectorAll<HTMLElement>(sel).forEach((el) => elements.push(el));
  }
  return elements;
}

function setInputText(
  el: HTMLTextAreaElement | HTMLInputElement | HTMLElement,
  text: string,
): void {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    // Use native setter to trigger React/Vue change detection.
    const nativeSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set ?? Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )?.set;

    if (nativeSetter) {
      nativeSetter.call(el, text);
    } else {
      el.value = text;
    }

    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  } else {
    // contenteditable
    el.textContent = text;
    el.dispatchEvent(new InputEvent("input", { bubbles: true, data: text }));
  }
}

// ---------------------------------------------------------------------------
// Handle anonymization requests from the scanner
// ---------------------------------------------------------------------------

window.addEventListener("kail-anonymize-request", async (event) => {
  const detail = (event as CustomEvent<AnonymizeRequest>).detail;
  if (!detail) return;

  const { text, findings } = detail;
  const anonymized = session.anonymize(text, findings);

  showIndicator();
  updateIndicator();

  // Find the active input and replace text.
  const inputs = findPromptInputs();
  for (const input of inputs) {
    const currentText =
      input instanceof HTMLTextAreaElement || input instanceof HTMLInputElement
        ? input.value
        : input.textContent ?? "";

    if (currentText.includes(text) || currentText === text) {
      setInputText(input, anonymized);
      break;
    }
  }

  // Brief pause then simulate submit.
  await sleep(200);
  simulateSubmit();
});

// ---------------------------------------------------------------------------
// Response de-anonymization
//
// We observe the DOM for new assistant message elements and reverse tokens.
// ---------------------------------------------------------------------------

function setupResponseObserver(): void {
  const observer = new MutationObserver((mutations) => {
    if (session.size === 0) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        const el = node as HTMLElement;

        // Look for assistant message containers (varies by site).
        const messageEls = [
          ...el.querySelectorAll<HTMLElement>(
            '[data-message-author-role="assistant"],' +
            '.agent-turn,' +
            '.response-content,' +
            '.assistant-message,' +
            '[class*="bot-message"],' +
            '[class*="response"]',
          ),
        ];

        // Also check if the added node itself is a message.
        if (el.matches?.('[data-message-author-role="assistant"], .agent-turn, .response-content')) {
          messageEls.push(el);
        }

        for (const msgEl of messageEls) {
          deanonymizeElement(msgEl);
        }
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
}

function deanonymizeElement(el: HTMLElement): void {
  // Walk text nodes and replace tokens.
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  let textNode: Text | null;
  while ((textNode = walker.nextNode() as Text | null)) {
    const original = textNode.textContent ?? "";
    const deanon = session.deanonymize(original);
    if (deanon !== original) {
      textNode.textContent = deanon;
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function simulateSubmit(): void {
  // Try clicking the send button.
  const sendBtnSelectors = [
    'button[data-testid="send-button"]',
    'button[aria-label="Send message"]',
    'button[aria-label="Send"]',
    "button.send-button",
    'button[type="submit"]',
  ];

  for (const sel of sendBtnSelectors) {
    const btn = document.querySelector<HTMLButtonElement>(sel);
    if (btn && !btn.disabled) {
      btn.click();
      return;
    }
  }

  // Fallback: fire Enter on the input.
  const inputs = findPromptInputs();
  if (inputs.length > 0) {
    inputs[0].dispatchEvent(
      new KeyboardEvent("keydown", {
        key: "Enter",
        code: "Enter",
        keyCode: 13,
        bubbles: true,
      }),
    );
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

function initAnonymizer(): void {
  setupResponseObserver();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initAnonymizer);
} else {
  initAnonymizer();
}
