export {};

// ---------------------------------------------------------------------------
// Kill-AI-Leak — Extension Popup UI
//
// Communicates with the background service worker via chrome.runtime messages
// to display current protection status, AI usage, and settings controls.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Types (must stay in sync with service-worker message responses)
// ---------------------------------------------------------------------------

interface StatusResponse {
  protectionEnabled: boolean;
  isAIDomain: boolean;
  provider: string | null;
  decision: string;
  reason: string;
  mode: string;
}

interface UsageTool {
  provider: string;
  domain: string;
  category: string;
  count: number;
}

interface UsageResponse {
  tools: UsageTool[];
  totalPrompts: number;
}

interface SettingsResponse {
  settings: {
    apiBaseUrl: string;
    protectionEnabled: boolean;
    sensitivityLevel: "low" | "medium" | "high";
    defaultAction?: "ask" | "block" | "anonymize";
    notificationsEnabled: boolean;
  };
}

// ---------------------------------------------------------------------------
// DOM references
// ---------------------------------------------------------------------------

const statusBadge = document.getElementById("status-badge")!;
const pageIcon = document.getElementById("page-icon")!;
const pageProvider = document.getElementById("page-provider")!;
const pageDomain = document.getElementById("page-domain")!;
const pageDecision = document.getElementById("page-decision")!;
const toggleProtection = document.getElementById(
  "toggle-protection",
) as HTMLInputElement;
const totalTools = document.getElementById("total-tools")!;
const totalPrompts = document.getElementById("total-prompts")!;
const toolList = document.getElementById("tool-list")!;
const defaultAction = document.getElementById(
  "default-action",
) as HTMLSelectElement;
const sensitivityLevel = document.getElementById(
  "sensitivity-level",
) as HTMLSelectElement;
const toggleNotifications = document.getElementById(
  "toggle-notifications",
) as HTMLInputElement;
const totalBlocked = document.getElementById("total-blocked")!;
const scanHistoryList = document.getElementById("scan-history")!;
const btnAllowTemp = document.getElementById(
  "btn-allow-temp",
) as HTMLButtonElement;
const btnDashboard = document.getElementById(
  "btn-dashboard",
) as HTMLAnchorElement;
const linkDashboard = document.getElementById(
  "link-dashboard",
) as HTMLAnchorElement;

// ---------------------------------------------------------------------------
// Current tab info
// ---------------------------------------------------------------------------

let currentTabUrl = "";
let currentTabDomain = "";

async function getCurrentTab(): Promise<chrome.tabs.Tab | null> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] ?? null;
}

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Load status
// ---------------------------------------------------------------------------

async function loadStatus(): Promise<void> {
  const tab = await getCurrentTab();
  currentTabUrl = tab?.url ?? "";
  currentTabDomain = extractDomain(currentTabUrl);

  // Get status from service worker.
  const status = await sendMessage<StatusResponse>({
    type: "GET_STATUS",
    url: currentTabUrl,
  });

  // Update protection toggle.
  toggleProtection.checked = status.protectionEnabled;

  // Update page info.
  pageDomain.textContent = currentTabDomain || "--";

  if (status.isAIDomain && status.provider) {
    pageProvider.textContent = status.provider;
    pageIcon.textContent = getCategoryIcon(status.decision);

    // Decision-based badge.
    switch (status.decision) {
      case "block":
        statusBadge.textContent = "Blocked";
        statusBadge.className = "header-badge badge-blocked";
        pageDecision.textContent = `Blocked: ${status.reason}`;
        pageDecision.style.color = "#e94560";
        break;
      case "anonymize":
        statusBadge.textContent = "Protected";
        statusBadge.className = "header-badge badge-protected";
        pageDecision.textContent = "Anonymization active";
        pageDecision.style.color = "#16a34a";
        break;
      case "coach":
        statusBadge.textContent = "Monitoring";
        statusBadge.className = "header-badge badge-unprotected";
        pageDecision.textContent = `Coach: ${status.reason}`;
        pageDecision.style.color = "#eab308";
        break;
      default:
        statusBadge.textContent = status.protectionEnabled
          ? "Protected"
          : "Disabled";
        statusBadge.className = `header-badge ${
          status.protectionEnabled ? "badge-protected" : "badge-unprotected"
        }`;
        pageDecision.textContent =
          status.mode === "enforce" ? "Policy enforced" : `Mode: ${status.mode}`;
        pageDecision.style.color = "#888";
    }

    // Enable temp allow button.
    btnAllowTemp.disabled = false;
  } else {
    pageProvider.textContent = "Not an AI site";
    pageIcon.textContent = "---";
    statusBadge.textContent = status.protectionEnabled ? "Active" : "Disabled";
    statusBadge.className = `header-badge ${
      status.protectionEnabled ? "badge-protected" : "badge-unprotected"
    }`;
    pageDecision.textContent = "";
    btnAllowTemp.disabled = true;
  }
}

// ---------------------------------------------------------------------------
// Load usage
// ---------------------------------------------------------------------------

async function loadUsage(): Promise<void> {
  const usage = await sendMessage<UsageResponse>({ type: "GET_USAGE" });

  totalTools.textContent = String(usage.tools.length);
  totalPrompts.textContent = String(usage.totalPrompts);

  if (usage.tools.length === 0) {
    toolList.innerHTML =
      '<li class="empty-state">No AI tools used today.</li>';
    return;
  }

  // Sort by count descending.
  const sorted = [...usage.tools].sort((a, b) => b.count - a.count);

  toolList.innerHTML = sorted
    .slice(0, 8)
    .map((tool) => {
      const dotClass = getCategoryDotClass(tool.category);
      return `
        <li class="tool-item">
          <span class="tool-dot ${dotClass}"></span>
          <span class="tool-name">${escapeHtml(tool.provider)}</span>
          <span class="tool-count">${tool.count}</span>
        </li>
      `;
    })
    .join("");
}

// ---------------------------------------------------------------------------
// Load scan history (real detection data)
// ---------------------------------------------------------------------------

interface ScanHistoryResponse {
  scans: Array<{
    timestamp: number;
    domain: string;
    findings: Array<{ type: string; severity: string }>;
    action: string;
  }>;
  blockedToday: number;
  criticalToday: number;
}

async function loadScanHistory(): Promise<void> {
  const res = await sendMessage<ScanHistoryResponse>({ type: "GET_SCAN_HISTORY" });

  totalBlocked.textContent = String(res.blockedToday);

  if (res.scans.length === 0) {
    scanHistoryList.innerHTML =
      '<li class="empty-state">No threats detected today.</li>';
    return;
  }

  scanHistoryList.innerHTML = res.scans
    .slice(0, 8)
    .map((scan) => {
      const time = new Date(scan.timestamp);
      const timeStr = time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const types = scan.findings.map((f) => f.type).join(", ");
      const hasCritical = scan.findings.some((f) => f.severity === "critical");
      const dotColor = hasCritical ? "background: #ef4444;" : "background: #f59e0b;";

      return `
        <li class="tool-item">
          <span class="tool-dot" style="${dotColor}"></span>
          <span class="tool-name" style="font-size: 12px;">
            <strong>${escapeHtml(types)}</strong>
            <span style="color: #5a7184; font-weight: 400;"> on ${escapeHtml(scan.domain)}</span>
          </span>
          <span class="tool-count">${timeStr}</span>
        </li>
      `;
    })
    .join("");
}

// ---------------------------------------------------------------------------
// Load settings
// ---------------------------------------------------------------------------

async function loadSettings(): Promise<void> {
  const res = await sendMessage<SettingsResponse>({ type: "GET_SETTINGS" });
  const s = res.settings;

  defaultAction.value = s.defaultAction ?? "ask";
  sensitivityLevel.value = s.sensitivityLevel;
  toggleNotifications.checked = s.notificationsEnabled;

  // Set dashboard link.
  const dashUrl = s.apiBaseUrl
    ? s.apiBaseUrl.replace(/\/api.*/, "") + "/dashboard"
    : "https://app.kill-ai-leak.local/dashboard";
  btnDashboard.href = dashUrl;
  linkDashboard.href = dashUrl;
}

// ---------------------------------------------------------------------------
// Event listeners
// ---------------------------------------------------------------------------

toggleProtection.addEventListener("change", async () => {
  await sendMessage({
    type: "TOGGLE_PROTECTION",
    enabled: toggleProtection.checked,
  });
  await loadStatus();
});

btnAllowTemp.addEventListener("click", async () => {
  if (!currentTabDomain) return;
  await sendMessage({ type: "TEMP_ALLOW_SITE", domain: currentTabDomain });
  btnAllowTemp.textContent = "Allowed (1h)";
  btnAllowTemp.disabled = true;
});

defaultAction.addEventListener("change", async () => {
  await sendMessage({
    type: "UPDATE_SETTINGS",
    settings: { defaultAction: defaultAction.value },
  });
});

sensitivityLevel.addEventListener("change", async () => {
  await sendMessage({
    type: "UPDATE_SETTINGS",
    settings: { sensitivityLevel: sensitivityLevel.value },
  });
});

toggleNotifications.addEventListener("change", async () => {
  await sendMessage({
    type: "UPDATE_SETTINGS",
    settings: { notificationsEnabled: toggleNotifications.checked },
  });
});

btnDashboard.addEventListener("click", (e) => {
  const href = btnDashboard.href;
  if (href && href !== "#") {
    chrome.tabs.create({ url: href });
    e.preventDefault();
  }
});

linkDashboard.addEventListener("click", (e) => {
  const href = linkDashboard.href;
  if (href && href !== "#") {
    chrome.tabs.create({ url: href });
    e.preventDefault();
  }
});

// ---------------------------------------------------------------------------
// Messaging helper
// ---------------------------------------------------------------------------

function sendMessage<T>(message: Record<string, unknown>): Promise<T> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response: T) => {
      resolve(response);
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getCategoryIcon(decision: string): string {
  switch (decision) {
    case "block":
      return "\u26D4";   // no entry
    case "anonymize":
      return "\uD83D\uDEE1"; // shield
    case "coach":
      return "\u26A0";   // warning
    default:
      return "\u2705";   // check
  }
}

function getCategoryDotClass(category: string): string {
  switch (category) {
    case "chat_ai":
      return "tool-dot-chat";
    case "code_ai":
      return "tool-dot-code";
    case "image_ai":
      return "tool-dot-image";
    case "search_ai":
      return "tool-dot-search";
    case "api_endpoint":
      return "tool-dot-api";
    default:
      return "tool-dot-other";
  }
}

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init(): Promise<void> {
  await Promise.all([loadStatus(), loadUsage(), loadScanHistory(), loadSettings()]);
}

document.addEventListener("DOMContentLoaded", init);
