// ---------------------------------------------------------------------------
// Kill-AI-Leak — Browser Extension Service Worker (Manifest V3)
//
// Runs as the background service worker. Responsibilities:
//   1. Intercept requests to known AI domains (webRequest.onBeforeRequest)
//   2. Enforce policy (block / allow / anonymize / coach)
//   3. Track shadow AI usage per user
//   4. Rate-limit per user
//   5. Forward events to the Kill-AI-Leak API
// ---------------------------------------------------------------------------

import {
  isAIDomain,
  getAIProvider,
  getAIDomainEntry,
  getAllDomains,
  type AIDomainEntry,
} from "./domains";
import {
  PolicyManager,
  type PolicyDecision,
} from "./policy";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Persisted per-user settings. */
interface UserSettings {
  apiBaseUrl: string;
  authToken: string;
  userId: string;
  team?: string;
  protectionEnabled: boolean;
  sensitivityLevel: "low" | "medium" | "high";
  notificationsEnabled: boolean;
}

/** An entry in the shadow AI usage tracker. */
interface UsageRecord {
  domain: string;
  provider: string;
  category: string;
  count: number;
  firstSeen: number;
  lastSeen: number;
}

/** Rate limit bucket for sliding-window enforcement. */
interface RateBucket {
  timestamps: number[];
}

/** Event payload sent to the Kill-AI-Leak API (mirrors models.Event). */
interface SecurityEvent {
  id: string;
  timestamp: string;
  source: "browser";
  severity: "info" | "low" | "medium" | "high" | "critical";
  actor: {
    type: "browser_user";
    id: string;
    name?: string;
    team?: string;
  };
  target: {
    type: "llm_provider";
    id: string;
    provider: string;
    endpoint: string;
  };
  action: {
    type: "api_call";
    direction: "outbound";
    protocol: string;
    method: string;
  };
  content: {
    has_prompt: boolean;
    blocked: boolean;
    anonymized: boolean;
    pii_detected?: string[];
    injection_score?: number;
  };
  metadata?: Record<string, string>;
  session_id?: string;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const DEFAULT_SETTINGS: UserSettings = {
  apiBaseUrl: "https://api.kill-ai-leak.local",
  authToken: "",
  userId: "",
  protectionEnabled: true,
  sensitivityLevel: "medium",
  notificationsEnabled: true,
};

let settings: UserSettings = { ...DEFAULT_SETTINGS };
let policyManager: PolicyManager | null = null;

/** domain -> UsageRecord. Persisted to chrome.storage.local. */
const usageTracker = new Map<string, UsageRecord>();

/** userId -> RateBucket. Kept in memory (resets on SW restart). */
const rateBuckets = new Map<string, RateBucket>();

/** Queue of events waiting to be flushed to the API. */
let eventQueue: SecurityEvent[] = [];
const EVENT_FLUSH_MAX_BATCH = 50;

/** Set of temporarily allowed domains (user override from popup). */
const temporaryAllowList = new Set<string>();

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(async () => {
  await loadSettings();
  await initPolicyManager();
  await loadUsageTracker();
  schedulePeriodicTasks();
});

chrome.runtime.onStartup.addListener(async () => {
  await loadSettings();
  await initPolicyManager();
  await loadUsageTracker();
  schedulePeriodicTasks();
});

// ---------------------------------------------------------------------------
// WebRequest interception
// ---------------------------------------------------------------------------

chrome.webRequest.onBeforeRequest.addListener(
  handleBeforeRequest,
  {
    urls: buildUrlFilters(),
    types: ["main_frame", "sub_frame", "xmlhttprequest", "other"],
  },
  ["requestBody"],
);

function handleBeforeRequest(
  details: chrome.webRequest.WebRequestBodyDetails,
): chrome.webRequest.BlockingResponse | void {
  // If protection is off, just track and let it through.
  if (!settings.protectionEnabled) {
    recordUsage(details.url, details.method);
    return;
  }

  const entry = getAIDomainEntry(details.url);
  if (!entry) return;

  // Temporary allow-list bypass.
  if (temporaryAllowList.has(entry.domain)) {
    recordUsage(details.url, details.method);
    return;
  }

  // Evaluate policy.
  const evaluation = policyManager?.evaluate(
    settings.userId,
    settings.team,
    details.url,
  ) ?? { decision: "allow" as PolicyDecision, reason: "no policy manager", policyName: "", mode: "discover" as const };

  // Record usage regardless of decision.
  recordUsage(details.url, details.method);

  // Rate limiting.
  if (isRateLimited(settings.userId, evaluation.rateLimit?.requests_per_minute)) {
    emitEvent(details, entry, "block", "high", "rate limit exceeded");
    notifyUser("Rate Limit", `You have exceeded the request limit for ${entry.provider}.`);
    return { cancel: true };
  }

  // Enforcement.
  switch (evaluation.decision) {
    case "block": {
      emitEvent(details, entry, "block", "high", evaluation.reason);
      notifyUser("Blocked", `Access to ${entry.provider} was blocked: ${evaluation.reason}`);
      // For main_frame requests we redirect to a block page; for XHR we cancel.
      if (details.type === "main_frame") {
        return {
          redirectUrl: chrome.runtime.getURL(
            `dist/popup/blocked.html?reason=${encodeURIComponent(evaluation.reason)}&provider=${encodeURIComponent(entry.provider)}`,
          ),
        };
      }
      return { cancel: true };
    }
    case "coach": {
      emitEvent(details, entry, "coach", "medium", evaluation.reason);
      // Coaching: allow but notify.
      notifyUser("Security Reminder", `${entry.provider}: ${evaluation.reason}`);
      return;
    }
    case "anonymize": {
      // Anonymization is handled by the content script; here we just record it.
      emitEvent(details, entry, "anonymize", "medium", evaluation.reason);
      return;
    }
    default: {
      // allow / log
      emitEvent(details, entry, "allow", "info", evaluation.reason);
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// URL filters (for webRequest listener registration)
// ---------------------------------------------------------------------------

function buildUrlFilters(): string[] {
  return getAllDomains().flatMap((d) => [
    `https://${d}/*`,
    `http://${d}/*`,
  ]);
}

// ---------------------------------------------------------------------------
// Usage tracking
// ---------------------------------------------------------------------------

function recordUsage(url: string, _method: string): void {
  const entry = getAIDomainEntry(url);
  if (!entry) return;

  const key = entry.domain;
  const now = Date.now();
  const existing = usageTracker.get(key);

  if (existing) {
    existing.count++;
    existing.lastSeen = now;
  } else {
    usageTracker.set(key, {
      domain: entry.domain,
      provider: entry.provider,
      category: entry.category,
      count: 1,
      firstSeen: now,
      lastSeen: now,
    });
  }

  // Persist asynchronously — fire and forget.
  persistUsageTracker().catch(() => {});
}

async function persistUsageTracker(): Promise<void> {
  const serializable = Object.fromEntries(usageTracker);
  await chrome.storage.local.set({ kail_usage: serializable });
}

async function loadUsageTracker(): Promise<void> {
  try {
    const result = await chrome.storage.local.get("kail_usage");
    const raw = result.kail_usage as Record<string, UsageRecord> | undefined;
    if (raw) {
      usageTracker.clear();
      for (const [key, value] of Object.entries(raw)) {
        usageTracker.set(key, value);
      }
    }
  } catch {
    // First install — no data yet.
  }
}

// ---------------------------------------------------------------------------
// Rate limiting (in-memory sliding window)
// ---------------------------------------------------------------------------

function isRateLimited(
  userId: string,
  maxPerMinute: number | undefined,
): boolean {
  if (!maxPerMinute || maxPerMinute <= 0) return false;

  const now = Date.now();
  const windowMs = 60_000;
  let bucket = rateBuckets.get(userId);

  if (!bucket) {
    bucket = { timestamps: [] };
    rateBuckets.set(userId, bucket);
  }

  // Evict timestamps outside the window.
  bucket.timestamps = bucket.timestamps.filter((t) => now - t < windowMs);
  bucket.timestamps.push(now);

  return bucket.timestamps.length > maxPerMinute;
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

function emitEvent(
  details: chrome.webRequest.WebRequestBodyDetails,
  entry: AIDomainEntry,
  decision: string,
  severity: SecurityEvent["severity"],
  reason: string,
): void {
  const event: SecurityEvent = {
    id: generateULID(),
    timestamp: new Date().toISOString(),
    source: "browser",
    severity,
    actor: {
      type: "browser_user",
      id: settings.userId || "unknown",
      team: settings.team,
    },
    target: {
      type: "llm_provider",
      id: entry.domain,
      provider: entry.provider,
      endpoint: details.url,
    },
    action: {
      type: "api_call",
      direction: "outbound",
      protocol: "https",
      method: details.method,
    },
    content: {
      has_prompt: details.method === "POST",
      blocked: decision === "block",
      anonymized: decision === "anonymize",
    },
    metadata: {
      decision,
      reason,
      tab_id: String(details.tabId),
    },
  };

  eventQueue.push(event);

  if (eventQueue.length >= EVENT_FLUSH_MAX_BATCH) {
    flushEvents().catch(() => {});
  }
}

async function flushEvents(): Promise<void> {
  if (eventQueue.length === 0 || !settings.authToken) return;

  const batch = eventQueue.splice(0, EVENT_FLUSH_MAX_BATCH);

  try {
    const res = await fetch(`${settings.apiBaseUrl}/api/v1/events`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${settings.authToken}`,
      },
      body: JSON.stringify({ events: batch }),
    });

    if (!res.ok) {
      // Re-queue events on failure (up to a cap).
      if (eventQueue.length < 500) {
        eventQueue.unshift(...batch);
      }
    }
  } catch {
    // Network failure — re-queue.
    if (eventQueue.length < 500) {
      eventQueue.unshift(...batch);
    }
  }
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

function notifyUser(title: string, message: string): void {
  if (!settings.notificationsEnabled) return;

  chrome.notifications.create({
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
    title: `Kill-AI-Leak: ${title}`,
    message,
    priority: 1,
  });
}

// ---------------------------------------------------------------------------
// Message handling (popup / content scripts communicate via messages)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener(
  (
    message: Record<string, unknown>,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: unknown) => void,
  ): boolean => {
    const type = message.type as string;

    switch (type) {
      case "GET_STATUS": {
        const tabUrl = message.url as string | undefined;
        const isDomain = tabUrl ? isAIDomain(tabUrl) : false;
        const provider = tabUrl ? getAIProvider(tabUrl) : null;
        const evaluation = tabUrl && policyManager
          ? policyManager.evaluate(settings.userId, settings.team, tabUrl)
          : null;

        sendResponse({
          protectionEnabled: settings.protectionEnabled,
          isAIDomain: isDomain,
          provider,
          decision: evaluation?.decision ?? "allow",
          reason: evaluation?.reason ?? "",
          mode: evaluation?.mode ?? "discover",
        });
        return false;
      }

      case "GET_USAGE": {
        const records = Array.from(usageTracker.values());
        // Filter to today.
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const todayMs = todayStart.getTime();
        const todayRecords = records.filter((r) => r.lastSeen >= todayMs);
        const totalPrompts = todayRecords.reduce((s, r) => s + r.count, 0);

        sendResponse({
          tools: todayRecords.map((r) => ({
            provider: r.provider,
            domain: r.domain,
            category: r.category,
            count: r.count,
          })),
          totalPrompts,
        });
        return false;
      }

      case "TOGGLE_PROTECTION": {
        settings.protectionEnabled = message.enabled as boolean;
        saveSettings().catch(() => {});
        sendResponse({ ok: true, protectionEnabled: settings.protectionEnabled });
        return false;
      }

      case "TEMP_ALLOW_SITE": {
        const domain = message.domain as string;
        temporaryAllowList.add(domain);
        // Auto-expire after 1 hour.
        setTimeout(() => temporaryAllowList.delete(domain), 60 * 60 * 1000);
        sendResponse({ ok: true });
        return false;
      }

      case "UPDATE_SETTINGS": {
        const updates = message.settings as Partial<UserSettings>;
        Object.assign(settings, updates);
        saveSettings().catch(() => {});
        if (updates.apiBaseUrl || updates.authToken) {
          initPolicyManager().catch(() => {});
        }
        sendResponse({ ok: true });
        return false;
      }

      case "GET_SETTINGS": {
        sendResponse({ settings });
        return false;
      }

      case "SCAN_RESULT": {
        // Content script reports PII/secret findings.
        const findings = message.findings as Array<{
          type: string;
          severity: string;
        }>;
        if (findings && findings.length > 0) {
          const tabUrl = sender.tab?.url ?? "";
          const entry = getAIDomainEntry(tabUrl);
          if (entry) {
            const severity = findings.some((f) => f.severity === "critical")
              ? "critical"
              : findings.some((f) => f.severity === "high")
                ? "high"
                : "medium";
            emitEvent(
              {
                url: tabUrl,
                method: "POST",
                requestId: "",
                tabId: sender.tab?.id ?? -1,
                type: "xmlhttprequest",
                timeStamp: Date.now(),
                frameId: 0,
                parentFrameId: -1,
                initiator: undefined,
              } as chrome.webRequest.WebRequestBodyDetails,
              entry,
              "anonymize",
              severity as SecurityEvent["severity"],
              `PII/secrets detected: ${findings.map((f) => f.type).join(", ")}`,
            );
          }
        }
        sendResponse({ ok: true });
        return false;
      }

      case "FORCE_POLICY_REFRESH": {
        policyManager
          ?.fetchPolicies()
          .then(() => sendResponse({ ok: true }))
          .catch((err) =>
            sendResponse({ ok: false, error: String(err) }),
          );
        return true; // async response
      }

      default:
        sendResponse({ error: "unknown message type" });
        return false;
    }
  },
);

// ---------------------------------------------------------------------------
// Settings persistence
// ---------------------------------------------------------------------------

async function loadSettings(): Promise<void> {
  try {
    const result = await chrome.storage.local.get("kail_settings");
    const raw = result.kail_settings as Partial<UserSettings> | undefined;
    if (raw) {
      settings = { ...DEFAULT_SETTINGS, ...raw };
    }
  } catch {
    // Use defaults.
  }
}

async function saveSettings(): Promise<void> {
  await chrome.storage.local.set({ kail_settings: settings });
}

// ---------------------------------------------------------------------------
// Policy manager init
// ---------------------------------------------------------------------------

async function initPolicyManager(): Promise<void> {
  if (!settings.apiBaseUrl || !settings.authToken) return;
  policyManager = new PolicyManager(settings.apiBaseUrl, settings.authToken);
  await policyManager.initialize();
}

// ---------------------------------------------------------------------------
// Periodic tasks (alarms API for Manifest V3)
// ---------------------------------------------------------------------------

function schedulePeriodicTasks(): void {
  // Flush event queue every 10 seconds.
  chrome.alarms.create("flush_events", { periodInMinutes: 1 / 6 });
  // Refresh policies every 5 minutes.
  chrome.alarms.create("refresh_policies", { periodInMinutes: 5 });
  // Persist usage tracker every minute.
  chrome.alarms.create("persist_usage", { periodInMinutes: 1 });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  switch (alarm.name) {
    case "flush_events":
      flushEvents().catch(() => {});
      break;
    case "refresh_policies":
      policyManager?.fetchPolicies().catch(() => {});
      break;
    case "persist_usage":
      persistUsageTracker().catch(() => {});
      break;
  }
});

// ---------------------------------------------------------------------------
// ULID generation (simplified; good enough for event IDs)
// ---------------------------------------------------------------------------

function generateULID(): string {
  const timestamp = Date.now().toString(36).padStart(10, "0");
  const random = Array.from(
    crypto.getRandomValues(new Uint8Array(10)),
    (b) => b.toString(36),
  ).join("");
  return (timestamp + random).slice(0, 26).toUpperCase();
}
