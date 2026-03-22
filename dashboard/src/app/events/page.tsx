"use client";

import { useState, useEffect, useMemo } from "react";
import { formatDistanceToNow, format } from "date-fns";
import {
  Search,
  Filter,
  ChevronDown,
  X,
  RefreshCw,
  Clock,
} from "lucide-react";
import SeverityBadge from "@/components/SeverityBadge";
import StatusBadge from "@/components/StatusBadge";
import { fetchEvents } from "@/lib/api";
import type { Event, Severity, EventSource } from "@/lib/types";

// ---------------------------------------------------------------------------
// Demo data
// ---------------------------------------------------------------------------

function genEvent(
  id: string,
  minutesAgo: number,
  source: EventSource,
  severity: Severity,
  actorName: string,
  actorNs: string,
  provider: string,
  model: string,
  ruleName: string | null,
  decision: "block" | "allow" | "anonymize" | "alert" | "throttle",
  reason: string | null,
  pii: string[] | undefined,
  injectionScore: number,
): Event {
  const blocked = decision === "block";
  return {
    id,
    timestamp: new Date(Date.now() - minutesAgo * 60_000).toISOString(),
    source,
    severity,
    actor: { type: "pod", id: `${actorName}-abc`, name: actorName, namespace: actorNs },
    target: { type: "llm_provider", id: `${provider.toLowerCase()}-1`, provider, model },
    action: { type: "api_call", direction: "outbound" },
    content: {
      has_prompt: true,
      blocked,
      anonymized: decision === "anonymize",
      pii_detected: pii,
      injection_score: injectionScore,
      tokens_input: Math.floor(Math.random() * 3000) + 200,
      tokens_output: blocked ? 0 : Math.floor(Math.random() * 2000) + 100,
    },
    guardrails: ruleName
      ? [
          {
            rule_id: ruleName.toLowerCase().replace(/\s/g, "-"),
            rule_name: ruleName,
            stage: "input",
            decision,
            confidence: 0.85 + Math.random() * 0.14,
            reason: reason ?? undefined,
            latency_ms: Math.floor(Math.random() * 40) + 2,
          },
        ]
      : [],
    cost_usd: blocked ? 0 : Math.random() * 0.05,
    latency_ms: Math.floor(Math.random() * 600) + 10,
  };
}

const demoEvents: Event[] = [
  genEvent("evt-101", 1, "inline_gateway", "critical", "data-pipeline-llm", "data-eng", "OpenAI", "gpt-4o", "PII Blocker", "block", "SSN detected in prompt", ["ssn", "email"], 0.12),
  genEvent("evt-102", 3, "kernel_observer", "high", "unknown-svc", "default", "Anthropic", "claude-sonnet-4-20250514", "Shadow AI Detector", "alert", "Unregistered service calling LLM", undefined, 0.05),
  genEvent("evt-103", 7, "inline_gateway", "high", "code-review-agent", "engineering", "OpenAI", "gpt-4o", "Prompt Injection Guard", "block", "High injection score", undefined, 0.92),
  genEvent("evt-104", 12, "browser", "medium", "marketing-tool", "marketing", "OpenAI", "gpt-4o-mini", "PII Anonymizer", "anonymize", "Email addresses anonymized", ["email"], 0.08),
  genEvent("evt-105", 18, "mcp_gateway", "high", "deploy-agent", "platform", "OpenAI", "gpt-4o", "Agent Filesystem Guard", "block", "Write to /etc/passwd denied", undefined, 0.01),
  genEvent("evt-106", 25, "inline_gateway", "medium", "support-summarizer", "customer-ops", "OpenAI", "gpt-4o-mini", "Rate Limiter", "throttle", "Approaching hourly limit", undefined, 0.03),
  genEvent("evt-107", 38, "inline_gateway", "low", "chatbot-api", "production", "OpenAI", "gpt-4o-mini", null, "allow", null, undefined, 0.02),
  genEvent("evt-108", 52, "cicd", "medium", "ci-runner", "ci", "Anthropic", "claude-sonnet-4-20250514", "Secrets Scanner", "block", "API key in prompt", undefined, 0.04),
  genEvent("evt-109", 68, "ide", "info", "dev-vscode", "engineering", "OpenAI", "gpt-4o", null, "allow", null, undefined, 0.01),
  genEvent("evt-110", 85, "inline_gateway", "critical", "rogue-scraper", "default", "OpenAI", "gpt-4o", "Jailbreak Detector", "block", "Jailbreak attempt detected", undefined, 0.97),
  genEvent("evt-111", 102, "inline_gateway", "low", "chatbot-api", "production", "OpenAI", "gpt-4o-mini", null, "allow", null, undefined, 0.01),
  genEvent("evt-112", 115, "kernel_observer", "high", "unknown-svc-2", "default", "Mistral", "mistral-large", "Shadow AI Detector", "alert", "Unregistered service detected", undefined, 0.03),
  genEvent("evt-113", 130, "inline_gateway", "medium", "sales-copilot", "go-to-market", "OpenAI", "gpt-4o", "PII Anonymizer", "anonymize", "Phone numbers anonymized", ["phone"], 0.06),
  genEvent("evt-114", 145, "browser", "info", "marketing-content-gen", "marketing", "OpenAI", "gpt-4o-mini", null, "allow", null, undefined, 0.02),
  genEvent("evt-115", 160, "inline_gateway", "high", "data-pipeline-llm", "data-eng", "OpenAI", "gpt-4o", "Exfiltration Guard", "block", "Large data payload detected", ["credit_card"], 0.15),
  genEvent("evt-116", 180, "mcp_gateway", "medium", "deploy-agent", "platform", "OpenAI", "gpt-4o", "Agent Command Guard", "block", "rm -rf command denied", undefined, 0.01),
  genEvent("evt-117", 200, "inline_gateway", "low", "support-summarizer", "customer-ops", "OpenAI", "gpt-4o-mini", null, "allow", null, undefined, 0.03),
  genEvent("evt-118", 220, "inline_gateway", "info", "code-review-agent", "engineering", "Anthropic", "claude-sonnet-4-20250514", null, "allow", null, undefined, 0.04),
  genEvent("evt-119", 245, "cicd", "high", "ci-runner", "ci", "OpenAI", "gpt-4o", "Secrets Scanner", "block", "AWS credentials in prompt", undefined, 0.02),
  genEvent("evt-120", 280, "inline_gateway", "critical", "rogue-scraper", "default", "Mistral", "mistral-large", "Toxicity Guard", "block", "Toxic content in request", undefined, 0.88),
];

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function EventsPage() {
  const [events, setEvents] = useState<Event[]>(demoEvents);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      setLoading(true);
      try {
        const response = await fetchEvents({
          severity: severityFilter || undefined,
          source: sourceFilter || undefined,
          decision: decisionFilter === "blocked" ? "blocked" : decisionFilter === "allowed" ? "allowed" : undefined,
          search: search || undefined,
        });
        if (!cancelled && response.data) {
          setEvents(response.data);
        }
      } catch {
        // keep demo data on failure
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadData();
    return () => { cancelled = true; };
  }, [severityFilter, sourceFilter, decisionFilter, search]);

  const sources = useMemo(
    () => Array.from(new Set(events.map((e) => e.source))).sort(),
    [events],
  );

  const filtered = useMemo(() => {
    return events.filter((evt) => {
      if (search) {
        const q = search.toLowerCase();
        const match =
          evt.actor.name?.toLowerCase().includes(q) ||
          evt.target.provider?.toLowerCase().includes(q) ||
          evt.target.model?.toLowerCase().includes(q) ||
          evt.guardrails?.some((g) =>
            g.rule_name.toLowerCase().includes(q),
          );
        if (!match) return false;
      }
      if (severityFilter && evt.severity !== severityFilter) return false;
      if (sourceFilter && evt.source !== sourceFilter) return false;
      if (decisionFilter) {
        const isBlocked = evt.content.blocked;
        if (decisionFilter === "blocked" && !isBlocked) return false;
        if (decisionFilter === "allowed" && isBlocked) return false;
      }
      return true;
    });
  }, [events, search, severityFilter, sourceFilter, decisionFilter]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Events</h1>
          <p className="mt-1 text-sm text-gray-500">
            Real-time AI security event stream
          </p>
        </div>
        <button className="btn-secondary">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search actors, providers, rules..."
            className="input pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div className="relative">
          <select
            className="select appearance-none pr-8"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
        </div>

        <div className="relative">
          <select
            className="select appearance-none pr-8"
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
          >
            <option value="">All Sources</option>
            {sources.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
        </div>

        <div className="relative">
          <select
            className="select appearance-none pr-8"
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
          >
            <option value="">All Decisions</option>
            <option value="blocked">Blocked</option>
            <option value="allowed">Allowed</option>
          </select>
          <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
        </div>

        {(search || severityFilter || sourceFilter || decisionFilter) && (
          <button
            className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200"
            onClick={() => {
              setSearch("");
              setSeverityFilter("");
              setSourceFilter("");
              setDecisionFilter("");
            }}
          >
            <X className="h-3 w-3" /> Clear
          </button>
        )}

        <span className="text-xs text-gray-500">
          <Filter className="mr-1 inline h-3 w-3" />
          {filtered.length} events
        </span>
      </div>

      {/* Table */}
      <div className="table-wrapper">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-300 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Target</th>
                <th className="px-4 py-3">Rule Triggered</th>
                <th className="px-4 py-3">Decision</th>
                <th className="px-4 py-3">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-300">
              {filtered.map((evt) => {
                const topRule = evt.guardrails?.[0];
                const decision = evt.content.blocked
                  ? "blocked"
                  : evt.content.anonymized
                    ? "anonymize"
                    : "allowed";

                return (
                  <tr
                    key={evt.id}
                    className="group cursor-pointer transition-colors hover:bg-surface-200/60"
                    onClick={() => setSelectedEvent(evt)}
                  >
                    <td className="whitespace-nowrap px-4 py-3 text-gray-400">
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3 w-3 text-gray-600" />
                        <span title={format(new Date(evt.timestamp), "PPpp")}>
                          {formatDistanceToNow(new Date(evt.timestamp), {
                            addSuffix: true,
                          })}
                        </span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <span className="rounded bg-surface-300 px-1.5 py-0.5 font-mono text-xs text-gray-300">
                        {evt.source}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-gray-300">
                      <div className="flex flex-col">
                        <span className="font-medium">
                          {evt.actor.name || evt.actor.id}
                        </span>
                        <span className="text-xs text-gray-500">
                          {evt.actor.namespace}
                        </span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-gray-300">
                      <div className="flex flex-col">
                        <span>{evt.target.provider}</span>
                        <span className="font-mono text-xs text-gray-500">
                          {evt.target.model}
                        </span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-gray-400">
                      {topRule ? (
                        <span className="text-gray-300">
                          {topRule.rule_name}
                        </span>
                      ) : (
                        <span className="text-gray-600">-</span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <StatusBadge status={decision} />
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <SeverityBadge severity={evt.severity} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filtered.length === 0 && (
            <div className="flex items-center justify-center py-16 text-gray-500">
              No events match the current filters.
            </div>
          )}
        </div>
      </div>

      {/* Event detail modal */}
      {selectedEvent && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => setSelectedEvent(null)}
        >
          <div
            className="mx-4 max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-surface-300 bg-surface-100 p-6 shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">
                  Event Detail
                </h3>
                <p className="mt-0.5 font-mono text-xs text-gray-500">
                  {selectedEvent.id}
                </p>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="rounded-lg p-1 text-gray-500 hover:bg-surface-200 hover:text-gray-300"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-5">
              {/* Meta grid */}
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
                <Field label="Timestamp" value={format(new Date(selectedEvent.timestamp), "PPpp")} />
                <Field label="Source" value={selectedEvent.source} mono />
                <Field label="Severity">
                  <SeverityBadge severity={selectedEvent.severity} />
                </Field>
                <Field label="Actor" value={selectedEvent.actor.name || selectedEvent.actor.id} />
                <Field label="Actor Namespace" value={selectedEvent.actor.namespace || "-"} mono />
                <Field label="Actor Type" value={selectedEvent.actor.type} />
                <Field label="Provider" value={selectedEvent.target.provider || "-"} />
                <Field label="Model" value={selectedEvent.target.model || "-"} mono />
                <Field label="Latency" value={`${selectedEvent.latency_ms}ms`} mono />
                <Field label="Tokens In" value={String(selectedEvent.content.tokens_input ?? 0)} mono />
                <Field label="Tokens Out" value={String(selectedEvent.content.tokens_output ?? 0)} mono />
                <Field label="Cost" value={selectedEvent.cost_usd ? `$${selectedEvent.cost_usd.toFixed(4)}` : "-"} mono />
              </div>

              {/* Decision */}
              <div className="rounded-lg border border-surface-300 bg-surface-200 p-4">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium text-gray-300">Final Decision:</span>
                  <StatusBadge status={selectedEvent.content.blocked ? "blocked" : "allowed"} />
                  {selectedEvent.content.anonymized && (
                    <StatusBadge status="anonymize" />
                  )}
                </div>
              </div>

              {/* Guardrails */}
              {selectedEvent.guardrails && selectedEvent.guardrails.length > 0 && (
                <div>
                  <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
                    Guardrails Triggered
                  </h4>
                  <div className="space-y-2">
                    {selectedEvent.guardrails.map((gr) => (
                      <div
                        key={gr.rule_id}
                        className="rounded-lg border border-surface-300 bg-surface-200 p-3"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-gray-200 text-sm">
                            {gr.rule_name}
                          </span>
                          <StatusBadge status={gr.decision} />
                        </div>
                        {gr.reason && (
                          <p className="mt-1 text-xs text-gray-400">
                            {gr.reason}
                          </p>
                        )}
                        <div className="mt-2 flex gap-4 text-xs text-gray-500">
                          <span>Stage: {gr.stage}</span>
                          <span>
                            Confidence:{" "}
                            {(gr.confidence * 100).toFixed(0)}%
                          </span>
                          <span>Latency: {gr.latency_ms}ms</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* PII */}
              {selectedEvent.content.pii_detected &&
                selectedEvent.content.pii_detected.length > 0 && (
                  <div>
                    <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
                      PII Detected
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedEvent.content.pii_detected.map((pii) => (
                        <span
                          key={pii}
                          className="rounded bg-red-500/15 px-2 py-0.5 text-xs text-red-400 ring-1 ring-inset ring-red-500/30"
                        >
                          {pii}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

              {(selectedEvent.content.injection_score ?? 0) > 0.5 && (
                <div className="rounded-lg border border-orange-500/30 bg-orange-500/5 p-3">
                  <span className="text-xs font-semibold text-orange-400">
                    Injection Score:{" "}
                    {((selectedEvent.content.injection_score ?? 0) * 100).toFixed(0)}%
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Field({
  label,
  value,
  mono,
  children,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div>
      <span className="text-[11px] font-medium uppercase text-gray-500">
        {label}
      </span>
      {children ? (
        <div className="mt-0.5">{children}</div>
      ) : (
        <p
          className={`mt-0.5 text-sm text-gray-300 ${mono ? "font-mono" : ""}`}
        >
          {value}
        </p>
      )}
    </div>
  );
}
