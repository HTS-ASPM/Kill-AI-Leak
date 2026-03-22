"use client";

import { useState, useEffect } from "react";
import {
  Server,
  Shield,
  ShieldAlert,
  Eye,
  DollarSign,
  ArrowUpRight,
} from "lucide-react";
import MetricCard from "@/components/MetricCard";
import EventTable from "@/components/EventTable";
import { ThreatActivityChart, RiskPieChart } from "@/components/Chart";
import {
  fetchStats,
  fetchThreatActivity,
  fetchRiskBreakdown,
  fetchTopServices,
  fetchRecentAlerts,
} from "@/lib/api";
import type {
  DashboardStats,
  Event,
  ThreatActivityPoint,
  RiskBreakdown,
  TopService,
} from "@/lib/types";

// ---------------------------------------------------------------------------
// Fallback demo data -- used when the API is unreachable
// ---------------------------------------------------------------------------

const demoStats: DashboardStats = {
  total_services: 47,
  active_guardrails: 23,
  blocked_threats_24h: 142,
  shadow_ai_detected: 8,
  monthly_cost_usd: 12_840,
  events_24h: 3_874,
  avg_latency_ms: 12,
};

const demoThreatActivity: ThreatActivityPoint[] = [
  { date: "Mar 14", blocked: 38, allowed: 1420 },
  { date: "Mar 15", blocked: 52, allowed: 1380 },
  { date: "Mar 16", blocked: 41, allowed: 1510 },
  { date: "Mar 17", blocked: 74, allowed: 1460 },
  { date: "Mar 18", blocked: 89, allowed: 1390 },
  { date: "Mar 19", blocked: 63, allowed: 1540 },
  { date: "Mar 20", blocked: 142, allowed: 1610 },
];

const demoRiskBreakdown: RiskBreakdown[] = [
  { category: "PII Exposure", count: 34, color: "#ef4444" },
  { category: "Injection", count: 22, color: "#f97316" },
  { category: "Shadow AI", count: 18, color: "#eab308" },
  { category: "Secrets Leak", count: 14, color: "#8b5cf6" },
  { category: "Jailbreak", count: 9, color: "#ec4899" },
  { category: "Toxicity", count: 6, color: "#06b6d4" },
];

const demoTopServices: TopService[] = [
  { name: "chatbot-api", namespace: "production", calls_7d: 42_810, cost_7d_usd: 2_140, risk_score: 0.23 },
  { name: "code-review-agent", namespace: "engineering", calls_7d: 28_340, cost_7d_usd: 1_830, risk_score: 0.41 },
  { name: "support-summarizer", namespace: "customer-ops", calls_7d: 19_720, cost_7d_usd: 890, risk_score: 0.18 },
  { name: "data-pipeline-llm", namespace: "data-eng", calls_7d: 15_600, cost_7d_usd: 1_240, risk_score: 0.67 },
  { name: "sales-copilot", namespace: "go-to-market", calls_7d: 12_450, cost_7d_usd: 620, risk_score: 0.55 },
];

const demoRecentEvents: Event[] = [
  {
    id: "evt-001",
    timestamp: new Date(Date.now() - 2 * 60_000).toISOString(),
    source: "inline_gateway",
    severity: "critical",
    actor: { type: "pod", id: "data-pipeline-llm-7f8d9", name: "data-pipeline-llm", namespace: "data-eng" },
    target: { type: "llm_provider", id: "openai-1", provider: "OpenAI", model: "gpt-4o" },
    action: { type: "api_call", direction: "outbound" },
    content: { has_prompt: true, blocked: true, anonymized: false, pii_detected: ["ssn", "email"], injection_score: 0.12, tokens_input: 1200, tokens_output: 0 },
    guardrails: [{ rule_id: "pii-block", rule_name: "PII Blocker", stage: "input", decision: "block", confidence: 0.98, reason: "SSN detected in prompt", latency_ms: 8 }],
    cost_usd: 0,
    latency_ms: 14,
  },
  {
    id: "evt-002",
    timestamp: new Date(Date.now() - 8 * 60_000).toISOString(),
    source: "kernel_observer",
    severity: "high",
    actor: { type: "pod", id: "unknown-svc-a3x", name: "unknown-svc", namespace: "default" },
    target: { type: "llm_provider", id: "anthropic-1", provider: "Anthropic", model: "claude-sonnet-4-20250514" },
    action: { type: "api_call", direction: "outbound" },
    content: { has_prompt: true, blocked: false, anonymized: false, tokens_input: 800, tokens_output: 1200 },
    guardrails: [{ rule_id: "shadow-detect", rule_name: "Shadow AI Detector", stage: "pre_input", decision: "alert", confidence: 0.95, reason: "Unregistered service calling LLM", latency_ms: 3 }],
    cost_usd: 0.024,
    latency_ms: 450,
  },
  {
    id: "evt-003",
    timestamp: new Date(Date.now() - 15 * 60_000).toISOString(),
    source: "inline_gateway",
    severity: "high",
    actor: { type: "user", id: "user-42", name: "j.smith", namespace: "engineering" },
    target: { type: "llm_provider", id: "openai-1", provider: "OpenAI", model: "gpt-4o" },
    action: { type: "api_call", direction: "outbound" },
    content: { has_prompt: true, blocked: true, anonymized: false, injection_score: 0.92, tokens_input: 340, tokens_output: 0 },
    guardrails: [{ rule_id: "injection-block", rule_name: "Prompt Injection Guard", stage: "input", decision: "block", confidence: 0.92, reason: "High injection score", latency_ms: 22 }],
    cost_usd: 0,
    latency_ms: 28,
  },
  {
    id: "evt-004",
    timestamp: new Date(Date.now() - 32 * 60_000).toISOString(),
    source: "browser",
    severity: "medium",
    actor: { type: "browser_user", id: "buser-18", name: "m.chen", team: "marketing" },
    target: { type: "llm_provider", id: "openai-1", provider: "OpenAI", model: "gpt-4o-mini" },
    action: { type: "api_call", direction: "outbound" },
    content: { has_prompt: true, blocked: false, anonymized: true, pii_detected: ["email"], tokens_input: 520, tokens_output: 610 },
    guardrails: [{ rule_id: "pii-anon", rule_name: "PII Anonymizer", stage: "input", decision: "anonymize", confidence: 0.88, reason: "Email addresses anonymized", latency_ms: 5 }],
    cost_usd: 0.003,
    latency_ms: 380,
  },
  {
    id: "evt-005",
    timestamp: new Date(Date.now() - 48 * 60_000).toISOString(),
    source: "mcp_gateway",
    severity: "high",
    actor: { type: "agent", id: "agent-7", name: "deploy-agent", namespace: "platform" },
    target: { type: "filesystem", id: "fs-prod-1" },
    action: { type: "file_access", direction: "outbound" },
    content: { has_prompt: false, blocked: true, anonymized: false },
    guardrails: [{ rule_id: "agent-fs", rule_name: "Agent Filesystem Guard", stage: "behavioral", decision: "block", confidence: 0.99, reason: "Write to /etc/passwd denied", latency_ms: 1 }],
    cost_usd: 0,
    latency_ms: 3,
  },
  {
    id: "evt-006",
    timestamp: new Date(Date.now() - 72 * 60_000).toISOString(),
    source: "inline_gateway",
    severity: "medium",
    actor: { type: "pod", id: "support-summarizer-d4e5", name: "support-summarizer", namespace: "customer-ops" },
    target: { type: "llm_provider", id: "openai-1", provider: "OpenAI", model: "gpt-4o-mini" },
    action: { type: "api_call", direction: "outbound" },
    content: { has_prompt: true, blocked: false, anonymized: false, tokens_input: 3200, tokens_output: 450 },
    guardrails: [{ rule_id: "rate-limit", rule_name: "Rate Limiter", stage: "pre_input", decision: "throttle", confidence: 1.0, reason: "Approaching hourly limit", latency_ms: 1 }],
    cost_usd: 0.012,
    latency_ms: 520,
  },
  {
    id: "evt-007",
    timestamp: new Date(Date.now() - 95 * 60_000).toISOString(),
    source: "inline_gateway",
    severity: "low",
    actor: { type: "pod", id: "chatbot-api-a1b2", name: "chatbot-api", namespace: "production" },
    target: { type: "llm_provider", id: "openai-1", provider: "OpenAI", model: "gpt-4o-mini" },
    action: { type: "api_call", direction: "outbound" },
    content: { has_prompt: true, blocked: false, anonymized: false, tokens_input: 280, tokens_output: 390 },
    guardrails: [],
    cost_usd: 0.002,
    latency_ms: 310,
  },
  {
    id: "evt-008",
    timestamp: new Date(Date.now() - 120 * 60_000).toISOString(),
    source: "cicd",
    severity: "medium",
    actor: { type: "service_account", id: "sa-deploy", name: "ci-runner", namespace: "ci" },
    target: { type: "llm_provider", id: "anthropic-1", provider: "Anthropic", model: "claude-sonnet-4-20250514" },
    action: { type: "api_call", direction: "outbound" },
    content: { has_prompt: true, blocked: true, anonymized: false, pii_detected: ["credit_card"], tokens_input: 1800, tokens_output: 0 },
    guardrails: [{ rule_id: "secrets-block", rule_name: "Secrets Scanner", stage: "input", decision: "block", confidence: 0.96, reason: "Credit card number in prompt", latency_ms: 6 }],
    cost_usd: 0,
    latency_ms: 12,
  },
  {
    id: "evt-009",
    timestamp: new Date(Date.now() - 180 * 60_000).toISOString(),
    source: "ide",
    severity: "info",
    actor: { type: "user", id: "user-19", name: "a.kumar", namespace: "engineering" },
    target: { type: "llm_provider", id: "openai-1", provider: "OpenAI", model: "gpt-4o" },
    action: { type: "api_call", direction: "outbound" },
    content: { has_prompt: true, blocked: false, anonymized: false, tokens_input: 940, tokens_output: 1400 },
    guardrails: [],
    cost_usd: 0.031,
    latency_ms: 620,
  },
  {
    id: "evt-010",
    timestamp: new Date(Date.now() - 240 * 60_000).toISOString(),
    source: "inline_gateway",
    severity: "critical",
    actor: { type: "pod", id: "code-review-agent-x9z", name: "code-review-agent", namespace: "engineering" },
    target: { type: "llm_provider", id: "openai-1", provider: "OpenAI", model: "gpt-4o" },
    action: { type: "api_call", direction: "outbound" },
    content: { has_prompt: true, blocked: true, anonymized: false, injection_score: 0.97, tokens_input: 2400, tokens_output: 0 },
    guardrails: [{ rule_id: "jailbreak-block", rule_name: "Jailbreak Detector", stage: "input", decision: "block", confidence: 0.97, reason: "Jailbreak attempt detected", latency_ms: 45 }],
    cost_usd: 0,
    latency_ms: 52,
  },
];

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function getRiskColor(score: number): string {
  if (score >= 0.7) return "text-red-600";
  if (score >= 0.4) return "text-amber-600";
  return "text-emerald-600";
}

function getRiskBar(score: number): string {
  if (score >= 0.7) return "bg-red-500";
  if (score >= 0.4) return "bg-yellow-500";
  return "bg-emerald-500";
}

export default function DashboardPage() {
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<DashboardStats>(demoStats);
  const [threatActivity, setThreatActivity] = useState<ThreatActivityPoint[]>(demoThreatActivity);
  const [riskBreakdown, setRiskBreakdown] = useState<RiskBreakdown[]>(demoRiskBreakdown);
  const [topServices, setTopServices] = useState<TopService[]>(demoTopServices);
  const [recentEvents, setRecentEvents] = useState<Event[]>(demoRecentEvents);

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      setLoading(true);
      try {
        const [statsData, threatData, riskData, servicesData, alertsData] =
          await Promise.all([
            fetchStats().catch(() => null),
            fetchThreatActivity().catch(() => null),
            fetchRiskBreakdown().catch(() => null),
            fetchTopServices().catch(() => null),
            fetchRecentAlerts().catch(() => null),
          ]);

        if (cancelled) return;

        if (statsData) setStats(statsData);
        if (threatData) setThreatActivity(threatData);
        if (riskData) setRiskBreakdown(riskData);
        if (servicesData) setTopServices(servicesData);
        if (alertsData) setRecentEvents(alertsData);
      } catch {
        // keep demo data on total failure
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadData();
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-bold text-[#0f2137]">Dashboard</h1>
        <p className="mt-1 text-sm text-[#5a7184]">
          AI security posture overview
        </p>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <MetricCard
          title="Total AI Services"
          value={stats.total_services}
          subtitle={`${stats.shadow_ai_detected} shadow`}
          icon={Server}
          accentColor="cyan"
          trend={{ value: 12, positive: true }}
        />
        <MetricCard
          title="Active Guardrails"
          value={stats.active_guardrails}
          subtitle="across 6 stages"
          icon={Shield}
          accentColor="green"
        />
        <MetricCard
          title="Blocked Threats (24h)"
          value={stats.blocked_threats_24h}
          icon={ShieldAlert}
          accentColor="red"
          trend={{ value: 28, positive: false }}
        />
        <MetricCard
          title="Shadow AI Detected"
          value={stats.shadow_ai_detected}
          subtitle="unregistered services"
          icon={Eye}
          accentColor="yellow"
          trend={{ value: 3, positive: false }}
        />
        <MetricCard
          title="Monthly Cost"
          value={`$${formatNumber(stats.monthly_cost_usd)}`}
          subtitle="estimated across all providers"
          icon={DollarSign}
          accentColor="blue"
          trend={{ value: 8, positive: true }}
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Threat activity */}
        <div className="card lg:col-span-2">
          <div className="card-header">
            <h2 className="card-title">Threat Activity (7 days)</h2>
            <span className="text-xs text-[#5a7184]">
              Blocked vs Allowed requests
            </span>
          </div>
          <ThreatActivityChart data={threatActivity} />
        </div>

        {/* Risk breakdown */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Risk Score Breakdown</h2>
          </div>
          <RiskPieChart data={riskBreakdown} />
        </div>
      </div>

      {/* Tables row */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
        {/* Recent alerts */}
        <div className="table-wrapper xl:col-span-3">
          <div className="flex items-center justify-between px-5 py-4">
            <h2 className="text-sm font-semibold text-[#0f2137]">
              Recent Alerts
            </h2>
            <a
              href="/events"
              className="flex items-center gap-1 text-xs font-medium text-blue-600 hover:text-blue-700 transition-colors"
            >
              View all <ArrowUpRight className="h-3 w-3" />
            </a>
          </div>
          <EventTable
            events={recentEvents}
            compact
            onRowClick={(e) => setSelectedEvent(e)}
          />
        </div>

        {/* Top services */}
        <div className="table-wrapper xl:col-span-2">
          <div className="px-5 py-4">
            <h2 className="text-sm font-semibold text-[#0f2137]">
              Top Services by Usage
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-blue-100 text-left text-xs font-medium uppercase tracking-wider text-[#5a7184]">
                  <th className="px-5 py-3">Service</th>
                  <th className="px-5 py-3 text-right">Calls (7d)</th>
                  <th className="px-5 py-3 text-right">Cost</th>
                  <th className="px-5 py-3">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-blue-50">
                {topServices.map((svc) => (
                  <tr
                    key={svc.name}
                    className="hover:bg-blue-50/80 transition-colors"
                  >
                    <td className="px-5 py-3">
                      <div className="flex flex-col">
                        <span className="font-medium text-[#1a2b3c]">
                          {svc.name}
                        </span>
                        <span className="text-xs text-[#5a7184]">
                          {svc.namespace}
                        </span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-5 py-3 text-right text-[#1a2b3c] font-mono text-xs">
                      {formatNumber(svc.calls_7d)}
                    </td>
                    <td className="whitespace-nowrap px-5 py-3 text-right text-[#1a2b3c] font-mono text-xs">
                      ${formatNumber(svc.cost_7d_usd)}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-16 rounded-full bg-blue-100">
                          <div
                            className={`h-1.5 rounded-full ${getRiskBar(svc.risk_score)}`}
                            style={{
                              width: `${Math.round(svc.risk_score * 100)}%`,
                            }}
                          />
                        </div>
                        <span
                          className={`text-xs font-mono ${getRiskColor(svc.risk_score)}`}
                        >
                          {(svc.risk_score * 100).toFixed(0)}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Event detail modal */}
      {selectedEvent && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => setSelectedEvent(null)}
        >
          <div
            className="mx-4 max-h-[80vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-blue-100 bg-white p-6 shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between">
              <div>
                <h3 className="text-lg font-semibold text-[#0f2137]">
                  Event Detail
                </h3>
                <p className="mt-0.5 font-mono text-xs text-[#5a7184]">
                  {selectedEvent.id}
                </p>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="rounded-lg p-1 text-[#5a7184] hover:bg-blue-50 hover:text-[#1a2b3c]"
              >
                <svg className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                </svg>
              </button>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-xs font-medium text-[#5a7184] uppercase">Source</span>
                  <p className="mt-0.5 font-mono text-sm text-[#1a2b3c]">{selectedEvent.source}</p>
                </div>
                <div>
                  <span className="text-xs font-medium text-[#5a7184] uppercase">Severity</span>
                  <div className="mt-1">
                    <SeverityBadgeInline severity={selectedEvent.severity} />
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-[#5a7184] uppercase">Actor</span>
                  <p className="mt-0.5 text-sm text-[#1a2b3c]">{selectedEvent.actor.name || selectedEvent.actor.id}</p>
                  <p className="text-xs text-[#5a7184]">{selectedEvent.actor.namespace} / {selectedEvent.actor.type}</p>
                </div>
                <div>
                  <span className="text-xs font-medium text-[#5a7184] uppercase">Target</span>
                  <p className="mt-0.5 text-sm text-[#1a2b3c]">{selectedEvent.target.provider || selectedEvent.target.id}</p>
                  {selectedEvent.target.model && <p className="text-xs text-[#5a7184]">{selectedEvent.target.model}</p>}
                </div>
              </div>

              {selectedEvent.guardrails && selectedEvent.guardrails.length > 0 && (
                <div>
                  <span className="text-xs font-medium text-[#5a7184] uppercase">Guardrails Triggered</span>
                  <div className="mt-2 space-y-2">
                    {selectedEvent.guardrails.map((gr) => (
                      <div key={gr.rule_id} className="rounded-lg border border-blue-100 bg-blue-50/50 p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium text-[#1a2b3c]">{gr.rule_name}</span>
                          <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${gr.decision === "block" ? "bg-red-50 text-red-600" : gr.decision === "allow" ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"}`}>
                            {gr.decision}
                          </span>
                        </div>
                        {gr.reason && <p className="mt-1 text-xs text-[#5a7184]">{gr.reason}</p>}
                        <div className="mt-2 flex gap-4 text-xs text-[#5a7184]">
                          <span>Stage: {gr.stage}</span>
                          <span>Confidence: {(gr.confidence * 100).toFixed(0)}%</span>
                          <span>Latency: {gr.latency_ms}ms</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedEvent.content.pii_detected && selectedEvent.content.pii_detected.length > 0 && (
                <div>
                  <span className="text-xs font-medium text-[#5a7184] uppercase">PII Detected</span>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {selectedEvent.content.pii_detected.map((pii) => (
                      <span key={pii} className="rounded bg-red-50 px-2 py-0.5 text-xs text-red-600 ring-1 ring-inset ring-red-200">
                        {pii}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Inline severity badge for modal (avoids import cycle in demo)
function SeverityBadgeInline({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    info: "bg-blue-50 text-blue-600 ring-blue-200",
    low: "bg-emerald-50 text-emerald-600 ring-emerald-200",
    medium: "bg-amber-50 text-amber-600 ring-amber-200",
    high: "bg-orange-50 text-orange-600 ring-orange-200",
    critical: "bg-red-50 text-red-600 ring-red-200",
  };
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${styles[severity] ?? styles.info}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}
