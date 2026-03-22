"use client";

import { useState, useEffect, useMemo } from "react";
import {
  Search,
  Filter,
  Download,
  ChevronDown,
  X,
  ExternalLink,
  Shield,
} from "lucide-react";
import StatusBadge from "@/components/StatusBadge";
import { fetchInventory } from "@/lib/api";
import type { AIService } from "@/lib/types";

// ---------------------------------------------------------------------------
// Fallback demo data -- used when the API is unreachable
// ---------------------------------------------------------------------------

const demoServices: AIService[] = [
  {
    id: "svc-1",
    name: "chatbot-api",
    namespace: "production",
    team: "platform",
    providers: [
      { provider: "OpenAI", models: ["gpt-4o", "gpt-4o-mini"], call_count_7d: 42810, tokens_used_7d: 8_400_000, data_transferred_7d: 128_000_000, est_cost_7d_usd: 2140, last_call_at: new Date().toISOString() },
    ],
    exposure_type: "external",
    risk_score: 0.23,
    discovered_at: "2025-11-10T08:00:00Z",
    last_seen_at: new Date().toISOString(),
    discovered_by: "inline_gateway",
    policy_applied: "production-standard",
    gateway_enrolled: true,
    labels: { tier: "critical" },
  },
  {
    id: "svc-2",
    name: "code-review-agent",
    namespace: "engineering",
    team: "devtools",
    providers: [
      { provider: "OpenAI", models: ["gpt-4o"], call_count_7d: 28340, tokens_used_7d: 12_200_000, data_transferred_7d: 94_000_000, est_cost_7d_usd: 1830, last_call_at: new Date().toISOString() },
      { provider: "Anthropic", models: ["claude-sonnet-4-20250514"], call_count_7d: 4200, tokens_used_7d: 3_800_000, data_transferred_7d: 22_000_000, est_cost_7d_usd: 420, last_call_at: new Date().toISOString() },
    ],
    exposure_type: "internal",
    risk_score: 0.41,
    discovered_at: "2025-12-01T10:00:00Z",
    last_seen_at: new Date().toISOString(),
    discovered_by: "inline_gateway",
    policy_applied: "engineering-permissive",
    gateway_enrolled: true,
  },
  {
    id: "svc-3",
    name: "support-summarizer",
    namespace: "customer-ops",
    team: "support",
    providers: [
      { provider: "OpenAI", models: ["gpt-4o-mini"], call_count_7d: 19720, tokens_used_7d: 4_100_000, data_transferred_7d: 38_000_000, est_cost_7d_usd: 890, last_call_at: new Date().toISOString() },
    ],
    exposure_type: "internal",
    risk_score: 0.18,
    discovered_at: "2025-10-15T14:00:00Z",
    last_seen_at: new Date().toISOString(),
    discovered_by: "inline_gateway",
    policy_applied: "production-standard",
    gateway_enrolled: true,
  },
  {
    id: "svc-4",
    name: "data-pipeline-llm",
    namespace: "data-eng",
    team: "data",
    providers: [
      { provider: "OpenAI", models: ["gpt-4o"], call_count_7d: 15600, tokens_used_7d: 22_400_000, data_transferred_7d: 210_000_000, est_cost_7d_usd: 1240, last_call_at: new Date().toISOString() },
    ],
    databases: [{ type: "postgresql", host: "prod-db.internal", database: "analytics" }],
    exposure_type: "internal",
    risk_score: 0.67,
    discovered_at: "2026-01-05T09:00:00Z",
    last_seen_at: new Date().toISOString(),
    discovered_by: "kernel_observer",
    policy_applied: "data-strict",
    gateway_enrolled: true,
  },
  {
    id: "svc-5",
    name: "sales-copilot",
    namespace: "go-to-market",
    team: "sales",
    providers: [
      { provider: "OpenAI", models: ["gpt-4o"], call_count_7d: 12450, tokens_used_7d: 5_600_000, data_transferred_7d: 42_000_000, est_cost_7d_usd: 620, last_call_at: new Date().toISOString() },
    ],
    exposure_type: "external",
    risk_score: 0.55,
    discovered_at: "2026-02-01T11:00:00Z",
    last_seen_at: new Date().toISOString(),
    discovered_by: "inline_gateway",
    gateway_enrolled: true,
  },
  {
    id: "svc-6",
    name: "unknown-ml-svc",
    namespace: "default",
    providers: [
      { provider: "Anthropic", models: ["claude-sonnet-4-20250514"], call_count_7d: 3200, tokens_used_7d: 1_800_000, data_transferred_7d: 14_000_000, est_cost_7d_usd: 180, last_call_at: new Date().toISOString() },
    ],
    exposure_type: "internal",
    risk_score: 0.89,
    discovered_at: "2026-03-18T16:00:00Z",
    last_seen_at: new Date().toISOString(),
    discovered_by: "kernel_observer",
    gateway_enrolled: false,
  },
  {
    id: "svc-7",
    name: "marketing-content-gen",
    namespace: "marketing",
    team: "content",
    providers: [
      { provider: "OpenAI", models: ["gpt-4o-mini"], call_count_7d: 8400, tokens_used_7d: 2_200_000, data_transferred_7d: 18_000_000, est_cost_7d_usd: 340, last_call_at: new Date().toISOString() },
    ],
    exposure_type: "internal",
    risk_score: 0.31,
    discovered_at: "2026-01-20T13:00:00Z",
    last_seen_at: new Date().toISOString(),
    discovered_by: "browser",
    gateway_enrolled: false,
  },
  {
    id: "svc-8",
    name: "rogue-scraper",
    namespace: "default",
    providers: [
      { provider: "OpenAI", models: ["gpt-4o"], call_count_7d: 1100, tokens_used_7d: 900_000, data_transferred_7d: 8_000_000, est_cost_7d_usd: 95, last_call_at: new Date().toISOString() },
      { provider: "Mistral", models: ["mistral-large"], call_count_7d: 620, tokens_used_7d: 400_000, data_transferred_7d: 3_000_000, est_cost_7d_usd: 28, last_call_at: new Date().toISOString() },
    ],
    exposure_type: "external",
    risk_score: 0.94,
    discovered_at: "2026-03-19T22:00:00Z",
    last_seen_at: new Date().toISOString(),
    discovered_by: "kernel_observer",
    gateway_enrolled: false,
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

function getRiskLevel(score: number): string {
  if (score >= 0.8) return "critical";
  if (score >= 0.6) return "high";
  if (score >= 0.3) return "medium";
  return "low";
}

function getRiskColor(score: number): string {
  if (score >= 0.8) return "text-red-400";
  if (score >= 0.6) return "text-orange-400";
  if (score >= 0.3) return "text-yellow-400";
  return "text-emerald-400";
}

function getRiskBar(score: number): string {
  if (score >= 0.8) return "bg-red-500";
  if (score >= 0.6) return "bg-orange-500";
  if (score >= 0.3) return "bg-yellow-500";
  return "bg-emerald-500";
}

function isShadow(svc: AIService): boolean {
  return !svc.gateway_enrolled && !svc.policy_applied;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function InventoryPage() {
  const [services, setServices] = useState<AIService[]>(demoServices);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [nsFilter, setNsFilter] = useState<string>("");
  const [providerFilter, setProviderFilter] = useState<string>("");
  const [riskFilter, setRiskFilter] = useState<string>("");
  const [selectedService, setSelectedService] = useState<AIService | null>(
    null,
  );

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      setLoading(true);
      try {
        const response = await fetchInventory({
          namespace: nsFilter || undefined,
          provider: providerFilter || undefined,
          search: search || undefined,
        });
        if (!cancelled && response.data) {
          setServices(response.data);
        }
      } catch {
        // keep demo data on failure
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadData();
    return () => { cancelled = true; };
  }, [nsFilter, providerFilter, search]);

  const namespaces = useMemo(
    () => Array.from(new Set(services.map((s) => s.namespace))).sort(),
    [services],
  );
  const providers = useMemo(
    () =>
      Array.from(
        new Set(services.flatMap((s) => s.providers.map((p) => p.provider))),
      ).sort(),
    [services],
  );

  const filtered = useMemo(() => {
    return services.filter((svc) => {
      if (search) {
        const q = search.toLowerCase();
        const matchName = svc.name.toLowerCase().includes(q);
        const matchNs = svc.namespace.toLowerCase().includes(q);
        const matchProv = svc.providers.some((p) =>
          p.provider.toLowerCase().includes(q),
        );
        if (!matchName && !matchNs && !matchProv) return false;
      }
      if (nsFilter && svc.namespace !== nsFilter) return false;
      if (
        providerFilter &&
        !svc.providers.some((p) => p.provider === providerFilter)
      )
        return false;
      if (riskFilter && getRiskLevel(svc.risk_score) !== riskFilter)
        return false;
      return true;
    });
  }, [services, search, nsFilter, providerFilter, riskFilter]);

  const activeFilters =
    [nsFilter, providerFilter, riskFilter].filter(Boolean).length;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">
            AI Service Inventory (AIBOM)
          </h1>
          <p className="mt-1 text-sm text-gray-500">
            {services.length} services discovered across{" "}
            {namespaces.length} namespaces
          </p>
        </div>
        <button className="btn-secondary">
          <Download className="h-4 w-4" />
          Export AIBOM
        </button>
      </div>

      {/* Filters bar */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search services, namespaces, providers..."
            className="input pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Namespace */}
        <div className="relative">
          <select
            className="select appearance-none pr-8"
            value={nsFilter}
            onChange={(e) => setNsFilter(e.target.value)}
          >
            <option value="">All Namespaces</option>
            {namespaces.map((ns) => (
              <option key={ns} value={ns}>
                {ns}
              </option>
            ))}
          </select>
          <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
        </div>

        {/* Provider */}
        <div className="relative">
          <select
            className="select appearance-none pr-8"
            value={providerFilter}
            onChange={(e) => setProviderFilter(e.target.value)}
          >
            <option value="">All Providers</option>
            {providers.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
        </div>

        {/* Risk Level */}
        <div className="relative">
          <select
            className="select appearance-none pr-8"
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
          >
            <option value="">All Risk Levels</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
        </div>

        {activeFilters > 0 && (
          <button
            className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200"
            onClick={() => {
              setNsFilter("");
              setProviderFilter("");
              setRiskFilter("");
              setSearch("");
            }}
          >
            <X className="h-3 w-3" /> Clear filters
          </button>
        )}

        <div className="flex items-center gap-1.5 text-xs text-gray-500">
          <Filter className="h-3.5 w-3.5" />
          {filtered.length} of {services.length}
        </div>
      </div>

      {/* Table */}
      <div className="table-wrapper">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-300 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                <th className="px-4 py-3">Service Name</th>
                <th className="px-4 py-3">Namespace</th>
                <th className="px-4 py-3">Provider(s)</th>
                <th className="px-4 py-3">Model(s)</th>
                <th className="px-4 py-3 text-right">Calls (7d)</th>
                <th className="px-4 py-3 text-right">Data (7d)</th>
                <th className="px-4 py-3 text-right">Cost (7d)</th>
                <th className="px-4 py-3">Risk Score</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Gateway</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-300">
              {filtered.map((svc) => {
                const totalCalls = svc.providers.reduce(
                  (a, p) => a + p.call_count_7d,
                  0,
                );
                const totalData = svc.providers.reduce(
                  (a, p) => a + p.data_transferred_7d,
                  0,
                );
                const totalCost = svc.providers.reduce(
                  (a, p) => a + p.est_cost_7d_usd,
                  0,
                );
                const allModels = svc.providers.flatMap((p) => p.models);
                const shadow = isShadow(svc);

                return (
                  <tr
                    key={svc.id}
                    className="group cursor-pointer transition-colors hover:bg-surface-200/60"
                    onClick={() => setSelectedService(svc)}
                  >
                    <td className="whitespace-nowrap px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-gray-200">
                          {svc.name}
                        </span>
                        {shadow && (
                          <span className="rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-red-400 ring-1 ring-inset ring-red-500/30">
                            Shadow
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-gray-400">
                      <span className="rounded bg-surface-300 px-1.5 py-0.5 font-mono text-xs">
                        {svc.namespace}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {svc.providers.map((p) => (
                          <span
                            key={p.provider}
                            className="rounded bg-cyan-500/10 px-1.5 py-0.5 text-xs text-cyan-400"
                          >
                            {p.provider}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-400">
                      <div className="flex flex-wrap gap-1">
                        {allModels.slice(0, 2).map((m) => (
                          <span
                            key={m}
                            className="rounded bg-surface-300 px-1.5 py-0.5 font-mono text-[11px]"
                          >
                            {m}
                          </span>
                        ))}
                        {allModels.length > 2 && (
                          <span className="text-xs text-gray-500">
                            +{allModels.length - 2}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-right font-mono text-xs text-gray-300">
                      {formatNumber(totalCalls)}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-right font-mono text-xs text-gray-300">
                      {formatBytes(totalData)}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-right font-mono text-xs text-gray-300">
                      ${formatNumber(totalCost)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-14 rounded-full bg-surface-300">
                          <div
                            className={`h-1.5 rounded-full ${getRiskBar(svc.risk_score)}`}
                            style={{
                              width: `${Math.round(svc.risk_score * 100)}%`,
                            }}
                          />
                        </div>
                        <span
                          className={`font-mono text-xs ${getRiskColor(svc.risk_score)}`}
                        >
                          {(svc.risk_score * 100).toFixed(0)}
                        </span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <StatusBadge
                        status={shadow ? "shadow" : "active"}
                      />
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <StatusBadge
                        status={
                          svc.gateway_enrolled ? "enrolled" : "inactive"
                        }
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filtered.length === 0 && (
            <div className="flex items-center justify-center py-16 text-gray-500">
              No services match the current filters.
            </div>
          )}
        </div>
      </div>

      {/* Detail side-panel / modal */}
      {selectedService && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-end bg-black/50 backdrop-blur-sm"
          onClick={() => setSelectedService(null)}
        >
          <div
            className="h-full w-full max-w-lg overflow-y-auto border-l border-surface-300 bg-surface-100 p-6 shadow-2xl animate-slide-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-lg font-bold text-white">
                    {selectedService.name}
                  </h2>
                  {isShadow(selectedService) && (
                    <span className="rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-red-400 ring-1 ring-inset ring-red-500/30">
                      Shadow
                    </span>
                  )}
                </div>
                <p className="mt-0.5 font-mono text-xs text-gray-500">
                  {selectedService.id}
                </p>
              </div>
              <button
                onClick={() => setSelectedService(null)}
                className="rounded-lg p-1.5 text-gray-500 hover:bg-surface-200 hover:text-gray-300"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="mt-6 space-y-6">
              {/* Overview */}
              <section>
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
                  Overview
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  <DetailField label="Namespace" value={selectedService.namespace} />
                  <DetailField label="Team" value={selectedService.team || "-"} />
                  <DetailField label="Exposure" value={selectedService.exposure_type} />
                  <DetailField label="Discovered By" value={selectedService.discovered_by} />
                  <DetailField label="Policy" value={selectedService.policy_applied || "None"} />
                  <DetailField label="Gateway" value={selectedService.gateway_enrolled ? "Enrolled" : "Not enrolled"} />
                </div>
              </section>

              {/* Risk */}
              <section>
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
                  Risk Assessment
                </h3>
                <div className="flex items-center gap-3">
                  <div className="h-2 flex-1 rounded-full bg-surface-300">
                    <div
                      className={`h-2 rounded-full ${getRiskBar(selectedService.risk_score)}`}
                      style={{ width: `${Math.round(selectedService.risk_score * 100)}%` }}
                    />
                  </div>
                  <span className={`text-lg font-bold font-mono ${getRiskColor(selectedService.risk_score)}`}>
                    {(selectedService.risk_score * 100).toFixed(0)}
                  </span>
                </div>
              </section>

              {/* Providers */}
              <section>
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
                  Provider Usage (7d)
                </h3>
                <div className="space-y-3">
                  {selectedService.providers.map((p) => (
                    <div
                      key={p.provider}
                      className="rounded-lg border border-surface-300 bg-surface-200 p-3"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-cyan-400">
                          {p.provider}
                        </span>
                        <span className="font-mono text-xs text-gray-400">
                          ${formatNumber(p.est_cost_7d_usd)}
                        </span>
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {p.models.map((m) => (
                          <span
                            key={m}
                            className="rounded bg-surface-300 px-1.5 py-0.5 font-mono text-[11px] text-gray-400"
                          >
                            {m}
                          </span>
                        ))}
                      </div>
                      <div className="mt-2 grid grid-cols-3 gap-2 text-xs text-gray-500">
                        <span>{formatNumber(p.call_count_7d)} calls</span>
                        <span>{formatNumber(p.tokens_used_7d)} tokens</span>
                        <span>{formatBytes(p.data_transferred_7d)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Databases */}
              {selectedService.databases && selectedService.databases.length > 0 && (
                <section>
                  <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
                    Database Connections
                  </h3>
                  <div className="space-y-2">
                    {selectedService.databases.map((db, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-3 rounded-lg border border-surface-300 bg-surface-200 px-3 py-2"
                      >
                        <span className="rounded bg-purple-500/10 px-1.5 py-0.5 text-xs text-purple-400">
                          {db.type}
                        </span>
                        <span className="font-mono text-xs text-gray-400">
                          {db.host}
                        </span>
                        {db.database && (
                          <span className="text-xs text-gray-500">
                            / {db.database}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Actions */}
              <section className="flex gap-3 border-t border-surface-300 pt-4">
                <button className="btn-primary text-xs">
                  <Shield className="h-3.5 w-3.5" /> Apply Policy
                </button>
                <button className="btn-secondary text-xs">
                  <ExternalLink className="h-3.5 w-3.5" /> View Events
                </button>
              </section>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-[11px] font-medium text-gray-500 uppercase">
        {label}
      </span>
      <p className="mt-0.5 text-sm text-gray-300">{value}</p>
    </div>
  );
}

