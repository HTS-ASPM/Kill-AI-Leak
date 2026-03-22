"use client";

import { useState, useEffect } from "react";
import { Shield, Search, ChevronDown, ToggleLeft, ToggleRight } from "lucide-react";
import StatusBadge from "@/components/StatusBadge";
import { fetchGuardrails, updateGuardrail } from "@/lib/api";
import type { GuardrailRuleConfig, EnforcementMode, GuardrailStage, RuleCategory } from "@/lib/types";

// ---------------------------------------------------------------------------
// Demo guardrail rules
// ---------------------------------------------------------------------------

const demoRules: GuardrailRuleConfig[] = [
  { id: "pii-block", name: "PII Blocker", description: "Blocks prompts containing sensitive PII (SSN, credit cards, medical IDs)", stage: "input", category: "pii", mode: "enforce", priority: 10, enabled: true },
  { id: "pii-anon", name: "PII Anonymizer", description: "Replaces detected PII with anonymized tokens before forwarding to LLM", stage: "input", category: "pii", mode: "enforce", priority: 20, enabled: true },
  { id: "secrets-scan", name: "Secrets Scanner", description: "Detects API keys, tokens, passwords, and credentials in prompts", stage: "input", category: "secrets", mode: "enforce", priority: 15, enabled: true },
  { id: "injection-guard", name: "Prompt Injection Guard", description: "ML-based detection of prompt injection and manipulation attempts", stage: "input", category: "injection", mode: "enforce", priority: 5, enabled: true },
  { id: "jailbreak-detect", name: "Jailbreak Detector", description: "Identifies jailbreak patterns and system prompt override attempts", stage: "input", category: "jailbreak", mode: "enforce", priority: 8, enabled: true },
  { id: "toxicity-filter", name: "Toxicity Filter", description: "Blocks toxic, harmful, or inappropriate content in requests and responses", stage: "output", category: "toxicity", mode: "monitor", priority: 30, enabled: true },
  { id: "code-safety", name: "Code Safety Scanner", description: "Scans LLM-generated code for known vulnerabilities and unsafe patterns", stage: "output", category: "code_safety", mode: "monitor", priority: 35, enabled: true },
  { id: "exfil-guard", name: "Exfiltration Guard", description: "Detects unusually large data payloads that may indicate data exfiltration", stage: "input", category: "exfiltration", mode: "enforce", priority: 12, enabled: true },
  { id: "shadow-detect", name: "Shadow AI Detector", description: "Identifies unregistered services making LLM API calls", stage: "pre_input", category: "shadow_ai", mode: "enforce", priority: 1, enabled: true },
  { id: "rate-limiter", name: "Rate Limiter", description: "Enforces request and cost rate limits per user, service, and namespace", stage: "pre_input", category: "rate_limit", mode: "enforce", priority: 2, enabled: true },
  { id: "allowlist", name: "Provider Allowlist", description: "Validates requests against the configured provider and model allowlists", stage: "routing", category: "allowlist", mode: "enforce", priority: 3, enabled: true },
  { id: "data-residency", name: "Data Residency Router", description: "Routes requests to specific regions based on data classification", stage: "routing", category: "data_residency", mode: "discover", priority: 25, enabled: false },
  { id: "agent-fs-guard", name: "Agent Filesystem Guard", description: "Controls file system access for AI agents based on policy", stage: "behavioral", category: "agent_control", mode: "enforce", priority: 40, enabled: true },
  { id: "agent-cmd-guard", name: "Agent Command Guard", description: "Blocks dangerous command execution by AI agents", stage: "behavioral", category: "agent_control", mode: "enforce", priority: 41, enabled: true },
  { id: "brand-safety", name: "Brand Safety Filter", description: "Ensures LLM outputs align with brand guidelines and messaging standards", stage: "output", category: "brand_safety", mode: "monitor", priority: 50, enabled: false },
  { id: "output-pii-check", name: "Output PII Leakage Check", description: "Scans LLM responses for PII that may have leaked from training data", stage: "output", category: "pii", mode: "monitor", priority: 32, enabled: true },
  { id: "prompt-leak-check", name: "Prompt Leakage Check", description: "Detects when system prompts or instructions are leaked in responses", stage: "post_output", category: "compliance", mode: "monitor", priority: 45, enabled: true },
  { id: "auth-check", name: "Auth & Identity Check", description: "Validates actor identity and permissions before processing requests", stage: "pre_input", category: "auth", mode: "enforce", priority: 0, enabled: true },
];

const stageOrder: GuardrailStage[] = ["pre_input", "input", "routing", "output", "post_output", "behavioral"];

const stageLabels: Record<GuardrailStage, string> = {
  pre_input: "Pre-Input",
  input: "Input",
  routing: "Routing",
  output: "Output",
  post_output: "Post-Output",
  behavioral: "Behavioral",
};

const stageBg: Record<GuardrailStage, string> = {
  pre_input: "bg-blue-50 text-blue-600 ring-blue-500/20",
  input: "bg-cyan-50 text-cyan-600 ring-cyan-200",
  routing: "bg-purple-50 text-purple-600 ring-purple-500/20",
  output: "bg-emerald-50 text-emerald-600 ring-emerald-500/20",
  post_output: "bg-amber-50 text-amber-600 ring-yellow-500/20",
  behavioral: "bg-orange-50 text-orange-600 ring-orange-500/20",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function GuardrailsPage() {
  const [guardrails, setGuardrails] = useState(demoRules);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [stageFilter, setStageFilter] = useState<string>("");
  const [modeFilter, setModeFilter] = useState<string>("");

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      setLoading(true);
      try {
        const data = await fetchGuardrails();
        if (!cancelled && data) {
          setGuardrails(data);
        }
      } catch {
        // keep demo data on failure
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadData();
    return () => { cancelled = true; };
  }, []);

  const filtered = guardrails
    .filter((r) => {
      if (search) {
        const q = search.toLowerCase();
        if (
          !r.name.toLowerCase().includes(q) &&
          !r.description.toLowerCase().includes(q) &&
          !r.category.toLowerCase().includes(q)
        )
          return false;
      }
      if (stageFilter && r.stage !== stageFilter) return false;
      if (modeFilter && r.mode !== modeFilter) return false;
      return true;
    })
    .sort(
      (a, b) =>
        stageOrder.indexOf(a.stage) - stageOrder.indexOf(b.stage) ||
        a.priority - b.priority,
    );

  function toggleRule(id: string) {
    const rule = guardrails.find((r) => r.id === id);
    if (!rule) return;
    const newEnabled = !rule.enabled;

    // Optimistic update
    setGuardrails((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: newEnabled } : r)),
    );

    // Persist to API (revert on failure)
    updateGuardrail(id, { enabled: newEnabled }).catch(() => {
      setGuardrails((prev) =>
        prev.map((r) => (r.id === id ? { ...r, enabled: !newEnabled } : r)),
      );
    });
  }

  function cycleMode(id: string) {
    const modes: EnforcementMode[] = ["off", "discover", "monitor", "enforce"];
    const rule = guardrails.find((r) => r.id === id);
    if (!rule) return;
    const oldMode = rule.mode;
    const idx = modes.indexOf(oldMode);
    const newMode = modes[(idx + 1) % modes.length];

    // Optimistic update
    setGuardrails((prev) =>
      prev.map((r) => (r.id === id ? { ...r, mode: newMode } : r)),
    );

    // Persist to API (revert on failure)
    updateGuardrail(id, { mode: newMode }).catch(() => {
      setGuardrails((prev) =>
        prev.map((r) => (r.id === id ? { ...r, mode: oldMode } : r)),
      );
    });
  }

  const enabledCount = guardrails.filter((r) => r.enabled).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-[#0f2137]">Guardrails</h1>
        <p className="mt-1 text-sm text-[#5a7184]">
          {enabledCount} of {guardrails.length} rules active across the
          security pipeline
        </p>
      </div>

      {/* Pipeline stage overview */}
      <div className="flex gap-1 overflow-x-auto rounded-lg border border-blue-100 bg-white p-2">
        {stageOrder.map((stage) => {
          const count = guardrails.filter(
            (r) => r.stage === stage && r.enabled,
          ).length;
          return (
            <button
              key={stage}
              onClick={() =>
                setStageFilter(stageFilter === stage ? "" : stage)
              }
              className={`flex flex-1 min-w-[100px] flex-col items-center gap-1 rounded-md px-3 py-2.5 transition-colors ${
                stageFilter === stage
                  ? "bg-blue-50"
                  : "hover:bg-blue-50/50"
              }`}
            >
              <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset ${stageBg[stage]}`}>
                {stageLabels[stage]}
              </span>
              <span className="text-lg font-bold text-[#0f2137]">{count}</span>
              <span className="text-[10px] text-[#5a7184]">active</span>
            </button>
          );
        })}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#5a7184]" />
          <input
            type="text"
            placeholder="Search rules..."
            className="input pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="relative">
          <select
            className="select appearance-none pr-8"
            value={modeFilter}
            onChange={(e) => setModeFilter(e.target.value)}
          >
            <option value="">All Modes</option>
            <option value="enforce">Enforce</option>
            <option value="monitor">Monitor</option>
            <option value="discover">Discover</option>
            <option value="off">Off</option>
          </select>
          <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#5a7184]" />
        </div>
      </div>

      {/* Rules list */}
      <div className="space-y-2">
        {filtered.map((rule) => (
          <div
            key={rule.id}
            className={`flex items-center gap-4 rounded-xl border p-4 transition-colors ${
              rule.enabled
                ? "border-blue-100 bg-white"
                : "border-blue-100/50 bg-white/50 opacity-60"
            }`}
          >
            {/* Toggle */}
            <button
              onClick={() => toggleRule(rule.id)}
              className="shrink-0"
              title={rule.enabled ? "Disable rule" : "Enable rule"}
            >
              {rule.enabled ? (
                <ToggleRight className="h-6 w-6 text-blue-600" />
              ) : (
                <ToggleLeft className="h-6 w-6 text-[#5a7184]" />
              )}
            </button>

            {/* Info */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-[#1a2b3c] truncate">
                  {rule.name}
                </span>
                <span
                  className={`rounded px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset ${stageBg[rule.stage]}`}
                >
                  {stageLabels[rule.stage]}
                </span>
                <span className="rounded bg-blue-50 px-1.5 py-0.5 text-[10px] text-[#5a7184]">
                  {rule.category}
                </span>
              </div>
              <p className="mt-0.5 text-xs text-[#5a7184] truncate">
                {rule.description}
              </p>
            </div>

            {/* Priority */}
            <span className="shrink-0 font-mono text-[10px] text-[#5a7184]">
              P{rule.priority}
            </span>

            {/* Mode toggle */}
            <button
              onClick={() => cycleMode(rule.id)}
              className="shrink-0"
              title={`Current: ${rule.mode}. Click to cycle.`}
            >
              <StatusBadge status={rule.mode} />
            </button>
          </div>
        ))}

        {filtered.length === 0 && (
          <div className="flex items-center justify-center py-16 text-[#5a7184]">
            No guardrail rules match the current filters.
          </div>
        )}
      </div>
    </div>
  );
}
