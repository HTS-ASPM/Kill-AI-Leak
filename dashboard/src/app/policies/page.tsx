"use client";

import { useState, useEffect } from "react";
import {
  Plus,
  Pencil,
  Trash2,
  Play,
  X,
  ChevronDown,
  Check,
  AlertTriangle,
  Shield,
  Eye,
  Radio,
  Power,
} from "lucide-react";
import StatusBadge from "@/components/StatusBadge";
import {
  fetchPolicies,
  createPolicy,
  updatePolicy,
  deletePolicy,
  dryRunPolicy,
} from "@/lib/api";
import type { AISecurityPolicy, EnforcementMode } from "@/lib/types";

// ---------------------------------------------------------------------------
// Demo policies
// ---------------------------------------------------------------------------

const demoPolicies: AISecurityPolicy[] = [
  {
    apiVersion: "killaileak.io/v1",
    kind: "AISecurityPolicy",
    metadata: { name: "production-standard", namespace: "production" },
    spec: {
      scope: { namespaces: ["production"], teams: ["platform", "support"] },
      providers: { allow: ["OpenAI", "Anthropic"], deny: ["*"] },
      models: { allow: ["gpt-4o", "gpt-4o-mini", "claude-sonnet-4-20250514"], deny: [] },
      input: {
        block_pii: true,
        anonymize_pii: false,
        block_secrets: true,
        block_injection_score_above: 0.8,
        pii_types: ["ssn", "credit_card", "phone"],
        blocked_topics: ["weapons", "illegal"],
      },
      output: {
        block_toxic_score_above: 0.7,
        scan_generated_code: true,
        block_vulnerable_code: true,
        check_pii_leakage: true,
        check_prompt_leakage: true,
      },
      rate_limits: {
        per_service: { requests_per_minute: 100, cost_per_day_usd: 500 },
      },
      mode: "enforce",
    },
  },
  {
    apiVersion: "killaileak.io/v1",
    kind: "AISecurityPolicy",
    metadata: { name: "engineering-permissive", namespace: "engineering" },
    spec: {
      scope: { namespaces: ["engineering"], teams: ["devtools", "infra"] },
      providers: { allow: ["*"], deny: [] },
      input: {
        block_pii: false,
        anonymize_pii: true,
        block_secrets: true,
        block_injection_score_above: 0.9,
      },
      output: {
        block_toxic_score_above: 0.8,
        scan_generated_code: true,
        block_vulnerable_code: false,
        check_pii_leakage: false,
        check_prompt_leakage: false,
      },
      mode: "monitor",
    },
  },
  {
    apiVersion: "killaileak.io/v1",
    kind: "AISecurityPolicy",
    metadata: { name: "data-strict", namespace: "data-eng" },
    spec: {
      scope: { namespaces: ["data-eng"] },
      providers: { allow: ["OpenAI"], deny: ["*"] },
      models: { allow: ["gpt-4o"], deny: [] },
      input: {
        block_pii: true,
        anonymize_pii: true,
        block_secrets: true,
        block_injection_score_above: 0.7,
        pii_types: ["ssn", "credit_card", "email", "phone", "address"],
        max_tokens_per_request: 4000,
      },
      output: {
        block_toxic_score_above: 0.5,
        scan_generated_code: true,
        block_vulnerable_code: true,
        check_pii_leakage: true,
        check_prompt_leakage: true,
      },
      rate_limits: {
        per_service: { requests_per_hour: 200, cost_per_day_usd: 200 },
      },
      mode: "enforce",
    },
  },
  {
    apiVersion: "killaileak.io/v1",
    kind: "AISecurityPolicy",
    metadata: { name: "shadow-discovery" },
    spec: {
      scope: { namespaces: ["default", "kube-system"] },
      mode: "discover",
    },
  },
  {
    apiVersion: "killaileak.io/v1",
    kind: "AISecurityPolicy",
    metadata: { name: "marketing-basic", namespace: "marketing" },
    spec: {
      scope: { namespaces: ["marketing"], teams: ["content"] },
      providers: { allow: ["OpenAI"], deny: ["*"] },
      models: { allow: ["gpt-4o-mini"], deny: [] },
      input: {
        block_pii: false,
        anonymize_pii: true,
        block_secrets: true,
        block_injection_score_above: 0.85,
      },
      output: {
        block_toxic_score_above: 0.6,
        scan_generated_code: false,
        block_vulnerable_code: false,
        check_pii_leakage: false,
        check_prompt_leakage: false,
      },
      mode: "monitor",
    },
  },
];

const modeIcons: Record<EnforcementMode, typeof Shield> = {
  off: Power,
  discover: Eye,
  monitor: Radio,
  enforce: Shield,
};

const modeDescriptions: Record<EnforcementMode, string> = {
  off: "Policy is disabled",
  discover: "Log-only, no blocking or alerting",
  monitor: "Alert on violations but do not block",
  enforce: "Actively block policy violations",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function PoliciesPage() {
  const [policies, setPolicies] = useState(demoPolicies);
  const [loading, setLoading] = useState(true);
  const [showEditor, setShowEditor] = useState(false);
  const [editorContent, setEditorContent] = useState("");
  const [editingPolicy, setEditingPolicy] = useState<string | null>(null);
  const [showDryRun, setShowDryRun] = useState(false);
  const [dryRunPrompt, setDryRunPrompt] = useState("");
  const [dryRunPolicyName, setDryRunPolicyName] = useState("");
  const [dryRunResult, setDryRunResult] = useState<{
    decision: string;
    rules: Array<{ name: string; decision: string; reason: string }>;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      setLoading(true);
      try {
        const data = await fetchPolicies();
        if (!cancelled && data) {
          setPolicies(data);
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

  function openEditor(policy?: AISecurityPolicy) {
    if (policy) {
      setEditingPolicy(policy.metadata.name);
      setEditorContent(JSON.stringify(policy, null, 2));
    } else {
      setEditingPolicy(null);
      setEditorContent(
        JSON.stringify(
          {
            apiVersion: "killaileak.io/v1",
            kind: "AISecurityPolicy",
            metadata: { name: "", namespace: "" },
            spec: {
              scope: { namespaces: [] },
              mode: "discover",
            },
          },
          null,
          2,
        ),
      );
    }
    setShowEditor(true);
  }

  function toggleMode(policyName: string) {
    setPolicies((prev) =>
      prev.map((p) => {
        if (p.metadata.name !== policyName) return p;
        const modes: EnforcementMode[] = [
          "off",
          "discover",
          "monitor",
          "enforce",
        ];
        const currentIdx = modes.indexOf(p.spec.mode);
        const nextMode = modes[(currentIdx + 1) % modes.length];
        return {
          ...p,
          spec: { ...p.spec, mode: nextMode },
        };
      }),
    );
  }

  async function runDryRun() {
    try {
      const result = await dryRunPolicy({
        prompt: dryRunPrompt,
        policy_name: dryRunPolicyName || undefined,
      });
      setDryRunResult({
        decision: result.blocked ? "block" : result.decision,
        rules: result.evaluations.map((e) => ({
          name: e.rule_name,
          decision: e.decision,
          reason: e.reason ?? "",
        })),
      });
    } catch {
      // Fallback to simulated result on API failure
      setDryRunResult({
        decision: "block",
        rules: [
          {
            name: "PII Blocker",
            decision: "block",
            reason: "Email address detected in prompt",
          },
          {
            name: "Secrets Scanner",
            decision: "allow",
            reason: "No secrets found",
          },
          {
            name: "Injection Guard",
            decision: "allow",
            reason: "Injection score: 0.12 (below threshold)",
          },
        ],
      });
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Policies</h1>
          <p className="mt-1 text-sm text-gray-500">
            AI security policy management and enforcement
          </p>
        </div>
        <div className="flex gap-3">
          <button
            className="btn-secondary"
            onClick={() => setShowDryRun(true)}
          >
            <Play className="h-4 w-4" />
            Dry Run
          </button>
          <button className="btn-primary" onClick={() => openEditor()}>
            <Plus className="h-4 w-4" />
            Create Policy
          </button>
        </div>
      </div>

      {/* Policies list */}
      <div className="space-y-3">
        {policies.map((policy) => {
          const ModeIcon = modeIcons[policy.spec.mode];
          const scopeText = [
            ...(policy.spec.scope.namespaces ?? []),
            ...(policy.spec.scope.teams?.map((t) => `team:${t}`) ?? []),
          ].join(", ") || "Global";

          const ruleCount = [
            policy.spec.input ? 1 : 0,
            policy.spec.output ? 1 : 0,
            policy.spec.providers ? 1 : 0,
            policy.spec.models ? 1 : 0,
            policy.spec.rate_limits ? 1 : 0,
            policy.spec.agent ? 1 : 0,
            policy.spec.data_residency ? 1 : 0,
          ].reduce((a, b) => a + b, 0);

          return (
            <div
              key={policy.metadata.name}
              className="rounded-xl border border-surface-300 bg-surface-100 p-5 transition-colors hover:border-surface-400"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-4">
                  {/* Mode icon */}
                  <div
                    className={`mt-0.5 rounded-lg p-2.5 ${
                      policy.spec.mode === "enforce"
                        ? "bg-emerald-500/10 text-emerald-400"
                        : policy.spec.mode === "monitor"
                          ? "bg-yellow-500/10 text-yellow-400"
                          : policy.spec.mode === "discover"
                            ? "bg-blue-500/10 text-blue-400"
                            : "bg-gray-500/10 text-gray-500"
                    }`}
                  >
                    <ModeIcon className="h-5 w-5" />
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold text-white">
                        {policy.metadata.name}
                      </h3>
                      <StatusBadge status={policy.spec.mode} />
                    </div>
                    <p className="mt-1 text-xs text-gray-500">
                      {modeDescriptions[policy.spec.mode]}
                    </p>
                    <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-gray-400">
                      <span>
                        Scope:{" "}
                        <span className="font-mono text-gray-300">
                          {scopeText}
                        </span>
                      </span>
                      {policy.metadata.namespace && (
                        <span>
                          Namespace:{" "}
                          <span className="rounded bg-surface-300 px-1 py-0.5 font-mono">
                            {policy.metadata.namespace}
                          </span>
                        </span>
                      )}
                      <span>{ruleCount} rule sections</span>
                      {policy.spec.providers && (
                        <span>
                          Providers:{" "}
                          {policy.spec.providers.allow.join(", ")}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => toggleMode(policy.metadata.name)}
                    className="rounded-lg p-2 text-gray-500 hover:bg-surface-200 hover:text-gray-300 transition-colors"
                    title="Toggle enforcement mode"
                  >
                    <Shield className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => openEditor(policy)}
                    className="rounded-lg p-2 text-gray-500 hover:bg-surface-200 hover:text-gray-300 transition-colors"
                    title="Edit policy"
                  >
                    <Pencil className="h-4 w-4" />
                  </button>
                  <button
                    className="rounded-lg p-2 text-gray-500 hover:bg-red-500/10 hover:text-red-400 transition-colors"
                    title="Delete policy"
                    onClick={async () => {
                      try {
                        await deletePolicy(policy.metadata.name);
                        setPolicies((prev) =>
                          prev.filter((p) => p.metadata.name !== policy.metadata.name),
                        );
                      } catch {
                        // API failure - keep current state
                      }
                    }}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Inline rule summary */}
              {(policy.spec.input || policy.spec.output) && (
                <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
                  {policy.spec.input?.block_pii && (
                    <RuleChip label="Block PII" color="red" />
                  )}
                  {policy.spec.input?.anonymize_pii && (
                    <RuleChip label="Anonymize PII" color="yellow" />
                  )}
                  {policy.spec.input?.block_secrets && (
                    <RuleChip label="Block Secrets" color="red" />
                  )}
                  {policy.spec.output?.scan_generated_code && (
                    <RuleChip label="Code Scan" color="blue" />
                  )}
                  {policy.spec.output?.block_vulnerable_code && (
                    <RuleChip label="Block Vuln Code" color="red" />
                  )}
                  {policy.spec.output?.check_pii_leakage && (
                    <RuleChip label="PII Leakage Check" color="orange" />
                  )}
                  {policy.spec.rate_limits && (
                    <RuleChip label="Rate Limited" color="cyan" />
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* YAML/JSON Editor Modal */}
      {showEditor && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => setShowEditor(false)}
        >
          <div
            className="mx-4 flex max-h-[90vh] w-full max-w-3xl flex-col rounded-xl border border-surface-300 bg-surface-100 shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-surface-300 px-6 py-4">
              <h3 className="text-lg font-semibold text-white">
                {editingPolicy
                  ? `Edit: ${editingPolicy}`
                  : "Create New Policy"}
              </h3>
              <button
                onClick={() => setShowEditor(false)}
                className="rounded-lg p-1 text-gray-500 hover:bg-surface-200 hover:text-gray-300"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6">
              <textarea
                className="h-96 w-full rounded-lg border border-surface-300 bg-surface font-mono text-sm text-gray-300 p-4 focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/30 resize-none"
                value={editorContent}
                onChange={(e) => setEditorContent(e.target.value)}
                spellCheck={false}
              />
            </div>

            <div className="flex items-center justify-end gap-3 border-t border-surface-300 px-6 py-4">
              <button
                className="btn-secondary"
                onClick={() => setShowEditor(false)}
              >
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={async () => {
                  try {
                    const parsed = JSON.parse(editorContent) as AISecurityPolicy;
                    if (editingPolicy) {
                      const updated = await updatePolicy(editingPolicy, parsed).catch(() => null);
                      if (updated) {
                        setPolicies((prev) =>
                          prev.map((p) => (p.metadata.name === editingPolicy ? updated : p)),
                        );
                      }
                    } else {
                      const created = await createPolicy(parsed).catch(() => null);
                      if (created) {
                        setPolicies((prev) => [...prev, created]);
                      }
                    }
                  } catch {
                    // JSON parse error or API failure - keep current state
                  }
                  setShowEditor(false);
                }}
              >
                <Check className="h-4 w-4" />
                {editingPolicy ? "Update Policy" : "Create Policy"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Dry Run Modal */}
      {showDryRun && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => {
            setShowDryRun(false);
            setDryRunResult(null);
          }}
        >
          <div
            className="mx-4 max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-surface-300 bg-surface-100 shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-surface-300 px-6 py-4">
              <div>
                <h3 className="text-lg font-semibold text-white">
                  Policy Dry Run
                </h3>
                <p className="mt-0.5 text-xs text-gray-500">
                  Test a prompt against policies without forwarding to the LLM
                </p>
              </div>
              <button
                onClick={() => {
                  setShowDryRun(false);
                  setDryRunResult(null);
                }}
                className="rounded-lg p-1 text-gray-500 hover:bg-surface-200 hover:text-gray-300"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4 p-6">
              {/* Policy selector */}
              <div>
                <label className="mb-1.5 block text-xs font-medium text-gray-400">
                  Policy (optional, tests all if empty)
                </label>
                <div className="relative">
                  <select
                    className="select w-full appearance-none pr-8"
                    value={dryRunPolicyName}
                    onChange={(e) => setDryRunPolicyName(e.target.value)}
                  >
                    <option value="">All policies</option>
                    {policies.map((p) => (
                      <option key={p.metadata.name} value={p.metadata.name}>
                        {p.metadata.name}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
                </div>
              </div>

              {/* Prompt input */}
              <div>
                <label className="mb-1.5 block text-xs font-medium text-gray-400">
                  Test Prompt
                </label>
                <textarea
                  className="h-32 w-full rounded-lg border border-surface-300 bg-surface-200 p-3 text-sm text-gray-300 placeholder-gray-500 focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/30 resize-none"
                  placeholder="Enter a prompt to test against the selected policy..."
                  value={dryRunPrompt}
                  onChange={(e) => setDryRunPrompt(e.target.value)}
                />
              </div>

              <button
                className="btn-primary w-full justify-center"
                onClick={runDryRun}
                disabled={!dryRunPrompt.trim()}
              >
                <Play className="h-4 w-4" />
                Run Test
              </button>

              {/* Results */}
              {dryRunResult && (
                <div className="space-y-3 border-t border-surface-300 pt-4">
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-medium text-gray-300">
                      Final Decision:
                    </span>
                    <StatusBadge status={dryRunResult.decision} />
                  </div>

                  <div className="space-y-2">
                    {dryRunResult.rules.map((rule, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between rounded-lg border border-surface-300 bg-surface-200 p-3"
                      >
                        <div>
                          <span className="text-sm font-medium text-gray-200">
                            {rule.name}
                          </span>
                          <p className="mt-0.5 text-xs text-gray-500">
                            {rule.reason}
                          </p>
                        </div>
                        <StatusBadge status={rule.decision} />
                      </div>
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

function RuleChip({
  label,
  color,
}: {
  label: string;
  color: "red" | "yellow" | "blue" | "orange" | "cyan" | "green";
}) {
  const styles: Record<string, string> = {
    red: "bg-red-500/10 text-red-400 ring-red-500/20",
    yellow: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
    blue: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
    orange: "bg-orange-500/10 text-orange-400 ring-orange-500/20",
    cyan: "bg-cyan-500/10 text-cyan-400 ring-cyan-500/20",
    green: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20",
  };

  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-1 text-[11px] font-medium ring-1 ring-inset ${styles[color]}`}
    >
      {label}
    </span>
  );
}
