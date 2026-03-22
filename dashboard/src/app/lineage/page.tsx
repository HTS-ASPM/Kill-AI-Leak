"use client";

import { useState, useCallback } from "react";
import { X, AlertTriangle, Database, Server, Cloud, User } from "lucide-react";
import type { LineageNode, LineageEdge } from "@/lib/types";

// ---------------------------------------------------------------------------
// Demo lineage graph data
// ---------------------------------------------------------------------------

const nodes: LineageNode[] = [
  // Databases (left column)
  { id: "db-pg-1", label: "analytics-db", type: "database", risk: "safe", x: 80, y: 80, details: { type: "PostgreSQL", host: "prod-db.internal", database: "analytics" } },
  { id: "db-pg-2", label: "customers-db", type: "database", risk: "warning", x: 80, y: 200, details: { type: "PostgreSQL", host: "prod-db.internal", database: "customers" } },
  { id: "db-redis", label: "cache-redis", type: "database", risk: "safe", x: 80, y: 320, details: { type: "Redis", host: "redis.internal" } },
  { id: "db-mongo", label: "logs-mongo", type: "database", risk: "safe", x: 80, y: 440, details: { type: "MongoDB", host: "mongo.internal", database: "logs" } },

  // Services (center column)
  { id: "svc-1", label: "chatbot-api", type: "service", risk: "safe", x: 380, y: 80, details: { namespace: "production", team: "platform" } },
  { id: "svc-2", label: "data-pipeline-llm", type: "service", risk: "critical", x: 380, y: 200, details: { namespace: "data-eng", team: "data", pii_exposure: "SSN, Credit Card, Email" } },
  { id: "svc-3", label: "support-summarizer", type: "service", risk: "safe", x: 380, y: 320, details: { namespace: "customer-ops", team: "support" } },
  { id: "svc-4", label: "code-review-agent", type: "service", risk: "warning", x: 380, y: 440, details: { namespace: "engineering", team: "devtools" } },
  { id: "svc-5", label: "rogue-scraper", type: "service", risk: "critical", x: 380, y: 540, details: { namespace: "default", shadow: "true" } },

  // LLM Providers (right column)
  { id: "llm-openai", label: "OpenAI", type: "llm_provider", risk: "safe", x: 680, y: 140, details: { models: "gpt-4o, gpt-4o-mini", region: "us-east-1" } },
  { id: "llm-anthropic", label: "Anthropic", type: "llm_provider", risk: "safe", x: 680, y: 340, details: { models: "claude-sonnet-4-20250514", region: "us-east-1" } },
  { id: "llm-mistral", label: "Mistral", type: "llm_provider", risk: "warning", x: 680, y: 500, details: { models: "mistral-large", region: "eu-west-1" } },

  // User
  { id: "user-browser", label: "Browser Users", type: "user", risk: "warning", x: 380, y: 640, details: { count: "~120 users", teams: "marketing, sales" } },
];

const edges: LineageEdge[] = [
  // Database -> Service
  { id: "e1", source: "db-pg-1", target: "svc-1", label: "queries", has_pii: false, data_volume: "2.4 GB/d" },
  { id: "e2", source: "db-pg-2", target: "svc-2", label: "customer data", has_pii: true, data_volume: "8.1 GB/d" },
  { id: "e3", source: "db-pg-2", target: "svc-3", label: "ticket data", has_pii: true, data_volume: "1.2 GB/d" },
  { id: "e4", source: "db-redis", target: "svc-1", label: "cache", has_pii: false, data_volume: "4.8 GB/d" },
  { id: "e5", source: "db-mongo", target: "svc-4", label: "code logs", has_pii: false, data_volume: "0.6 GB/d" },

  // Service -> LLM Provider
  { id: "e6", source: "svc-1", target: "llm-openai", label: "42.8K calls/w", has_pii: false, data_volume: "128 MB/d" },
  { id: "e7", source: "svc-2", target: "llm-openai", label: "15.6K calls/w", has_pii: true, data_volume: "210 MB/d" },
  { id: "e8", source: "svc-3", target: "llm-openai", label: "19.7K calls/w", has_pii: false, data_volume: "38 MB/d" },
  { id: "e9", source: "svc-4", target: "llm-openai", label: "28.3K calls/w", has_pii: false, data_volume: "94 MB/d" },
  { id: "e10", source: "svc-4", target: "llm-anthropic", label: "4.2K calls/w", has_pii: false, data_volume: "22 MB/d" },
  { id: "e11", source: "svc-5", target: "llm-openai", label: "1.1K calls/w", has_pii: true, data_volume: "8 MB/d" },
  { id: "e12", source: "svc-5", target: "llm-mistral", label: "620 calls/w", has_pii: false, data_volume: "3 MB/d" },

  // User -> LLM Provider (via browser)
  { id: "e13", source: "user-browser", target: "llm-openai", label: "browser ext", has_pii: true, data_volume: "14 MB/d" },
];

// ---------------------------------------------------------------------------
// Color and shape helpers
// ---------------------------------------------------------------------------

const riskColors = {
  safe: { fill: "#ecfdf5", stroke: "#10b981", text: "#065f46" },
  warning: { fill: "#fffbeb", stroke: "#f59e0b", text: "#92400e" },
  critical: { fill: "#fef2f2", stroke: "#ef4444", text: "#991b1b" },
};

const nodeTypeIcons: Record<string, typeof Database> = {
  database: Database,
  service: Server,
  llm_provider: Cloud,
  user: User,
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function LineagePage() {
  const [selectedNode, setSelectedNode] = useState<LineageNode | null>(null);
  const [highlightPII, setHighlightPII] = useState(true);

  const piiEdges = edges.filter((e) => e.has_pii);
  const piiNodeIds = new Set(
    piiEdges.flatMap((e) => [e.source, e.target]),
  );

  const getNodeById = useCallback(
    (id: string) => nodes.find((n) => n.id === id),
    [],
  );

  // SVG viewBox dimensions
  const svgWidth = 840;
  const svgHeight = 720;
  const nodeW = 150;
  const nodeH = 48;

  function getEdgePath(edge: LineageEdge): string {
    const src = getNodeById(edge.source);
    const tgt = getNodeById(edge.target);
    if (!src || !tgt) return "";

    const x1 = src.x + nodeW / 2;
    const y1 = src.y + nodeH / 2;
    const x2 = tgt.x + nodeW / 2;
    const y2 = tgt.y + nodeH / 2;

    // Bezier curve
    const midX = (x1 + x2) / 2;
    return `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-[#0f2137]">Data Lineage</h1>
          <p className="mt-1 text-sm text-[#5a7184]">
            Visual data flow: Database &rarr; Service &rarr; LLM Provider
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-[#5a7184] cursor-pointer">
          <input
            type="checkbox"
            checked={highlightPII}
            onChange={(e) => setHighlightPII(e.target.checked)}
            className="h-4 w-4 rounded border-blue-100 bg-blue-50/50 text-blue-600 focus:ring-blue-200"
          />
          <AlertTriangle className="h-3.5 w-3.5 text-amber-600" />
          Highlight PII paths
        </label>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-6 rounded-lg border border-blue-100 bg-white px-5 py-3 text-xs text-[#5a7184]">
        <span className="font-medium text-[#1a2b3c]">Legend:</span>
        <span className="flex items-center gap-1.5">
          <span className="h-3 w-3 rounded-full border-2" style={{ borderColor: "#10b981", backgroundColor: "#ecfdf5" }} />
          Safe
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-3 w-3 rounded-full border-2" style={{ borderColor: "#f59e0b", backgroundColor: "#fffbeb" }} />
          Warning
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-3 w-3 rounded-full border-2" style={{ borderColor: "#ef4444", backgroundColor: "#fef2f2" }} />
          Critical
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-0.5 w-4 bg-gray-500" />
          Data flow
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-0.5 w-4 bg-red-500" style={{ strokeDasharray: "4 2" }} />
          PII exposure path
        </span>
      </div>

      {/* Graph */}
      <div className="overflow-auto rounded-xl border border-blue-100 bg-white">
        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          className="min-h-[500px] w-full"
          style={{ minWidth: 700 }}
        >
          <defs>
            {/* Arrow marker */}
            <marker
              id="arrow"
              viewBox="0 0 10 10"
              refX="10"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#5a7184" />
            </marker>
            <marker
              id="arrow-pii"
              viewBox="0 0 10 10"
              refX="10"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
            </marker>

            {/* Glow filter */}
            <filter id="glow">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Column labels */}
          <text x={80 + nodeW / 2} y={40} textAnchor="middle" className="fill-gray-600 text-[11px] font-medium uppercase tracking-wider">
            Databases
          </text>
          <text x={380 + nodeW / 2} y={40} textAnchor="middle" className="fill-gray-600 text-[11px] font-medium uppercase tracking-wider">
            Services
          </text>
          <text x={680 + nodeW / 2} y={40} textAnchor="middle" className="fill-gray-600 text-[11px] font-medium uppercase tracking-wider">
            LLM Providers
          </text>

          {/* Edges */}
          {edges.map((edge) => {
            const isPII = edge.has_pii;
            const shouldHighlight = highlightPII && isPII;

            return (
              <g key={edge.id}>
                <path
                  d={getEdgePath(edge)}
                  fill="none"
                  stroke={shouldHighlight ? "#ef4444" : "#c7d4e2"}
                  strokeWidth={shouldHighlight ? 2 : 1.5}
                  strokeDasharray={isPII ? "6 3" : undefined}
                  markerEnd={
                    shouldHighlight ? "url(#arrow-pii)" : "url(#arrow)"
                  }
                  opacity={shouldHighlight ? 1 : 0.6}
                  filter={shouldHighlight ? "url(#glow)" : undefined}
                />
                {/* Edge label */}
                {edge.label && (
                  <EdgeLabel edge={edge} getNodeById={getNodeById} nodeW={nodeW} nodeH={nodeH} isPII={isPII && highlightPII} />
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const colors = riskColors[node.risk];
            const isPIINode = highlightPII && piiNodeIds.has(node.id);
            const Icon = nodeTypeIcons[node.type];

            return (
              <g
                key={node.id}
                className="cursor-pointer"
                onClick={() => setSelectedNode(node)}
              >
                <rect
                  x={node.x}
                  y={node.y}
                  width={nodeW}
                  height={nodeH}
                  rx={8}
                  fill={colors.fill}
                  stroke={isPIINode ? "#ef4444" : colors.stroke}
                  strokeWidth={isPIINode ? 2 : 1.5}
                  filter={isPIINode ? "url(#glow)" : undefined}
                  opacity={0.9}
                />
                <text
                  x={node.x + 12}
                  y={node.y + 20}
                  fill={colors.text}
                  className="text-[11px] font-medium"
                >
                  {node.label}
                </text>
                <text
                  x={node.x + 12}
                  y={node.y + 36}
                  fill="#5a7184"
                  className="text-[9px]"
                >
                  {node.type.replace("_", " ")}
                </text>

                {/* Risk indicator dot */}
                <circle
                  cx={node.x + nodeW - 12}
                  cy={node.y + 12}
                  r={4}
                  fill={colors.stroke}
                  opacity={0.8}
                />
              </g>
            );
          })}
        </svg>
      </div>

      {/* Node detail panel */}
      {selectedNode && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
          onClick={() => setSelectedNode(null)}
        >
          <div
            className="mx-4 w-full max-w-md rounded-xl border border-blue-100 bg-white p-6 shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div
                  className="rounded-lg p-2"
                  style={{
                    backgroundColor: riskColors[selectedNode.risk].fill,
                    borderColor: riskColors[selectedNode.risk].stroke,
                    borderWidth: 1,
                  }}
                >
                  {(() => {
                    const Icon = nodeTypeIcons[selectedNode.type];
                    return (
                      <Icon
                        className="h-5 w-5"
                        style={{ color: riskColors[selectedNode.risk].text }}
                      />
                    );
                  })()}
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-[#0f2137]">
                    {selectedNode.label}
                  </h3>
                  <p className="text-xs text-[#5a7184] capitalize">
                    {selectedNode.type.replace("_", " ")} &middot;{" "}
                    <span
                      style={{
                        color: riskColors[selectedNode.risk].text,
                      }}
                    >
                      {selectedNode.risk}
                    </span>
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="rounded-lg p-1 text-[#5a7184] hover:bg-blue-50/50 hover:text-[#1a2b3c]"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {selectedNode.details && (
              <div className="mt-5 space-y-3">
                {Object.entries(selectedNode.details).map(([key, val]) => (
                  <div key={key}>
                    <span className="text-[11px] font-medium uppercase text-[#5a7184]">
                      {key.replace("_", " ")}
                    </span>
                    <p
                      className={`mt-0.5 text-sm ${
                        key === "pii_exposure" || key === "shadow"
                          ? "text-red-600 font-medium"
                          : "text-[#1a2b3c]"
                      }`}
                    >
                      {val}
                    </p>
                  </div>
                ))}
              </div>
            )}

            {/* Connections */}
            <div className="mt-5">
              <span className="text-[11px] font-medium uppercase text-[#5a7184]">
                Connections
              </span>
              <div className="mt-2 space-y-1.5">
                {edges
                  .filter(
                    (e) =>
                      e.source === selectedNode.id ||
                      e.target === selectedNode.id,
                  )
                  .map((e) => {
                    const other =
                      e.source === selectedNode.id
                        ? getNodeById(e.target)
                        : getNodeById(e.source);
                    const direction =
                      e.source === selectedNode.id ? "to" : "from";
                    return (
                      <div
                        key={e.id}
                        className="flex items-center justify-between rounded-lg bg-blue-50/50 px-3 py-2"
                      >
                        <span className="text-xs text-[#5a7184]">
                          {direction}{" "}
                          <span className="text-[#1a2b3c] font-medium">
                            {other?.label}
                          </span>
                        </span>
                        <div className="flex items-center gap-2">
                          {e.has_pii && (
                            <span className="rounded bg-red-50 px-1.5 py-0.5 text-[10px] text-red-600 ring-1 ring-inset ring-red-200">
                              PII
                            </span>
                          )}
                          {e.data_volume && (
                            <span className="font-mono text-[10px] text-[#5a7184]">
                              {e.data_volume}
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Edge label sub-component
// ---------------------------------------------------------------------------

function EdgeLabel({
  edge,
  getNodeById,
  nodeW,
  nodeH,
  isPII,
}: {
  edge: LineageEdge;
  getNodeById: (id: string) => LineageNode | undefined;
  nodeW: number;
  nodeH: number;
  isPII: boolean;
}) {
  const src = getNodeById(edge.source);
  const tgt = getNodeById(edge.target);
  if (!src || !tgt) return null;

  const midX = (src.x + nodeW / 2 + tgt.x + nodeW / 2) / 2;
  const midY = (src.y + nodeH / 2 + tgt.y + nodeH / 2) / 2;

  return (
    <text
      x={midX}
      y={midY - 6}
      textAnchor="middle"
      fill={isPII ? "#fca5a5" : "#5a7184"}
      className="text-[9px]"
    >
      {edge.label}
    </text>
  );
}
