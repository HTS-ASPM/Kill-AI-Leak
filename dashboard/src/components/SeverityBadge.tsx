"use client";

import { clsx } from "clsx";
import type { Severity } from "@/lib/types";

const severityStyles: Record<Severity, string> = {
  info: "bg-blue-500/15 text-blue-400 ring-blue-500/30",
  low: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 ring-yellow-500/30",
  high: "bg-orange-500/15 text-orange-400 ring-orange-500/30",
  critical: "bg-red-500/15 text-red-400 ring-red-500/30",
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export default function SeverityBadge({
  severity,
  className,
}: SeverityBadgeProps) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset",
        severityStyles[severity] ?? severityStyles.info,
        className,
      )}
    >
      {severity === "critical" && (
        <span className="mr-1 h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse-slow" />
      )}
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}
