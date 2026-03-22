"use client";

import { clsx } from "clsx";
import type { Severity } from "@/lib/types";

const severityStyles: Record<Severity, string> = {
  info: "bg-blue-50 text-blue-600 ring-blue-200",
  low: "bg-emerald-50 text-emerald-600 ring-emerald-200",
  medium: "bg-amber-50 text-amber-600 ring-amber-200",
  high: "bg-orange-50 text-orange-600 ring-orange-200",
  critical: "bg-red-50 text-red-600 ring-red-200",
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
        <span className="mr-1 h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse-slow" />
      )}
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}
