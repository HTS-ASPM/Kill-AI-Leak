"use client";

import { clsx } from "clsx";

type Status =
  | "active"
  | "inactive"
  | "enrolled"
  | "shadow"
  | "blocked"
  | "allowed"
  | "discover"
  | "monitor"
  | "enforce"
  | "off";

const statusStyles: Record<Status, string> = {
  active: "bg-emerald-50 text-emerald-600 ring-emerald-200",
  inactive: "bg-gray-50 text-gray-500 ring-gray-200",
  enrolled: "bg-cyan-50 text-cyan-600 ring-cyan-200",
  shadow: "bg-red-50 text-red-600 ring-red-200",
  blocked: "bg-red-50 text-red-600 ring-red-200",
  allowed: "bg-emerald-50 text-emerald-600 ring-emerald-200",
  discover: "bg-blue-50 text-blue-600 ring-blue-200",
  monitor: "bg-amber-50 text-amber-600 ring-amber-200",
  enforce: "bg-emerald-50 text-emerald-600 ring-emerald-200",
  off: "bg-gray-50 text-gray-500 ring-gray-200",
};

interface StatusBadgeProps {
  status: string;
  className?: string;
}

export default function StatusBadge({ status, className }: StatusBadgeProps) {
  const key = status.toLowerCase() as Status;
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset capitalize",
        statusStyles[key] ?? statusStyles.inactive,
        className,
      )}
    >
      {status === "shadow" && (
        <span className="mr-1 h-1.5 w-1.5 rounded-full bg-red-500" />
      )}
      {status}
    </span>
  );
}
