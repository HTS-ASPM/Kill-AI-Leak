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
  active: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30",
  inactive: "bg-gray-500/15 text-gray-400 ring-gray-500/30",
  enrolled: "bg-cyan-500/15 text-cyan-400 ring-cyan-500/30",
  shadow: "bg-red-500/15 text-red-400 ring-red-500/30",
  blocked: "bg-red-500/15 text-red-400 ring-red-500/30",
  allowed: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30",
  discover: "bg-blue-500/15 text-blue-400 ring-blue-500/30",
  monitor: "bg-yellow-500/15 text-yellow-400 ring-yellow-500/30",
  enforce: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30",
  off: "bg-gray-500/15 text-gray-400 ring-gray-500/30",
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
        <span className="mr-1 h-1.5 w-1.5 rounded-full bg-red-400" />
      )}
      {status}
    </span>
  );
}
