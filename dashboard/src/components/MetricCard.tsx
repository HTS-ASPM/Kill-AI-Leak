"use client";

import { clsx } from "clsx";
import type { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: {
    value: number;
    positive: boolean;
  };
  accentColor?: "green" | "cyan" | "red" | "yellow" | "blue";
  className?: string;
}

const accentMap = {
  green: {
    icon: "text-emerald-600 bg-emerald-50",
    border: "border-emerald-100",
  },
  cyan: {
    icon: "text-cyan-600 bg-cyan-50",
    border: "border-cyan-100",
  },
  red: {
    icon: "text-red-600 bg-red-50",
    border: "border-red-100",
  },
  yellow: {
    icon: "text-amber-600 bg-amber-50",
    border: "border-amber-100",
  },
  blue: {
    icon: "text-blue-600 bg-blue-50",
    border: "border-blue-100",
  },
};

export default function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  accentColor = "green",
  className,
}: MetricCardProps) {
  const accent = accentMap[accentColor];

  return (
    <div
      className={clsx(
        "relative overflow-hidden rounded-xl border bg-white p-5 shadow-sm hover:shadow-md transition-shadow",
        accent.border,
        className,
      )}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-sm font-medium text-[#5a7184]">{title}</p>
          <p className="text-2xl font-bold tracking-tight text-[#0f2137]">
            {value}
          </p>
          {subtitle && (
            <p className="text-xs text-[#5a7184]">{subtitle}</p>
          )}
          {trend && (
            <div className="flex items-center gap-1 text-xs">
              <span
                className={clsx(
                  "font-medium",
                  trend.positive ? "text-emerald-600" : "text-red-600",
                )}
              >
                {trend.positive ? "+" : ""}
                {trend.value}%
              </span>
              <span className="text-[#5a7184]">vs last period</span>
            </div>
          )}
        </div>
        <div className={clsx("rounded-lg p-2.5", accent.icon)}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}
