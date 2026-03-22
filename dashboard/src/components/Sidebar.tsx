"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { clsx } from "clsx";
import {
  LayoutDashboard,
  Package,
  Activity,
  FileText,
  Shield,
  GitBranch,
  Bug,
  Settings,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useState } from "react";

const navigation = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Inventory (AIBOM)", href: "/inventory", icon: Package },
  { name: "Events", href: "/events", icon: Activity },
  { name: "Policies", href: "/policies", icon: FileText },
  { name: "Guardrails", href: "/guardrails", icon: Shield },
  { name: "Data Lineage", href: "/lineage", icon: GitBranch },
  { name: "Fuzzer", href: "/fuzzer", icon: Bug },
  { name: "Settings", href: "/settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={clsx(
        "flex h-screen flex-col border-r border-blue-100 bg-white transition-all duration-200",
        collapsed ? "w-16" : "w-60",
      )}
    >
      {/* Logo / Brand */}
      <div className="flex h-16 items-center gap-3 border-b border-blue-100 px-4">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500">
          <Shield className="h-4 w-4 text-white" />
        </div>
        {!collapsed && (
          <div className="flex flex-col overflow-hidden">
            <span className="truncate text-sm font-bold text-[#0f2137] tracking-wide">
              Kill AI Leak
            </span>
            <span className="truncate text-[10px] text-[#5a7184] uppercase tracking-widest">
              Security Platform
            </span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-4">
        {navigation.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.name}
              href={item.href}
              className={clsx(
                "group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-blue-50 text-blue-700 border-l-[3px] border-blue-500"
                  : "text-[#5a7184] hover:bg-blue-50/60 hover:text-[#1a2b3c]",
              )}
              title={collapsed ? item.name : undefined}
            >
              <item.icon
                className={clsx(
                  "h-[18px] w-[18px] shrink-0",
                  isActive
                    ? "text-blue-600"
                    : "text-[#94a3b8] group-hover:text-blue-500",
                )}
              />
              {!collapsed && <span className="truncate">{item.name}</span>}
              {isActive && !collapsed && (
                <span className="ml-auto h-1.5 w-1.5 rounded-full bg-blue-500" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <div className="border-t border-blue-100 p-2">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex w-full items-center justify-center rounded-lg p-2 text-[#94a3b8] hover:bg-blue-50 hover:text-blue-600 transition-colors"
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronLeft className="h-4 w-4" />
          )}
        </button>
      </div>
    </aside>
  );
}
