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
        "flex h-screen flex-col bg-[#1e3a5f] transition-all duration-200",
        collapsed ? "w-16" : "w-60",
      )}
    >
      {/* Logo / Brand */}
      <div className="flex h-16 items-center gap-3 border-b border-white/10 px-4">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-white/10">
          <Shield className="h-4.5 w-4.5 text-white" />
        </div>
        {!collapsed && (
          <div className="flex flex-col overflow-hidden">
            <span className="truncate text-sm font-bold text-white tracking-wide">
              Kill AI Leak
            </span>
            <span className="truncate text-[10px] text-blue-200/60 uppercase tracking-widest">
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
                  ? "border-l-3 border-blue-400 bg-[#2b4f7e] text-white"
                  : "text-blue-100/70 hover:bg-white/10 hover:text-white",
              )}
              title={collapsed ? item.name : undefined}
            >
              <item.icon
                className={clsx(
                  "h-[18px] w-[18px] shrink-0",
                  isActive
                    ? "text-blue-300"
                    : "text-blue-200/50 group-hover:text-white",
                )}
              />
              {!collapsed && <span className="truncate">{item.name}</span>}
              {isActive && !collapsed && (
                <span className="ml-auto h-1.5 w-1.5 rounded-full bg-blue-400" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <div className="border-t border-white/10 p-2">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex w-full items-center justify-center rounded-lg p-2 text-blue-200/50 hover:bg-white/10 hover:text-white transition-colors"
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
