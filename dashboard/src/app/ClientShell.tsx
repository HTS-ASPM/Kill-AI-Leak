"use client";

import Sidebar from "@/components/Sidebar";
import { Bell, Search, User } from "lucide-react";

export default function ClientShell({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />

      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Top bar */}
        <header className="flex h-16 shrink-0 items-center justify-between border-b border-surface-300 bg-surface-50 px-6">
          {/* Left: org & breadcrumb area */}
          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2">
              <span className="text-sm font-semibold text-gray-200">
                Acme Corp
              </span>
              <span className="text-gray-600">/</span>
              <span className="text-sm text-gray-400">Production</span>
            </div>
          </div>

          {/* Right: search, notifications, user */}
          <div className="flex items-center gap-3">
            {/* Search */}
            <div className="relative hidden lg:block">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <input
                type="text"
                placeholder="Search events, services..."
                className="w-64 rounded-lg border border-surface-300 bg-surface-200 py-1.5 pl-9 pr-3 text-sm text-gray-300 placeholder-gray-500 focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/30"
              />
              <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-surface-400 bg-surface-300 px-1.5 py-0.5 font-mono text-[10px] text-gray-500">
                /
              </kbd>
            </div>

            {/* Notifications */}
            <button className="relative rounded-lg p-2 text-gray-400 hover:bg-surface-200 hover:text-gray-200 transition-colors">
              <Bell className="h-[18px] w-[18px]" />
              <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-red-500" />
            </button>

            {/* Divider */}
            <div className="h-6 w-px bg-surface-300" />

            {/* User avatar */}
            <button className="flex items-center gap-2 rounded-lg p-1.5 hover:bg-surface-200 transition-colors">
              <div className="flex h-7 w-7 items-center justify-center rounded-full bg-accent/20 text-accent">
                <User className="h-3.5 w-3.5" />
              </div>
              <span className="hidden text-sm font-medium text-gray-300 md:block">
                Admin
              </span>
            </button>
          </div>
        </header>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto bg-surface p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
