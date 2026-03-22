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
        <header className="flex h-16 shrink-0 items-center justify-between border-b border-blue-100 bg-white px-6 shadow-sm">
          {/* Left: org & breadcrumb area */}
          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2">
              <span className="text-sm font-semibold text-[#0f2137]">
                Acme Corp
              </span>
              <span className="text-blue-300">/</span>
              <span className="text-sm text-[#5a7184]">Production</span>
            </div>
          </div>

          {/* Right: search, notifications, user */}
          <div className="flex items-center gap-3">
            {/* Search */}
            <div className="relative hidden lg:block">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#5a7184]" />
              <input
                type="text"
                placeholder="Search events, services..."
                className="w-64 rounded-lg border border-blue-200 bg-[#f0f4f8] py-1.5 pl-9 pr-3 text-sm text-[#1a2b3c] placeholder-[#5a7184] focus:border-blue-400 focus:outline-none focus:ring-1 focus:ring-blue-200"
              />
              <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-blue-200 bg-blue-50 px-1.5 py-0.5 font-mono text-[10px] text-[#5a7184]">
                /
              </kbd>
            </div>

            {/* Notifications */}
            <button className="relative rounded-lg p-2 text-[#5a7184] hover:bg-blue-50 hover:text-blue-600 transition-colors">
              <Bell className="h-[18px] w-[18px]" />
              <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-red-500" />
            </button>

            {/* Divider */}
            <div className="h-6 w-px bg-blue-200" />

            {/* User avatar */}
            <button className="flex items-center gap-2 rounded-lg p-1.5 hover:bg-blue-50 transition-colors">
              <div className="flex h-7 w-7 items-center justify-center rounded-full bg-blue-100 text-blue-600">
                <User className="h-3.5 w-3.5" />
              </div>
              <span className="hidden text-sm font-medium text-[#1a2b3c] md:block">
                Admin
              </span>
            </button>
          </div>
        </header>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto bg-[#f0f4f8] p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
