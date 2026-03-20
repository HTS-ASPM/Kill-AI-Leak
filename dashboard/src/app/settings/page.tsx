"use client";

import { useState } from "react";
import {
  Settings,
  Key,
  Globe,
  Bell,
  Users,
  Database,
  Save,
  Plus,
  Trash2,
  Eye,
  EyeOff,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState("general");
  const [apiUrl, setApiUrl] = useState("https://api.killaileak.io/v1");
  const [orgName, setOrgName] = useState("Acme Corp");
  const [env, setEnv] = useState("production");
  const [showToken, setShowToken] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("https://hooks.slack.com/services/T00/B00/xxx");
  const [emailAlerts, setEmailAlerts] = useState("security@acme.com");

  const tabs = [
    { id: "general", label: "General", icon: Settings },
    { id: "api", label: "API & Auth", icon: Key },
    { id: "notifications", label: "Notifications", icon: Bell },
    { id: "team", label: "Team", icon: Users },
    { id: "integrations", label: "Integrations", icon: Globe },
    { id: "data", label: "Data Retention", icon: Database },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Settings</h1>
        <p className="mt-1 text-sm text-gray-500">
          Platform configuration and integrations
        </p>
      </div>

      <div className="flex gap-6">
        {/* Tab navigation */}
        <nav className="w-48 shrink-0 space-y-0.5">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors ${
                activeTab === tab.id
                  ? "bg-accent/10 text-accent font-medium"
                  : "text-gray-400 hover:bg-surface-200 hover:text-gray-200"
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="flex-1">
          {activeTab === "general" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-white">General Settings</h2>
              <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-gray-400">
                    Organization Name
                  </label>
                  <input
                    type="text"
                    className="input"
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-gray-400">
                    Environment
                  </label>
                  <select
                    className="select w-full"
                    value={env}
                    onChange={(e) => setEnv(e.target.value)}
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                  </select>
                </div>
              </div>
              <div className="flex justify-end border-t border-surface-300 pt-4">
                <button className="btn-primary">
                  <Save className="h-4 w-4" />
                  Save Changes
                </button>
              </div>
            </div>
          )}

          {activeTab === "api" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-white">API & Authentication</h2>
              <div className="space-y-5">
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-gray-400">
                    API Base URL
                  </label>
                  <input
                    type="url"
                    className="input font-mono"
                    value={apiUrl}
                    onChange={(e) => setApiUrl(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-gray-400">
                    API Token
                  </label>
                  <div className="relative">
                    <input
                      type={showToken ? "text" : "password"}
                      className="input pr-10 font-mono"
                      value="kal_prod_a1b2c3d4e5f6g7h8i9j0..."
                      readOnly
                    />
                    <button
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                      onClick={() => setShowToken(!showToken)}
                    >
                      {showToken ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                  <p className="mt-1 text-xs text-gray-500">
                    Used for authenticating dashboard requests to the API server.
                  </p>
                </div>
                <button className="btn-secondary">
                  <Key className="h-4 w-4" />
                  Rotate Token
                </button>
              </div>
            </div>
          )}

          {activeTab === "notifications" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-white">Notification Settings</h2>
              <div className="space-y-5">
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-gray-400">
                    Slack Webhook URL
                  </label>
                  <input
                    type="url"
                    className="input font-mono text-xs"
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-gray-400">
                    Email Alerts
                  </label>
                  <input
                    type="email"
                    className="input"
                    value={emailAlerts}
                    onChange={(e) => setEmailAlerts(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-3 block text-xs font-medium text-gray-400">
                    Alert Thresholds
                  </label>
                  <div className="space-y-3">
                    {["Critical events", "Shadow AI detected", "Policy violations", "Rate limit exceeded"].map(
                      (label) => (
                        <label
                          key={label}
                          className="flex items-center gap-3 text-sm text-gray-300"
                        >
                          <input
                            type="checkbox"
                            defaultChecked
                            className="h-4 w-4 rounded border-surface-300 bg-surface-200 text-accent focus:ring-accent/30"
                          />
                          {label}
                        </label>
                      ),
                    )}
                  </div>
                </div>
              </div>
              <div className="flex justify-end border-t border-surface-300 pt-4">
                <button className="btn-primary">
                  <Save className="h-4 w-4" />
                  Save Changes
                </button>
              </div>
            </div>
          )}

          {activeTab === "team" && (
            <div className="card space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-white">Team Members</h2>
                <button className="btn-secondary text-xs">
                  <Plus className="h-3.5 w-3.5" />
                  Invite
                </button>
              </div>
              <div className="space-y-2">
                {[
                  { name: "Admin User", email: "admin@acme.com", role: "Owner" },
                  { name: "Security Analyst", email: "analyst@acme.com", role: "Admin" },
                  { name: "Dev Lead", email: "devlead@acme.com", role: "Viewer" },
                  { name: "SOC Team", email: "soc@acme.com", role: "Admin" },
                ].map((member) => (
                  <div
                    key={member.email}
                    className="flex items-center justify-between rounded-lg border border-surface-300 bg-surface-200 px-4 py-3"
                  >
                    <div className="flex items-center gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-accent/20 text-accent text-xs font-bold">
                        {member.name
                          .split(" ")
                          .map((n) => n[0])
                          .join("")}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-200">
                          {member.name}
                        </p>
                        <p className="text-xs text-gray-500">{member.email}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="rounded bg-surface-300 px-2 py-0.5 text-xs text-gray-400">
                        {member.role}
                      </span>
                      <button className="text-gray-600 hover:text-red-400 transition-colors">
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === "integrations" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-white">Integrations</h2>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {[
                  { name: "Kubernetes", status: "connected", desc: "eBPF sensor deployed in 3 clusters" },
                  { name: "Slack", status: "connected", desc: "Alerts to #ai-security channel" },
                  { name: "PagerDuty", status: "not_configured", desc: "Incident management" },
                  { name: "Splunk", status: "connected", desc: "Event forwarding enabled" },
                  { name: "Jira", status: "not_configured", desc: "Ticket creation for violations" },
                  { name: "GitHub", status: "connected", desc: "PR checks and code scanning" },
                ].map((int) => (
                  <div
                    key={int.name}
                    className="flex items-center justify-between rounded-lg border border-surface-300 bg-surface-200 p-4"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-gray-200">
                          {int.name}
                        </span>
                        <span
                          className={`h-2 w-2 rounded-full ${
                            int.status === "connected"
                              ? "bg-emerald-400"
                              : "bg-gray-600"
                          }`}
                        />
                      </div>
                      <p className="mt-0.5 text-xs text-gray-500">
                        {int.desc}
                      </p>
                    </div>
                    <button className="btn-secondary text-xs px-3 py-1.5">
                      {int.status === "connected" ? "Configure" : "Connect"}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === "data" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-white">Data Retention</h2>
              <div className="space-y-5">
                <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
                  <div>
                    <label className="mb-1.5 block text-xs font-medium text-gray-400">
                      Event Retention
                    </label>
                    <select className="select w-full">
                      <option>30 days</option>
                      <option>60 days</option>
                      <option selected>90 days</option>
                      <option>180 days</option>
                      <option>365 days</option>
                    </select>
                  </div>
                  <div>
                    <label className="mb-1.5 block text-xs font-medium text-gray-400">
                      Prompt/Response Storage
                    </label>
                    <select className="select w-full">
                      <option>Disabled (hash only)</option>
                      <option selected>7 days then hash</option>
                      <option>30 days then hash</option>
                      <option>Full retention</option>
                    </select>
                  </div>
                </div>
                <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3">
                  <p className="text-xs text-yellow-400">
                    Prompt and response text is stored encrypted at rest and automatically
                    purged after the retention period. Only cryptographic hashes are retained
                    for audit purposes.
                  </p>
                </div>
              </div>
              <div className="flex justify-end border-t border-surface-300 pt-4">
                <button className="btn-primary">
                  <Save className="h-4 w-4" />
                  Save Changes
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
