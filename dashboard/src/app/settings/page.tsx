"use client";

import { useState, useCallback, useEffect } from "react";
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
  Check,
  Copy,
  RefreshCw,
  X,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Toast
// ---------------------------------------------------------------------------

function Toast({ message, onClose }: { message: string; onClose: () => void }) {
  return (
    <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-3 text-sm font-medium text-white shadow-lg animate-fade-in">
      <Check className="h-4 w-4" />
      {message}
      <button onClick={onClose} className="ml-2 hover:opacity-70">
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState("general");
  const [toast, setToast] = useState<string | null>(null);

  // General
  const [orgName, setOrgName] = useState("Acme Corp");
  const [env, setEnv] = useState("production");

  // API
  const [apiUrl, setApiUrl] = useState("http://localhost:8080/api/v1");
  const [apiToken, setApiToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [tokenCopied, setTokenCopied] = useState(false);

  // Notifications
  const [webhookUrl, setWebhookUrl] = useState("");
  const [emailAlerts, setEmailAlerts] = useState("");
  const [alertSettings, setAlertSettings] = useState<Record<string, boolean>>({
    "Critical events": true,
    "Shadow AI detected": true,
    "Policy violations": true,
    "Rate limit exceeded": false,
  });

  // Load saved values from localStorage on mount
  useEffect(() => {
    setOrgName(localStorage.getItem("kal_org_name") ?? "Acme Corp");
    setEnv(localStorage.getItem("kal_env") ?? "production");
    setApiUrl(localStorage.getItem("kal_api_url") ?? "http://localhost:8080/api/v1");
    setApiToken(localStorage.getItem("kal_api_token") ?? "");
    setWebhookUrl(localStorage.getItem("kal_webhook_url") ?? "");
    setEmailAlerts(localStorage.getItem("kal_email_alerts") ?? "");
    const savedAlerts = localStorage.getItem("kal_alert_settings");
    if (savedAlerts) {
      try { setAlertSettings(JSON.parse(savedAlerts)); } catch { /* ignore */ }
    }
    setEventRetention(localStorage.getItem("kal_event_retention") ?? "90");
    setPromptRetention(localStorage.getItem("kal_prompt_retention") ?? "7_days");
  }, []);

  // Team
  const [members, setMembers] = useState([
    { name: "Admin User", email: "admin@acme.com", role: "Owner" },
    { name: "Security Analyst", email: "analyst@acme.com", role: "Admin" },
    { name: "Dev Lead", email: "devlead@acme.com", role: "Viewer" },
  ]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("Viewer");
  const [showInvite, setShowInvite] = useState(false);

  // Integrations
  const [integrations, setIntegrations] = useState([
    { name: "Kubernetes", status: "connected", desc: "eBPF sensor deployed in 3 clusters" },
    { name: "Slack", status: "connected", desc: "Alerts to #ai-security channel" },
    { name: "PagerDuty", status: "not_configured", desc: "Incident management" },
    { name: "Splunk", status: "connected", desc: "Event forwarding enabled" },
    { name: "Jira", status: "not_configured", desc: "Ticket creation for violations" },
    { name: "GitHub", status: "connected", desc: "PR checks and code scanning" },
  ]);

  // Data Retention
  const [eventRetention, setEventRetention] = useState("90");
  const [promptRetention, setPromptRetention] = useState("7_days");

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  }, []);

  const saveGeneral = () => {
    localStorage.setItem("kal_org_name", orgName);
    localStorage.setItem("kal_env", env);
    showToast("General settings saved");
  };

  const saveApi = () => {
    localStorage.setItem("kal_api_url", apiUrl);
    if (apiToken) localStorage.setItem("kal_api_token", apiToken);
    showToast("API settings saved");
  };

  const rotateToken = () => {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const token = "kal_" + env.slice(0, 4) + "_" + Array.from({ length: 32 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
    setApiToken(token);
    localStorage.setItem("kal_api_token", token);
    showToast("API token rotated");
  };

  const copyToken = () => {
    navigator.clipboard.writeText(apiToken);
    setTokenCopied(true);
    setTimeout(() => setTokenCopied(false), 2000);
  };

  const saveNotifications = () => {
    localStorage.setItem("kal_webhook_url", webhookUrl);
    localStorage.setItem("kal_email_alerts", emailAlerts);
    localStorage.setItem("kal_alert_settings", JSON.stringify(alertSettings));
    showToast("Notification settings saved");
  };

  const toggleAlert = (label: string) => {
    setAlertSettings((prev) => ({ ...prev, [label]: !prev[label] }));
  };

  const inviteMember = () => {
    if (!inviteEmail) return;
    setMembers((prev) => [...prev, {
      name: inviteEmail.split("@")[0],
      email: inviteEmail,
      role: inviteRole,
    }]);
    setInviteEmail("");
    setShowInvite(false);
    showToast(`Invite sent to ${inviteEmail}`);
  };

  const removeMember = (email: string) => {
    setMembers((prev) => prev.filter((m) => m.email !== email));
    showToast("Team member removed");
  };

  const toggleIntegration = (name: string) => {
    setIntegrations((prev) =>
      prev.map((i) =>
        i.name === name
          ? { ...i, status: i.status === "connected" ? "not_configured" : "connected" }
          : i,
      ),
    );
    showToast(`${name} ${integrations.find((i) => i.name === name)?.status === "connected" ? "disconnected" : "connected"}`);
  };

  const saveDataRetention = () => {
    localStorage.setItem("kal_event_retention", eventRetention);
    localStorage.setItem("kal_prompt_retention", promptRetention);
    showToast("Data retention settings saved");
  };

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
        <h1 className="text-xl font-bold text-[#0f2137]">Settings</h1>
        <p className="mt-1 text-sm text-[#5a7184]">
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
                  ? "bg-blue-50 text-blue-600 font-medium"
                  : "text-[#5a7184] hover:bg-blue-50/50 hover:text-[#1a2b3c]"
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="flex-1">
          {/* General */}
          {activeTab === "general" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-[#0f2137]">General Settings</h2>
              <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#5a7184]">Organization Name</label>
                  <input type="text" className="input" value={orgName} onChange={(e) => setOrgName(e.target.value)} />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#5a7184]">Environment</label>
                  <select className="select w-full" value={env} onChange={(e) => setEnv(e.target.value)}>
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                  </select>
                </div>
              </div>
              <div className="flex justify-end border-t border-blue-100 pt-4">
                <button className="btn-primary" onClick={saveGeneral}>
                  <Save className="h-4 w-4" /> Save Changes
                </button>
              </div>
            </div>
          )}

          {/* API & Auth */}
          {activeTab === "api" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-[#0f2137]">API & Authentication</h2>
              <div className="space-y-5">
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#5a7184]">API Base URL</label>
                  <input type="url" className="input font-mono" value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#5a7184]">API Token</label>
                  <div className="relative">
                    <input
                      type={showToken ? "text" : "password"}
                      className="input pr-20 font-mono"
                      value={apiToken || "Generate a token..."}
                      onChange={(e) => setApiToken(e.target.value)}
                      readOnly={!apiToken}
                    />
                    <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                      {apiToken && (
                        <button className="p-1 text-[#5a7184] hover:text-blue-600" onClick={copyToken} title="Copy">
                          {tokenCopied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}
                        </button>
                      )}
                      <button className="p-1 text-[#5a7184] hover:text-[#1a2b3c]" onClick={() => setShowToken(!showToken)}>
                        {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                </div>
                <div className="flex gap-3">
                  <button className="btn-secondary" onClick={rotateToken}>
                    <RefreshCw className="h-4 w-4" /> Rotate Token
                  </button>
                  <button className="btn-primary" onClick={saveApi}>
                    <Save className="h-4 w-4" /> Save
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Notifications */}
          {activeTab === "notifications" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-[#0f2137]">Notification Settings</h2>
              <div className="space-y-5">
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#5a7184]">Slack Webhook URL</label>
                  <input
                    type="url"
                    className="input font-mono text-xs"
                    placeholder="https://hooks.slack.com/services/..."
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#5a7184]">Email Alerts</label>
                  <input
                    type="email"
                    className="input"
                    placeholder="security@company.com"
                    value={emailAlerts}
                    onChange={(e) => setEmailAlerts(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-3 block text-xs font-medium text-[#5a7184]">Alert Types</label>
                  <div className="space-y-3">
                    {Object.keys(alertSettings).map((label) => (
                      <label key={label} className="flex items-center gap-3 text-sm text-[#1a2b3c] cursor-pointer">
                        <input
                          type="checkbox"
                          checked={alertSettings[label]}
                          onChange={() => toggleAlert(label)}
                          className="h-4 w-4 rounded border-blue-200 text-blue-600 focus:ring-blue-200"
                        />
                        {label}
                      </label>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex justify-end border-t border-blue-100 pt-4">
                <button className="btn-primary" onClick={saveNotifications}>
                  <Save className="h-4 w-4" /> Save Changes
                </button>
              </div>
            </div>
          )}

          {/* Team */}
          {activeTab === "team" && (
            <div className="card space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-[#0f2137]">Team Members</h2>
                <button className="btn-secondary text-xs" onClick={() => setShowInvite(!showInvite)}>
                  <Plus className="h-3.5 w-3.5" /> Invite
                </button>
              </div>

              {showInvite && (
                <div className="rounded-lg border border-blue-200 bg-blue-50/50 p-4 space-y-3">
                  <p className="text-xs font-medium text-[#5a7184]">Invite new member</p>
                  <div className="flex gap-2">
                    <input
                      type="email"
                      className="input flex-1"
                      placeholder="email@company.com"
                      value={inviteEmail}
                      onChange={(e) => setInviteEmail(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && inviteMember()}
                    />
                    <select className="select" value={inviteRole} onChange={(e) => setInviteRole(e.target.value)}>
                      <option value="Viewer">Viewer</option>
                      <option value="Admin">Admin</option>
                      <option value="Owner">Owner</option>
                    </select>
                    <button className="btn-primary text-xs px-4" onClick={inviteMember}>Send</button>
                    <button className="btn-secondary text-xs px-3" onClick={() => setShowInvite(false)}>
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              )}

              <div className="space-y-2">
                {members.map((member) => (
                  <div
                    key={member.email}
                    className="flex items-center justify-between rounded-lg border border-blue-100 bg-blue-50/30 px-4 py-3"
                  >
                    <div className="flex items-center gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-100 text-blue-600 text-xs font-bold">
                        {member.name.split(" ").map((n) => n[0]).join("")}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-[#1a2b3c]">{member.name}</p>
                        <p className="text-xs text-[#5a7184]">{member.email}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="rounded-full bg-blue-50 px-2.5 py-0.5 text-xs font-medium text-blue-600">
                        {member.role}
                      </span>
                      {member.role !== "Owner" && (
                        <button
                          className="text-[#94a3b8] hover:text-red-500 transition-colors"
                          onClick={() => removeMember(member.email)}
                          title="Remove member"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Integrations */}
          {activeTab === "integrations" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-[#0f2137]">Integrations</h2>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {integrations.map((int) => (
                  <div
                    key={int.name}
                    className="flex items-center justify-between rounded-lg border border-blue-100 bg-blue-50/30 p-4"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-[#1a2b3c]">{int.name}</span>
                        <span
                          className={`h-2 w-2 rounded-full ${
                            int.status === "connected" ? "bg-emerald-500" : "bg-gray-300"
                          }`}
                        />
                      </div>
                      <p className="mt-0.5 text-xs text-[#5a7184]">{int.desc}</p>
                    </div>
                    <button
                      className={`text-xs px-3 py-1.5 rounded-lg font-medium transition-colors ${
                        int.status === "connected"
                          ? "bg-red-50 text-red-600 hover:bg-red-100"
                          : "bg-blue-50 text-blue-600 hover:bg-blue-100"
                      }`}
                      onClick={() => toggleIntegration(int.name)}
                    >
                      {int.status === "connected" ? "Disconnect" : "Connect"}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Data Retention */}
          {activeTab === "data" && (
            <div className="card space-y-6">
              <h2 className="text-sm font-semibold text-[#0f2137]">Data Retention</h2>
              <div className="space-y-5">
                <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
                  <div>
                    <label className="mb-1.5 block text-xs font-medium text-[#5a7184]">Event Retention</label>
                    <select className="select w-full" value={eventRetention} onChange={(e) => setEventRetention(e.target.value)}>
                      <option value="30">30 days</option>
                      <option value="60">60 days</option>
                      <option value="90">90 days</option>
                      <option value="180">180 days</option>
                      <option value="365">365 days</option>
                    </select>
                  </div>
                  <div>
                    <label className="mb-1.5 block text-xs font-medium text-[#5a7184]">Prompt/Response Storage</label>
                    <select className="select w-full" value={promptRetention} onChange={(e) => setPromptRetention(e.target.value)}>
                      <option value="disabled">Disabled (hash only)</option>
                      <option value="7_days">7 days then hash</option>
                      <option value="30_days">30 days then hash</option>
                      <option value="full">Full retention</option>
                    </select>
                  </div>
                </div>
                <div className="rounded-lg border border-amber-200 bg-amber-50/50 p-3">
                  <p className="text-xs text-amber-700">
                    Prompt and response text is stored encrypted at rest and automatically
                    purged after the retention period. Only cryptographic hashes are retained
                    for audit purposes.
                  </p>
                </div>
              </div>
              <div className="flex justify-end border-t border-blue-100 pt-4">
                <button className="btn-primary" onClick={saveDataRetention}>
                  <Save className="h-4 w-4" /> Save Changes
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {toast && <Toast message={toast} onClose={() => setToast(null)} />}
    </div>
  );
}
