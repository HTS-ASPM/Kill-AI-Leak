// ---------------------------------------------------------------------------
// Kill-AI-Leak — VS Code Extension Entry Point
//
// Activated on startup. Responsibilities:
//   1. Register commands (enable, disable, scanFile, status, scanWorkspace)
//   2. Start local proxy for AI assistant traffic interception (optional)
//   3. Watch for .cursorrules, AGENTS.md, CLAUDE.md file changes
//   4. Scan files on save (auto-scan)
//   5. Status bar indicator showing protection status
//   6. Notifications for detected threats
// ---------------------------------------------------------------------------

import * as vscode from "vscode";
import { Scanner, type ScanFinding } from "./scanner";
import { ProxyServer } from "./proxy";

// ---------------------------------------------------------------------------
// Extension state
// ---------------------------------------------------------------------------

let scanner: Scanner;
let proxyServer: ProxyServer | null = null;
let statusBarItem: vscode.StatusBarItem;
let diagnosticCollection: vscode.DiagnosticCollection;
let protectionEnabled = true;
let outputChannel: vscode.OutputChannel;

/** Agent config files to watch for prompt injection. */
const AGENT_CONFIG_FILES = [
  ".cursorrules",
  "AGENTS.md",
  "CLAUDE.md",
  ".github/copilot-instructions.md",
  ".ai/rules.md",
  "RULES.md",
  "copilot-instructions.md",
];

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

export async function activate(
  context: vscode.ExtensionContext,
): Promise<void> {
  outputChannel = vscode.window.createOutputChannel("Kill-AI-Leak");
  outputChannel.appendLine("Kill-AI-Leak extension activating...");

  const config = vscode.workspace.getConfiguration("killAiLeak");

  // Initialize scanner.
  scanner = new Scanner({
    sensitivityLevel: config.get<string>("sensitivityLevel", "medium") as
      | "low"
      | "medium"
      | "high",
    serverUrl: config.get<string>("serverUrl", ""),
    authToken: config.get<string>("authToken", ""),
  });

  // Diagnostic collection for VS Code problem panel.
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("kill-ai-leak");
  context.subscriptions.push(diagnosticCollection);

  // Status bar.
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100,
  );
  statusBarItem.command = "killAiLeak.status";
  context.subscriptions.push(statusBarItem);
  updateStatusBar();

  // -----------------------------------------------------------------------
  // Register commands
  // -----------------------------------------------------------------------

  context.subscriptions.push(
    vscode.commands.registerCommand("killAiLeak.enable", () => {
      protectionEnabled = true;
      updateStatusBar();
      vscode.window.showInformationMessage(
        "Kill-AI-Leak protection enabled.",
      );
      outputChannel.appendLine("Protection enabled.");
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("killAiLeak.disable", () => {
      protectionEnabled = false;
      updateStatusBar();
      vscode.window.showWarningMessage(
        "Kill-AI-Leak protection disabled. AI assistant traffic is not being monitored.",
      );
      outputChannel.appendLine("Protection disabled.");
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("killAiLeak.scanFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("No active file to scan.");
        return;
      }
      await scanDocument(editor.document);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("killAiLeak.status", () => {
      showStatusPanel();
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("killAiLeak.scanWorkspace", async () => {
      await scanWorkspace();
    }),
  );

  // -----------------------------------------------------------------------
  // Auto-scan on save
  // -----------------------------------------------------------------------

  if (config.get<boolean>("autoScan", true)) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (!protectionEnabled) return;
        await scanDocument(document);
      }),
    );
  }

  // -----------------------------------------------------------------------
  // Watch agent config files
  // -----------------------------------------------------------------------

  if (config.get<boolean>("watchAgentFiles", true)) {
    setupAgentFileWatchers(context);
  }

  // -----------------------------------------------------------------------
  // Scan on paste (detect AI-generated code insertions)
  // -----------------------------------------------------------------------

  if (config.get<boolean>("scanOnPaste", true)) {
    context.subscriptions.push(
      vscode.workspace.onDidChangeTextDocument((event) => {
        if (!protectionEnabled) return;
        handleDocumentChange(event);
      }),
    );
  }

  // -----------------------------------------------------------------------
  // Start local proxy (if enabled)
  // -----------------------------------------------------------------------

  if (config.get<boolean>("proxyEnabled", false)) {
    const port = config.get<number>("proxyPort", 18080);
    await startProxy(port, context);
  }

  // -----------------------------------------------------------------------
  // Configuration change handler
  // -----------------------------------------------------------------------

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("killAiLeak")) {
        handleConfigChange();
      }
    }),
  );

  outputChannel.appendLine("Kill-AI-Leak extension activated successfully.");
}

// ---------------------------------------------------------------------------
// Deactivation
// ---------------------------------------------------------------------------

export function deactivate(): void {
  proxyServer?.stop();
  diagnosticCollection?.dispose();
  outputChannel?.appendLine("Kill-AI-Leak extension deactivated.");
  outputChannel?.dispose();
}

// ---------------------------------------------------------------------------
// Document scanning
// ---------------------------------------------------------------------------

async function scanDocument(document: vscode.TextDocument): Promise<void> {
  const text = document.getText();
  const fileName = document.fileName;
  const languageId = document.languageId;

  outputChannel.appendLine(`Scanning: ${fileName}`);

  const result = scanner.scanFile(text, fileName, languageId);

  if (result.findings.length === 0) {
    // Clear previous diagnostics for this file.
    diagnosticCollection.delete(document.uri);
    return;
  }

  // Convert findings to VS Code diagnostics.
  const diagnostics = result.findings.map((finding) =>
    findingToDiagnostic(document, finding),
  );

  diagnosticCollection.set(document.uri, diagnostics);

  // Show notification for critical/high findings.
  const criticalCount = result.findings.filter(
    (f) => f.severity === "critical",
  ).length;
  const highCount = result.findings.filter(
    (f) => f.severity === "high",
  ).length;

  if (criticalCount > 0 || highCount > 0) {
    const parts: string[] = [];
    if (criticalCount > 0) parts.push(`${criticalCount} critical`);
    if (highCount > 0) parts.push(`${highCount} high`);

    const action = await vscode.window.showWarningMessage(
      `Kill-AI-Leak: Found ${parts.join(", ")} issue(s) in ${vscode.workspace.asRelativePath(fileName)}`,
      "Show Problems",
      "Dismiss",
    );

    if (action === "Show Problems") {
      vscode.commands.executeCommand("workbench.action.problems.focus");
    }
  }

  outputChannel.appendLine(
    `  Found ${result.findings.length} issue(s) (${criticalCount} critical, ${highCount} high)`,
  );
}

function findingToDiagnostic(
  document: vscode.TextDocument,
  finding: ScanFinding,
): vscode.Diagnostic {
  // Convert byte positions to VS Code positions.
  let range: vscode.Range;

  if (finding.startPos >= 0 && finding.endPos > finding.startPos) {
    const startPos = document.positionAt(finding.startPos);
    const endPos = document.positionAt(finding.endPos);
    range = new vscode.Range(startPos, endPos);
  } else if (finding.line >= 0) {
    const line = Math.min(finding.line, document.lineCount - 1);
    range = document.lineAt(line).range;
  } else {
    range = new vscode.Range(0, 0, 0, 0);
  }

  const severity = mapSeverity(finding.severity);

  const diagnostic = new vscode.Diagnostic(
    range,
    `[${finding.category}] ${finding.message}`,
    severity,
  );
  diagnostic.source = "Kill-AI-Leak";
  diagnostic.code = finding.ruleId;

  return diagnostic;
}

function mapSeverity(
  severity: string,
): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

// ---------------------------------------------------------------------------
// Workspace scan
// ---------------------------------------------------------------------------

async function scanWorkspace(): Promise<void> {
  const files = await vscode.workspace.findFiles(
    "**/*.{ts,tsx,js,jsx,py,go,java,rb,rs,c,cpp,cs,php,sh,yaml,yml,json,toml,env}",
    "**/node_modules/**",
    500,
  );

  if (files.length === 0) {
    vscode.window.showInformationMessage("No files found to scan.");
    return;
  }

  const progress = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Kill-AI-Leak: Scanning workspace...",
      cancellable: true,
    },
    async (progress, token) => {
      let scanned = 0;
      let totalFindings = 0;

      for (const file of files) {
        if (token.isCancellationRequested) break;

        try {
          const document = await vscode.workspace.openTextDocument(file);
          const text = document.getText();
          const result = scanner.scanFile(
            text,
            file.fsPath,
            document.languageId,
          );

          if (result.findings.length > 0) {
            const diagnostics = result.findings.map((f) =>
              findingToDiagnostic(document, f),
            );
            diagnosticCollection.set(file, diagnostics);
            totalFindings += result.findings.length;
          }
        } catch {
          // Skip files that cannot be opened.
        }

        scanned++;
        progress.report({
          increment: (100 / files.length),
          message: `${scanned}/${files.length} files`,
        });
      }

      return { scanned, totalFindings };
    },
  );

  vscode.window.showInformationMessage(
    `Kill-AI-Leak: Scanned ${progress.scanned} files, found ${progress.totalFindings} issue(s).`,
  );
}

// ---------------------------------------------------------------------------
// Agent config file watchers
// ---------------------------------------------------------------------------

function setupAgentFileWatchers(context: vscode.ExtensionContext): void {
  for (const pattern of AGENT_CONFIG_FILES) {
    const watcher = vscode.workspace.createFileSystemWatcher(
      `**/${pattern}`,
    );

    watcher.onDidChange(async (uri) => {
      outputChannel.appendLine(
        `Agent config file changed: ${uri.fsPath}`,
      );
      await scanAgentConfigFile(uri);
    });

    watcher.onDidCreate(async (uri) => {
      outputChannel.appendLine(
        `Agent config file created: ${uri.fsPath}`,
      );
      await scanAgentConfigFile(uri);
    });

    context.subscriptions.push(watcher);
  }
}

async function scanAgentConfigFile(uri: vscode.Uri): Promise<void> {
  try {
    const document = await vscode.workspace.openTextDocument(uri);
    const text = document.getText();
    const result = scanner.scanAgentConfig(text, uri.fsPath);

    if (result.findings.length === 0) {
      diagnosticCollection.delete(uri);
      return;
    }

    const diagnostics = result.findings.map((f) =>
      findingToDiagnostic(document, f),
    );
    diagnosticCollection.set(uri, diagnostics);

    const hasCritical = result.findings.some(
      (f) => f.severity === "critical" || f.severity === "high",
    );

    if (hasCritical) {
      const action = await vscode.window.showErrorMessage(
        `Kill-AI-Leak: Potential prompt injection detected in ${vscode.workspace.asRelativePath(uri.fsPath)}!`,
        "Show Problems",
        "Open File",
        "Dismiss",
      );

      if (action === "Show Problems") {
        vscode.commands.executeCommand("workbench.action.problems.focus");
      } else if (action === "Open File") {
        vscode.window.showTextDocument(uri);
      }
    }
  } catch {
    // File might be binary or inaccessible.
  }
}

// ---------------------------------------------------------------------------
// Document change handler (paste detection)
// ---------------------------------------------------------------------------

/** Threshold: if a single edit inserts more than this many characters, flag it. */
const LARGE_PASTE_THRESHOLD = 200;

function handleDocumentChange(
  event: vscode.TextDocumentChangeEvent,
): void {
  for (const change of event.contentChanges) {
    // Detect large insertions (likely paste or AI completion).
    if (change.text.length > LARGE_PASTE_THRESHOLD) {
      const result = scanner.scanFile(
        change.text,
        event.document.fileName + " (pasted)",
        event.document.languageId,
      );

      if (result.findings.length > 0) {
        const criticalFindings = result.findings.filter(
          (f) => f.severity === "critical" || f.severity === "high",
        );

        if (criticalFindings.length > 0) {
          vscode.window.showWarningMessage(
            `Kill-AI-Leak: Detected ${criticalFindings.length} issue(s) in pasted/generated code.`,
            "Show Problems",
          ).then((action) => {
            if (action === "Show Problems") {
              vscode.commands.executeCommand(
                "workbench.action.problems.focus",
              );
            }
          });
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

async function startProxy(
  port: number,
  context: vscode.ExtensionContext,
): Promise<void> {
  try {
    const config = vscode.workspace.getConfiguration("killAiLeak");
    proxyServer = new ProxyServer({
      port,
      serverUrl: config.get<string>("serverUrl", ""),
      authToken: config.get<string>("authToken", ""),
      onEvent: (event) => {
        outputChannel.appendLine(
          `[Proxy] ${event.severity}: ${event.message}`,
        );
      },
    });

    await proxyServer.start();
    outputChannel.appendLine(`Local proxy started on port ${port}.`);

    context.subscriptions.push({
      dispose: () => proxyServer?.stop(),
    });
  } catch (err) {
    outputChannel.appendLine(
      `Failed to start proxy: ${err instanceof Error ? err.message : String(err)}`,
    );
    vscode.window.showErrorMessage(
      `Kill-AI-Leak: Failed to start local proxy on port ${port}. ` +
      `The port may be in use.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

function updateStatusBar(): void {
  if (protectionEnabled) {
    statusBarItem.text = "$(shield) Kill-AI-Leak";
    statusBarItem.tooltip = "Kill-AI-Leak: Protection active. Click for status.";
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = "$(warning) Kill-AI-Leak OFF";
    statusBarItem.tooltip =
      "Kill-AI-Leak: Protection disabled. Click for status.";
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground",
    );
  }
  statusBarItem.show();
}

// ---------------------------------------------------------------------------
// Status panel
// ---------------------------------------------------------------------------

function showStatusPanel(): void {
  const items: string[] = [
    `Protection: ${protectionEnabled ? "ENABLED" : "DISABLED"}`,
    `Proxy: ${proxyServer ? "Running" : "Not started"}`,
    `Sensitivity: ${vscode.workspace.getConfiguration("killAiLeak").get("sensitivityLevel")}`,
    "",
    `Diagnostics: ${countDiagnostics()} total finding(s)`,
  ];

  vscode.window.showQuickPick(
    [
      ...items.map((label) => ({ label, kind: vscode.QuickPickItemKind.Default })),
      { label: "", kind: vscode.QuickPickItemKind.Separator },
      { label: "$(play) Enable Protection", kind: vscode.QuickPickItemKind.Default },
      { label: "$(debug-stop) Disable Protection", kind: vscode.QuickPickItemKind.Default },
      { label: "$(search) Scan Current File", kind: vscode.QuickPickItemKind.Default },
      { label: "$(search-fuzzy) Scan Workspace", kind: vscode.QuickPickItemKind.Default },
    ],
    { title: "Kill-AI-Leak Status", placeHolder: "Select an action" },
  ).then((selected) => {
    if (!selected) return;
    switch (selected.label) {
      case "$(play) Enable Protection":
        vscode.commands.executeCommand("killAiLeak.enable");
        break;
      case "$(debug-stop) Disable Protection":
        vscode.commands.executeCommand("killAiLeak.disable");
        break;
      case "$(search) Scan Current File":
        vscode.commands.executeCommand("killAiLeak.scanFile");
        break;
      case "$(search-fuzzy) Scan Workspace":
        vscode.commands.executeCommand("killAiLeak.scanWorkspace");
        break;
    }
  });
}

function countDiagnostics(): number {
  let total = 0;
  diagnosticCollection.forEach((_, diagnostics) => {
    total += diagnostics.length;
  });
  return total;
}

// ---------------------------------------------------------------------------
// Configuration change handler
// ---------------------------------------------------------------------------

function handleConfigChange(): void {
  const config = vscode.workspace.getConfiguration("killAiLeak");

  scanner = new Scanner({
    sensitivityLevel: config.get<string>("sensitivityLevel", "medium") as
      | "low"
      | "medium"
      | "high",
    serverUrl: config.get<string>("serverUrl", ""),
    authToken: config.get<string>("authToken", ""),
  });

  outputChannel.appendLine("Configuration updated.");
}
