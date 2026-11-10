import { randomBytes } from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import {
  formatShellCommand,
  isTrustedWorkspace,
  resolveCliLaunch,
  runCli,
  workspaceFolder,
  workspaceWrapper,
} from "./cli";
import {
  buildScanArgs,
  parseScanReport,
  RULE_SOURCES,
  ScanHistoryEntry,
  ScanMode,
  ScanReport,
} from "./scan";

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

interface RunScanMessage {
  type: "runScan";
  sources?: unknown;
  mode?: unknown;
  include?: unknown;
}

interface OpenFindingMessage {
  type: "openFinding";
  file?: unknown;
  line?: unknown;
  column?: unknown;
}

interface SuppressFindingMessage {
  type: "suppressFinding";
  file?: unknown;
  line?: unknown;
  ruleId?: unknown;
}

interface SaveStateMessage {
  type: "saveState";
  selectedSources?: unknown;
  scanMode?: unknown;
}

type PanelMessage =
  | RunScanMessage
  | OpenFindingMessage
  | SuppressFindingMessage
  | SaveStateMessage
  | { type: "openGui" }
  | { type: "cancelScan" }
  | { type: "exportResults" }
  | { type: "selectAll"; selected?: unknown };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

// ---------------------------------------------------------------------------
// ScanPanelProvider
// ---------------------------------------------------------------------------

export class ScanPanelProvider implements vscode.WebviewViewProvider {
  static readonly viewType = "commitguard.scanView";

  private view: vscode.WebviewView | undefined;
  private scanToken: vscode.CancellationTokenSource | undefined;  // commit-guard-ignore: generic-api-key
  private guiTerminal: vscode.Terminal | undefined;
  private lastReport: ScanReport | undefined;
  private lastScanSources: string[] = [];
  private lastScanMode: ScanMode = "staged";
  private scanHistory: ScanHistoryEntry[] = [];

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly output: vscode.OutputChannel,
    private readonly onScanComplete?: (count: number) => void,
  ) {
    // Restore persisted state
    this.lastReport = this.context.workspaceState.get<ScanReport>("commitguard.lastReport");
    this.lastScanSources = this.context.workspaceState.get<string[]>("commitguard.selectedSources") ?? [];
    this.lastScanMode = this.context.workspaceState.get<ScanMode>("commitguard.scanMode") ?? "staged";
    this.scanHistory = this.context.workspaceState.get<ScanHistoryEntry[]>("commitguard.scanHistory") ?? [];
  }

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.html = this.html(view.webview);
    this.context.subscriptions.push(
      view.webview.onDidReceiveMessage((message: unknown) => {
        void this.onMessage(message);
      }),
      view.onDidDispose(() => {
        this.scanToken?.cancel();
        this.scanToken?.dispose();
        this.scanToken = undefined;
        this.view = undefined;
      }),
    );

    // Send persisted state to the webview after it loads
    setTimeout(() => {
      const cfg = vscode.workspace.getConfiguration("commitguard");
      const defaultSources = cfg.get<string[]>("defaultSources", []);
      const sources = this.lastScanSources.length > 0
        ? this.lastScanSources
        : defaultSources;
      this.post({
        type: "init",
        selectedSources: sources,
        scanMode: this.lastScanMode,
        lastReport: this.lastReport,
        history: this.scanHistory,
        workspace: this.workspaceName(),
        trusted: isTrustedWorkspace(),
        hasFolder: !!workspaceFolder(),
      });
    }, 100);
  }

  focus(): void {
    void vscode.commands.executeCommand(`${ScanPanelProvider.viewType}.focus`);
  }

  /** Programmatically trigger a scan from commands or scan-on-save. */
  public triggerScan(mode: ScanMode, sources?: string[], include?: string): void {
    this.focus();
    const configured = sources ?? this.lastScanSources;
    const useSources = configured.length
      ? configured
      : include
        ? RULE_SOURCES.map((source) => source.id)
        : [];
    if (!useSources.length) {
      void vscode.window.showWarningMessage(
        "CommitGuard: Select at least one rule database in the scan panel before scanning.",
      );
      return;
    }
    this.post({ type: "triggerScan", mode, sources: useSources });
    // Also run it directly
    void this.runScan({ type: "runScan", sources: useSources, mode, include });
  }

  /** Export the last scan report as JSON via a save dialog. */
  public async exportResults(): Promise<void> {
    if (!this.lastReport) {
      await vscode.window.showInformationMessage("CommitGuard: No scan results to export yet.");
      return;
    }
    const uri = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(path.join(os.homedir(), "commitguard-report.json")),
      filters: { "JSON files": ["json"] },
      title: "Export CommitGuard Results",
    });
    if (!uri) return;
    const payload = JSON.stringify(
      { exportedAt: new Date().toISOString(), mode: this.lastScanMode, sources: this.lastScanSources, report: this.lastReport },
      null,
      2,
    );
    await fs.promises.writeFile(uri.fsPath, payload, "utf8");
    await vscode.window.showInformationMessage(`CommitGuard: Results exported to ${uri.fsPath}`);
  }

  /** Clear results in the webview. */
  public clearResults(): void {
    this.lastReport = undefined;
    void this.context.workspaceState.update("commitguard.lastReport", undefined);
    this.post({ type: "clearResults" });
  }

  async openGui(): Promise<void> {
    const folder = workspaceFolder();
    if (!folder) {
      await vscode.window.showWarningMessage(
        "Open a folder before launching the CommitGuard GUI.",
      );
      return;
    }
    try {
      const wrapper = isTrustedWorkspace()
        ? workspaceWrapper(folder)
        : undefined;
      const launch = wrapper
        ? { command: wrapper, args: ["gui", folder.uri.fsPath], label: wrapper }
        : resolveCliLaunch(["gui", folder.uri.fsPath]);
      if (!this.guiTerminal || this.guiTerminal.exitStatus !== undefined) {
        this.guiTerminal = vscode.window.createTerminal({
          name: "CommitGuard GUI",
          cwd: folder.uri.fsPath,
        });
        this.context.subscriptions.push(this.guiTerminal);
      }
      this.guiTerminal.show();
      this.guiTerminal.sendText(formatShellCommand(launch), true);
      this.output.appendLine(`Launching CommitGuard GUI: ${launch.label}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.output.appendLine(`Could not launch CommitGuard GUI: ${message}`);
      await vscode.window.showErrorMessage(
        `CommitGuard GUI could not start. ${message}`,
      );
    }
  }

  private workspaceName(): string {
    const folder = workspaceFolder();
    return folder ? path.basename(folder.uri.fsPath) : "No folder open";
  }

  private post(message: unknown): void {
    void this.view?.webview.postMessage(message);
  }

  private async onMessage(value: unknown): Promise<void> {
    if (!value || typeof value !== "object") return;
    const message = value as PanelMessage;
    if (message.type === "runScan") {
      await this.runScan(message);
    } else if (message.type === "openGui") {
      await this.openGui();
    } else if (message.type === "cancelScan") {
      this.scanToken?.cancel();
    } else if (message.type === "openFinding") {
      await this.openFinding(message);
    } else if (message.type === "suppressFinding") {
      await this.suppressFinding(message);
    } else if (message.type === "exportResults") {
      await this.exportResults();
    } else if (message.type === "saveState") {
      await this.saveWebviewState(message);
    }
  }

  private async saveWebviewState(message: SaveStateMessage): Promise<void> {
    if (Array.isArray(message.selectedSources)) {
      this.lastScanSources = message.selectedSources.filter(
        (s): s is string => typeof s === "string",
      );
      await this.context.workspaceState.update("commitguard.selectedSources", this.lastScanSources);
    }
    if (message.scanMode === "staged" || message.scanMode === "repo") {
      this.lastScanMode = message.scanMode;
      await this.context.workspaceState.update("commitguard.scanMode", this.lastScanMode);
    }
  }

  private async runScan(message: RunScanMessage): Promise<void> {
    if (this.scanToken) return;
    const folder = workspaceFolder();
    if (!folder) {
      this.post({
        type: "scanError",
        message: "Open a folder before running a scan.",
      });
      return;
    }
    const requested = Array.isArray(message.sources)
      ? message.sources.filter((item): item is string => typeof item === "string")
      : [];
    const allowed = new Set(RULE_SOURCES.map((source) => source.id));
    const sources = [...new Set(requested.filter((item) => allowed.has(item)))];
    if (!sources.length) {
      this.post({
        type: "scanError",
        message: "Select at least one rule database.",
      });
      return;
    }
    const mode: ScanMode = message.mode === "staged" ? "staged" : "repo";
    const include = typeof message.include === "string" && message.include.trim()
      ? message.include.trim()
      : undefined;
    this.lastScanSources = sources;
    this.lastScanMode = mode;
    await this.context.workspaceState.update("commitguard.selectedSources", sources);
    await this.context.workspaceState.update("commitguard.scanMode", mode);

    const temp = await fs.promises.mkdtemp(
      path.join(os.tmpdir(), "commitguard-scan-"),
    );
    const reportPath = path.join(temp, "report.json");
    const token = new vscode.CancellationTokenSource();
    this.scanToken = token;
    const startMs = Date.now();
    this.post({ type: "scanStarted", sources, mode });
    this.output.appendLine(
      `Running ${mode === "repo" ? "repository" : "staged"} scan with sources: ${sources.join(", ")}`,
    );
    try {
      const result = await runCli(
        buildScanArgs(folder.uri.fsPath, reportPath, sources, mode, include),
        folder.uri.fsPath,
        token.token,
      );
      let report: ScanReport;
      try {
        const text = await fs.promises.readFile(reportPath, "utf8");
        report = parseScanReport(JSON.parse(text));
      } catch (readError) {
        const detail =
          result.stderr.trim() ||
          result.stdout.trim() ||
          (readError instanceof Error ? readError.message : String(readError));
        throw new Error(
          detail || `CommitGuard exited with code ${result.code}.`,
        );
      }
      const durationMs = Date.now() - startMs;
      this.lastReport = report;
      await this.context.workspaceState.update("commitguard.lastReport", report);

      // Add to history (keep last 20)
      const historyEntry: ScanHistoryEntry = {
        id: String(Date.now()),
        timestamp: new Date().toISOString(),
        durationMs,
        mode,
        sources,
        report,
      };
      this.scanHistory = [historyEntry, ...this.scanHistory].slice(0, 20);
      await this.context.workspaceState.update("commitguard.scanHistory", this.scanHistory);

      this.post({ type: "scanResult", report, sources, mode, durationMs, history: this.scanHistory });
      this.output.appendLine(
        `Scan finished: ${report.total} finding(s) from ${sources.join(", ")}.`,
      );
      this.onScanComplete?.(report.total);
    } catch (error) {
      const messageText =
        error instanceof Error ? error.message : String(error);
      this.post({ type: "scanError", message: messageText });
      this.output.appendLine(`Scan failed: ${messageText}`);
    } finally {
      token.dispose();
      this.scanToken = undefined;
      await fs.promises.rm(temp, { recursive: true, force: true });
    }
  }

  private async openFinding(message: OpenFindingMessage): Promise<void> {
    const folder = workspaceFolder();
    const file = asString(message.file);
    if (!folder || !file) return;
    const target = path.resolve(folder.uri.fsPath, file);
    const relative = path.relative(folder.uri.fsPath, target);
    if (
      relative === ".." ||
      relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)
    ) {
      await vscode.window.showWarningMessage(
        `Refusing to open a finding outside the workspace: ${file}`,
      );
      return;
    }
    try {
      const document = await vscode.workspace.openTextDocument(target);
      const editor = await vscode.window.showTextDocument(document, {
        preview: true,
      });
      const line = Math.max(0, (asNumber(message.line) ?? 1) - 1);
      const column = Math.max(0, (asNumber(message.column) ?? 1) - 1);
      const position = new vscode.Position(line, column);
      editor.selection = new vscode.Selection(position, position);
      editor.revealRange(
        new vscode.Range(position, position),
        vscode.TextEditorRevealType.InCenter,
      );
    } catch (error) {
      await vscode.window.showErrorMessage(
        `Could not open ${file}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  private async suppressFinding(message: SuppressFindingMessage): Promise<void> {
    const folder = workspaceFolder();
    const file = asString(message.file);
    const ruleId = asString(message.ruleId);
    const lineNum = asNumber(message.line) ?? 1;
    if (!folder || !file || !ruleId) return;
    const target = path.resolve(folder.uri.fsPath, file);
    const relative = path.relative(folder.uri.fsPath, target);
    if (
      relative === ".." ||
      relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)
    ) {
      await vscode.window.showWarningMessage(
        `Refusing to suppress a finding outside the workspace: ${file}`,
      );
      return;
    }
    try {
      const document = await vscode.workspace.openTextDocument(target);
      const editor = await vscode.window.showTextDocument(document, { preview: false });
      const targetLine = Math.max(0, lineNum - 1);
      const lineText = document.lineAt(targetLine).text;
      const indent = lineText.match(/^(\s*)/)?.[1] ?? "";
      const suppressComment = `${indent}# commit-guard-ignore: ${ruleId}`;
      await editor.edit((editBuilder) => {
        const insertPos = new vscode.Position(targetLine, 0);
        editBuilder.insert(insertPos, suppressComment + "\n");
      });
      await vscode.window.showInformationMessage(
        `CommitGuard: Suppressed rule "${ruleId}" in ${path.basename(file)}:${lineNum}`,
      );
    } catch (error) {
      await vscode.window.showErrorMessage(
        `Could not suppress finding in ${file}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  // ---------------------------------------------------------------------------
  // HTML
  // ---------------------------------------------------------------------------

  private html(webview: vscode.Webview): string {
    const nonce = randomBytes(16).toString("base64");
    const folder = workspaceFolder();
    const workspace = folder
      ? escapeHtml(path.basename(folder.uri.fsPath))
      : "No folder open";
    const trusted = isTrustedWorkspace();
    const disabled = folder && trusted ? "" : " disabled";

    // Build source checkboxes
    const sourcesHtml = RULE_SOURCES.map(
      (source) => `
        <label class="source" data-source-id="${escapeHtml(source.id)}">
          <input type="checkbox" data-source="${escapeHtml(source.id)}"${disabled}>
          <span class="source-text">
            <span class="source-name">${escapeHtml(source.label)}</span>
            <span class="source-desc">${escapeHtml(source.description)}</span>
          </span>
        </label>`,
    ).join("");

    const warningHtml = !folder
      ? '<div class="warning">Open a folder to run a scan.</div>'
      : !trusted
        ? '<div class="warning">CommitGuard is disabled in untrusted workspaces.</div>'
        : "";

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  :root {
    color-scheme: light dark;
    --sev-critical: #f44336;
    --sev-high: #ff7043;
    --sev-medium: #ffa726;
    --sev-low: #42a5f5;
    --sev-info: #78909c;
    --radius: 6px;
    --transition: 0.15s ease;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--vscode-foreground);
    background: var(--vscode-sideBar-background);
    overflow-x: hidden;
  }

  /* ── Header ── */
  .header {
    padding: 10px 12px 0;
  }
  .header-top {
    display: flex;
    align-items: center;
    gap: 7px;
    margin-bottom: 2px;
  }
  .header-top svg { width: 18px; height: 18px; color: var(--vscode-focusBorder); flex-shrink: 0; }
  .header-title { font-size: 14px; font-weight: 700; letter-spacing: -0.01em; flex: 1; }
  .header-workspace {
    color: var(--vscode-descriptionForeground);
    font-size: 11px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--vscode-panel-border, var(--vscode-sideBarSectionHeader-border));
    margin-bottom: 0;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 5px 0;
    border-bottom: 1px solid var(--vscode-panel-border, var(--vscode-sideBarSectionHeader-border));
    margin-bottom: 0;
  }
  .toolbar-spacer { flex: 1; }
  .btn-icon {
    display: inline-flex; align-items: center; justify-content: center;
    width: 26px; height: 26px; border: none; border-radius: var(--radius);
    background: transparent; color: var(--vscode-icon-foreground);
    cursor: pointer; font-size: 15px; transition: background var(--transition);
    padding: 0;
  }
  .btn-icon:hover:not(:disabled) { background: var(--vscode-toolbar-hoverBackground); }
  .btn-icon:disabled { opacity: 0.4; cursor: default; }
  .btn-icon svg { width: 15px; height: 15px; }

  /* ── Tabs ── */
  .tabs {
    display: flex;
    border-bottom: 1px solid var(--vscode-panel-border, var(--vscode-sideBarSectionHeader-border));
    padding: 0 12px;
    gap: 0;
  }
  .tab {
    padding: 7px 10px 6px;
    font-size: 12px; font-weight: 500;
    color: var(--vscode-descriptionForeground);
    cursor: pointer; border: none; background: transparent;
    border-bottom: 2px solid transparent;
    transition: color var(--transition), border-color var(--transition);
    position: relative; top: 1px;
  }
  .tab.active {
    color: var(--vscode-foreground);
    border-bottom-color: var(--vscode-focusBorder);
  }
  .tab:hover:not(.active) { color: var(--vscode-foreground); }

  /* ── Tab panels ── */
  .tab-panel { display: none; padding: 10px 12px; }
  .tab-panel.active { display: block; }

  /* ── Warning banner ── */
  .warning {
    padding: 8px 10px; border-radius: var(--radius); margin-bottom: 10px;
    color: var(--vscode-inputValidation-warningForeground);
    background: var(--vscode-inputValidation-warningBackground);
    border: 1px solid var(--vscode-inputValidation-warningBorder);
    font-size: 11.5px;
  }

  /* ── Section headers ── */
  .section-header {
    display: flex; align-items: center; gap: 6px;
    font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.07em;
    color: var(--vscode-descriptionForeground);
    padding: 6px 0 4px; cursor: pointer; user-select: none;
  }
  .section-header .chevron {
    transition: transform var(--transition); font-size: 10px;
  }
  .section-header.collapsed .chevron { transform: rotate(-90deg); }
  .section-content { overflow: hidden; transition: max-height 0.2s ease; }

  /* ── Sources ── */
  .sources-controls {
    display: flex; align-items: center; gap: 5px; margin-bottom: 6px;
  }
  .sources-search {
    flex: 1; padding: 4px 8px 4px 26px;
    background: var(--vscode-input-background);
    color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border, transparent);
    border-radius: var(--radius); font-size: 11.5px; font-family: inherit;
    position: relative;
  }
  .sources-search:focus { outline: 1px solid var(--vscode-focusBorder); }
  .search-wrap { position: relative; flex: 1; }
  .search-wrap svg {
    position: absolute; left: 7px; top: 50%; transform: translateY(-50%);
    width: 12px; height: 12px;
    color: var(--vscode-descriptionForeground); pointer-events: none;
  }
  .btn-xs {
    font-family: inherit; font-size: 11px; padding: 3px 7px;
    color: var(--vscode-button-secondaryForeground);
    background: var(--vscode-button-secondaryBackground);
    border: none; border-radius: var(--radius); cursor: pointer;
    transition: background var(--transition);
    white-space: nowrap;
  }
  .btn-xs:hover:not(:disabled) { background: var(--vscode-button-secondaryHoverBackground); }
  .btn-xs:disabled { opacity: 0.4; cursor: default; }
  .sources { display: flex; flex-direction: column; gap: 2px; max-height: 230px; overflow-y: auto; }
  .sources::-webkit-scrollbar { width: 4px; }
  .sources::-webkit-scrollbar-thumb { background: var(--vscode-scrollbarSlider-background); border-radius: 2px; }
  .source {
    display: flex; gap: 8px; align-items: flex-start;
    padding: 6px 8px; border-radius: var(--radius); cursor: pointer;
    border: 1px solid transparent; transition: background var(--transition), border-color var(--transition);
  }
  .source:hover { background: var(--vscode-list-hoverBackground); }
  .source:has(input:checked) { border-color: var(--vscode-focusBorder); background: var(--vscode-list-inactiveSelectionBackground); }
  .source input { margin: 2px 0 0; accent-color: var(--vscode-button-background); flex-shrink: 0; }
  .source-text { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
  .source-name { font-weight: 600; font-size: 11.5px; }
  .source-desc { color: var(--vscode-descriptionForeground); font-size: 10.5px; line-height: 1.35; }
  .source-hidden { display: none !important; }

  /* ── Scope + actions ── */
  .scope-label { font-size: 11px; font-weight: 600; color: var(--vscode-descriptionForeground); margin-bottom: 4px; }
  .scope-row { display: flex; gap: 4px; }
  .scope-btn {
    flex: 1; padding: 5px 4px; font-size: 11.5px; font-family: inherit;
    color: var(--vscode-button-secondaryForeground);
    background: var(--vscode-button-secondaryBackground);
    border: 1px solid transparent; border-radius: var(--radius);
    cursor: pointer; text-align: center; transition: background var(--transition), border-color var(--transition);
  }
  .scope-btn:hover:not(:disabled) { background: var(--vscode-button-secondaryHoverBackground); }
  .scope-btn.active {
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    border-color: var(--vscode-focusBorder);
  }
  .scope-btn:disabled { opacity: 0.4; cursor: default; }
  .actions { display: flex; gap: 6px; margin-top: 8px; }
  .btn-primary {
    flex: 1; padding: 7px 10px; font-size: 12px; font-family: inherit; font-weight: 600;
    color: var(--vscode-button-foreground); background: var(--vscode-button-background);
    border: none; border-radius: var(--radius); cursor: pointer;
    display: flex; align-items: center; justify-content: center; gap: 5px;
    transition: background var(--transition);
  }
  .btn-primary:hover:not(:disabled) { background: var(--vscode-button-hoverBackground); }
  .btn-primary:disabled { opacity: 0.5; cursor: default; }
  .btn-danger {
    padding: 7px 10px; font-size: 12px; font-family: inherit;
    color: var(--vscode-errorForeground);
    background: var(--vscode-inputValidation-errorBackground);
    border: 1px solid var(--vscode-inputValidation-errorBorder, transparent);
    border-radius: var(--radius); cursor: pointer;
    transition: opacity var(--transition);
  }
  .btn-danger:hover:not(:disabled) { opacity: 0.85; }
  .btn-danger:disabled { opacity: 0.4; cursor: default; }
  .btn-secondary {
    flex: 1; padding: 6px 10px; font-size: 12px; font-family: inherit;
    color: var(--vscode-button-secondaryForeground);
    background: var(--vscode-button-secondaryBackground);
    border: none; border-radius: var(--radius); cursor: pointer;
    transition: background var(--transition);
  }
  .btn-secondary:hover:not(:disabled) { background: var(--vscode-button-secondaryHoverBackground); }

  /* ── Status line ── */
  .status-line {
    min-height: 16px; margin: 7px 0 0;
    color: var(--vscode-descriptionForeground); font-size: 11px; line-height: 1.4;
  }
  .status-line.error { color: var(--vscode-errorForeground); }
  .status-line.ok { color: var(--vscode-testing-iconPassed, #4caf50); }
  .spinner {
    display: inline-block; width: 10px; height: 10px;
    border: 1.5px solid currentColor; border-right-color: transparent;
    border-radius: 50%; animation: spin 0.7s linear infinite; vertical-align: -1px;
    margin-right: 4px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Results ── */
  .results-section { margin-top: 10px; }
  .badges { display: flex; flex-wrap: wrap; gap: 4px; margin: 6px 0 8px; }
  .badge {
    border-radius: 999px; padding: 2px 8px; font-size: 10.5px; font-weight: 600;
    background: var(--vscode-badge-background); color: var(--vscode-badge-foreground);
    white-space: nowrap;
  }
  .badge.critical { background: rgba(244,67,54,0.2); color: var(--sev-critical); }
  .badge.high { background: rgba(255,112,67,0.2); color: var(--sev-high); }
  .badge.medium { background: rgba(255,167,38,0.2); color: var(--sev-medium); }
  .badge.low { background: rgba(66,165,245,0.2); color: var(--sev-low); }
  .badge.info { background: rgba(120,144,156,0.2); color: var(--sev-info); }

  /* ── Filter bar ── */
  .filter-bar { display: flex; gap: 5px; margin-bottom: 6px; align-items: center; }
  .filter-search {
    flex: 1; padding: 4px 8px 4px 26px; font-family: inherit; font-size: 11.5px;
    background: var(--vscode-input-background); color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border, transparent); border-radius: var(--radius);
  }
  .filter-search:focus { outline: 1px solid var(--vscode-focusBorder); }
  .filter-wrap { position: relative; flex: 1; }
  .filter-wrap svg {
    position: absolute; left: 7px; top: 50%; transform: translateY(-50%);
    width: 12px; height: 12px; color: var(--vscode-descriptionForeground); pointer-events: none;
  }
  .sev-pills { display: flex; flex-wrap: wrap; gap: 3px; margin-bottom: 6px; }
  .sev-pill {
    padding: 2px 7px; border-radius: 999px; font-size: 10px; font-weight: 600;
    cursor: pointer; border: 1px solid transparent; transition: all var(--transition);
    color: var(--vscode-descriptionForeground); background: transparent;
    font-family: inherit;
  }
  .sev-pill.active { background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); }
  .sev-pill[data-sev="critical"].active { background: rgba(244,67,54,0.2); color: var(--sev-critical); border-color: var(--sev-critical); }
  .sev-pill[data-sev="high"].active { background: rgba(255,112,67,0.2); color: var(--sev-high); border-color: var(--sev-high); }
  .sev-pill[data-sev="medium"].active { background: rgba(255,167,38,0.2); color: var(--sev-medium); border-color: var(--sev-medium); }
  .sev-pill[data-sev="low"].active { background: rgba(66,165,245,0.2); color: var(--sev-low); border-color: var(--sev-low); }
  .sev-pill[data-sev="info"].active { background: rgba(120,144,156,0.2); color: var(--sev-info); border-color: var(--sev-info); }

  .group-row { display: flex; align-items: center; gap: 5px; margin-bottom: 6px; }
  .group-label { font-size: 10.5px; color: var(--vscode-descriptionForeground); }
  .group-btn {
    padding: 2px 7px; font-size: 10.5px; font-family: inherit;
    border: 1px solid var(--vscode-input-border, transparent);
    border-radius: 3px; cursor: pointer; background: transparent;
    color: var(--vscode-descriptionForeground); transition: all var(--transition);
  }
  .group-btn.active {
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground); border-color: transparent;
  }

  /* ── Finding cards ── */
  .findings { display: flex; flex-direction: column; gap: 4px; }
  .group-title {
    font-size: 10.5px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.06em; color: var(--vscode-descriptionForeground);
    padding: 8px 0 3px; border-bottom: 1px solid var(--vscode-panel-border, transparent);
    margin-bottom: 2px;
  }
  .finding-card {
    border-radius: var(--radius);
    border: 1px solid var(--vscode-sideBarSectionHeader-border, var(--vscode-panel-border));
    border-left: 3px solid var(--vscode-focusBorder);
    background: var(--vscode-editor-background);
    overflow: hidden; transition: border-color var(--transition), background var(--transition);
  }
  .finding-card:hover { background: var(--vscode-list-hoverBackground); }
  .finding-card[data-sev="critical"] { border-left-color: var(--sev-critical); }
  .finding-card[data-sev="high"] { border-left-color: var(--sev-high); }
  .finding-card[data-sev="medium"] { border-left-color: var(--sev-medium); }
  .finding-card[data-sev="low"] { border-left-color: var(--sev-low); }
  .finding-card[data-sev="info"] { border-left-color: var(--sev-info); }
  .finding-main {
    padding: 7px 8px 4px;
    display: flex; flex-direction: column; gap: 2px;
    cursor: pointer; width: 100%; background: none; border: none;
    color: inherit; font-family: inherit; font-size: inherit; text-align: left;
  }
  .finding-top { display: flex; gap: 5px; align-items: center; }
  .finding-rule { font-weight: 700; font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; }
  .finding-loc { color: var(--vscode-textLink-foreground); font-size: 10.5px; white-space: nowrap; flex-shrink: 0; cursor: pointer; }
  .finding-loc:hover { text-decoration: underline; }
  .finding-desc { color: var(--vscode-descriptionForeground); font-size: 11px; line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
  .finding-desc.expanded { display: block; -webkit-line-clamp: unset; }
  .finding-meta { color: var(--vscode-descriptionForeground); font-size: 10px; }
  .finding-actions {
    display: flex; gap: 3px; padding: 3px 8px 7px;
    border-top: 1px solid transparent;
  }
  .finding-card:hover .finding-actions { border-top-color: var(--vscode-panel-border, transparent); }
  .btn-micro {
    padding: 2px 7px; font-size: 10.5px; font-family: inherit;
    color: var(--vscode-button-secondaryForeground);
    background: var(--vscode-button-secondaryBackground);
    border: none; border-radius: 3px; cursor: pointer;
    transition: background var(--transition);
  }
  .btn-micro:hover { background: var(--vscode-button-secondaryHoverBackground); }

  /* ── Empty state ── */
  .empty-state {
    padding: 30px 20px; text-align: center;
    color: var(--vscode-descriptionForeground);
    display: flex; flex-direction: column; align-items: center; gap: 10px;
  }
  .empty-state svg { width: 52px; height: 52px; color: var(--vscode-testing-iconPassed, #4caf50); opacity: 0.8; }
  .empty-state p { font-size: 12px; line-height: 1.5; }
  .empty-state .empty-title { font-size: 13px; font-weight: 600; color: var(--vscode-foreground); }

  /* ── Export button ── */
  .export-row { margin-top: 8px; display: flex; gap: 5px; }

  /* ── History tab ── */
  .history-list { display: flex; flex-direction: column; gap: 6px; }
  .history-card {
    padding: 10px 12px; border-radius: var(--radius);
    border: 1px solid var(--vscode-sideBarSectionHeader-border, var(--vscode-panel-border));
    background: var(--vscode-editor-background); cursor: pointer;
    transition: background var(--transition); display: flex; flex-direction: column; gap: 4px;
  }
  .history-card:hover { background: var(--vscode-list-hoverBackground); }
  .history-card-top { display: flex; align-items: center; gap: 6px; }
  .history-ts { font-size: 11px; font-weight: 600; flex: 1; }
  .history-mode { font-size: 10px; padding: 1px 6px; border-radius: 999px; background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); }
  .history-badges { display: flex; flex-wrap: wrap; gap: 3px; }
  .history-meta { font-size: 10px; color: var(--vscode-descriptionForeground); }
  .history-empty { padding: 24px; text-align: center; color: var(--vscode-descriptionForeground); font-size: 11.5px; }

  /* ── Misc ── */
  .hidden { display: none !important; }
  .mt6 { margin-top: 6px; }
  .mt10 { margin-top: 10px; }
  .divider { border: none; border-top: 1px solid var(--vscode-panel-border, var(--vscode-sideBarSectionHeader-border)); margin: 8px 0; }
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="header-top">
    <svg aria-hidden="true" viewBox="0 0 24 24" fill="none">
      <path d="M12 2.5 4.5 5.6v5.2c0 4.7 3.1 9 7.5 10.7 4.4-1.7 7.5-6 7.5-10.7V5.6L12 2.5Z"
        stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>
      <path d="m8.5 12 2.3 2.3 4.7-4.8"
        stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <span class="header-title">CommitGuard</span>
  </div>
  <div class="header-workspace" id="workspaceLabel">${workspace}</div>
</div>

<!-- Toolbar -->
<div class="toolbar">
  <span class="toolbar-spacer"></span>
  <button class="btn-icon" id="tbStagedBtn" title="Scan Staged Changes"${disabled}>
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
    </svg>
  </button>
  <button class="btn-icon" id="tbRepoBtn" title="Scan Full Repository"${disabled}>
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <path d="M3 3h18v18H3z"/><path d="M3 9h18M9 21V9"/>
    </svg>
  </button>
  <button class="btn-icon" id="tbGuiBtn" title="Open CommitGuard GUI"${disabled}>
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
    </svg>
  </button>
</div>

<!-- Tabs -->
<div class="tabs">
  <button class="tab active" data-tab="scan">Scan</button>
  <button class="tab" data-tab="history">History</button>
</div>

<!-- Scan Tab -->
<div class="tab-panel active" id="panel-scan">
  ${warningHtml}

  <!-- Rule Databases (collapsible) -->
  <div class="section-header" id="sourcesHeader">
    <span class="chevron">▾</span>
    <span>Rule Databases</span>
    <span style="margin-left:auto;font-size:10px" id="selectedCount">0 selected</span>
  </div>
  <div class="section-content" id="sourcesBody">
    <div class="sources-controls">
      <div class="search-wrap">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        <input class="sources-search" id="sourcesSearch" type="text" placeholder="Filter databases…" autocomplete="off">
      </div>
      <button class="btn-xs" id="allBtn"${disabled}>All</button>
      <button class="btn-xs" id="noneBtn"${disabled}>Clear</button>
    </div>
    <div class="sources" id="sources">${sourcesHtml}</div>
  </div>

  <hr class="divider">

  <!-- Scan scope -->
  <div class="scope-label">Scan scope</div>
  <div class="scope-row" id="scopeRow">
    <button class="scope-btn active" data-scope="staged"${disabled}>⚡ Staged Only</button>
    <button class="scope-btn" data-scope="repo"${disabled}>🗂 Whole Repo</button>
  </div>

  <!-- Scan actions -->
  <div class="actions mt6">
    <button class="btn-primary" id="scanBtn"${disabled}>
      ▶ Run Scan
    </button>
    <button class="btn-danger hidden" id="cancelBtn" type="button">✕ Cancel</button>
  </div>
  <div class="actions" style="margin-top:4px">
    <button class="btn-secondary" id="guiBtn"${disabled}>Open CommitGuard GUI</button>
  </div>

  <!-- Status line -->
  <div class="status-line" id="status">${folder && trusted ? "Select rule databases, then run a scan." : ""}</div>

  <!-- Results area -->
  <div id="results" class="results-section hidden">
    <div class="badges" id="badges"></div>
    <div class="filter-bar">
      <div class="filter-wrap">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        <input class="filter-search" id="filterSearch" type="text" placeholder="Filter findings…" autocomplete="off">
      </div>
    </div>
    <div class="sev-pills" id="sevPills">
      <button class="sev-pill active" data-sev="all">All</button>
      <button class="sev-pill" data-sev="critical">Critical</button>
      <button class="sev-pill" data-sev="high">High</button>
      <button class="sev-pill" data-sev="medium">Medium</button>
      <button class="sev-pill" data-sev="low">Low</button>
      <button class="sev-pill" data-sev="info">Info</button>
    </div>
    <div class="group-row">
      <span class="group-label">Group by:</span>
      <button class="group-btn active" data-group="flat">Flat</button>
      <button class="group-btn" data-group="file">File</button>
      <button class="group-btn" data-group="severity">Severity</button>
    </div>
    <div class="findings" id="findings"></div>
    <div class="export-row">
      <button class="btn-xs" id="exportBtn">⬇ Export JSON</button>
    </div>
  </div>
</div>

<!-- History Tab -->
<div class="tab-panel" id="panel-history">
  <div class="history-list" id="historyList">
    <div class="history-empty">No scan history yet.</div>
  </div>
</div>

<script nonce="${nonce}">
(function () {
  const vscode = acquireVsCodeApi();

  // ── DOM refs ──
  const workspaceLabel = document.getElementById('workspaceLabel');
  const sourcesHeader = document.getElementById('sourcesHeader');
  const sourcesBody = document.getElementById('sourcesBody');
  const sourcesSearch = document.getElementById('sourcesSearch');
  const selectedCount = document.getElementById('selectedCount');
  const allBtn = document.getElementById('allBtn');
  const noneBtn = document.getElementById('noneBtn');
  const scopeRow = document.getElementById('scopeRow');
  const scopeBtns = Array.from(scopeRow.querySelectorAll('.scope-btn'));
  const scanBtn = document.getElementById('scanBtn');
  const cancelBtn = document.getElementById('cancelBtn');
  const guiBtn = document.getElementById('guiBtn');
  const tbStagedBtn = document.getElementById('tbStagedBtn');
  const tbRepoBtn = document.getElementById('tbRepoBtn');
  const tbGuiBtn = document.getElementById('tbGuiBtn');
  const statusEl = document.getElementById('status');
  const resultsEl = document.getElementById('results');
  const badgesEl = document.getElementById('badges');
  const findingsEl = document.getElementById('findings');
  const filterSearch = document.getElementById('filterSearch');
  const sevPills = document.getElementById('sevPills');
  const exportBtn = document.getElementById('exportBtn');
  const historyList = document.getElementById('historyList');

  const tabs = Array.from(document.querySelectorAll('.tab'));
  const panels = Array.from(document.querySelectorAll('.tab-panel'));

  // ── State ──
  let running = false;
  let currentScope = 'staged';
  let currentReport = null;
  let currentSources = [];
  let currentMode = 'staged';
  let filterText = '';
  let filterSev = 'all';
  let groupBy = 'flat';
  let sourcesCollapsed = false;
  let scanHistory = [];

  // Restore persisted webview state
  const persisted = vscode.getState() || {};
  if (persisted.scope) currentScope = persisted.scope;
  if (persisted.sourcesCollapsed) sourcesCollapsed = persisted.sourcesCollapsed;
  if (persisted.groupBy) groupBy = persisted.groupBy;

  function saveState() {
    vscode.setState({ scope: currentScope, sourcesCollapsed, groupBy });
  }

  // ── Tabs ──
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === target));
      panels.forEach(p => p.classList.toggle('active', p.id === 'panel-' + target));
      if (target === 'history') renderHistory();
    });
  });

  // ── Collapsible sources ──
  function applySourcesCollapsed() {
    if (sourcesCollapsed) {
      sourcesBody.style.maxHeight = '0';
      sourcesBody.style.overflow = 'hidden';
      sourcesHeader.classList.add('collapsed');
    } else {
      sourcesBody.style.maxHeight = '';
      sourcesBody.style.overflow = '';
      sourcesHeader.classList.remove('collapsed');
    }
  }
  applySourcesCollapsed();
  sourcesHeader.addEventListener('click', () => {
    sourcesCollapsed = !sourcesCollapsed;
    applySourcesCollapsed();
    saveState();
  });

  // ── Sources ──
  const boxes = Array.from(document.querySelectorAll('input[data-source]'));

  function getSelected() {
    return boxes.filter(b => b.checked).map(b => b.dataset.source);
  }

  function refreshSelection() {
    const count = getSelected().length;
    selectedCount.textContent = count + ' selected';
    scanBtn.disabled = running || count === 0;
  }

  function setRunning(value) {
    running = value;
    scanBtn.disabled = value || getSelected().length === 0;
    cancelBtn.classList.toggle('hidden', !value);
    boxes.forEach(b => { b.disabled = value; });
    allBtn.disabled = value;
    noneBtn.disabled = value;
    scopeBtns.forEach(b => { b.disabled = value; });
    tbStagedBtn.disabled = value;
    tbRepoBtn.disabled = value;
  }

  function setStatus(text, kind) {
    statusEl.textContent = text || '';
    statusEl.className = 'status-line' + (kind ? ' ' + kind : '');
  }

  // Source filtering
  sourcesSearch.addEventListener('input', () => {
    const q = sourcesSearch.value.toLowerCase();
    document.querySelectorAll('.source').forEach(el => {
      const name = el.querySelector('.source-name').textContent.toLowerCase();
      const desc = el.querySelector('.source-desc').textContent.toLowerCase();
      el.classList.toggle('source-hidden', q.length > 0 && !name.includes(q) && !desc.includes(q));
    });
  });

  boxes.forEach(b => b.addEventListener('change', () => {
    refreshSelection();
    vscode.postMessage({ type: 'saveState', selectedSources: getSelected(), scanMode: currentScope });
  }));

  allBtn.addEventListener('click', () => {
    boxes.forEach(b => { if (!b.disabled) b.checked = true; });
    refreshSelection();
    vscode.postMessage({ type: 'saveState', selectedSources: getSelected(), scanMode: currentScope });
  });
  noneBtn.addEventListener('click', () => {
    boxes.forEach(b => { b.checked = false; });
    refreshSelection();
    vscode.postMessage({ type: 'saveState', selectedSources: getSelected(), scanMode: currentScope });
  });

  // ── Scope ──
  function setScope(scope) {
    currentScope = scope;
    scopeBtns.forEach(b => b.classList.toggle('active', b.dataset.scope === scope));
    saveState();
    vscode.postMessage({ type: 'saveState', selectedSources: getSelected(), scanMode: scope });
  }
  scopeBtns.forEach(b => b.addEventListener('click', () => setScope(b.dataset.scope)));
  setScope(currentScope); // restore

  // ── Group by ──
  document.querySelectorAll('.group-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.group === groupBy);
    btn.addEventListener('click', () => {
      groupBy = btn.dataset.group;
      document.querySelectorAll('.group-btn').forEach(b => b.classList.toggle('active', b.dataset.group === groupBy));
      saveState();
      if (currentReport) renderFindings(currentReport.findings);
    });
  });

  // ── Severity pills ──
  sevPills.querySelectorAll('.sev-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      filterSev = pill.dataset.sev;
      sevPills.querySelectorAll('.sev-pill').forEach(p => p.classList.toggle('active', p.dataset.sev === filterSev));
      if (currentReport) renderFindings(currentReport.findings);
    });
  });

  // ── Filter search ──
  filterSearch.addEventListener('input', () => {
    filterText = filterSearch.value.toLowerCase();
    if (currentReport) renderFindings(currentReport.findings);
  });

  // ── Scan / cancel ──
  guiBtn.addEventListener('click', () => vscode.postMessage({ type: 'openGui' }));
  tbGuiBtn.addEventListener('click', () => vscode.postMessage({ type: 'openGui' }));

  function doScan(mode) {
    const sources = getSelected();
    if (!sources.length) { setStatus('Select at least one rule database.', 'error'); return; }
    setRunning(true);
    setStatus('Running CommitGuard scan…', '');
    vscode.postMessage({ type: 'runScan', sources, mode: mode || currentScope });
  }

  scanBtn.addEventListener('click', () => doScan(currentScope));
  tbStagedBtn.addEventListener('click', () => doScan('staged'));
  tbRepoBtn.addEventListener('click', () => doScan('repo'));

  cancelBtn.addEventListener('click', () => {
    cancelBtn.disabled = true;
    setStatus('Cancelling scan…', '');
    vscode.postMessage({ type: 'cancelScan' });
  });

  exportBtn.addEventListener('click', () => vscode.postMessage({ type: 'exportResults' }));

  // ── Render badges ──
  function renderBadges(report) {
    badgesEl.replaceChildren();
    const makeBadge = (label, value, cls) => {
      const s = document.createElement('span');
      s.className = 'badge' + (cls ? ' ' + cls : '');
      s.textContent = label + ': ' + value;
      return s;
    };
    badgesEl.appendChild(makeBadge('Total', report.total, ''));
    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      const c = report.summary[sev] || 0;
      if (c) badgesEl.appendChild(makeBadge(sev, c, sev));
    }
  }

  // ── Render findings ──
  function applyFilters(findings) {
    return findings.filter(f => {
      if (filterSev !== 'all' && f.severity !== filterSev) return false;
      if (filterText) {
        const haystack = (f.rule_id + ' ' + f.file + ' ' + f.description + ' ' + f.source).toLowerCase();
        if (!haystack.includes(filterText)) return false;
      }
      return true;
    });
  }

  function makeFindingCard(finding) {
    const card = document.createElement('div');
    card.className = 'finding-card';
    card.dataset.sev = finding.severity;

    const main = document.createElement('button');
    main.type = 'button';
    main.className = 'finding-main';

    const top = document.createElement('div');
    top.className = 'finding-top';

    const badge = document.createElement('span');
    badge.className = 'badge ' + finding.severity;
    badge.textContent = finding.severity;

    const rule = document.createElement('span');
    rule.className = 'finding-rule';
    rule.textContent = finding.rule_id;

    const loc = document.createElement('span');
    loc.className = 'finding-loc';
    loc.textContent = finding.file.split('/').pop() + ':' + finding.line;
    loc.title = finding.file + ':' + finding.line;
    loc.addEventListener('click', e => {
      e.stopPropagation();
      vscode.postMessage({ type: 'openFinding', file: finding.file, line: finding.line, column: finding.column });
    });

    top.append(badge, rule, loc);

    const desc = document.createElement('div');
    desc.className = 'finding-desc';
    desc.textContent = finding.description || 'CommitGuard finding';

    const meta = document.createElement('div');
    meta.className = 'finding-meta';
    meta.textContent = finding.source + (finding.category ? ' · ' + finding.category : '');

    main.append(top, desc, meta);
    main.addEventListener('click', () => {
      desc.classList.toggle('expanded');
      vscode.postMessage({ type: 'openFinding', file: finding.file, line: finding.line, column: finding.column });
    });

    const actions = document.createElement('div');
    actions.className = 'finding-actions';

    const openBtn = document.createElement('button');
    openBtn.className = 'btn-micro';
    openBtn.textContent = 'Open';
    openBtn.addEventListener('click', () => {
      vscode.postMessage({ type: 'openFinding', file: finding.file, line: finding.line, column: finding.column });
    });

    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn-micro';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => {
      const text = '[' + finding.severity.toUpperCase() + '] ' + finding.rule_id + ' in ' + finding.file + ':' + finding.line + '\\n' + finding.description;
      navigator.clipboard.writeText(text).catch(() => {});
    });

    const suppressBtn = document.createElement('button');
    suppressBtn.className = 'btn-micro';
    suppressBtn.textContent = 'Suppress';
    suppressBtn.addEventListener('click', () => {
      vscode.postMessage({ type: 'suppressFinding', file: finding.file, line: finding.line, ruleId: finding.rule_id });
    });

    actions.append(openBtn, copyBtn, suppressBtn);
    card.append(main, actions);
    return card;
  }

  function renderFindings(allFindings) {
    findingsEl.replaceChildren();
    const filtered = applyFilters(allFindings);

    if (!filtered.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      if (allFindings.length === 0) {
        const svgNs = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(svgNs, 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('fill', 'none');
        const shield = document.createElementNS(svgNs, 'path');
        shield.setAttribute('d', 'M12 2.5 4.5 5.6v5.2c0 4.7 3.1 9 7.5 10.7 4.4-1.7 7.5-6 7.5-10.7V5.6L12 2.5Z');
        shield.setAttribute('stroke', 'currentColor');
        shield.setAttribute('stroke-width', '1.5');
        shield.setAttribute('stroke-linejoin', 'round');
        const check = document.createElementNS(svgNs, 'path');
        check.setAttribute('d', 'm8.5 12 2.3 2.3 4.7-4.8');
        check.setAttribute('stroke', 'currentColor');
        check.setAttribute('stroke-width', '1.5');
        check.setAttribute('stroke-linecap', 'round');
        check.setAttribute('stroke-linejoin', 'round');
        svg.append(shield, check);
        const title = document.createElement('span');
        title.className = 'empty-title';
        title.textContent = 'All clear!';
        const detail = document.createElement('p');
        detail.textContent = 'No findings — your code looks clean!';
        empty.append(svg, title, detail);
      } else {
        const detail = document.createElement('p');
        detail.textContent = 'No findings match the current filter.';
        empty.appendChild(detail);
      }
      findingsEl.appendChild(empty);
      return;
    }

    if (groupBy === 'flat') {
      filtered.forEach(f => findingsEl.appendChild(makeFindingCard(f)));
    } else if (groupBy === 'file') {
      const groups = {};
      filtered.forEach(f => { (groups[f.file] = groups[f.file] || []).push(f); });
      for (const [file, items] of Object.entries(groups).sort(([a], [b]) => a.localeCompare(b))) {
        const title = document.createElement('div');
        title.className = 'group-title';
        title.textContent = file + ' (' + items.length + ')';
        findingsEl.appendChild(title);
        items.forEach(f => findingsEl.appendChild(makeFindingCard(f)));
      }
    } else {
      const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
      const groups = {};
      filtered.forEach(f => { (groups[f.severity] = groups[f.severity] || []).push(f); });
      for (const sev of sevOrder) {
        const items = groups[sev];
        if (!items) continue;
        const title = document.createElement('div');
        title.className = 'group-title';
        title.textContent = sev.toUpperCase() + ' (' + items.length + ')';
        findingsEl.appendChild(title);
        items.forEach(f => findingsEl.appendChild(makeFindingCard(f)));
      }
    }
  }

  function renderReport(report, sources, mode, durationMs) {
    currentReport = report;
    currentSources = sources || [];
    currentMode = mode || 'repo';
    renderBadges(report);
    renderFindings(report.findings);
    resultsEl.classList.remove('hidden');
    const srcLabel = currentSources.length === 1 ? currentSources[0] : currentSources.length + ' databases';
    const scopeLabel = currentMode === 'staged' ? 'staged changes' : 'whole repository';
    const dur = durationMs ? ' · ' + (durationMs / 1000).toFixed(1) + 's' : '';
    const count = report.total;
    setStatus(
      count === 0
        ? '✓ Clean scan of ' + scopeLabel + dur
        : count + ' finding(s) in ' + scopeLabel + dur,
      count === 0 ? 'ok' : ''
    );
  }

  // ── History ──
  function formatRelativeTime(isoStr) {
    const diff = Date.now() - new Date(isoStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    return Math.floor(hrs / 24) + 'd ago';
  }

  function renderHistory() {
    historyList.replaceChildren();
    if (!scanHistory.length) {
      const empty = document.createElement('div');
      empty.className = 'history-empty';
      empty.textContent = 'No scan history yet.';
      historyList.appendChild(empty);
      return;
    }
    scanHistory.slice(0, 5).forEach(entry => {
      const card = document.createElement('div');
      card.className = 'history-card';

      const top = document.createElement('div');
      top.className = 'history-card-top';
      const ts = document.createElement('span');
      ts.className = 'history-ts';
      ts.textContent = formatRelativeTime(entry.timestamp);
      const mode = document.createElement('span');
      mode.className = 'history-mode';
      mode.textContent = entry.mode;
      top.append(ts, mode);

      const badges = document.createElement('div');
      badges.className = 'history-badges';
      const totalB = document.createElement('span');
      totalB.className = 'badge';
      totalB.textContent = 'Total: ' + entry.report.total;
      badges.appendChild(totalB);
      for (const sev of ['critical', 'high', 'medium']) {
        const c = entry.report.summary[sev] || 0;
        if (c) {
          const b = document.createElement('span');
          b.className = 'badge ' + sev;
          b.textContent = sev + ': ' + c;
          badges.appendChild(b);
        }
      }

      const meta = document.createElement('div');
      meta.className = 'history-meta';
      const dur = entry.durationMs ? (entry.durationMs / 1000).toFixed(1) + 's' : '';
      meta.textContent = entry.sources.length + ' db(s)' + (dur ? ' · ' + dur : '') + ' · ' + new Date(entry.timestamp).toLocaleString();

      card.append(top, badges, meta);
      card.addEventListener('click', () => {
        // Switch to scan tab and restore this result
        tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === 'scan'));
        panels.forEach(p => p.classList.toggle('active', p.id === 'panel-scan'));
        renderReport(entry.report, entry.sources, entry.mode, entry.durationMs);
      });
      historyList.appendChild(card);
    });
  }

  // ── Message handler ──
  window.addEventListener('message', event => {
    const msg = event.data;
    if (!msg || !msg.type) return;

    if (msg.type === 'init') {
      // Restore persisted state from extension
      if (msg.workspace) workspaceLabel.textContent = msg.workspace;
      if (msg.selectedSources && Array.isArray(msg.selectedSources)) {
        boxes.forEach(b => { b.checked = msg.selectedSources.includes(b.dataset.source); });
        refreshSelection();
        if (msg.selectedSources.length > 0) {
          sourcesCollapsed = true;
          applySourcesCollapsed();
        }
      }
      if (msg.scanMode) setScope(msg.scanMode);
      if (msg.history) scanHistory = msg.history;
      if (msg.lastReport) {
        renderReport(msg.lastReport, [], msg.scanMode || 'repo', 0);
        setStatus('Restored last scan results.', '');
      }
    } else if (msg.type === 'scanStarted') {
      setRunning(true);
      setStatus('Running CommitGuard scan…', '');
    } else if (msg.type === 'scanResult') {
      cancelBtn.disabled = false;
      setRunning(false);
      if (msg.history) scanHistory = msg.history;
      renderReport(msg.report, msg.sources || [], msg.mode, msg.durationMs);
    } else if (msg.type === 'scanError') {
      cancelBtn.disabled = false;
      setRunning(false);
      setStatus(msg.message || 'Scan failed.', 'error');
    } else if (msg.type === 'triggerScan') {
      // Triggered programmatically from extension commands
      if (msg.sources && Array.isArray(msg.sources)) {
        boxes.forEach(b => { b.checked = msg.sources.includes(b.dataset.source); });
        refreshSelection();
      }
      if (msg.mode) setScope(msg.mode);
    } else if (msg.type === 'clearResults') {
      currentReport = null;
      resultsEl.classList.add('hidden');
      findingsEl.replaceChildren();
      badgesEl.replaceChildren();
      setStatus('Results cleared.', '');
    }
  });

  // ── Init ──
  refreshSelection();
})();
</script>
</body>
</html>`;
  }
}
