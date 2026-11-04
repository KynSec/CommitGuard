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
  ScanMode,
  ScanReport,
} from "./scan";

interface RunScanMessage {
  type: "runScan";
  sources?: unknown;
  mode?: unknown;
}

interface OpenFindingMessage {
  type: "openFinding";
  file?: unknown;
  line?: unknown;
  column?: unknown;
}

type PanelMessage =
  | RunScanMessage
  | OpenFindingMessage
  | { type: "openGui" }
  | { type: "cancelScan" }
  | { type: "selectAll"; selected?: unknown };

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

export class ScanPanelProvider implements vscode.WebviewViewProvider {
  static readonly viewType = "commitguard.scanView";

  private view: vscode.WebviewView | undefined;
  private scanToken: vscode.CancellationTokenSource | undefined;  // commit-guard-ignore: generic-api-key
  private guiTerminal: vscode.Terminal | undefined;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly output: vscode.OutputChannel,
  ) {}

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
  }

  focus(): void {
    void vscode.commands.executeCommand(`${ScanPanelProvider.viewType}.focus`);
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
    const temp = await fs.promises.mkdtemp(
      path.join(os.tmpdir(), "commitguard-scan-"),
    );
    const reportPath = path.join(temp, "report.json");
    const token = new vscode.CancellationTokenSource();
    this.scanToken = token;
    this.post({ type: "scanStarted", sources, mode });
    this.output.appendLine(
      `Running ${mode === "repo" ? "repository" : "staged"} scan with sources: ${sources.join(", ")}`,
    );
    try {
      const result = await runCli(
        buildScanArgs(folder.uri.fsPath, reportPath, sources, mode),
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
      this.post({ type: "scanResult", report, sources, mode });
      this.output.appendLine(
        `Scan finished: ${report.total} finding(s) from ${sources.join(", ")}.`,
      );
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

  private html(webview: vscode.Webview): string {
    const nonce = randomBytes(16).toString("base64");
    const folder = workspaceFolder();
    const workspace = folder
      ? escapeHtml(path.basename(folder.uri.fsPath))
      : "No folder open";
    const trusted = isTrustedWorkspace();
    const disabled = folder && trusted ? "" : " disabled";
    const sources = RULE_SOURCES.map(
      (source) => `
        <label class="source">
          <input type="checkbox" data-source="${escapeHtml(source.id)}"${disabled}>
          <span class="source-text">
            <span class="source-name">${escapeHtml(source.label)}</span>
            <span class="source-desc">${escapeHtml(source.description)}</span>
          </span>
        </label>`,
    ).join("");
    const warning = !folder
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
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 12px;
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--vscode-foreground);
    background: var(--vscode-sideBar-background);
  }
  h1 { display: flex; align-items: center; gap: 8px; margin: 0 0 2px; font-size: 15px; letter-spacing: -0.01em; }
  h1 svg { width: 20px; height: 20px; color: var(--vscode-focusBorder); }
  .workspace { color: var(--vscode-descriptionForeground); font-size: 11.5px; margin-bottom: 12px; }
  h2 { margin: 16px 0 7px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--vscode-descriptionForeground); }
  .row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .grow { flex: 1; }
  .count { font-size: 11px; color: var(--vscode-descriptionForeground); }
  .sources { display: flex; flex-direction: column; gap: 3px; }
  .source {
    display: flex; gap: 8px; align-items: flex-start;
    padding: 7px 8px; border-radius: 5px; cursor: pointer;
    border: 1px solid transparent;
  }
  .source:hover { background: var(--vscode-list-hoverBackground); }
  .source:has(input:checked) { border-color: var(--vscode-focusBorder); background: var(--vscode-list-inactiveSelectionBackground); }
  .source input { margin: 2px 0 0; accent-color: var(--vscode-button-background); }
  .source-text { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
  .source-name { font-weight: 600; }
  .source-desc { color: var(--vscode-descriptionForeground); font-size: 11px; line-height: 1.35; }
  select, button {
    font-family: inherit; font-size: 12px;
    color: var(--vscode-button-foreground); background: var(--vscode-button-background);
    border: 1px solid transparent; border-radius: 4px; padding: 6px 10px;
  }
  select {
    width: 100%; color: var(--vscode-dropdown-foreground);
    background: var(--vscode-dropdown-background); border-color: var(--vscode-dropdown-border);
  }
  button { cursor: pointer; }
  button:hover:not(:disabled) { background: var(--vscode-button-hoverBackground); }
  button:focus-visible, select:focus-visible, .source:has(input:focus-visible) { outline: 1px solid var(--vscode-focusBorder); outline-offset: 1px; }
  button:disabled { opacity: 0.55; cursor: default; }
  button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
  button.secondary:hover:not(:disabled) { background: var(--vscode-button-secondaryHoverBackground); }
  button.icon { padding: 4px 7px; color: var(--vscode-icon-foreground); background: transparent; }
  button.icon:hover:not(:disabled) { background: var(--vscode-toolbar-hoverBackground); }
  .actions { display: grid; grid-template-columns: 1fr auto; gap: 6px; margin-top: 10px; }
  .actions .danger { color: var(--vscode-errorForeground); background: var(--vscode-inputValidation-errorBackground); }
  .badges { display: flex; flex-wrap: wrap; gap: 5px; margin: 8px 0; }
  .badge {
    border-radius: 999px; padding: 2px 7px; font-size: 10.5px; font-weight: 600;
    background: var(--vscode-badge-background); color: var(--vscode-badge-foreground);
  }
  .badge.critical, .badge.high { background: var(--vscode-inputValidation-errorBackground); color: var(--vscode-errorForeground); }
  .badge.medium { background: var(--vscode-inputValidation-warningBackground); color: var(--vscode-editorWarning-foreground); }
  .badge.low, .badge.info { background: var(--vscode-inputValidation-infoBackground); color: var(--vscode-editorInfo-foreground); }
  .findings { display: flex; flex-direction: column; gap: 5px; margin-top: 6px; }
  .finding {
    display: block; width: 100%; text-align: left; padding: 8px;
    color: var(--vscode-foreground); background: var(--vscode-editor-background);
    border: 1px solid var(--vscode-sideBarSectionHeader-border, var(--vscode-panel-border));
    border-left: 3px solid var(--vscode-focusBorder);
    border-radius: 5px; cursor: pointer;
  }
  .finding:hover { background: var(--vscode-list-hoverBackground); }
  .finding-top { display: flex; gap: 6px; align-items: center; margin-bottom: 3px; }
  .finding-rule { font-weight: 600; font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .finding-loc { margin-left: auto; color: var(--vscode-textLink-foreground); font-size: 10.5px; white-space: nowrap; }
  .finding-desc { color: var(--vscode-descriptionForeground); font-size: 11px; line-height: 1.4; }
  .finding-meta { color: var(--vscode-descriptionForeground); font-size: 10px; margin-top: 3px; }
  .status { min-height: 17px; margin-top: 9px; color: var(--vscode-descriptionForeground); font-size: 11.5px; line-height: 1.4; }
  .status.error { color: var(--vscode-errorForeground); }
  .status.ok { color: var(--vscode-testing-iconPassed, var(--vscode-terminal-ansiGreen)); }
  .warning {
    padding: 8px; border-radius: 5px; margin-bottom: 10px;
    color: var(--vscode-inputValidation-warningForeground);
    background: var(--vscode-inputValidation-warningBackground);
    border: 1px solid var(--vscode-inputValidation-warningBorder);
    font-size: 11.5px;
  }
  .empty { padding: 18px 8px; text-align: center; color: var(--vscode-descriptionForeground); font-size: 11.5px; }
  .spinner { display: inline-block; width: 11px; height: 11px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: spin .8s linear infinite; vertical-align: -1px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .hidden { display: none !important; }
</style>
</head>
<body>
  <h1>
    <svg aria-hidden="true" viewBox="0 0 24 24" fill="none"><path d="M12 2.5 4.5 5.6v5.2c0 4.7 3.1 9 7.5 10.7 4.4-1.7 7.5-6 7.5-10.7V5.6L12 2.5Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="m8.5 12 2.3 2.3 4.7-4.8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
    CommitGuard
  </h1>
  <div class="workspace">${workspace}</div>
  ${warning}

  <h2>Rule databases</h2>
  <div class="row">
    <span class="count grow" id="selectedCount">0 selected</span>
    <button class="icon" id="allBtn" type="button" title="Select all"${disabled}>All</button>
    <button class="icon" id="noneBtn" type="button" title="Clear selection"${disabled}>Clear</button>
  </div>
  <div class="sources" id="sources">${sources}</div>

  <h2>Scan scope</h2>
  <select id="mode"${disabled}>
    <option value="repo">Whole repository</option>
    <option value="staged">Staged changes only</option>
  </select>

  <div class="actions">
    <button id="scanBtn" type="button"${disabled}>Run selected scan</button>
    <button id="cancelBtn" class="danger hidden" type="button">Cancel</button>
  </div>
  <div class="actions" style="grid-template-columns:1fr">
    <button id="guiBtn" class="secondary" type="button"${disabled}>Open CommitGuard GUI</button>
  </div>
  <div class="status" id="status">${folder && trusted ? "Select rule databases, then run a scan." : ""}</div>

  <div id="results" class="hidden">
    <h2>Results</h2>
    <div class="badges" id="badges"></div>
    <div class="findings" id="findings"></div>
  </div>

<script nonce="${nonce}">
(function () {
  const vscode = acquireVsCodeApi();
  const boxes = Array.from(document.querySelectorAll("input[data-source]"));
  const selectedCount = document.getElementById("selectedCount");
  const scanBtn = document.getElementById("scanBtn");
  const cancelBtn = document.getElementById("cancelBtn");
  const allBtn = document.getElementById("allBtn");
  const noneBtn = document.getElementById("noneBtn");
  const guiBtn = document.getElementById("guiBtn");
  const mode = document.getElementById("mode");
  const status = document.getElementById("status");
  const results = document.getElementById("results");
  const badges = document.getElementById("badges");
  const findings = document.getElementById("findings");
  let running = false;

  function selected() {
    return boxes.filter((box) => box.checked).map((box) => box.dataset.source);
  }

  function refreshSelection() {
    const count = selected().length;
    selectedCount.textContent = count + " selected";
    scanBtn.disabled = running || count === 0;
  }

  function setRunning(value) {
    running = value;
    scanBtn.disabled = value || selected().length === 0;
    cancelBtn.classList.toggle("hidden", !value);
    boxes.forEach((box) => { box.disabled = value; });
    allBtn.disabled = value;
    noneBtn.disabled = value;
  }

  function setStatus(text, kind) {
    status.textContent = text || "";
    status.className = "status" + (kind ? " " + kind : "");
  }

  function makeBadge(label, value, kind) {
    const node = document.createElement("span");
    node.className = "badge" + (kind ? " " + kind : "");
    node.textContent = label + ": " + value;
    return node;
  }

  function renderReport(report, sources, scanMode) {
    badges.textContent = "";
    findings.textContent = "";
    const order = ["critical", "high", "medium", "low", "info"];
    badges.appendChild(makeBadge("Total", report.total, ""));
    order.forEach((severity) => {
      const count = report.summary[severity] || 0;
      if (count) badges.appendChild(makeBadge(severity, count, severity));
    });
    const sourceLabel = sources.length === 1 ? sources[0] : sources.length + " databases";
    const scopeLabel = scanMode === "staged" ? "staged changes" : "whole repository";
    if (!report.findings.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No findings from " + sourceLabel + " in " + scopeLabel + ".";
      findings.appendChild(empty);
      setStatus("Clean scan.", "ok");
    } else {
      report.findings.forEach((finding) => {
        const item = document.createElement("button");
        item.type = "button";
        item.className = "finding";
        item.title = "Open " + finding.file + ":" + finding.line;
        const top = document.createElement("div");
        top.className = "finding-top";
        const kind = document.createElement("span");
        kind.className = "badge " + finding.severity;
        kind.textContent = finding.severity;
        const rule = document.createElement("span");
        rule.className = "finding-rule";
        rule.textContent = finding.rule_id;
        const location = document.createElement("span");
        location.className = "finding-loc";
        location.textContent = finding.file + ":" + finding.line;
        top.appendChild(kind);
        top.appendChild(rule);
        top.appendChild(location);
        const description = document.createElement("div");
        description.className = "finding-desc";
        description.textContent = finding.description || "CommitGuard finding";
        const meta = document.createElement("div");
        meta.className = "finding-meta";
        meta.textContent = finding.source + (finding.category ? " · " + finding.category : "");
        item.appendChild(top);
        item.appendChild(description);
        item.appendChild(meta);
        item.addEventListener("click", () => {
          vscode.postMessage({ type: "openFinding", file: finding.file, line: finding.line, column: finding.column });
        });
        findings.appendChild(item);
      });
      setStatus(report.total + " finding(s) from " + sourceLabel + " in " + scopeLabel + ".", report.total ? "" : "ok");
    }
    results.classList.remove("hidden");
  }

  boxes.forEach((box) => box.addEventListener("change", refreshSelection));
  allBtn.addEventListener("click", () => { boxes.forEach((box) => { box.checked = true; }); refreshSelection(); });
  noneBtn.addEventListener("click", () => { boxes.forEach((box) => { box.checked = false; }); refreshSelection(); });
  guiBtn.addEventListener("click", () => vscode.postMessage({ type: "openGui" }));
  scanBtn.addEventListener("click", () => {
    if (!selected().length) { setStatus("Select at least one rule database.", "error"); return; }
    setRunning(true);
    setStatus("Running CommitGuard scan...", "");
    vscode.postMessage({ type: "runScan", sources: selected(), mode: mode.value });
  });
  cancelBtn.addEventListener("click", () => {
    cancelBtn.disabled = true;
    setStatus("Cancelling scan...", "");
    vscode.postMessage({ type: "cancelScan" });
  });

  window.addEventListener("message", (event) => {
    const message = event.data;
    if (!message || !message.type) return;
    if (message.type === "scanStarted") {
      setRunning(true);
      setStatus("Running CommitGuard scan...", "");
    } else if (message.type === "scanResult") {
      cancelBtn.disabled = false;
      setRunning(false);
      renderReport(message.report, message.sources || [], message.mode);
    } else if (message.type === "scanError") {
      cancelBtn.disabled = false;
      setRunning(false);
      setStatus(message.message || "Scan failed.", "error");
    }
  });

  refreshSelection();
})();
</script>
</body>
</html>`;
  }
}
