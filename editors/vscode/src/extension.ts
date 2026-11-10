import * as path from "path";
import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  Middleware,
  ServerOptions,
  Trace,
  TransportKind,
} from "vscode-languageclient/node";
import { serverLaunch, workspaceFolder } from "./cli";
import { ScanPanelProvider } from "./panel";

const LANGUAGE_IDS = [
  "python",
  "javascript",
  "typescript",
  "javascriptreact",
  "typescriptreact",
  "go",
  "rust",
  "java",
  "c",
  "cpp",
  "csharp",
  "ruby",
  "php",
  "yaml",
  "json",
  "dockerfile",
  "shellscript",
];
const CHANGE_DEBOUNCE_MS = 250;

let client: LanguageClient | undefined;
let startPromise: Promise<void> | undefined;
let restartAfterStart = false;
let startupRequested = false;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;

// Exported so panel.ts can call it after a scan completes.
export function setStatusFindingCount(count: number): void {
  const cfg = vscode.workspace.getConfiguration("commitguard");
  const show = cfg.get<boolean>("showFindingCount", true);
  if (show) {
    status.text =
      count === 0
        ? "$(shield) CommitGuard · ✓ Clean"
        : `$(shield) CommitGuard · ${count} issue${count === 1 ? "" : "s"}`;
  } else {
    status.text = "$(shield) CommitGuard";
  }
  status.tooltip = "Open the CommitGuard scan panel";
  status.command = "commitguard.openPanel";
}

interface PendingChange {
  event: vscode.TextDocumentChangeEvent;
  next: (event: vscode.TextDocumentChangeEvent) => Promise<void>;
  timer: ReturnType<typeof setTimeout>;
  resolve: () => void;
  reject: (error: unknown) => void;
}

function createChangeMiddleware(): Middleware {
  const pending = new Map<string, PendingChange>();

  const flush = async (uri: string): Promise<void> => {
    const change = pending.get(uri);
    if (!change) return;
    clearTimeout(change.timer);
    pending.delete(uri);
    try {
      await change.next(change.event);
      change.resolve();
    } catch (error) {
      change.reject(error);
      throw error;
    }
  };

  const cancel = (uri: string): void => {
    const change = pending.get(uri);
    if (!change) return;
    clearTimeout(change.timer);
    pending.delete(uri);
    change.resolve();
  };

  return {
    didChange: (event, next) => {
      const uri = event.document.uri.toString();
      cancel(uri);
      return new Promise<void>((resolve, reject) => {
        const change: PendingChange = {
          event,
          next,
          timer: setTimeout(() => {
            void flush(uri).catch((error: unknown) => {
              output.appendLine(
                `Failed to send document changes: ${String(error)}`,
              );
            });
          }, CHANGE_DEBOUNCE_MS),
          resolve,
          reject,
        };
        pending.set(uri, change);
      });
    },
    didSave: async (event, next) => {
      await flush(event.uri.toString());
      await next(event);
    },
    didClose: async (event, next) => {
      cancel(event.uri.toString());
      await next(event);
    },
  };
}

function serverOptions(): ServerOptions {
  const launch = serverLaunch();
  const options =
    launch.cwd || launch.windowsVerbatimArguments
      ? {
          cwd: launch.cwd,
          windowsVerbatimArguments: launch.windowsVerbatimArguments,
        }
      : undefined;
  return {
    run: {
      command: launch.command,
      args: launch.args,
      options,
      transport: TransportKind.stdio,
    },
    debug: {
      command: launch.command,
      args: launch.args,
      options,
      transport: TransportKind.stdio,
    },
  };
}

function clientOptions(): LanguageClientOptions {
  const folder = workspaceFolder();
  return {
    documentSelector: LANGUAGE_IDS.map((language) => ({
      scheme: "file",
      language,
    })),
    workspaceFolder: folder,
    middleware: createChangeMiddleware(),
    outputChannel: output,
    connectionOptions: { maxRestartCount: 3 },
  };
}

function supportsDocument(
  document: vscode.TextDocument | undefined,
): boolean {
  return !!document && LANGUAGE_IDS.includes(document.languageId);
}

function requestServerStart(document: vscode.TextDocument | undefined): void {
  if (startupRequested || !supportsDocument(document)) return;
  startupRequested = true;
  setTimeout(() => void startServer(), 0);
}

function showStartupError(error: unknown): void {
  const message = String(error);
  output.appendLine(`Language server failed to start: ${message}`);
  status.text = "$(error) CommitGuard";
  status.tooltip = "CommitGuard language server failed to start";
  status.command = "commitguard.restartServer";
  void vscode.window
    .showErrorMessage(
      `CommitGuard could not start its language server. Check the CommitGuard output for details. ${message}`,
      "Show Output",
      "Open Settings",
      "Retry",
    )
    .then((action) => {
      if (action === "Show Output") output.show(true);
      if (action === "Open Settings") {
        void vscode.commands.executeCommand(
          "workbench.action.openSettings",
          "commitguard.executable",
        );
      }
      if (action === "Retry") setTimeout(() => void startServer(), 0);
    });
}

async function startServer(): Promise<void> {
  startupRequested = true;
  if (startPromise) return startPromise;
  startPromise = (async () => {
    status.text = "$(sync~spin) CommitGuard";
    status.tooltip = "Starting CommitGuard language server";
    status.command = "commitguard.restartServer";
    try {
      if (client) {
        await client.stop();
        client = undefined;
      }
      client = new LanguageClient(
        "commitguard",
        "CommitGuard",
        serverOptions(),
        clientOptions(),
      );
      const trace = vscode.workspace
        .getConfiguration("commitguard")
        .get<string>("trace.server", "off");
      await client.setTrace(
        trace === "verbose"
          ? Trace.Verbose
          : trace === "messages"
            ? Trace.Messages
            : Trace.Off,
      );
      await client.start();
      status.text = "$(shield) CommitGuard";
      status.tooltip = "Open the CommitGuard scan panel";
      status.command = "commitguard.openPanel";
      output.appendLine("Language server started.");
    } catch (error) {
      const failedClient = client;
      client = undefined;
      if (failedClient) {
        try {
          await failedClient.stop();
        } catch (stopError) {
          output.appendLine(`Could not stop failed client: ${String(stopError)}`);
        }
      }
      showStartupError(error);
    }
  })().finally(() => {
    startPromise = undefined;
    if (restartAfterStart) {
      restartAfterStart = false;
      setTimeout(() => void startServer(), 0);
    }
  });
  return startPromise;
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  output = vscode.window.createOutputChannel("CommitGuard");
  status = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    10,
  );
  status.command = "commitguard.openPanel";
  status.text = "$(shield) CommitGuard";
  status.tooltip = "Open the CommitGuard scan panel";
  status.show();

  const panel = new ScanPanelProvider(context, output, setStatusFindingCount);
  context.subscriptions.push(
    output,
    status,
    vscode.window.registerWebviewViewProvider(
      ScanPanelProvider.viewType,
      panel,
      { webviewOptions: { retainContextWhenHidden: true } },
    ),
    vscode.commands.registerCommand("commitguard.openPanel", () =>
      panel.focus(),
    ),
    vscode.commands.registerCommand("commitguard.openGui", () =>
      panel.openGui(),
    ),
    vscode.commands.registerCommand("commitguard.restartServer", startServer),

    // New commands
    vscode.commands.registerCommand("commitguard.scanCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        await vscode.window.showWarningMessage(
          "CommitGuard: Open a file before scanning the current file.",
        );
        return;
      }
      const folder = vscode.workspace.getWorkspaceFolder(editor.document.uri);
      if (!folder) {
        await vscode.window.showWarningMessage(
          "CommitGuard: The current file is outside the workspace.",
        );
        return;
      }
      const relative = path.relative(folder.uri.fsPath, editor.document.uri.fsPath);
      if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
        await vscode.window.showWarningMessage(
          "CommitGuard: The current file is outside the workspace.",
        );
        return;
      }
      panel.triggerScan("repo", undefined, relative.split(path.sep).join("/"));
    }),
    vscode.commands.registerCommand("commitguard.scanStaged", () =>
      panel.triggerScan("staged"),
    ),
    vscode.commands.registerCommand("commitguard.scanRepo", () =>
      panel.triggerScan("repo"),
    ),
    vscode.commands.registerCommand("commitguard.showDashboard", () =>
      panel.focus(),
    ),
    vscode.commands.registerCommand("commitguard.exportResults", () =>
      panel.exportResults(),
    ),
    vscode.commands.registerCommand("commitguard.clearResults", () =>
      panel.clearResults(),
    ),

    // Scan-on-save
    vscode.workspace.onDidSaveTextDocument((document) => {
      const cfg = vscode.workspace.getConfiguration("commitguard");
      const scanOnSave = cfg.get<boolean>("scanOnSave", false);
      if (!scanOnSave || !vscode.workspace.isTrusted) return;
      const scope = cfg.get<string>("autoScanScope", "staged") === "repo" ? "repo" : "staged";
      panel.triggerScan(scope as "repo" | "staged");
      output.appendLine(`Auto-scan triggered on save: ${document.uri.fsPath}`);
    }),

    vscode.workspace.onDidOpenTextDocument((document) =>
      requestServerStart(document),
    ),
    vscode.window.onDidChangeActiveTextEditor((editor) =>
      requestServerStart(editor?.document),
    ),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (
        event.affectsConfiguration("commitguard") &&
        (startupRequested || startPromise)
      ) {
        if (startPromise) restartAfterStart = true;
        void startServer();
      }
    }),
    {
      dispose: () => {
        void client?.stop();
      },
    },
  );

  const activeDocument = vscode.window.activeTextEditor?.document;
  requestServerStart(
    supportsDocument(activeDocument)
      ? activeDocument
      : vscode.workspace.textDocuments.find((document) =>
          supportsDocument(document),
        ),
  );
}

export async function deactivate(): Promise<void> {
  if (client) {
    await client.stop();
    client = undefined;
  }
}
