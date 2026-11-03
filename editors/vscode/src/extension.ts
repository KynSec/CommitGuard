import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  Middleware,
  ServerOptions,
  Trace,
  TransportKind,
} from "vscode-languageclient/node";

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
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;

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

function workspaceFolder(): vscode.WorkspaceFolder | undefined {
  const activeDocument = vscode.window.activeTextEditor?.document;
  return (
    (activeDocument &&
      vscode.workspace.getWorkspaceFolder(activeDocument.uri)) ||
    vscode.workspace.workspaceFolders?.[0]
  );
}

function serverOptions(): ServerOptions {
  const configuration = vscode.workspace.getConfiguration("commitguard");
  const executable = configuration
    .get<string>("executable", "commit-guard")
    .trim();
  if (!executable) {
    throw new Error(
      "Set commitguard.executable to the CommitGuard CLI executable.",
    );
  }
  const extraArgs = configuration.get<unknown>("extraArgs", []);
  if (
    !Array.isArray(extraArgs) ||
    !extraArgs.every((arg) => typeof arg === "string")
  ) {
    throw new Error("commitguard.extraArgs must be an array of strings.");
  }
  const folder = workspaceFolder();
  const args = [...extraArgs, "lsp"];
  if (folder) args.push(folder.uri.fsPath);
  const options = folder ? { cwd: folder.uri.fsPath } : undefined;
  return {
    run: {
      command: executable,
      args,
      options,
      transport: TransportKind.stdio,
    },
    debug: {
      command: executable,
      args,
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

async function showStartupError(error: unknown): Promise<void> {
  const message = String(error);
  output.appendLine(`Language server failed to start: ${message}`);
  status.text = "$(error) CommitGuard";
  status.tooltip = "CommitGuard language server failed to start";
  status.command = "commitguard.restartServer";
  const action = await vscode.window.showErrorMessage(
    `CommitGuard could not start its language server. Check the CommitGuard output for details. ${message}`,
    "Show Output",
    "Open Settings",
    "Retry",
  );
  if (action === "Show Output") output.show(true);
  if (action === "Open Settings") {
    await vscode.commands.executeCommand(
      "workbench.action.openSettings",
      "commitguard.executable",
    );
  }
  if (action === "Retry") setTimeout(() => void startServer(), 0);
}

async function startServer(): Promise<void> {
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
      status.tooltip = "CommitGuard language server is running";
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
      await showStartupError(error);
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

async function explainFinding(
  ruleId: string,
  fingerprint: string,
): Promise<void> {
  output.appendLine(`Finding: ${ruleId}`);
  output.appendLine(`Fingerprint: ${fingerprint}`);
  output.show(true);
  await vscode.window.showInformationMessage(
    `CommitGuard finding: ${ruleId}. Details are in the CommitGuard output.`,
  );
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  output = vscode.window.createOutputChannel("CommitGuard");
  status = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    10,
  );
  status.command = "commitguard.restartServer";
  status.text = "$(sync~spin) CommitGuard";
  status.tooltip = "Starting CommitGuard language server";
  status.show();

  context.subscriptions.push(
    output,
    status,
    vscode.commands.registerCommand("commitguard.restartServer", startServer),
    vscode.commands.registerCommand("commitguard.explain", explainFinding),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("commitguard")) {
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

  await startServer();
}

export async function deactivate(): Promise<void> {
  if (client) {
    await client.stop();
    client = undefined;
  }
}
