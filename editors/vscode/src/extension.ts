import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

function serverOptions(): ServerOptions {
  const configuration = vscode.workspace.getConfiguration("commitguard");
  const executable = configuration.get<string>("executable", "commit-guard");
  const extraArgs = configuration.get<string[]>("extraArgs", []);
  const args = [...extraArgs, "lsp"];
  return {
    run: { command: executable, args, transport: TransportKind.stdio },
    debug: { command: executable, args, transport: TransportKind.stdio },
  };
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "python" },
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescriptreact" },
    ],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher(
        "**/*.{py,pyi,js,jsx,ts,tsx}",
      ),
    },
  };

  client = new LanguageClient(
    "commitguard",
    "CommitGuard",
    serverOptions(),
    clientOptions,
  );

  try {
    await client.start();
  } catch (error) {
    void vscode.window.showErrorMessage(
      "CommitGuard language server failed to start: " + String(error),
    );
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("commitguard.restartServer", async () => {
      if (client) {
        await client.stop();
      }
      client = new LanguageClient(
        "commitguard",
        "CommitGuard",
        serverOptions(),
        clientOptions,
      );
      await client.start();
    }),
  );

  context.subscriptions.push({
    dispose: () => {
      void client?.stop();
    },
  });
}

export async function deactivate(): Promise<void> {
  if (client) {
    await client.stop();
    client = undefined;
  }
}
