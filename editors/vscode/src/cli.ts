import { spawn, spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

export interface CliLaunch {
  command: string;
  args: string[];
  cwd?: string;
  label: string;
  windowsVerbatimArguments?: boolean;
}

interface NormalizedLaunch {
  command: string;
  args: string[];
  windowsVerbatimArguments?: boolean;
}

interface PythonCandidate {
  command: string;
  prefix: string[];
}

export interface CliResult {
  code: number;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

export function workspaceFolder(): vscode.WorkspaceFolder | undefined {
  const activeDocument = vscode.window.activeTextEditor?.document;
  return (
    (activeDocument &&
      vscode.workspace.getWorkspaceFolder(activeDocument.uri)) ||
    vscode.workspace.workspaceFolders?.[0]
  );
}

function settingString(key: string): string {
  const value = vscode.workspace
    .getConfiguration("commitguard")
    .get<unknown>(key, "");
  return typeof value === "string" ? value.trim() : "";
}

export function extraArgs(): string[] {
  const value = vscode.workspace
    .getConfiguration("commitguard")
    .get<unknown>("extraArgs", []);
  if (!Array.isArray(value) || !value.every((arg) => typeof arg === "string")) {
    throw new Error("commitguard.extraArgs must be an array of strings.");
  }
  return value;
}

export function workspaceWrapper(
  folder: vscode.WorkspaceFolder | undefined,
): string | undefined {
  if (!folder) return undefined;
  const names =
    process.platform === "win32"
      ? ["commit-guard.cmd", "commit-guard.exe", "commit-guard.bat", "commit-guard"]
      : ["commit-guard"];
  for (const name of names) {
    const candidate = path.join(folder.uri.fsPath, name);
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // Keep looking.
    }
  }
  return undefined;
}

export function isTrustedWorkspace(): boolean {
  return vscode.workspace.isTrusted !== false;
}

function pythonFromSettings(): string[] {
  const result: string[] = [];
  const configured = settingString("pythonPath");
  if (configured) result.push(configured);
  if (!isTrustedWorkspace()) return result;
  try {
    const pythonConfig = vscode.workspace.getConfiguration("python");
    for (const key of ["defaultInterpreterPath", "pythonPath"]) {
      const value = pythonConfig.get<unknown>(key);
      if (typeof value === "string" && value.trim()) result.push(value.trim());
    }
  } catch {
    // The Python extension is optional.
  }
  return result;
}

function pythonCandidates(
  folder: vscode.WorkspaceFolder | undefined,
): PythonCandidate[] {
  const commands: PythonCandidate[] = pythonFromSettings().map((command) => ({
    command,
    prefix: [],
  }));
  if (folder && isTrustedWorkspace()) {
    const venvRoots = [".venv", "venv", "env"];
    const executables =
      process.platform === "win32"
        ? [path.join("Scripts", "python.exe")]
        : [path.join("bin", "python3"), path.join("bin", "python")];
    for (const root of venvRoots) {
      for (const executable of executables) {
        const candidate = path.join(folder.uri.fsPath, root, executable);
        try {
          if (fs.statSync(candidate).isFile()) {
            commands.push({ command: candidate, prefix: [] });
          }
        } catch {
          // Keep looking.
        }
      }
    }
  }
  if (process.platform === "win32") {
    commands.push({ command: "py", prefix: ["-3"] });
    commands.push({ command: "python", prefix: [] });
    commands.push({ command: "python3", prefix: [] });
  } else {
    commands.push({ command: "python3", prefix: [] });
    commands.push({ command: "python", prefix: [] });
  }
  const seen = new Set<string>();
  return commands.filter((candidate) => {
    const key = `${candidate.command}\u0000${candidate.prefix.join("\u0000")}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function probe(
  command: string,
  args: string[],
  windowsVerbatimArguments = false,
): boolean {
  try {
    const result = spawnSync(command, args, {
      timeout: 4000,
      windowsHide: true,
      windowsVerbatimArguments,
      stdio: "ignore",
    });
    return result.status === 0;
  } catch {
    return false;
  }
}

function probePython(candidate: PythonCandidate): boolean {
  return probe(candidate.command, [
    ...candidate.prefix,
    "-c",
    "import install_hook, core.lsp",
  ]);
}

function isWindowsScript(command: string): boolean {
  return process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
}

function quoteForCmd(value: string): string {
  if (!/[\s"&|<>^()]/.test(value)) return value;
  return `"${value.replace(/"/g, '""')}"`;
}

function normalizeLaunch(command: string, args: string[]): NormalizedLaunch {
  if (!isWindowsScript(command)) return { command, args };
  const commandLine = [command, ...args].map(quoteForCmd).join(" ");
  return {
    command: process.env.ComSpec || process.env.COMSPEC || "cmd.exe",
    args: ["/d", "/s", "/c", commandLine],
    windowsVerbatimArguments: true,
  };
}

export function resolveCliLaunch(args: string[]): CliLaunch {
  const folder = workspaceFolder();
  const cwd = folder?.uri.fsPath;
  const explicit = settingString("executable");
  if (explicit) {
    const normalized = normalizeLaunch(explicit, args);
    return {
      command: normalized.command,
      args: normalized.args,
      cwd,
      label: explicit,
      windowsVerbatimArguments: normalized.windowsVerbatimArguments,
    };
  }

  const checked: string[] = [];
  const wrapper = isTrustedWorkspace() ? workspaceWrapper(folder) : undefined;
  if (wrapper) {
    checked.push(wrapper);
    const probeLaunch = normalizeLaunch(wrapper, ["--version"]);
    if (
      probe(
        probeLaunch.command,
        probeLaunch.args,
        probeLaunch.windowsVerbatimArguments,
      )
    ) {
      const normalized = normalizeLaunch(wrapper, args);
      return {
        command: normalized.command,
        args: normalized.args,
        cwd,
        label: wrapper,
        windowsVerbatimArguments: normalized.windowsVerbatimArguments,
      };
    }
  }

  for (const candidate of pythonCandidates(folder)) {
    const label = [...candidate.prefix, candidate.command].join(" ");
    checked.push(`${label} -m install_hook`);
    if (probePython(candidate)) {
      return {
        command: candidate.command,
        args: [...candidate.prefix, "-m", "install_hook", ...args],
        cwd,
        label: `${label} -m install_hook`,
      };
    }
  }

  for (const command of ["commit-guard", "commit-guard.exe", "commit-guard.cmd"]) {
    checked.push(command);
    const probeLaunch = normalizeLaunch(command, ["--version"]);
    if (
      probe(
        probeLaunch.command,
        probeLaunch.args,
        probeLaunch.windowsVerbatimArguments,
      )
    ) {
      const normalized = normalizeLaunch(command, args);
      return {
        command: normalized.command,
        args: normalized.args,
        cwd,
        label: command,
        windowsVerbatimArguments: normalized.windowsVerbatimArguments,
      };
    }
  }

  throw new Error(
    "Could not locate the CommitGuard command. Install it with " +
      "`python -m pip install commit-guard`, add the launcher to PATH, or set " +
      "`commitguard.executable` to its absolute path. Checked: " +
      checked.join(", "),
  );
}

export function serverLaunch(): CliLaunch {
  const folder = workspaceFolder();
  const args = [...extraArgs(), "lsp"];
  if (folder) args.push(folder.uri.fsPath);
  return resolveCliLaunch(args);
}

export function formatShellCommand(launch: CliLaunch): string {
  if (launch.windowsVerbatimArguments) {
    return [launch.command, ...launch.args].join(" ");
  }
  const quote = (value: string): string => {
    if (!/[\s"&|<>^()$`'\\]/.test(value)) return value;
    if (process.platform === "win32") {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return `'${value.replace(/'/g, "'\\''")}'`;
  };
  return [launch.command, ...launch.args].map(quote).join(" ");
}

export function runCli(
  args: string[],
  cwd: string | undefined,
  token?: vscode.CancellationToken,
): Promise<CliResult> {
  const launch = resolveCliLaunch(args);
  return new Promise<CliResult>((resolve, reject) => {
    const child = spawn(launch.command, launch.args, {
      cwd: cwd ?? launch.cwd,
      env: process.env,
      windowsHide: true,
      windowsVerbatimArguments: launch.windowsVerbatimArguments,
    });
    const limit = 2 * 1024 * 1024;
    let stdout = "";
    let stderr = "";
    let cancelled = false;
    const cancellation = token?.onCancellationRequested(() => {
      cancelled = true;
      child.kill();
    });
    child.stdout?.on("data", (chunk: Buffer) => {
      if (stdout.length < limit) stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < limit) stderr += chunk.toString();
    });
    child.on("error", (error) => {
      cancellation?.dispose();
      reject(error);
    });
    child.on("close", (code, signal) => {
      cancellation?.dispose();
      if (cancelled) {
        reject(new Error("Scan cancelled."));
        return;
      }
      resolve({ code: code ?? -1, signal, stdout, stderr });
    });
  });
}
