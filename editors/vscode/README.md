# CommitGuard VS Code Extension

[CommitGuard](https://github.com/KynSec/CommitGuard) security diagnostics,
rule-database scans, and GUI launcher for VS Code. Everything runs locally and
offline against your own rule databases.

## Install

1. Install the
   [CommitGuard Security Scanner (KynSec)](https://marketplace.visualstudio.com/items?itemName=AmrKhaledEldhshan.commitguard-kynsec)
   extension from the VS Code Marketplace.
2. Install the CommitGuard CLI so the extension can launch the language server
   and scanner:

   ```bash
   pipx install commit-guard
   # or: python -m pip install commit-guard
   ```

3. Open a folder, trust the workspace, and open the **CommitGuard** icon in the
   Activity Bar.

If auto-detection cannot find the CLI, set `commitguard.executable` to the
absolute launcher path or `commitguard.pythonPath` to the Python interpreter
where CommitGuard is installed. To test a local build, run `npm run package` in
this directory and install the generated `.vsix` with **Extensions: Install from
VSIX...**.

## Quick start

1. Select one or more rule databases in the **Scan** view.
2. Choose **Whole repository** or **Staged changes only**.
3. Click **Run selected scan**.
4. Click a finding to jump to the file, line, and column.
5. Use **Open CommitGuard GUI** for the full desktop Control Center.

Use **CommitGuard: Open Scan Panel** from the Command Palette if the view is
hidden.

## Features

### Live diagnostics

The extension connects VS Code to the CommitGuard stdio language server and
provides live diagnostics and safe quick fixes for Python, JavaScript,
TypeScript, Go, Rust, Java, C/C++, C#, Ruby, PHP, YAML, JSON, Dockerfiles, and
shell scripts. Changes are debounced while typing and scanned after a short
pause.

The language server provides CommitGuard security diagnostics and quick fixes
over the Language Server Protocol. It is not an autocomplete or type-checking
server.

### Scan view

The **CommitGuard** Activity Bar view includes:

- checkboxes for each rule database (`custom`, `gitleaks`, `nuclei`, `devskim`,
  `semgrep`, `semgrep:semgrep_python`, `python_ast`, `javascript_ast`);
- whole-repository or staged-changes scan scope;
- a **Run selected scan** button that passes each chosen database as
  `--rule-source` and shows findings in the panel;
- clickable findings that open the file at the reported line and column;
- an **Open CommitGuard GUI** button that runs `commit-guard gui` in an
  integrated terminal.

Each scan runs against a temporary JSON report, so results stay local and are
not uploaded anywhere. Scans can be cancelled while they are running.

### Status and output

The CommitGuard status item shows server state and can restart the server.
Language-server output and quick-fix explanations are available in the
**CommitGuard** output channel.

## Commands

| Command | Description |
| --- | --- |
| `CommitGuard: Open Scan Panel` | Focus the rule-database scan view. |
| `CommitGuard: Open GUI` | Launch the CommitGuard desktop Control Center. |
| `CommitGuard: Restart Language Server` | Stop and restart the LSP server. |

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `commitguard.executable` | `""` | Absolute path or command for the CommitGuard CLI. Leave empty to auto-detect. |
| `commitguard.pythonPath` | `""` | Python interpreter used with `-m install_hook` when the launcher is not on `PATH`. |
| `commitguard.extraArgs` | `[]` | Extra arguments passed before the `lsp` subcommand. |
| `commitguard.trace.server` | `"off"` | LSP transport tracing: `off`, `messages`, or `verbose`. |

Changes to CommitGuard settings restart the language server automatically.

## Launcher detection

The extension resolves the CLI in this order:

1. `commitguard.executable`, if set.
2. The repository's `commit-guard` / `commit-guard.cmd` wrapper.
3. A Python interpreter from `commitguard.pythonPath` or the Python extension's
   selected interpreter, verified with `-m install_hook`.
4. `commit-guard` from pipx, `~/.local/bin`, Homebrew, pyenv, or per-user
   Windows/macOS Python script directories.
5. A Python interpreter from a workspace `.venv`/`venv`/`env`, common absolute
   install locations, or `py -3` / `python3` / `python`, verified with
   `-m install_hook`.
6. `commit-guard` on `PATH`.

A normal `pipx install commit-guard` works without any settings, even when VS
Code was launched without your shell's `PATH`. If detection fails, the error
lists every command that was checked. Set `commitguard.pythonPath` to the
interpreter that has CommitGuard installed, or set `commitguard.executable` to
the absolute launcher path. The extension does not use an activated shell, so a
virtualenv that is only active in a terminal is not visible until you point at
its Python executable.

For safety, the extension does not run in untrusted workspaces.

## Roadmap: scan view enhancements

These are planned improvements, not behavior in the current release:

- **Persist panel state per workspace** — remember selected rule databases,
  scan scope, last results, and scroll position across window reloads.
- **Filter and group findings** — search by rule, file, severity, or message;
  group by file or rule; show counts per database.
- **Per-finding actions** — Fix, Suppress, Open in GUI, Copy fingerprint, and
  Reveal in Explorer directly from the finding row.
- **Better scan workflow** — re-scan, show last-scan time and duration,
  optional scan-on-save, live progress, and clear staged-versus-repository
  summaries.
- **First-run and setup states** — detect a missing CLI and offer **Open
  Settings**, **Show Output**, **Retry**, and a short installation guide that
  lists the exact commands checked.
- **Quick actions** — scan the current file or staged files without opening the
  full panel.
- **Rule-database health** — show which databases are installed, recommended
  defaults, and missing optional dependencies.
- **Export results** — save findings as SARIF, JSON, Markdown, or HTML.
- **Status bar summary** — show the current finding count and open the scan
  view on click.
- **Open in Control Center** — jump from a finding to the matching entry in the
  CommitGuard desktop GUI.

## Troubleshooting

**"Could not locate the CommitGuard command"** — install the CLI with
`pipx install commit-guard` or `python -m pip install commit-guard`, then set
`commitguard.executable` to the absolute path of the launcher. Use **Show
Output** from the error notification for the full list of checked commands.

**The server starts but no diagnostics appear** — open a supported file in a
trusted workspace, check the **CommitGuard** output channel, and confirm the
CLI version supports `commit-guard lsp --stdio`.

**A virtualenv is not detected** — VS Code does not inherit a shell's activated
environment. Point `commitguard.pythonPath` at the virtualenv's Python
executable.

**Windows launchers** — `.cmd` and `.bat` wrappers are supported. If a wrapper
fails, set `commitguard.executable` to `commit-guard.cmd` or the Python
interpreter instead.

## Development

```bash
npm install
npm run compile
npm test
npm run package
```

Open this folder in VS Code and press `F5` to launch an Extension Development
Host. Install CommitGuard first (`pipx install commit-guard`). The extension
starts CommitGuard's stdio language server in the workspace root when a
supported file needs diagnostics. The bundled extension keeps activation and
the published VSIX small; tests still load the individually compiled modules
from `out/`.
