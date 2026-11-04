# CommitGuard VS Code Extension

The extension connects VS Code to the CommitGuard stdio language server. It
provides live diagnostics and safe quick fixes for Python, JavaScript,
TypeScript, Go, Rust, Java, C/C++, C#, Ruby, PHP, YAML, JSON, Dockerfiles, and
shell scripts.

It also adds a **CommitGuard** Activity Bar view with:

- checkboxes for each rule database (`custom`, `gitleaks`, `nuclei`, `devskim`,
  `semgrep`, `semgrep:semgrep_python`, `python_ast`, `javascript_ast`);
- whole-repository or staged-changes scan scope;
- a **Run selected scan** button that passes each chosen database as
  `--rule-source` and shows findings in the panel;
- clickable findings that open the file at the reported line;
- an **Open CommitGuard GUI** button that runs `./commit-guard gui` in an
  integrated terminal.

Use **CommitGuard: Open Scan Panel** from the Command Palette if the view is
hidden.

## Development

```bash
npm install
npm run compile
npm test
npm run package
```

Open this folder in VS Code and press `F5` to launch an Extension Development
Host. Install CommitGuard first (`python -m pip install commit-guard`). The
extension starts CommitGuard's stdio language server in the workspace root.

The launcher is auto-detected in this order:

1. `commitguard.executable`, if set.
2. The repository's `commit-guard` / `commit-guard.cmd` wrapper.
3. A Python interpreter from `commitguard.pythonPath`, the Python extension's
   selected interpreter, a workspace `.venv`/`venv`/`env`, or `py -3` /
   `python3` / `python`, verified with `-m install_hook`.
4. `commit-guard` on `PATH`.

If detection fails, the error lists every command that was checked. Set
`commitguard.pythonPath` to the interpreter that has CommitGuard installed, or
set `commitguard.executable` to the absolute launcher path. The extension does
not use a terminal and inherits VS Code's environment, so a virtualenv that is
only activated in a shell is not visible until you point at its Python
executable.

The language server provides CommitGuard diagnostics and quick fixes over the
Language Server Protocol. It is not an autocomplete or type-checking server.
For safety, the extension does not run in untrusted workspaces.

Changes are debounced while typing and scanned after a short pause. The
CommitGuard status item can restart the server; server output and quick-fix
explanations are available in the **CommitGuard** output channel. If startup
fails, use **Open Settings** in the error message to correct the executable or
Python path.

The `commitguard.trace.server` setting controls LSP logging. Changes to
CommitGuard settings restart the server automatically.
