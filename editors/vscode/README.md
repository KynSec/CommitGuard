# CommitGuard VS Code Extension

The extension connects VS Code to the CommitGuard stdio language server. It
provides live diagnostics and safe quick fixes for Python, JavaScript,
TypeScript, Go, Rust, Java, C/C++, C#, Ruby, PHP, YAML, JSON, Dockerfiles, and
shell scripts.

## Development

```bash
npm install
npm run compile
```

Open this folder in VS Code and press `F5` to launch an Extension Development
Host. Install CommitGuard first (`python -m pip install commit-guard`) and make
the `commit-guard` command available to VS Code. The extension starts
`commit-guard lsp <workspace>` from the workspace root.

If CommitGuard is not on `PATH`, set `commitguard.executable` to the absolute
path of its launcher. Alternatively, use your Python executable and set
`commitguard.extraArgs` to `["-m", "install_hook"]`.

Changes are debounced while typing and scanned after a short pause. The
CommitGuard status item can restart the server; server output and quick-fix
explanations are available in the **CommitGuard** output channel. If startup
fails, use **Open Settings** in the error message to correct the executable.

The `commitguard.trace.server` setting controls LSP logging. Changes to
CommitGuard settings restart the server automatically.
