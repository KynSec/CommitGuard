# CommitGuard VS Code Extension

This is the Phase 2 extension skeleton for the CommitGuard stdio language
server. It provides diagnostics and quick fixes through the same LSP server
used by other editors.

## Development

```bash
npm install
npm run compile
```

Open this folder in VS Code and press `F5` to launch an Extension Development
Host. The extension starts `commit-guard lsp` in the workspace root.

If CommitGuard is not on `PATH`, set `commitguard.executable` to the absolute
path of the `commit-guard` launcher created by `commit-guard install`.

## Scope

The skeleton covers document sync, diagnostics, and code actions exposed by
`core/lsp.py`. Publishing to the VS Code Marketplace and richer UI features are
outside Phase 2.
