# 🛡️ CommitGuard Security Scanner

> **The offline-first, zero-telemetry SAST scanner for VS Code.**<br>
> Catch secrets, vulnerabilities, and code issues before they ever leave your machine.

[![Version](https://img.shields.io/visual-studio-marketplace/v/AmrKhaledEldhshan.commitguard-kynsec?label=VS%20Code%20Marketplace&color=blue)](https://marketplace.visualstudio.com/items?itemName=AmrKhaledEldhshan.commitguard-kynsec)
[![Offline](https://img.shields.io/badge/offline-100%25-brightgreen)](https://github.com/KynSec/CommitGuard)
[![Zero Telemetry](https://img.shields.io/badge/telemetry-zero-blue)](https://github.com/KynSec/CommitGuard)
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey)](LICENSE)
[![GitHub](https://img.shields.io/badge/source-GitHub-black?logo=github)](https://github.com/KynSec/CommitGuard)

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🔒 | **100% Offline** | All scanning happens locally — no data leaves your machine, ever. |
| 🔑 | **Secret Detection** | Catch API keys, tokens, and credentials with Gitleaks + Nuclei patterns. |
| 🧠 | **Interprocedural Taint Analysis** | Deep data-flow analysis for Python, JavaScript, TypeScript, Java, and Go. |
| 🔍 | **Multi-Engine SAST** | Runs Semgrep, DevSkim, and custom CommitGuard rules simultaneously. |
| 📡 | **LSP Diagnostics** | Real-time squiggles and diagnostics powered by a Language Server. |
| ⚡ | **Scan Staged Changes** | Pre-commit style scanning of only your staged git changes. |
| 🗂️ | **Full Repo Scanning** | Deep scan of the entire repository on demand. |
| 📋 | **Export Results** | Export findings as JSON for CI/CD integration or reporting. |
| 🔕 | **Suppress Findings** | Insert `# commit-guard-ignore` comments directly from the panel. |
| 📜 | **Scan History** | Review and restore the last 20 scan results. |
| 🎨 | **Rich Panel UI** | Filter, group, and explore findings in a polished side panel. |
| ⌨️ | **Keyboard Shortcuts** | Trigger scans without leaving the keyboard. |
| 🛠️ | **Scan on Save** | Optional auto-scan on every file save. |

---

## 📦 Quick Install

1. Open VS Code
2. Press `Ctrl+P` (macOS: `Cmd+P`)
3. Run: `ext install AmrKhaledEldhshan.commitguard-kynsec`

Or search **CommitGuard** in the Extensions Marketplace sidebar.

> **Requires** the [CommitGuard CLI](https://github.com/KynSec/CommitGuard) to be installed (`pip install commit-guard`).

---

## 🚀 Quick Start

1. **Install the CLI**: `pip install commit-guard`
2. **Open a workspace** folder in VS Code
3. **Click the shield icon** in the Activity Bar to open the CommitGuard panel
4. **Select rule databases** (or click *All*)
5. **Click ▶ Run Scan** — findings appear instantly in the panel

---

## ⌨️ Commands

| Command | Description | Shortcut |
|---|---|---|
| `CommitGuard: Open Scan Panel` | Open the CommitGuard side panel | `Ctrl+Shift+G P` |
| `CommitGuard: Scan Staged Changes` | Scan only staged git changes | `Ctrl+Shift+G S` |
| `CommitGuard: Scan Full Repository` | Scan the entire repository | — |
| `CommitGuard: Scan Current File` | Quick scan of the active file | Editor title button |
| `CommitGuard: Open GUI` | Launch the CommitGuard desktop GUI | — |
| `CommitGuard: Restart Language Server` | Restart the LSP backend | — |
| `CommitGuard: Export Results as JSON` | Save findings to a JSON file | — |
| `CommitGuard: Clear Results` | Clear the current scan results | — |
| `CommitGuard: Show Dashboard` | Focus the CommitGuard scan panel | — |

> **macOS**: Replace `Ctrl` with `Cmd` in all shortcuts.

---

## ⚙️ Settings

| Setting | Type | Default | Description |
|---|---|---|---|
| `commitguard.executable` | `string` | `""` | Absolute path to the `commit-guard` CLI. Auto-detected if empty. |
| `commitguard.pythonPath` | `string` | `""` | Python interpreter to use when running via `-m install_hook`. |
| `commitguard.extraArgs` | `string[]` | `[]` | Extra arguments passed before the `lsp` subcommand. |
| `commitguard.trace.server` | `"off" \| "messages" \| "verbose"` | `"off"` | LSP protocol tracing level. |
| `commitguard.scanOnSave` | `boolean` | `false` | Auto-scan on file save. |
| `commitguard.autoScanScope` | `"staged" \| "repo"` | `"staged"` | Scope used for auto-scan on save. |
| `commitguard.defaultSources` | `string[]` | `[]` | Rule databases pre-selected when the scan panel opens. |
| `commitguard.showFindingCount` | `boolean` | `true` | Show the finding count in the status bar. |

---

## 🌐 Supported Languages

CommitGuard's LSP diagnostics and AST/taint engines support:

| | | | |
|---|---|---|---|
| 🐍 Python | ☕ Java | 🦀 Rust | 🐘 PHP |
| 🟨 JavaScript | 🐹 Go | 💎 Ruby | 🐚 Shell |
| 🔷 TypeScript | 🔵 C / C++ | 📄 YAML | 🐳 Dockerfile |
| ⚛️ React (JSX/TSX) | 🟣 C# | 📝 JSON | — |

---

## 🗄️ Rule Databases

| ID | Name | Description |
|---|---|---|
| `custom` | CommitGuard Rules | Built-in regex and language rules |
| `gitleaks` | Gitleaks Secrets | Credential and token patterns |
| `nuclei` | Nuclei Secrets | Nuclei secret templates |
| `devskim` | DevSkim | Security and cryptography rules |
| `semgrep` | All Semgrep DBs | Every installed Semgrep rule database |
| `semgrep:semgrep_python` | Semgrep Python | Python-specific Semgrep rules |
| `python_ast` | Python AST/Taint | Python data-flow and AST analysis |
| `javascript_ast` | JavaScript AST/Taint | JS/TS data-flow analysis |
| `java_ast` | Java AST/Taint | Java interprocedural analysis |
| `go_ast` | Go AST/Taint | Go interprocedural analysis |

---

## 🏆 Why CommitGuard?

| Feature | CommitGuard | Cloud SAST tools |
|---|---|---|
| **Privacy** | ✅ 100% local | ❌ Code sent to cloud |
| **Internet required** | ✅ No | ❌ Yes |
| **API keys needed** | ✅ No | ❌ Yes |
| **Telemetry** | ✅ Zero | ❌ Often yes |
| **Works offline** | ✅ Always | ❌ No |
| **Pre-commit integration** | ✅ Yes | ⚠️ Varies |
| **Multiple SAST engines** | ✅ 10 sources | ⚠️ Varies |
| **Free** | ✅ Apache-2.0 | ⚠️ Freemium |

---

## 🔧 Troubleshooting

### "Could not locate the CommitGuard command"

The extension could not find the `commit-guard` CLI. Fix with one of:

```bash
# Option A — pip install
pip install commit-guard

# Option B — pipx (recommended)
pipx install commit-guard

# Option C — set explicit path in settings
# commitguard.executable: "/home/user/.local/bin/commit-guard"
```

### Language server won't start

1. Open the **CommitGuard** output channel (View → Output → CommitGuard)
2. Check the error message
3. Run `commitguard.restartServer` from the Command Palette
4. If it persists, set `commitguard.trace.server` to `"verbose"` and check the output

### Scan produces no findings / empty report

- Ensure the workspace is **trusted** (VS Code workspace trust prompt)
- Confirm git is initialized (`git init`) and files are staged (`git add .`) for staged scans
- Try `commitguard.scanRepo` to scan the full repository
- Check the CommitGuard output channel for CLI errors

### Staged scan shows "No staged changes"

You need to stage files first: `git add <file>` or `git add -A`. Staged-only mode respects git's index.

---

## 👩‍💻 Development

```bash
# Clone the repo
git clone https://github.com/KynSec/CommitGuard.git
cd CommitGuard/editors/vscode

# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Watch mode
npm run watch

# Run tests
npm test

# Package extension
npm run package
```

Open the `editors/vscode` folder in VS Code and press `F5` to launch the Extension Development Host.

---

## 📄 License

[Apache-2.0](https://github.com/KynSec/CommitGuard/blob/main/LICENSE) © KynSec / Amr Khaled Eldhshan

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/KynSec">KynSec</a> ·
  <a href="https://github.com/KynSec/CommitGuard/issues">Report a bug</a> ·
  <a href="https://github.com/KynSec/CommitGuard">GitHub</a>
</p>
