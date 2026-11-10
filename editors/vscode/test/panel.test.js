"use strict";

const assert = require("assert");
const Module = require("module");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const folder = { uri: { fsPath: path.join(ROOT, "sample workspace") } };
const vscodeMock = {
  workspace: {
    isTrusted: true,
    get workspaceFolders() {
      return [folder];
    },
    getConfiguration() {
      return { get(_key, fallback) { return fallback; } };
    },
  },
  window: { activeTextEditor: undefined },
  commands: { executeCommand() {} },
  Position: class {},
  Selection: class {},
  Range: class {},
  TextEditorRevealType: { InCenter: 1 },
};
const load = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === "vscode") return vscodeMock;
  return load.call(this, request, parent, isMain);
};

const { ScanPanelProvider } = require("../out/panel.js");
const store = new Map();
const context = {
  subscriptions: [],
  workspaceState: {
    get(key, fallback) {
      return store.has(key) ? store.get(key) : fallback;
    },
    update(key, value) {
      store.set(key, value);
      return Promise.resolve();
    },
  },
};
const provider = new ScanPanelProvider(
  context,
  { appendLine() {} },
  () => {},
);
let html = "";
const view = {
  webview: {
    options: {},
    cspSource: "vscode-resource:",
    onDidReceiveMessage() {
      return { dispose() {} };
    },
    postMessage() {
      return Promise.resolve(true);
    },
    get html() {
      return html;
    },
    set html(value) {
      html = value;
    },
  },
  onDidDispose() {
    return { dispose() {} };
  },
};
provider.resolveWebviewView(view);

assert.ok(html.includes('data-source="gitleaks"'));
assert.ok(html.includes('data-source="semgrep:semgrep_python"'));
assert.ok(html.includes('data-source="java_ast"'));
assert.ok(html.includes('data-source="go_ast"'));
assert.ok(html.includes("Open CommitGuard GUI"));
assert.ok(html.includes("Run Scan"));
assert.ok(html.includes("script-src 'nonce-"));
assert.ok(html.includes("sample workspace"));
console.log("webview panel: ok");
