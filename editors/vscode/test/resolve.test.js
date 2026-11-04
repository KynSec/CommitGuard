"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const Module = require("module");

const ROOT = path.resolve(__dirname, "..", "..", "..");
process.chdir(ROOT);
process.env.PYTHONPATH = ROOT + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : "");

let workspaceFolderPath;
let workspaceTrusted = true;
const configuration = new Map();

const vscodeMock = {
  StatusBarAlignment: { Left: 1 },
  window: {
    get activeTextEditor() {
      return undefined;
    },
  },
  workspace: {
    get isTrusted() {
      return workspaceTrusted;
    },
    get workspaceFolders() {
      return workspaceFolderPath
        ? [{ uri: { fsPath: workspaceFolderPath } }]
        : undefined;
    },
    getConfiguration(section) {
      return {
        get(key, fallback) {
          const full = `${section}.${key}`;
          return configuration.has(full) ? configuration.get(full) : fallback;
        },
      };
    },
  },
};
const load = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === "vscode") return vscodeMock;
  return load.call(this, request, parent, isMain);
};

const cli = require("../out/cli.js");

function reset(folder, trusted = true) {
  workspaceFolderPath = folder;
  workspaceTrusted = trusted;
  configuration.clear();
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "commitguard-vscode-"));
try {
  reset(temp);
  configuration.set("commitguard.extraArgs", ["--no-cache"]);
  fs.writeFileSync(path.join(temp, "commit-guard"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  let launch = cli.serverLaunch();
  assert.strictEqual(launch.command, path.join(temp, "commit-guard"));
  assert.deepStrictEqual(launch.args, ["--no-cache", "lsp", temp]);

  reset(temp);
  configuration.set("commitguard.executable", "/custom/bin/commit-guard");
  launch = cli.serverLaunch();
  assert.strictEqual(launch.command, "/custom/bin/commit-guard");
  assert.deepStrictEqual(launch.args, ["lsp", temp]);

  reset(temp, false);
  configuration.set("commitguard.pythonPath", "python3");
  launch = cli.serverLaunch();
  assert.strictEqual(launch.command, "python3");
  assert.deepStrictEqual(launch.args, ["-m", "install_hook", "lsp", temp]);

  fs.unlinkSync(path.join(temp, "commit-guard"));
  reset(temp);
  configuration.set("commitguard.pythonPath", "python3");
  launch = cli.serverLaunch();
  assert.strictEqual(launch.command, "python3");
  assert.deepStrictEqual(launch.args, ["-m", "install_hook", "lsp", temp]);
  assert.strictEqual(launch.label, "python3 -m install_hook");

  console.log("vscode launcher resolution: ok");
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
