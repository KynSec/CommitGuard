"use strict";

const assert = require("assert");
const { buildScanArgs, parseScanReport, RULE_SOURCES } = require("../out/scan.js");

const args = buildScanArgs(
  "/work/repo",
  "/tmp/report.json",
  ["gitleaks", "python_ast"],
  "repo",
);
assert.deepStrictEqual(args, [
  "scan",
  "/work/repo",
  "--format",
  "json",
  "--report-path",
  "/tmp/report.json",
  "--quiet",
  "--soft-fail",
  "--all",
  "--rule-source",
  "gitleaks",
  "--rule-source",
  "python_ast",
]);

assert.ok(RULE_SOURCES.some((source) => source.id === "semgrep:semgrep_python"));
assert.ok(RULE_SOURCES.some((source) => source.id === "java_ast"));
assert.ok(RULE_SOURCES.some((source) => source.id === "go_ast"));
assert.ok(!buildScanArgs("/repo", "/tmp/r.json", [], "staged").includes("--all"));

const report = parseScanReport({
  generated: "now",
  total: 1,
  summary: { high: 1, critical: "bad" },
  findings: [
    {
      file: "src/app.py",
      line: 4,
      column: 2,
      rule_id: "cg-test",
      category: "secret",
      severity: "high",
      source: "custom",
      description: "test finding",
      fingerprint: "abc",
    },
    { file: "", rule_id: "ignored" },
  ],
});
assert.strictEqual(report.total, 1);
assert.strictEqual(report.summary.high, 1);
assert.strictEqual(report.summary.critical, undefined);
assert.strictEqual(report.findings.length, 1);
assert.strictEqual(report.findings[0].column, 2);

assert.throws(() => parseScanReport({}), /missing findings/);
console.log("scan report helpers: ok");
