export type ScanMode = "repo" | "staged";

export interface RuleSource {
  id: string;
  label: string;
  description: string;
}

export const RULE_SOURCES: RuleSource[] = [
  {
    id: "custom",
    label: "Custom CommitGuard rules",
    description: "Built-in CommitGuard regex and language rules.",
  },
  {
    id: "gitleaks",
    label: "Gitleaks secrets",
    description: "Credential and token patterns.",
  },
  {
    id: "nuclei",
    label: "Nuclei secrets",
    description: "Nuclei secret templates.",
  },
  {
    id: "devskim",
    label: "DevSkim",
    description: "DevSkim security and cryptography rules.",
  },
  {
    id: "semgrep",
    label: "All Semgrep databases",
    description: "Every Semgrep rule database that is installed.",
  },
  {
    id: "semgrep:semgrep_python",
    label: "Semgrep Python",
    description: "The Python Semgrep database only.",
  },
  {
    id: "python_ast",
    label: "Python AST / taint",
    description: "Python data-flow and AST rules.",
  },
  {
    id: "javascript_ast",
    label: "JavaScript AST / taint",
    description: "JavaScript and TypeScript data-flow rules.",
  },
  {
    id: "java_ast",
    label: "Java AST / taint",
    description: "Java interprocedural data-flow rules.",
  },
  {
    id: "go_ast",
    label: "Go AST / taint",
    description: "Go interprocedural data-flow rules.",
  },
];

export interface ScanFinding {
  file: string;
  line: number;
  column: number | null;
  end_line: number | null;
  end_column: number | null;
  rule_id: string;
  category: string;
  severity: string;
  source: string;
  description: string;
  fingerprint: string;
}

export interface ScanReport {
  generated: string;
  total: number;
  summary: Record<string, number>;
  findings: ScanFinding[];
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

export function buildScanArgs(
  folder: string,
  reportPath: string,
  sources: string[],
  mode: ScanMode,
): string[] {
  const args = [
    "scan",
    folder,
    "--format",
    "json",
    "--report-path",
    reportPath,
    "--quiet",
    "--soft-fail",
    mode === "repo" ? "--all" : "--staged",
  ];
  for (const source of sources) args.push("--rule-source", source);
  return args;
}

export function parseScanReport(value: unknown): ScanReport {
  if (!value || typeof value !== "object") {
    throw new Error("CommitGuard returned an invalid report.");
  }
  const payload = value as Record<string, unknown>;
  const summary: Record<string, number> = {};
  const rawSummary = payload.summary;
  if (rawSummary && typeof rawSummary === "object") {
    for (const [key, count] of Object.entries(rawSummary)) {
      const numeric = asNumber(count);
      if (numeric !== null) summary[key] = numeric;
    }
  }
  const rawFindings = payload.findings;
  if (!Array.isArray(rawFindings)) {
    throw new Error("CommitGuard report is missing findings.");
  }
  const findings: ScanFinding[] = [];
  for (const item of rawFindings) {
    if (!item || typeof item !== "object") continue;
    const finding = item as Record<string, unknown>;
    const file = asString(finding.file);
    const ruleId = asString(finding.rule_id);
    if (!file || !ruleId) continue;
    findings.push({
      file,
      line: asNumber(finding.line) ?? 1,
      column: asNumber(finding.column),
      end_line: asNumber(finding.end_line),
      end_column: asNumber(finding.end_column),
      rule_id: ruleId,
      category: asString(finding.category),
      severity: asString(finding.severity) || "info",
      source: asString(finding.source) || "unknown",
      description: asString(finding.description),
      fingerprint: asString(finding.fingerprint) || asString(finding.id),
    });
  }
  return {
    generated: asString(payload.generated),
    total: asNumber(payload.total) ?? findings.length,
    summary,
    findings,
  };
}
