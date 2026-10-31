"""Phase 1 command implementations shared by the CLI and tests."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from core import __version__
from core.engines.normalize import dedupe_findings
from core.findings import SCHEMA_VERSION, finding_to_dict
from core.ingest import IngestError, ingest_files
from core.policy import (
    GateResult,
    PolicyError,
    evaluate_gate,
    explain_finding,
    load_policy,
)
from core.report_merge import (
    MergeError,
    ReportSource,
    load_report,
    merge_reports,
)
from core.reporter import (
    build_markdown_report,
    build_sarif_report,
)
from core.scanner import Finding
from core.suppressions import build_baseline, parse_baseline_entries
from core.triage import (
    TriageError,
    apply_triage,
    audit_triage,
    load_triage,
    prune_triage,
    save_triage,
    set_entry,
)


class CommandError(RuntimeError):
    """A user-facing command failure; exit code 2."""


def main_script() -> Path:
    root = Path(__file__).resolve().parent.parent
    return root / "main.py"


def _main_for_repo(repo: Path) -> Path:
    installed = repo / ".commit_guard" / "main.py"
    if installed.is_file():
        return installed
    return main_script()


def _baseline_fingerprints(repo: Path) -> set[str]:
    path = repo / ".commit_guard_ignore"
    if not path.is_file():
        return set()
    try:
        return set(build_baseline(parse_baseline_entries(path)).fingerprints)
    except OSError as exc:
        raise CommandError(f"could not read baseline {path}: {exc}") from exc


def _run_main(repo: Path, args: Iterable[str]) -> subprocess.CompletedProcess[str]:
    script = _main_for_repo(repo)
    if not script.is_file():
        raise CommandError("Commit Guard scan engine is missing.")
    command = [sys.executable, str(script), "--repo", str(repo), *args]
    result = subprocess.run(
        command, cwd=str(repo), text=True, capture_output=True, check=False
    )
    if result.returncode == 2:
        message = (result.stderr or result.stdout or "scan failed").strip()
        raise CommandError(message.splitlines()[-1])
    return result


def scan_to_report(
    repo: Path,
    *,
    staged: bool = True,
    diff_revision: str | None = None,
    scan_all: bool = False,
    history: int | None = None,
    include_baseline: bool = False,
) -> tuple[list[Finding], ReportSource]:
    with tempfile.TemporaryDirectory(prefix="commitguard-gate-") as directory:
        report_path = Path(directory) / "report.json"
        args = [
            "--format",
            "json",
            "--report-path",
            str(report_path),
            "--threshold",
            "info",
            "--soft-fail",
            "--quiet",
        ]
        if not include_baseline:
            args.append("--no-baseline")
        if diff_revision:
            args.extend(["--diff", diff_revision])
        elif scan_all:
            args.append("--all")
        elif history is not None:
            args.extend(["--history", str(history)])
        elif staged:
            pass
        _run_main(repo, args)
        if not report_path.is_file():
            raise CommandError("scan completed without producing a JSON report")
        return load_report(report_path, repo_root=repo)


def _write_or_print(text: str, output: str | Path | None) -> None:
    if output is None:
        print(text, end="" if text.endswith("\n") else "\n")
        return
    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"[commit-guard] Wrote {path}")


def gate_result_to_text(result: GateResult) -> str:
    status = "PASSED" if result.passed else "FAILED"
    lines = [
        f"CommitGuard gate: {status}",
        f"Profile: {result.profile} (threshold: {result.threshold}, fail_on: {result.fail_on})",
        f"Findings: {result.total}; new: {result.new_findings}; blocking: {result.blocking}",
    ]
    if result.suppressed:
        parts = ", ".join(
            f"{key}={value}" for key, value in sorted(result.suppressed.items())
        )
        lines.append(f"Suppressed: {parts}")
    if result.reasons:
        lines.append("Reasons:")
        for reason in result.reasons:
            location = f"{reason['path']}:{reason['line']}" if reason.get("path") else "-"
            lines.append(
                f"  - {location} [{reason['rule_id']}] {reason['reason']}"
            )
    return "\n".join(lines) + "\n"


def command_gate(
    repo: str | Path,
    *,
    report: str | Path | None = None,
    fmt: str = "text",
    output: str | Path | None = None,
    policy_path: str | Path | None = None,
    profile: str | None = None,
    threshold: str | None = None,
    staged: bool = True,
    diff_revision: str | None = None,
    scan_all: bool = False,
    history: int | None = None,
    triage_path: str | Path | None = None,
) -> int:
    root = Path(repo).expanduser().resolve()
    try:
        policy = load_policy(
            root, policy_path, profile=profile, threshold=threshold
        )
        if report is not None:
            findings, _source = load_report(report, repo_root=root)
        else:
            findings, _source = scan_to_report(
                root,
                staged=staged,
                diff_revision=diff_revision,
                scan_all=scan_all,
                history=history,
            )
        triage = load_triage(root, triage_path)
        triage_result = apply_triage(findings, triage)
        gate = evaluate_gate(
            triage_result.visible,
            policy,
            baseline_fingerprints=_baseline_fingerprints(root),
            suppressed={"triage": triage_result.suppressed_total},
        )
    except (CommandError, PolicyError, TriageError, MergeError, IngestError, OSError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    if fmt == "json":
        text = json.dumps(gate.to_dict(), indent=2) + "\n"
    else:
        text = gate_result_to_text(gate)
    try:
        _write_or_print(text, output)
    except OSError as exc:
        print(f"[commit-guard] ERROR: could not write gate output: {exc}", file=sys.stderr)
        return 2
    return 0 if gate.passed else 1


def command_ingest(
    inputs: Iterable[str | Path],
    *,
    repo: str | Path = ".",
    tool: str = "auto",
    fmt: str = "json",
    output: str | Path | None = None,
) -> int:
    root = Path(repo).expanduser().resolve()
    paths = [Path(path) for path in inputs]
    if not paths:
        print("[commit-guard] ERROR: ingest requires at least one input report.", file=sys.stderr)
        return 2
    try:
        findings = dedupe_findings(
            ingest_files(paths, tool=tool, repo_root=root)
        )
    except (IngestError, OSError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    if fmt == "sarif":
        text = build_sarif_report(findings, "info")
    elif fmt == "markdown":
        text = build_markdown_report(findings, "info")
    else:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "CommitGuard", "version": __version__},
            "inputs": [str(path) for path in paths],
            "total": len(findings),
            "findings": [finding_to_dict(finding) for finding in findings],
        }
        text = json.dumps(payload, indent=2) + "\n"
    try:
        _write_or_print(text, output)
    except OSError as exc:
        print(f"[commit-guard] ERROR: could not write report: {exc}", file=sys.stderr)
        return 2
    return 0


def command_report_merge(
    inputs: Iterable[str | Path],
    *,
    fmt: str = "json",
    output: str | Path | None = None,
    repo: str | Path = ".",
) -> int:
    paths = [Path(path) for path in inputs]
    if not paths:
        print("[commit-guard] ERROR: report merge requires an input.", file=sys.stderr)
        return 2
    try:
        merged = merge_reports(paths, repo_root=Path(repo).expanduser().resolve())
    except (MergeError, IngestError, OSError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    if fmt == "sarif":
        text = build_sarif_report(list(merged.findings), "info")
    elif fmt == "markdown":
        text = build_markdown_report(list(merged.findings), "info")
    else:
        text = json.dumps(merged.to_dict(), indent=2) + "\n"
    try:
        _write_or_print(text, output)
    except OSError as exc:
        print(f"[commit-guard] ERROR: could not write merged report: {exc}", file=sys.stderr)
        return 2
    return 0


def command_policy_validate(
    repo: str | Path,
    *,
    policy_path: str | Path | None = None,
    profile: str | None = None,
    threshold: str | None = None,
    fmt: str = "text",
    output: str | Path | None = None,
) -> int:
    try:
        policy = load_policy(
            Path(repo), policy_path, profile=profile, threshold=threshold
        )
    except PolicyError as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    if fmt == "json":
        text = json.dumps(
            {"valid": True, "policy": policy.to_dict()}, indent=2
        ) + "\n"
    else:
        text = (
            f"Policy is valid.\n"
            f"Profile: {policy.profile}\n"
            f"Threshold: {policy.threshold}\n"
            f"Fail on: {policy.fail_on}\n"
            f"Ratchet: {policy.ratchet}\n"
            f"Max new: {policy.max_new}\n"
            f"Source: {policy.source}\n"
        )
    _write_or_print(text, output)
    return 0


def command_policy_explain(
    repo: str | Path,
    fingerprint: str,
    *,
    report: str | Path,
    policy_path: str | Path | None = None,
    profile: str | None = None,
    triage_path: str | Path | None = None,
    fmt: str = "json",
    output: str | Path | None = None,
) -> int:
    root = Path(repo).expanduser().resolve()
    try:
        policy = load_policy(root, policy_path, profile=profile)
        findings, _source = load_report(report, repo_root=root)
        match = next(
            (finding for finding in findings if finding.fingerprint == fingerprint),
            None,
        )
        if match is None:
            raise CommandError(f"fingerprint not found in report: {fingerprint}")
        triage = load_triage(root, triage_path)
        entry = triage.by_fingerprint().get(fingerprint)
        result = explain_finding(
            match,
            policy,
            baseline_fingerprints=_baseline_fingerprints(root),
            triage_state=entry.state if entry else None,
        )
    except (CommandError, PolicyError, TriageError, MergeError, IngestError, OSError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    if fmt == "json":
        text = json.dumps(result, indent=2) + "\n"
    else:
        lines = [
            f"{result['rule_id']} at {result['path']}:{result['line']}",
            f"Fingerprint: {result['fingerprint']}",
        ]
        for stage in result["chain"]:
            lines.append(
                f"  {stage['stage']}: {stage['outcome']} — {stage['detail']}"
            )
        lines.append(
            "Gate: " + ("PASSED" if result["gate"]["passed"] else "FAILED")
        )
        text = "\n".join(lines) + "\n"
    _write_or_print(text, output)
    return 0


def _current_fingerprints(
    repo: Path,
    *,
    report: str | Path | None,
) -> set[str]:
    if report is not None:
        findings, _source = load_report(report, repo_root=repo)
    else:
        findings, _source = scan_to_report(repo)
    return {finding.fingerprint for finding in findings}


def command_triage(
    repo: str | Path,
    action: str,
    *,
    fingerprint: str | None = None,
    state: str | None = None,
    owner: str = "",
    reason: str = "",
    ticket: str = "",
    expires: str = "",
    evidence: str = "",
    rule_id: str = "",
    path: str = "",
    triage_path: str | Path | None = None,
    report: str | Path | None = None,
    dry_run: bool = False,
    strict: bool = False,
    fmt: str = "text",
    output: str | Path | None = None,
) -> int:
    root = Path(repo).expanduser().resolve()
    try:
        triage = load_triage(root, triage_path)
        if action == "list":
            payload = triage.to_dict()
            if fmt == "json":
                text = json.dumps(payload, indent=2) + "\n"
            elif not triage.entries:
                text = "No triage entries.\n"
            else:
                lines = ["Fingerprint       State           Owner            Expires"]
                for entry in triage.entries:
                    lines.append(
                        f"{entry.fingerprint:<17} {entry.state:<15} "
                        f"{entry.owner:<16} {entry.expires or '-'}"
                    )
                text = "\n".join(lines) + "\n"
            _write_or_print(text, output)
            return 0
        if action == "set":
            if not fingerprint or not state:
                raise CommandError("triage set requires FINGERPRINT and --state")
            triage = set_entry(
                triage,
                fingerprint=fingerprint,
                triage_state=state,
                owner=owner,
                reason=reason,
                rule_id=rule_id,
                path=path,
                ticket=ticket,
                expires=expires,
                evidence=evidence,
            )
            target = save_triage(triage)
            print(f"[commit-guard] Triage entry saved to {target}")
            return 0
        present = _current_fingerprints(root, report=report)
        if action == "prune":
            updated, removed = prune_triage(triage, present, dry_run=dry_run)
            if not dry_run and removed:
                save_triage(updated)
            if removed:
                label = "Would remove" if dry_run else "Removed"
                print(f"[commit-guard] {label} {len(removed)} fixed entr(y/ies).")
                for item in removed:
                    print(f"  - {item}")
            else:
                print("[commit-guard] No fixed entries to prune.")
            return 0
        if action == "audit":
            issues = audit_triage(triage, present)
            if fmt == "json":
                text = json.dumps({"issues": issues}, indent=2) + "\n"
            else:
                text = (
                    "No triage issues.\n"
                    if not issues
                    else "\n".join(issues) + "\n"
                )
            _write_or_print(text, output)
            return 1 if (strict and issues) else 0
    except (CommandError, TriageError, MergeError, IngestError, OSError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"[commit-guard] ERROR: unknown triage action: {action}", file=sys.stderr)
    return 2


def command_sbom(
    repo: str | Path = ".",
    *,
    fmt: str = "cyclonedx",
    output: str | Path | None = None,
    project_name: str | None = None,
    project_version: str = "1.0.0",
) -> int:
    from core.sbom import build_sbom, write_sbom

    root = Path(repo).expanduser().resolve()
    try:
        document = build_sbom(
            root,
            fmt=fmt,
            project_name=project_name,
            project_version=project_version,
        )
        if output is None:
            print(json.dumps(document, indent=2))
        else:
            target = write_sbom(document, output)
            print(f"[commit-guard] Wrote {fmt} SBOM to {target}")
    except (OSError, ValueError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


def command_license(
    repo: str | Path = ".",
    *,
    policy_path: str | Path | None = None,
    fmt: str = "text",
    output: str | Path | None = None,
    strict: bool = False,
    fail_on_unknown: bool | None = None,
    fail_on_review: bool | None = None,
    allow: Iterable[str] = (),
    deny: Iterable[str] = (),
    review: Iterable[str] = (),
) -> int:
    from core.license_policy import (
        LicensePolicyError,
        evaluate_licenses,
        format_license_report,
        load_license_policy,
    )

    root = Path(repo).expanduser().resolve()
    try:
        policy = load_license_policy(
            root,
            policy_path,
            allow=allow,
            deny=deny,
            review=review,
            fail_on_unknown=True if strict else fail_on_unknown,
            fail_on_review=True if strict else fail_on_review,
        )
        report = evaluate_licenses(root, policy=policy)
    except (LicensePolicyError, OSError, ValueError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    text = format_license_report(report, fmt=fmt)
    try:
        _write_or_print(text, output)
    except OSError as exc:
        print(f"[commit-guard] ERROR: could not write license report: {exc}", file=sys.stderr)
        return 2
    return 1 if report.failed else 0


def command_dashboard(
    repo: str | Path = ".",
    *,
    reports: Iterable[str | Path] | None = None,
    history: str | Path | None = None,
    output: str | Path | None = None,
    fmt: str = "html",
    owner: str = "unassigned",
) -> int:
    from core.dashboard import build_dashboard_data, dashboard_json, write_dashboard

    root = Path(repo).expanduser().resolve()
    try:
        data = build_dashboard_data(
            root,
            reports=reports,
            history=history,
            owner=owner,
        )
    except (OSError, ValueError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    if fmt == "json":
        text = dashboard_json(data)
        try:
            _write_or_print(text, output)
        except OSError as exc:
            print(f"[commit-guard] ERROR: could not write dashboard: {exc}", file=sys.stderr)
            return 2
        return 0
    if output is None:
        output = root / "commit_guard_reports" / "dashboard.html"
    try:
        target = write_dashboard(data, output)
    except OSError as exc:
        print(f"[commit-guard] ERROR: could not write dashboard: {exc}", file=sys.stderr)
        return 2
    print(f"[commit-guard] Wrote dashboard to {target}")
    return 0


def command_watch(
    repo: str | Path = ".",
    *,
    interval: float = 1.0,
    debounce: float = 0.25,
    once: bool = False,
    scan_all: bool = False,
    diff_revision: str | None = None,
    max_scans: int | None = None,
    quiet: bool = False,
) -> int:
    from core.watch import WatchEvent, run_watch

    root = Path(repo).expanduser().resolve()

    def scan(event: WatchEvent) -> None:
        if not quiet:
            label = ", ".join(event.paths[:3])
            if len(event.paths) > 3:
                label += f", +{len(event.paths) - 3}"
            print(f"[commit-guard] change detected: {label or 'initial scan'}")
        findings, _source = scan_to_report(
            root,
            staged=not scan_all and diff_revision is None,
            diff_revision=diff_revision,
            scan_all=scan_all,
        )
        if not quiet:
            counts: dict[str, int] = {}
            for finding in findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
            summary = ", ".join(
                f"{name}={counts[name]}"
                for name in ("critical", "high", "medium", "low", "info")
                if counts.get(name)
            )
            print(f"[commit-guard] {len(findings)} finding(s){': ' + summary if summary else ''}")

    try:
        state = run_watch(
            root,
            scan,
            interval=interval,
            debounce=debounce,
            once=once,
            max_scans=max_scans,
        )
    except KeyboardInterrupt:
        return 0
    except (CommandError, OSError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    if not quiet and not once:
        print(f"[commit-guard] watch stopped after {state.scans} scan(s).")
    return 0


def command_lsp(repo: str | Path = ".") -> int:
    from core.lsp import serve_stdio

    try:
        return serve_stdio(repo)
    except (OSError, ValueError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2


def command_compliance(
    repo: str | Path = ".",
    *,
    report: str | Path,
    packs: Iterable[str] | None = None,
    fmt: str = "markdown",
    output: str | Path | None = None,
) -> int:
    from core.compliance import (
        ComplianceError,
        discover_packs,
        evaluate_compliance,
        format_compliance_report,
    )

    root = Path(repo).expanduser().resolve()
    try:
        findings, _source = load_report(report, repo_root=root)
        selected = discover_packs(root / "rules" / "compliance", names=packs)
        if not selected:
            selected = discover_packs(names=packs)
        result = evaluate_compliance(findings, selected)
    except (ComplianceError, MergeError, IngestError, OSError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    text = format_compliance_report(result, fmt=fmt)
    try:
        _write_or_print(text, output)
    except OSError as exc:
        print(f"[commit-guard] ERROR: could not write compliance report: {exc}", file=sys.stderr)
        return 2
    return 0


def command_plugin(
    repo: str | Path = ".",
    action: str = "list",
    *,
    directory: str | Path | None = None,
    allow_unsigned: bool = False,
    timeout: float = 30.0,
    fmt: str = "text",
    output: str | Path | None = None,
) -> int:
    from core.plugins import (
        PluginError,
        discover_plugins,
        run_plugin,
        verify_manifest,
    )

    root = Path(repo).expanduser().resolve()
    payload: dict[str, Any]
    try:
        manifests = discover_plugins(directory)
        if action == "list":
            payload = {
                "plugins": [manifest.to_dict() for manifest in manifests]
            }
            if fmt == "json":
                text = json.dumps(payload, indent=2) + "\n"
            elif not manifests:
                text = "No plugins found.\n"
            else:
                lines = ["NAME                     VERSION   CAPABILITIES"]
                for manifest in manifests:
                    lines.append(
                        f"{manifest.name:<24} {manifest.version:<9} "
                        f"{', '.join(manifest.capabilities) or '-'}"
                    )
                text = "\n".join(lines) + "\n"
            _write_or_print(text, output)
            return 0
        if action == "validate":
            results: list[dict[str, Any]] = []
            failed = False
            for manifest in manifests:
                ok, reason = verify_manifest(
                    manifest, allow_unsigned=allow_unsigned
                )
                failed = failed or not ok
                results.append(
                    {
                        "name": manifest.name,
                        "version": manifest.version,
                        "valid": ok,
                        "reason": reason,
                    }
                )
            payload = {"valid": not failed, "plugins": results}
            if fmt == "json":
                text = json.dumps(payload, indent=2) + "\n"
            else:
                text = (
                    "No plugins found.\n"
                    if not results
                    else "\n".join(
                        f"{item['name']}: {'OK' if item['valid'] else 'FAILED'} "
                        f"({item['reason']})"
                        for item in results
                    )
                    + "\n"
                )
            _write_or_print(text, output)
            return 1 if failed else 0
        if action == "run":
            if not manifests:
                raise PluginError("no plugins found")
            all_findings: list[Finding] = []
            errors: list[str] = []
            for manifest in manifests:
                result = run_plugin(
                    manifest,
                    context={"repo_root": str(root)},
                    timeout=timeout,
                    allow_unsigned=allow_unsigned,
                )
                all_findings.extend(result.findings)
                errors.extend(result.errors)
            payload = {
                "schema_version": SCHEMA_VERSION,
                "tool": {"name": "CommitGuard", "version": __version__},
                "total": len(all_findings),
                "errors": errors,
                "findings": [finding_to_dict(finding) for finding in all_findings],
            }
            text = json.dumps(payload, indent=2) + "\n"
            _write_or_print(text, output)
            return 1 if errors else 0
    except (PluginError, OSError) as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"[commit-guard] ERROR: unknown plugin action: {action}", file=sys.stderr)
    return 2
