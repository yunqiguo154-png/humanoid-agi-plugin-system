from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any


SEVERITIES = {"critical", "high", "medium", "low", "unknown"}


def convert_pip_audit_report(payload: dict[str, Any], *, input_file: str | Path) -> dict[str, Any]:
    findings = _findings(payload)
    severity_summary: dict[str, int] = {}
    for finding in findings:
        severity = str(finding["severity"])
        severity_summary[severity] = severity_summary.get(severity, 0) + 1
    policy_decision = _policy_decision(severity_summary)
    return {
        "scanner_name": "pip-audit",
        "scanner_version": _scanner_version(payload),
        "generated_at": datetime.now(UTC).isoformat(),
        "input_file": str(input_file),
        "findings": findings,
        "severity_summary": severity_summary,
        "policy_decision": policy_decision,
        "status": policy_decision,
        "reason": _reason(policy_decision, severity_summary),
        "source": "real_scanner",
        "production_evidence": True,
        "coverage": {
            "python_dependency_vulnerabilities": True,
            "license_scan": False,
        },
    }


def load_pip_audit_report(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("pip-audit JSON must be an object")
    if "dependencies" not in payload and "vulnerabilities" not in payload:
        raise ValueError("pip-audit JSON is missing dependencies or vulnerabilities")
    return payload


def malformed_report(*, input_file: str | Path, error: str) -> dict[str, Any]:
    return {
        "scanner_name": "pip-audit",
        "scanner_version": "unknown",
        "generated_at": datetime.now(UTC).isoformat(),
        "input_file": str(input_file),
        "findings": [],
        "severity_summary": {},
        "policy_decision": "fail",
        "status": "fail",
        "reason": f"pip-audit JSON could not be converted: {error}",
        "source": "real_scanner",
        "production_evidence": False,
    }


def _findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for dependency in payload.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue
        name = str(dependency.get("name") or dependency.get("package") or "unknown")
        version = str(dependency.get("version") or "unknown")
        for vuln in dependency.get("vulns") or dependency.get("vulnerabilities") or []:
            if isinstance(vuln, dict):
                findings.append(_finding(name, version, vuln))
    for vuln in payload.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        name = str(vuln.get("name") or vuln.get("package") or vuln.get("dependency") or "unknown")
        version = str(vuln.get("version") or "unknown")
        findings.append(_finding(name, version, vuln))
    return findings


def _finding(package: str, version: str, vuln: dict[str, Any]) -> dict[str, Any]:
    fix_versions = vuln.get("fix_versions") or vuln.get("fixed_versions") or []
    recommendation = "review advisory and upgrade or remove the dependency"
    if isinstance(fix_versions, list) and fix_versions:
        recommendation = "upgrade to " + ", ".join(str(item) for item in fix_versions)
    return {
        "type": "vulnerability",
        "package": package,
        "version": version,
        "id": str(vuln.get("id") or vuln.get("vulnerability_id") or vuln.get("advisory") or "UNKNOWN"),
        "severity": _severity(vuln),
        "description": str(vuln.get("description") or vuln.get("summary") or "pip-audit vulnerability finding"),
        "recommendation": recommendation,
        "source": "pip-audit",
    }


def _severity(vuln: dict[str, Any]) -> str:
    value = str(vuln.get("severity") or vuln.get("risk") or "").strip().lower()
    if value in SEVERITIES:
        return value
    # pip-audit advisories often omit severity; fail closed as high.
    return "high"


def _policy_decision(summary: dict[str, int]) -> str:
    if summary.get("critical") or summary.get("high"):
        return "fail"
    if summary.get("medium") or summary.get("unknown"):
        return "warn"
    return "pass"


def _reason(policy_decision: str, summary: dict[str, int]) -> str:
    if policy_decision == "pass":
        return "pip-audit reported no Python dependency vulnerabilities"
    if policy_decision == "fail":
        return "pip-audit reported critical or high Python dependency vulnerabilities"
    return "pip-audit reported vulnerabilities requiring review"


def _scanner_version(payload: dict[str, Any]) -> str:
    metadata_payload = payload.get("metadata")
    if isinstance(metadata_payload, dict):
        for key in ["scanner_version", "pip_audit_version", "version"]:
            value = metadata_payload.get(key)
            if isinstance(value, str) and value:
                return value
    try:
        return metadata.version("pip-audit")
    except metadata.PackageNotFoundError:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert pip-audit JSON into Humanoid AGI scanner evidence")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    try:
        payload = convert_pip_audit_report(load_pip_audit_report(args.input), input_file=args.input)
        exit_code = 0 if payload["policy_decision"] == "pass" else 1
    except Exception as exc:
        payload = malformed_report(input_file=args.input, error=f"{type(exc).__name__}: {exc}")
        exit_code = 1
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
