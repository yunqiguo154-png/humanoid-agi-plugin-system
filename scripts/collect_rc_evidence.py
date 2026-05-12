from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.drill_common import write_json


EVIDENCE_NAMES = {
    "environment": "environment.json",
    "local_quality_gate": "local_quality_gate.json",
    "ci": "ci_result.json",
    "bwrap": "bwrap_validation.json",
    "scanner": "scanner_report.json",
    "doctor": "doctor.json",
    "acceptance": "acceptance_result.json",
    "audit": "audit_verify.json",
    "registry": "registry_verify.json",
    "revocation": "revocation_drill.json",
    "quarantine": "quarantine_drill.json",
    "rollback": "rollback_drill.json",
    "release_gate": "release_gate.json",
}


def collect_evidence(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []

    environment = collect_environment()
    items.append(_write_item(output_dir, "environment", environment))

    quality = collect_local_quality_gate(run_quality=bool(getattr(args, "run_quality", True)))
    items.append(_write_item(output_dir, "local_quality_gate", quality))

    ci = collect_ci_result()
    items.append(_write_item(output_dir, "ci", ci))

    bwrap = collect_bwrap_validation(output_dir)
    items.append(_write_item(output_dir, "bwrap", bwrap))

    scanner = collect_scanner_report(args.scanner_report)
    items.append(_write_item(output_dir, "scanner", scanner))

    doctor = run_json_command(
        "doctor",
        [sys.executable, "cli.py", "--production", "doctor", "--json"],
        production_blocking_on_fail=True,
    )
    items.append(_write_item(output_dir, "doctor", doctor))

    acceptance = run_json_command(
        "acceptance",
        [
            sys.executable,
            "scripts/run_production_acceptance.py",
            "--json",
            "--output",
            str(output_dir / EVIDENCE_NAMES["acceptance"]),
        ],
        production_blocking_on_fail=True,
        tolerate_existing_output=output_dir / EVIDENCE_NAMES["acceptance"],
    )
    items.append(_write_item(output_dir, "acceptance", acceptance))

    audit = collect_audit_verify(args.audit_log, args.audit_checkpoint, args.audit_public_key)
    items.append(_write_item(output_dir, "audit", audit))

    for evidence_id, script in [
        ("registry", "scripts/drill_registry_verify.py"),
        ("revocation", "scripts/drill_revocation.py"),
        ("quarantine", "scripts/drill_quarantine.py"),
        ("rollback", "scripts/drill_rollback.py"),
    ]:
        payload = run_json_command(
            evidence_id,
            [sys.executable, script, "--json", "--output", str(output_dir / EVIDENCE_NAMES[evidence_id])],
            production_blocking_on_fail=True,
            tolerate_existing_output=output_dir / EVIDENCE_NAMES[evidence_id],
        )
        items.append(_write_item(output_dir, evidence_id, payload))

    release_gate = collect_release_gate(output_dir)
    items.append(_write_item(output_dir, "release_gate", release_gate))

    index = {
        "generated_at": now(),
        "status": "not_ready" if any(item["production_blocking"] for item in items) else "pass",
        "production_ready": not any(item["production_blocking"] for item in items),
        "summary": (
            "one or more required RC evidence files are missing, skipped, or failed"
            if any(item["production_blocking"] for item in items)
            else "all locally collected RC evidence passed"
        ),
        "items": items,
    }
    write_json(output_dir / "index.json", index)
    return index


def collect_environment() -> dict[str, Any]:
    git_root = _run_text(["git", "rev-parse", "--show-toplevel"])
    commit = _run_text(["git", "rev-parse", "HEAD"])
    branch = _run_text(["git", "branch", "--show-current"])
    status = _run_text(["git", "status", "--short"])
    in_git_repo = git_root["exit_code"] == 0
    has_commit = commit["exit_code"] == 0
    dirty = bool(status["stdout"].strip()) if status["exit_code"] == 0 else True
    notes: list[str] = []
    if not in_git_repo:
        notes.append("current directory is not a Git repository; commit SHA evidence is missing")
    elif not has_commit:
        notes.append("Git repository exists but no committed SHA is available yet; pre-commit evidence only")
    if dirty:
        notes.append("working tree is not clean; evidence is not a formal immutable RC artifact")
    if platform.system().lower() != "linux":
        notes.append("current host is not target Linux+bwrap production environment")
    return {
        "status": "warn" if notes else "pass",
        "production_blocking": not in_git_repo or not has_commit or dirty,
        "commit_sha": commit["stdout"].strip() if has_commit else None,
        "branch": branch["stdout"].strip() if branch["exit_code"] == 0 else None,
        "working_tree_clean": in_git_repo and has_commit and not dirty,
        "python_version": platform.python_version(),
        "os": platform.system(),
        "platform": platform.platform(),
        "production_ready": in_git_repo and has_commit and not dirty and platform.system().lower() == "linux",
        "reason": "No committed SHA yet" if in_git_repo and not has_commit else None,
        "generated_at": now(),
        "notes": notes,
    }


def collect_local_quality_gate(*, run_quality: bool) -> dict[str, Any]:
    commands = {
        "pip_install_dev": [sys.executable, "-m", "pip", "install", "-e", ".[dev]"],
        "unittest": [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        "ruff": [sys.executable, "-m", "ruff", "check", "."],
        "mypy": [sys.executable, "-m", "mypy", "."],
        "coverage_run": [sys.executable, "-m", "coverage", "run", "-m", "unittest", "discover", "-s", "tests"],
        "coverage_report": [sys.executable, "-m", "coverage", "report"],
    }
    if not run_quality:
        return {
            "status": "skipped",
            "production_blocking": False,
            "reason": "local quality gate was not run; pass --run-quality to execute it",
            "recommendation": "Run with --run-quality before archiving local RC evidence.",
            "coverage_threshold": 70,
            "generated_at": now(),
            "commands": {name: " ".join(command) for name, command in commands.items()},
        }

    results = {name: _run_text(command) for name, command in commands.items()}
    coverage_percent = _parse_coverage_percent(results["coverage_report"]["stdout"])
    passed = all(item["exit_code"] == 0 for item in results.values())
    return {
        "status": "pass" if passed else "fail",
        "production_blocking": not passed,
        "pip_install_dev": _pass_fail(results["pip_install_dev"]["exit_code"]),
        "unittest": _pass_fail(results["unittest"]["exit_code"]),
        "unittest_summary": _excerpt(results["unittest"]["stderr"] or results["unittest"]["stdout"]),
        "ruff": _pass_fail(results["ruff"]["exit_code"]),
        "mypy": _pass_fail(results["mypy"]["exit_code"]),
        "coverage": _pass_fail(results["coverage_report"]["exit_code"]),
        "coverage_percent": coverage_percent,
        "coverage_threshold": 70,
        "skipped_summary": _extract_skipped_summary(results["unittest"]["stderr"] + results["unittest"]["stdout"]),
        "commands": {
            name: {
                "command": " ".join(commands[name]),
                "exit_code": result["exit_code"],
                "stdout_excerpt": _excerpt(result["stdout"]),
                "stderr_excerpt": _excerpt(result["stderr"]),
            }
            for name, result in results.items()
        },
        "generated_at": now(),
    }


def collect_ci_result() -> dict[str, Any]:
    if shutil.which("gh") is None:
        return missing_evidence(
            "ci_result",
            "gh CLI is not available; GitHub Actions run metadata was not collected",
            "Run gh run view <RUN_ID> --json url,headSha,status,conclusion,workflowName,jobs on a logged-in machine.",
        )
    result = _run_text(["gh", "run", "list", "--limit", "1", "--json", "url,headSha,status,conclusion,workflowName,jobs"])
    if result["exit_code"] != 0:
        return missing_evidence(
            "ci_result",
            "gh CLI did not return run metadata; it may be logged out or outside a GitHub repository",
            "Authenticate gh and collect the target workflow run.",
            details={"stderr_excerpt": _excerpt(result["stderr"])},
        )
    try:
        runs = json.loads(result["stdout"])
    except json.JSONDecodeError:
        runs = None
    if not isinstance(runs, list) or not runs:
        return missing_evidence(
            "ci_result",
            "gh CLI returned no workflow runs",
            "Provide the real GitHub Actions run URL and job matrix evidence.",
        )
    run = runs[0]
    conclusion = str(run.get("conclusion") or "").lower()
    status = "pass" if conclusion == "success" else "fail"
    return {
        "status": status,
        "production_blocking": status != "pass",
        "run_url": run.get("url"),
        "workflow_name": run.get("workflowName"),
        "head_sha": run.get("headSha"),
        "conclusion": run.get("conclusion"),
        "jobs": run.get("jobs"),
        "generated_at": now(),
        "reason": "latest GitHub Actions run metadata collected via gh CLI",
    }


def collect_bwrap_validation(output_dir: Path) -> dict[str, Any]:
    if platform.system().lower() != "linux" or shutil.which("bwrap") is None:
        reason = "bubblewrap validation requires target Linux host with bwrap installed"
        return {
            "status": "skipped",
            "production_blocking": True,
            "reason": reason,
            "recommendation": "Run scripts/validate_bwrap_sandbox.py --json on the target Linux+bwrap host.",
            "environment": {"os": platform.system(), "bwrap": shutil.which("bwrap")},
            "generated_at": now(),
        }
    return run_json_command(
        "bwrap_validation",
        [
            sys.executable,
            "scripts/validate_bwrap_sandbox.py",
            "--json",
        ],
        production_blocking_on_fail=True,
        tolerate_existing_output=output_dir / EVIDENCE_NAMES["bwrap"],
    )


def collect_scanner_report(path: str | None) -> dict[str, Any]:
    if not path:
        return {
            "status": "missing",
            "production_blocking": True,
            "controlled_risk_required": True,
            "reason": "real vulnerability/license scanner report was not provided",
            "recommendation": "Run pip-audit, OSV, Safety, Grype, or enterprise SCA and archive scanner_report.json.",
            "generated_at": now(),
        }
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "fail",
            "production_blocking": True,
            "reason": f"scanner report could not be read: {type(exc).__name__}: {exc}",
            "recommendation": "Provide a valid scanner report JSON.",
            "generated_at": now(),
        }
    if not isinstance(payload, dict):
        return {
            "status": "fail",
            "production_blocking": True,
            "reason": "scanner report must be a JSON object",
            "recommendation": "Provide a valid scanner report JSON.",
            "generated_at": now(),
        }
    payload.setdefault("status", "pass" if payload.get("policy_decision") == "pass" else "fail")
    payload.setdefault("generated_at", now())
    payload["production_blocking"] = payload.get("status") != "pass" and payload.get("policy_decision") != "pass"
    return payload


def collect_audit_verify(
    audit_log: str | None,
    audit_checkpoint: str | None,
    audit_public_key: str | None,
) -> dict[str, Any]:
    if not audit_log:
        return missing_evidence(
            "audit_verify",
            "audit log path was not provided",
            "Run plugin-cli audit verify/status with a real audit log and checkpoint evidence.",
        )
    command = [
        sys.executable,
        "cli.py",
        "audit",
        "status",
        "--log",
        audit_log,
    ]
    if audit_checkpoint:
        command.extend(["--checkpoint", audit_checkpoint])
    if audit_public_key:
        command.extend(["--public-key", audit_public_key])
    payload = run_json_or_yaml_command("audit_verify", command, production_blocking_on_fail=True)
    payload.setdefault("external_anchor_configured", False)
    payload.setdefault("production_immutability", False)
    if not audit_checkpoint:
        payload["status"] = "fail"
        payload["production_blocking"] = True
        payload["reason"] = "audit checkpoint evidence is missing"
    return payload


def collect_release_gate(output_dir: Path) -> dict[str, Any]:
    command = [
        sys.executable,
        "scripts/release_gate.py",
        "--doctor",
        str(output_dir / EVIDENCE_NAMES["doctor"]),
        "--bwrap",
        str(output_dir / EVIDENCE_NAMES["bwrap"]),
        "--audit",
        str(output_dir / EVIDENCE_NAMES["audit"]),
        "--scan",
        str(output_dir / EVIDENCE_NAMES["scanner"]),
        "--ci",
        str(output_dir / EVIDENCE_NAMES["ci"]),
        "--registry",
        str(output_dir / EVIDENCE_NAMES["registry"]),
        "--revocation",
        str(output_dir / EVIDENCE_NAMES["revocation"]),
        "--quarantine",
        str(output_dir / EVIDENCE_NAMES["quarantine"]),
        "--rollback",
        str(output_dir / EVIDENCE_NAMES["rollback"]),
        "--json",
    ]
    return run_json_command("release_gate", command, production_blocking_on_fail=True)


def run_json_command(
    evidence_id: str,
    command: list[str],
    *,
    production_blocking_on_fail: bool,
    tolerate_existing_output: Path | None = None,
) -> dict[str, Any]:
    result = _run_text(command)
    payload = _parse_json(result["stdout"])
    if payload is None and tolerate_existing_output and tolerate_existing_output.exists():
        payload = _parse_json(tolerate_existing_output.read_text(encoding="utf-8-sig"))
    if payload is None:
        payload = {
            "status": "pass" if result["exit_code"] == 0 else "fail",
            "reason": f"{evidence_id} command completed with exit_code={result['exit_code']}",
        }
    payload.setdefault("status", "pass" if result["exit_code"] == 0 else "fail")
    payload.setdefault("generated_at", now())
    payload["command"] = " ".join(command)
    payload["exit_code"] = result["exit_code"]
    payload["stdout_excerpt"] = _excerpt(result["stdout"])
    payload["stderr_excerpt"] = _excerpt(result["stderr"])
    status = str(payload.get("status", "")).lower()
    payload["production_blocking"] = bool(
        payload.get("production_blocking") or (production_blocking_on_fail and status != "pass")
    )
    if status == "skipped":
        payload["production_blocking"] = production_blocking_on_fail
    return payload


def run_json_or_yaml_command(
    evidence_id: str,
    command: list[str],
    *,
    production_blocking_on_fail: bool,
) -> dict[str, Any]:
    payload = run_json_command(evidence_id, command, production_blocking_on_fail=production_blocking_on_fail)
    if payload.get("reason", "").startswith(f"{evidence_id} command completed"):
        try:
            import yaml

            parsed = yaml.safe_load(str(payload.get("stdout_excerpt", "")))
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            parsed["command"] = payload["command"]
            parsed["exit_code"] = payload["exit_code"]
            parsed["stdout_excerpt"] = payload["stdout_excerpt"]
            parsed["stderr_excerpt"] = payload["stderr_excerpt"]
            parsed.setdefault("status", "pass" if payload["exit_code"] == 0 else "fail")
            parsed["production_blocking"] = production_blocking_on_fail and parsed["status"] != "pass"
            return parsed
    return payload


def missing_evidence(evidence_id: str, reason: str, recommendation: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "evidence_id": evidence_id,
        "status": "missing",
        "production_blocking": True,
        "reason": reason,
        "recommendation": recommendation,
        "details": details or {},
        "generated_at": now(),
    }


def _write_item(output_dir: Path, evidence_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    path = output_dir / EVIDENCE_NAMES[evidence_id]
    write_json(path, payload)
    status = str(payload.get("status", "fail")).lower()
    return {
        "evidence_id": evidence_id,
        "path": str(path),
        "status": status,
        "production_blocking": bool(payload.get("production_blocking") or status in {"missing", "failed", "fail"}),
        "reason": str(payload.get("reason") or payload.get("summary") or ""),
    }


def _run_text(command: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        return {"exit_code": 127, "stdout": "", "stderr": str(exc)}
    return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _parse_json(text: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _pass_fail(exit_code: int) -> str:
    return "pass" if exit_code == 0 else "fail"


def _parse_coverage_percent(text: str) -> float | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("TOTAL") and "%" in stripped:
            percent = stripped.rsplit(None, 1)[-1].rstrip("%")
            try:
                return float(percent)
            except ValueError:
                return None
    return None


def _extract_skipped_summary(text: str) -> str:
    for line in text.splitlines():
        if "skipped" in line.lower():
            return line.strip()
    return ""


def _excerpt(text: str, limit: int = 4000) -> str:
    cleaned = text.strip()
    return cleaned if len(cleaned) <= limit else cleaned[:limit] + "...<truncated>"


def now() -> str:
    return datetime.now(UTC).isoformat()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect local RC evidence JSON files")
    parser.add_argument("--output-dir", default="evidence")
    parser.set_defaults(run_quality=True)
    parser.add_argument("--run-quality", action="store_true", help="run pip install, unittest, ruff, mypy, and coverage")
    parser.add_argument(
        "--skip-quality",
        action="store_false",
        dest="run_quality",
        help="skip local quality gate collection; the evidence will be marked skipped",
    )
    parser.add_argument("--scanner-report", help="path to a real scanner report JSON")
    parser.add_argument("--audit-log")
    parser.add_argument("--audit-checkpoint")
    parser.add_argument("--audit-public-key")
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect_evidence(args)
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"RC evidence status={report['status']}")
        for item in report["items"]:
            blocking = " blocking" if item["production_blocking"] else ""
            print(f"- [{item['status']}] {item['evidence_id']}{blocking}: {item['path']}")
    return 0 if report["production_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
