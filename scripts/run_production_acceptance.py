from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_acceptance(args: argparse.Namespace) -> dict[str, Any]:
    steps = [
        _run_step("unittest", [sys.executable, "-m", "unittest", "discover", "-s", "tests"], blocking=True),
        _run_step(
            "doctor",
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(args.plugins_dir),
                "--production",
                "doctor",
                "--json",
                *(_optional_flag("--audit-log", args.audit_log)),
                *(["--scanner-configured"] if args.scanner_configured else []),
                *(["--audit-anchor-configured"] if args.audit_anchor_configured else []),
            ],
            blocking=True,
            json_status=True,
        ),
        _run_step(
            "bwrap_validation",
            [sys.executable, "scripts/validate_bwrap_sandbox.py", "--json"],
            blocking=False,
            json_status=True,
            skipped_not_ready=True,
        ),
    ]
    if args.audit_log:
        steps.append(
            _run_step(
                "audit_verify",
                [
                    sys.executable,
                    "cli.py",
                    "audit",
                    "status",
                    "--log",
                    str(args.audit_log),
                    *(_optional_flag("--checkpoint", args.audit_checkpoint)),
                    *(_optional_flag("--public-key", args.audit_public_key)),
                ],
                blocking=True,
                yaml_or_json_status=True,
            )
        )
    else:
        steps.append(_skipped_step("audit_verify", "provide --audit-log to verify audit evidence", blocking=True))

    if args.policy_source:
        steps.append(
            _run_step(
                "policy_check",
                [
                    sys.executable,
                    "cli.py",
                    "--production",
                    "policy",
                    "check",
                    str(args.policy_source),
                    "--json",
                    *(_optional_flag("--signature", args.policy_signature)),
                    *(_optional_flag("--public-key", args.policy_public_key)),
                    *(_optional_flag("--trust-store", args.policy_trust_store)),
                    *(_optional_flag("--scan-report", args.scan_report)),
                ],
                blocking=True,
                json_status=True,
            )
        )
    else:
        steps.append(_skipped_step("policy_check", "provide --policy-source to check a production plugin", blocking=True))

    if args.sample_sbom:
        steps.append(
            _run_step(
                "scan_sbom",
                [sys.executable, "cli.py", "scan", "sbom", str(args.sample_sbom), "--json"],
                blocking=True,
                json_status=True,
            )
        )
    else:
        steps.append(_skipped_step("scan_sbom", "provide --sample-sbom to run scanner adapter evidence", blocking=True))

    if args.registry_index:
        steps.append(
            _run_step(
                "signed_registry_verify",
                [
                    sys.executable,
                    "cli.py",
                    "--production",
                    "registry",
                    "list",
                    "--index",
                    str(args.registry_index),
                    *(_optional_flag("--index-signature", args.registry_index_signature)),
                    *(_optional_flag("--index-public-key", args.registry_public_key)),
                    *(_optional_flag("--index-trust-store", args.registry_trust_store)),
                ],
                blocking=True,
            )
        )
    else:
        steps.append(_skipped_step("signed_registry_verify", "provide --registry-index evidence", blocking=True))

    if args.revocation_drill_json:
        steps.append(_file_step("revocation_drill", args.revocation_drill_json, blocking=True))
    else:
        steps.append(_skipped_step("revocation_drill", "provide --revocation-drill-json evidence", blocking=True))

    production_ready = all(step["status"] == "pass" for step in steps)
    if any(step["status"] == "skipped" for step in steps):
        production_ready = False
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "pass" if production_ready else "not_ready",
        "production_ready": production_ready,
        "summary": (
            "all acceptance steps passed"
            if production_ready
            else "one or more acceptance steps failed or were skipped; do not treat as full production evidence"
        ),
        "steps": steps,
    }


def _run_step(
    step_id: str,
    command: list[str],
    *,
    blocking: bool,
    json_status: bool = False,
    yaml_or_json_status: bool = False,
    skipped_not_ready: bool = False,
) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    parsed = _parse_json(result.stdout) if json_status or yaml_or_json_status else None
    status = "pass" if result.returncode == 0 else "fail"
    if parsed and str(parsed.get("status", "")).lower() == "skipped":
        status = "skipped"
    if parsed and parsed.get("production_blocking"):
        status = "fail"
    if skipped_not_ready and status == "skipped":
        recommendation = "Run this step on the target Linux host with bubblewrap installed."
    else:
        recommendation = "Investigate failure before RC-1 approval." if status == "fail" else "Archive this evidence."
    return {
        "step_id": step_id,
        "command": _display_command(command),
        "status": status,
        "exit_code": result.returncode,
        "stdout_excerpt": _excerpt(result.stdout),
        "stderr_excerpt": _excerpt(result.stderr),
        "production_blocking": blocking and status != "pass",
        "recommendation": recommendation,
        "parsed": parsed,
    }


def _file_step(step_id: str, path: str | Path, *, blocking: bool) -> dict[str, Any]:
    payload = _parse_json(Path(path).read_text(encoding="utf-8"))
    status = str((payload or {}).get("status", "pass")).lower()
    status = "pass" if status in {"pass", "success", "ok"} else "fail"
    return {
        "step_id": step_id,
        "command": f"read {path}",
        "status": status,
        "exit_code": 0 if status == "pass" else 1,
        "stdout_excerpt": _excerpt(json.dumps(payload, sort_keys=True)),
        "stderr_excerpt": "",
        "production_blocking": blocking and status != "pass",
        "recommendation": "Archive this evidence." if status == "pass" else "Fix revocation drill before approval.",
        "parsed": payload,
    }


def _skipped_step(step_id: str, reason: str, *, blocking: bool) -> dict[str, Any]:
    return {
        "step_id": step_id,
        "command": "",
        "status": "skipped",
        "exit_code": None,
        "stdout_excerpt": "",
        "stderr_excerpt": "",
        "production_blocking": blocking,
        "recommendation": reason,
    }


def _parse_json(text: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _optional_flag(flag: str, value: str | Path | None) -> list[str]:
    return [flag, str(value)] if value else []


def _display_command(command: list[str]) -> str:
    return " ".join(command)


def _excerpt(text: str, limit: int = 4000) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run RC production acceptance evidence commands")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--output")
    parser.add_argument("--plugins-dir", default="data/plugins")
    parser.add_argument("--audit-log")
    parser.add_argument("--audit-checkpoint")
    parser.add_argument("--audit-public-key")
    parser.add_argument("--scanner-configured", action="store_true")
    parser.add_argument("--audit-anchor-configured", action="store_true")
    parser.add_argument("--policy-source")
    parser.add_argument("--policy-signature")
    parser.add_argument("--policy-public-key")
    parser.add_argument("--policy-trust-store")
    parser.add_argument("--scan-report")
    parser.add_argument("--sample-sbom")
    parser.add_argument("--registry-index")
    parser.add_argument("--registry-index-signature")
    parser.add_argument("--registry-public-key")
    parser.add_argument("--registry-trust-store")
    parser.add_argument("--revocation-drill-json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_acceptance(args)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    if args.json_output:
        print(text)
    else:
        print(f"production acceptance status={report['status']}")
        for step in report["steps"]:
            blocking = " blocking" if step["production_blocking"] else ""
            print(f"- [{step['status']}] {step['step_id']}{blocking}: {step['recommendation']}")
    return 0 if report["production_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
