from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.plugin_system.audit import (
    AuditLogIntegrityError,
    AuditLogger,
    LocalCheckpointAnchor,
    create_audit_checkpoint,
    verify_audit_log,
)


def generate_evidence(
    *,
    output: str | Path = "evidence/audit_verify.json",
    audit_log: str | Path | None = None,
    checkpoint: str | Path | None = None,
) -> dict[str, Any]:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if audit_log is None or checkpoint is None:
        audit_log_path, checkpoint_path = create_local_audit_pair(output_path.parent)
    else:
        audit_log_path = Path(audit_log)
        checkpoint_path = Path(checkpoint)

    report = verify_local_audit_pair(audit_log_path, checkpoint_path)
    report.update(
        {
            "evidence_id": "audit_verify",
            "audit_log_path": str(audit_log_path),
            "checkpoint_path": str(checkpoint_path),
            "external_anchor_configured": False,
            "production_immutability": False,
            "controlled_risk_required": True,
            "production_blocking": True,
            "generated_at": datetime.now(UTC).isoformat(),
        }
    )
    if report["hash_chain_verified"] and report["checkpoint_verified"]:
        report["status"] = "warn"
        report["reason"] = (
            "Local audit hash chain and checkpoint verified, but no external append-only/SIEM/WORM anchor is "
            "configured. This is tamper-evident local evidence only."
        )
        report["recommendation"] = (
            "Archive this local evidence, then configure an external audit anchor or record a formal accepted risk "
            "before controlled production approval."
        )
    else:
        report["status"] = "failed"
        report["reason"] = str(report.get("error") or "local audit verification failed")
        report["recommendation"] = "Fix audit hash chain/checkpoint verification before release approval."

    write_json(output_path, report)
    return report


def create_local_audit_pair(root: str | Path) -> tuple[Path, Path]:
    root_path = Path(root)
    root_path.mkdir(parents=True, exist_ok=True)
    audit_log_path = root_path / "audit.local.jsonl"
    checkpoint_path = root_path / "audit.local.checkpoint.json"

    if audit_log_path.exists():
        audit_log_path.unlink()
    if checkpoint_path.exists():
        checkpoint_path.unlink()

    audit_logger = AuditLogger(audit_log_path)
    audit_logger.record("audit.evidence.start", "success", plugin="audit_evidence", action="generate")
    audit_logger.record("audit.evidence.verify", "success", plugin="audit_evidence", action="verify")

    anchor = LocalCheckpointAnchor(checkpoint_path)
    anchor.write_checkpoint(create_audit_checkpoint(audit_log_path))
    return audit_log_path, checkpoint_path


def verify_local_audit_pair(audit_log: str | Path, checkpoint: str | Path) -> dict[str, Any]:
    audit_log_path = Path(audit_log)
    checkpoint_path = Path(checkpoint)
    anchor = LocalCheckpointAnchor(checkpoint_path)
    try:
        verification = verify_audit_log(audit_log_path, anchor=anchor)
        checkpoint_report = verification.get("checkpoint")
        checkpoint_verified = isinstance(checkpoint_report, dict) and checkpoint_report.get("status") == "success"
        return {
            "hash_chain_verified": verification.get("status") == "success",
            "checkpoint_verified": checkpoint_verified,
            "rollback_detection_available": checkpoint_verified,
            "verification": verification,
        }
    except AuditLogIntegrityError as exc:
        return {
            "hash_chain_verified": False,
            "checkpoint_verified": False,
            "rollback_detection_available": False,
            "error": str(exc),
        }


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate local audit verify evidence for RC acceptance")
    parser.add_argument("--output", default="evidence/audit_verify.json")
    parser.add_argument("--audit-log")
    parser.add_argument("--checkpoint")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)

    report = generate_evidence(output=args.output, audit_log=args.audit_log, checkpoint=args.checkpoint)
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] in {"pass", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
