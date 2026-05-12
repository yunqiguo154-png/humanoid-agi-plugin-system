from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


GO = "GO"
CONTROLLED_GO = "CONTROLLED_GO"
NO_GO = "NO_GO"


@dataclass(frozen=True)
class GateInput:
    doctor: dict[str, Any] | None = None
    bwrap: dict[str, Any] | None = None
    audit: dict[str, Any] | None = None
    scan: dict[str, Any] | None = None
    registry: dict[str, Any] | None = None
    revocation: dict[str, Any] | None = None
    quarantine: dict[str, Any] | None = None
    rollback: dict[str, Any] | None = None
    ci: dict[str, Any] | None = None
    risk_acceptance: dict[str, Any] | None = None


@dataclass(frozen=True)
class GateFinding:
    check_id: str
    status: str
    reason: str
    production_blocking: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": self.status,
            "reason": self.reason,
            "production_blocking": self.production_blocking,
        }


@dataclass(frozen=True)
class GateResult:
    decision: str
    reason: str
    findings: list[GateFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "findings": [item.to_dict() for item in self.findings],
        }


def evaluate_release_gate(inputs: GateInput) -> GateResult:
    findings: list[GateFinding] = []
    risks_accepted = _risks_accepted(inputs.risk_acceptance)

    findings.append(_ci_finding(inputs.ci, risks_accepted))
    findings.extend(_doctor_findings(inputs.doctor))
    findings.append(_status_finding("bwrap.validation", inputs.bwrap, require_pass=True))
    findings.append(_audit_finding(inputs.audit))
    findings.append(_scan_finding(inputs.scan, risks_accepted))
    findings.append(_status_finding("registry.verify", inputs.registry, require_pass=True))
    findings.append(_status_finding("revocation.drill", inputs.revocation, require_pass=True))
    findings.append(_status_finding("quarantine.drill", inputs.quarantine, require_pass=True))
    findings.append(_status_finding("rollback.drill", inputs.rollback, require_pass=True))
    findings = [item for item in findings if item is not None]

    if any(item.production_blocking or item.status == "fail" for item in findings):
        return GateResult(
            decision=NO_GO,
            reason="one or more production-blocking release checks failed",
            findings=findings,
        )

    controlled_reasons = [
        item.reason
        for item in findings
        if item.status in {"warn", "skipped"} or "accepted risk" in item.reason.lower()
    ]
    if controlled_reasons:
        return GateResult(
            decision=CONTROLLED_GO,
            reason="release is gated by accepted risks or incomplete non-blocking evidence",
            findings=findings,
        )

    return GateResult(decision=GO, reason="all release gate evidence passed", findings=findings)


def load_gate_input(
    *,
    doctor: str | Path | None = None,
    bwrap: str | Path | None = None,
    audit: str | Path | None = None,
    scan: str | Path | None = None,
    registry: str | Path | None = None,
    revocation: str | Path | None = None,
    quarantine: str | Path | None = None,
    rollback: str | Path | None = None,
    ci: str | Path | None = None,
    risk_acceptance: str | Path | None = None,
) -> GateInput:
    return GateInput(
        doctor=_read_json(doctor),
        bwrap=_read_json(bwrap),
        audit=_read_json(audit),
        scan=_read_json(scan),
        registry=_read_json(registry),
        revocation=_read_json(revocation),
        quarantine=_read_json(quarantine),
        rollback=_read_json(rollback),
        ci=_read_json(ci),
        risk_acceptance=_read_json(risk_acceptance),
    )


def _read_json(path: str | Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"release gate input must be a JSON object: {path}")
    return payload


def _risks_accepted(payload: dict[str, Any] | None) -> bool:
    if not payload:
        return False
    if payload.get("accepted") is True:
        return True
    accepted = payload.get("accepted_risks")
    return isinstance(accepted, list) and bool(accepted)


def _ci_finding(payload: dict[str, Any] | None, risks_accepted: bool) -> GateFinding:
    if payload is None:
        return GateFinding(
            "ci.matrix",
            "warn" if risks_accepted else "fail",
            "CI result metadata is missing" + ("; accepted risk" if risks_accepted else ""),
            production_blocking=not risks_accepted,
        )
    status = _normalized_status(payload)
    return GateFinding(
        "ci.matrix",
        "pass" if status == "pass" else "fail",
        str(payload.get("reason") or payload.get("summary") or f"CI status={status}"),
        production_blocking=status != "pass",
    )


def _doctor_findings(payload: dict[str, Any] | None) -> list[GateFinding]:
    if payload is None:
        return [
            GateFinding(
                "doctor.production",
                "fail",
                "Production Doctor evidence is missing",
                production_blocking=True,
            )
        ]
    findings: list[GateFinding] = []
    for item in payload.get("checks", []):
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id", "doctor.unknown"))
        status = str(item.get("status", "fail"))
        reason = str(item.get("reason", ""))
        blocking = bool(item.get("production_blocking"))
        findings.append(GateFinding(check_id, status, reason, production_blocking=blocking))
    if payload.get("production_blocking"):
        findings.append(
            GateFinding(
                "doctor.production_blocking",
                "fail",
                "Production Doctor reported production_blocking=true",
                production_blocking=True,
            )
        )
    return findings or [GateFinding("doctor.production", _normalized_status(payload), "doctor evidence parsed")]


def _status_finding(check_id: str, payload: dict[str, Any] | None, *, require_pass: bool) -> GateFinding:
    if payload is None:
        return GateFinding(check_id, "fail", f"{check_id} evidence is missing", production_blocking=require_pass)
    status = _normalized_status(payload)
    if check_id == "bwrap.validation" and status == "skipped":
        return GateFinding(
            check_id,
            "fail",
            "bwrap validation was skipped; target Linux sandbox evidence is required for full production",
            production_blocking=True,
        )
    return GateFinding(
        check_id,
        "pass" if status == "pass" else "fail",
        str(payload.get("reason") or payload.get("summary") or f"{check_id} status={status}"),
        production_blocking=require_pass and status != "pass",
    )


def _audit_finding(payload: dict[str, Any] | None) -> GateFinding:
    if payload is None:
        return GateFinding("audit.verify", "fail", "audit verification evidence is missing", production_blocking=True)
    status = _normalized_status(payload)
    checkpoint = payload.get("checkpoint")
    checkpoint_status = checkpoint.get("status") if isinstance(checkpoint, dict) else None
    if status == "pass" and checkpoint_status in {None, "success", "pass"}:
        return GateFinding("audit.verify", "pass", "audit hash chain and checkpoint verified")
    return GateFinding(
        "audit.verify",
        "fail",
        str(payload.get("reason") or f"audit status={status} checkpoint={checkpoint_status}"),
        production_blocking=True,
    )


def _scan_finding(payload: dict[str, Any] | None, risks_accepted: bool) -> GateFinding:
    if payload is None:
        return GateFinding(
            "scanner.policy",
            "warn" if risks_accepted else "fail",
            "scanner evidence is missing" + ("; accepted risk" if risks_accepted else ""),
            production_blocking=not risks_accepted,
        )
    status = _normalized_status(payload)
    policy_decision = str(payload.get("policy_decision", "")).lower()
    passed = status == "pass" or policy_decision == "pass"
    return GateFinding(
        "scanner.policy",
        "pass" if passed else "fail",
        str(payload.get("reason") or f"scanner status={status} policy_decision={policy_decision}"),
        production_blocking=not passed,
    )


def _normalized_status(payload: dict[str, Any]) -> str:
    for key in ["status", "conclusion", "decision", "policy_decision"]:
        value = payload.get(key)
        if isinstance(value, str) and value:
            normalized = value.strip().lower()
            if normalized in {"success", "ok", "passed", "pass", "go"}:
                return "pass"
            if normalized in {"controlled_go", "warn", "warning"}:
                return "warn"
            if normalized in {"skipped", "skip"}:
                return "skipped"
            return "fail"
    if payload.get("production_blocking"):
        return "fail"
    return "pass"


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate Humanoid AGI plugin RC release gate evidence")
    parser.add_argument("--doctor")
    parser.add_argument("--bwrap")
    parser.add_argument("--audit")
    parser.add_argument("--scan")
    parser.add_argument("--registry")
    parser.add_argument("--revocation")
    parser.add_argument("--quarantine")
    parser.add_argument("--rollback")
    parser.add_argument("--ci")
    parser.add_argument("--risk-acceptance")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    result = evaluate_release_gate(
        load_gate_input(
            doctor=args.doctor,
            bwrap=args.bwrap,
            audit=args.audit,
            scan=args.scan,
            registry=args.registry,
            revocation=args.revocation,
            quarantine=args.quarantine,
            rollback=args.rollback,
            ci=args.ci,
            risk_acceptance=args.risk_acceptance,
        )
    )
    payload = result.to_dict()
    if args.json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{payload['decision']}: {payload['reason']}")
        for item in payload["findings"]:
            blocking = " blocking" if item["production_blocking"] else ""
            print(f"- [{item['status']}] {item['check_id']}{blocking}: {item['reason']}")
    return 0 if result.decision in {GO, CONTROLLED_GO} else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
