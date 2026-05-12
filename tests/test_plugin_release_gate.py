from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.plugin_system.release_gate import CONTROLLED_GO, GO, NO_GO, GateInput, evaluate_release_gate
from scripts.run_production_acceptance import run_acceptance


class ReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix=f"{self._testMethodName}-", dir=Path.cwd() / "data" / "test_runs"))

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_all_key_evidence_passes_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap={"status": "pass"},
                audit={"status": "pass", "checkpoint": {"status": "success"}},
                scan={"policy_decision": "pass"},
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, GO)

    def test_scanner_missing_with_accepted_risk_is_controlled_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap={"status": "pass"},
                audit={"status": "pass", "checkpoint": {"status": "success"}},
                scan=None,
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
                risk_acceptance={"accepted": True, "accepted_risks": ["R-003"]},
            )
        )
        self.assertEqual(result.decision, CONTROLLED_GO)

    def test_bwrap_fail_is_no_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap={"status": "fail", "reason": "bubblewrap unavailable"},
                audit={"status": "pass", "checkpoint": {"status": "success"}},
                scan={"policy_decision": "pass"},
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)

    def test_audit_checkpoint_fail_is_no_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap={"status": "pass"},
                audit={"status": "pass", "checkpoint": {"status": "fail"}},
                scan={"policy_decision": "pass"},
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)

    def test_missing_ci_without_risk_acceptance_is_no_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci=None,
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap={"status": "pass"},
                audit={"status": "pass", "checkpoint": {"status": "success"}},
                scan={"policy_decision": "pass"},
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)

    def test_windows_third_party_production_doctor_finding_is_no_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={
                    "status": "warn",
                    "production_blocking": True,
                    "checks": [
                        {
                            "check_id": "sandbox.windows.boundary",
                            "status": "warn",
                            "reason": "Windows Job Object is not full isolation",
                            "production_blocking": True,
                        }
                    ],
                },
                bwrap={"status": "pass"},
                audit={"status": "pass", "checkpoint": {"status": "success"}},
                scan={"policy_decision": "pass"},
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)

    def test_release_gate_script_outputs_json(self) -> None:
        ci = self._write_json("ci.json", {"status": "pass"})
        doctor = self._write_json("doctor.json", {"status": "pass", "production_blocking": False, "checks": []})
        bwrap = self._write_json("bwrap.json", {"status": "pass"})
        audit = self._write_json("audit.json", {"status": "pass", "checkpoint": {"status": "success"}})
        scan = self._write_json("scan.json", {"policy_decision": "pass"})
        registry = self._write_json("registry.json", {"status": "pass"})
        revocation = self._write_json("revocation.json", {"status": "pass"})
        quarantine = self._write_json("quarantine.json", {"status": "pass"})
        rollback = self._write_json("rollback.json", {"status": "pass"})
        result = subprocess.run(
            [
                sys.executable,
                "scripts/release_gate.py",
                "--ci",
                str(ci),
                "--doctor",
                str(doctor),
                "--bwrap",
                str(bwrap),
                "--audit",
                str(audit),
                "--scan",
                str(scan),
                "--registry",
                str(registry),
                "--revocation",
                str(revocation),
                "--quarantine",
                str(quarantine),
                "--rollback",
                str(rollback),
                "--json",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["decision"], GO)

    def test_acceptance_runner_marks_missing_evidence_not_ready(self) -> None:
        args = argparse.Namespace(
            plugins_dir=self.root / "plugins",
            audit_log=None,
            audit_checkpoint=None,
            audit_public_key=None,
            scanner_configured=False,
            audit_anchor_configured=False,
            policy_source=None,
            policy_signature=None,
            policy_public_key=None,
            policy_trust_store=None,
            scan_report=None,
            sample_sbom=None,
            registry_index=None,
            registry_index_signature=None,
            registry_public_key=None,
            registry_trust_store=None,
            revocation_drill_json=None,
        )
        with patch("scripts.run_production_acceptance._run_step", side_effect=self._passing_acceptance_step):
            report = run_acceptance(args)
        self.assertEqual(report["status"], "not_ready")
        self.assertFalse(report["production_ready"])
        self.assertTrue(any(step["status"] == "skipped" for step in report["steps"]))

    def _passing_acceptance_step(self, step_id: str, command: list[str], **kwargs: object) -> dict[str, object]:
        return {
            "step_id": step_id,
            "command": " ".join(command),
            "status": "pass",
            "exit_code": 0,
            "stdout_excerpt": "",
            "stderr_excerpt": "",
            "production_blocking": False,
            "recommendation": "Archive this evidence.",
        }

    def _write_json(self, name: str, payload: dict[str, object]) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
