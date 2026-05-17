from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.plugin_system.release_gate import CONTROLLED_GO, GO, NO_GO, GateInput, evaluate_release_gate
from scripts.run_production_acceptance import run_acceptance
from tests.test_utils import make_test_root


class ReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = make_test_root(self._testMethodName)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_all_key_evidence_passes_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan=self._scan_payload(),
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
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
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
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)

    def test_github_hosted_diagnostic_fail_keeps_bwrap_blocker(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap={"mode": "diagnostic", "environment_class": "github_hosted", "status": "fail"},
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)
        blocking = {item.check_id for item in result.findings if item.production_blocking}
        self.assertIn("sandbox.target_linux_required", blocking)

    def test_github_hosted_diagnostic_unsupported_keeps_bwrap_blocker(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap={"mode": "diagnostic", "environment_class": "github_hosted", "status": "unsupported_environment"},
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)

    def test_diagnostic_pass_cannot_release_bwrap_blocker(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap=self._production_bwrap_payload(status="pass", mode="diagnostic", environment_class="self_hosted"),
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)

    def test_production_required_bwrap_pass_releases_blocker(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, GO)

    def test_production_required_bwrap_fail_is_no_go(self) -> None:
        payload = self._production_bwrap_payload(status="fail")
        payload["sandbox_backend"]["enforced"] = False
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap=payload,
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)

    def test_enforced_bwrap_worker_empty_output_has_specific_blocker(self) -> None:
        payload = self._production_bwrap_payload(status="fail")
        payload["reason"] = "production-required bwrap validation did not pass"
        payload["result"] = {
            "status": "error",
            "error_type": "WorkerNoOutput",
            "worker_started": False,
            "json_result_received": False,
        }
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap=payload,
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        blocking = {item.check_id for item in result.findings if item.production_blocking}
        self.assertIn("bwrap.validation.worker_execution_failed", blocking)
        self.assertEqual(result.decision, NO_GO)

    def test_enforced_bwrap_preflight_import_fail_has_specific_blocker(self) -> None:
        payload = self._production_bwrap_payload(status="fail")
        payload["reason"] = "runtime import failed under bwrap"
        payload["preflight"] = {"status": "fail", "import_runtime": "fail"}
        payload["result"] = {"status": "not_run", "worker_started": False, "json_result_received": False}
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap=payload,
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        blocking = {item.check_id for item in result.findings if item.production_blocking}
        self.assertIn("bwrap.validation.runtime_import_failed", blocking)
        self.assertEqual(result.decision, NO_GO)

    def test_audit_checkpoint_fail_is_no_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap=self._production_bwrap_payload(),
                audit={"status": "pass", "checkpoint": {"status": "fail"}},
                scan=self._scan_payload(),
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
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, NO_GO)

    def test_github_actions_completed_success_with_full_matrix_passes_ci(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={
                    "status": "completed",
                    "conclusion": "success",
                    "linux_python_3_11": "pass",
                    "linux_python_3_12": "pass",
                    "linux_python_3_13": "pass",
                    "windows_python_3_11": "pass",
                    "windows_python_3_12": "pass",
                    "windows_python_3_13": "pass",
                    "ruff_result": "pass",
                    "mypy_result": "pass",
                    "unittest_result": "pass",
                    "coverage_result": "pass",
                },
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        self.assertEqual(result.decision, GO)

    def test_github_actions_completed_success_with_failed_matrix_is_no_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={
                    "status": "completed",
                    "conclusion": "success",
                    "linux_python_3_11": "pass",
                    "linux_python_3_12": "failed",
                    "linux_python_3_13": "pass",
                    "windows_python_3_11": "pass",
                    "windows_python_3_12": "pass",
                    "windows_python_3_13": "pass",
                    "ruff_result": "pass",
                    "mypy_result": "pass",
                    "unittest_result": "pass",
                    "coverage_result": "pass",
                },
                doctor={"status": "pass", "production_blocking": False, "checks": [{"check_id": "doctor", "status": "pass"}]},
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan=self._scan_payload(),
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
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan=self._scan_payload(),
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
        bwrap = self._write_json("bwrap.json", self._production_bwrap_payload())
        audit = self._write_json("audit.json", self._audit_payload())
        scan = self._write_json("scan.json", self._scan_payload())
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

    def test_local_audit_verify_without_external_anchor_has_specific_blocker(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": []},
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(external_anchor=False),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        blocking = {item.check_id for item in result.findings if item.production_blocking}
        self.assertNotIn("audit.verify", blocking)
        self.assertIn("audit.external_anchor_missing", blocking)
        self.assertEqual(result.decision, NO_GO)

    def test_audit_external_anchor_missing_with_accepted_risk_is_controlled_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": []},
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(external_anchor=False),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
                risk_acceptance={"accepted": True, "accepted_risks": ["AUDIT-ANCHOR"]},
            )
        )
        findings = {item.check_id: item for item in result.findings}
        self.assertFalse(findings["audit.external_anchor_missing"].production_blocking)
        self.assertEqual(result.decision, CONTROLLED_GO)

    def test_doctor_scanner_missing_is_not_counted_twice(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={
                    "status": "fail",
                    "production_blocking": True,
                    "checks": [
                        {
                            "check_id": "scanner.configured",
                            "status": "fail",
                            "reason": "scanner missing",
                            "production_blocking": True,
                        }
                    ],
                },
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan=None,
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        blocking = [item.check_id for item in result.findings if item.production_blocking]
        self.assertIn("scanner.configured", blocking)
        self.assertIn("scanner.policy", blocking)
        self.assertNotIn("doctor.production_blocking", blocking)

    def test_doctor_audit_anchor_missing_is_not_counted_twice(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={
                    "status": "fail",
                    "production_blocking": True,
                    "checks": [
                        {
                            "check_id": "audit.external_anchor",
                            "status": "fail",
                            "reason": "anchor missing",
                            "production_blocking": True,
                        }
                    ],
                },
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(external_anchor=False),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        blocking = [item.check_id for item in result.findings if item.production_blocking]
        self.assertIn("audit.external_anchor_missing", blocking)
        self.assertNotIn("doctor.production_blocking", blocking)

    def test_real_doctor_sandbox_fail_keeps_doctor_blocker(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={
                    "status": "fail",
                    "production_blocking": True,
                    "checks": [
                        {
                            "check_id": "sandbox.windows.boundary",
                            "status": "warn",
                            "reason": "weak sandbox",
                            "production_blocking": True,
                        }
                    ],
                },
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        blocking = {item.check_id for item in result.findings if item.production_blocking}
        self.assertIn("doctor.production_blocking", blocking)

    def test_offline_scanner_does_not_clear_production_blocker(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": []},
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan={
                    "scanner_name": "OfflineVulnerabilityScanner/OfflineLicenseScanner adapter tests",
                    "source": "reference_only",
                    "status": "reference_only",
                    "policy_decision": "not_production_evidence",
                },
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine={"status": "pass"},
                rollback={"status": "pass"},
            )
        )
        blocking = {item.check_id for item in result.findings if item.production_blocking}
        self.assertIn("scanner.configured", blocking)
        self.assertIn("scanner.policy", blocking)

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

    def _audit_payload(self, *, external_anchor: bool = True) -> dict[str, object]:
        return {
            "status": "pass" if external_anchor else "warn",
            "hash_chain_verified": True,
            "checkpoint_verified": True,
            "external_anchor_configured": external_anchor,
            "production_immutability": external_anchor,
            "checkpoint": {"status": "success"},
        }

    def _scan_payload(self) -> dict[str, object]:
        return {
            "scanner_name": "pip-audit",
            "scanner_version": "2.9.0",
            "source": "real_scanner",
            "production_evidence": True,
            "policy_decision": "pass",
            "status": "pass",
        }

    def _production_bwrap_payload(
        self,
        *,
        status: str = "pass",
        mode: str = "production-required",
        environment_class: str = "self_hosted",
    ) -> dict[str, object]:
        return {
            "status": status,
            "mode": mode,
            "environment_class": environment_class,
            "sandbox_backend": {
                "enforced": True,
                "capabilities": {
                    "process_containment": True,
                    "resource_limits": True,
                    "filesystem_isolation": True,
                    "network_isolation": True,
                },
            },
            "checks": [
                {"check_id": check_id, "status": "pass"}
                for check_id in [
                    "bwrap_backend_enforced",
                    "bwrap_wrapped_command",
                    "bwrap_unshared_network",
                    "bwrap_private_tmp",
                    "host_home_blocked",
                    "env_blocked",
                    "core_blocked",
                    "code_readonly",
                    "private_tmp_writable",
                    "host_tmp_not_leaked",
                    "direct_network_blocked",
                    "data_write_allowed",
                    "audit_records_present",
                ]
            ],
        }


if __name__ == "__main__":
    unittest.main()
