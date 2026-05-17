from __future__ import annotations

import argparse
import json
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.plugin_system.release_gate import GO, NO_GO, GateInput, evaluate_release_gate
from scripts import collect_rc_evidence
from scripts.drill_quarantine import run_drill as run_quarantine_drill
from scripts.drill_registry_verify import run_drill as run_registry_drill
from scripts.drill_revocation import run_drill as run_revocation_drill
from scripts.drill_rollback import run_drill as run_rollback_drill
from scripts.generate_audit_verify_evidence import generate_evidence, verify_local_audit_pair
from scripts.create_scan_report_from_pip_audit import convert_pip_audit_report, load_pip_audit_report, malformed_report
from tests.test_utils import make_test_root


class RcEvidenceToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = make_test_root(self._testMethodName)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_drill_registry_verify_json_schema(self) -> None:
        self._assert_drill_schema(run_registry_drill(), "registry_verify")

    def test_drill_revocation_json_schema(self) -> None:
        self._assert_drill_schema(run_revocation_drill(), "revocation")

    def test_drill_quarantine_json_schema(self) -> None:
        self._assert_drill_schema(run_quarantine_drill(), "quarantine")

    def test_drill_rollback_json_schema(self) -> None:
        self._assert_drill_schema(run_rollback_drill(), "rollback")

    def test_collect_rc_evidence_missing_external_inputs_are_blocking(self) -> None:
        args = argparse.Namespace(
            output_dir=self.root / "evidence",
            run_quality=False,
            scanner_report=None,
            audit_log=None,
            audit_checkpoint=None,
            audit_public_key=None,
        )
        with (
            patch("scripts.collect_rc_evidence.platform.system", return_value="Windows"),
            patch("scripts.collect_rc_evidence.shutil.which", return_value=None),
            patch("scripts.collect_rc_evidence.collect_environment", return_value={"status": "warn", "production_blocking": True}),
            patch("scripts.collect_rc_evidence.run_json_command", side_effect=self._fake_json_command),
        ):
            report = collect_rc_evidence.collect_evidence(args)

        self.assertEqual(report["status"], "not_ready")
        self.assertFalse(report["production_ready"])
        index_path = self.root / "evidence" / "index.json"
        self.assertTrue(index_path.exists())
        bwrap = json.loads((self.root / "evidence" / "bwrap_validation.json").read_text(encoding="utf-8"))
        ci = json.loads((self.root / "evidence" / "ci_result.json").read_text(encoding="utf-8"))
        scanner = json.loads((self.root / "evidence" / "scanner_report.json").read_text(encoding="utf-8"))
        self.assertEqual(bwrap["status"], "skipped")
        self.assertTrue(bwrap["production_blocking"])
        self.assertEqual(ci["status"], "missing")
        self.assertTrue(ci["production_blocking"])
        self.assertEqual(scanner["status"], "missing")
        self.assertTrue(scanner["production_blocking"])

    def test_release_gate_missing_drills_remain_no_go(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": []},
                bwrap=self._production_bwrap_payload(),
                audit=self._audit_payload(),
                scan=self._scan_payload(),
                registry={"status": "pass"},
                revocation={"status": "pass"},
                quarantine=None,
                rollback=None,
            )
        )
        self.assertEqual(result.decision, NO_GO)
        blocking = {item.check_id for item in result.findings if item.production_blocking}
        self.assertIn("quarantine.drill", blocking)
        self.assertIn("rollback.drill", blocking)

    def test_release_gate_drill_pass_releases_blockers(self) -> None:
        result = evaluate_release_gate(
            GateInput(
                ci={"status": "pass"},
                doctor={"status": "pass", "production_blocking": False, "checks": []},
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

    def test_generate_audit_verify_evidence_json_schema(self) -> None:
        output = self.root / "evidence" / "audit_verify.json"
        payload = generate_evidence(output=output)

        self.assertTrue(output.exists())
        self.assertEqual(payload["status"], "warn")
        self.assertTrue(payload["hash_chain_verified"])
        self.assertTrue(payload["checkpoint_verified"])
        self.assertTrue(payload["rollback_detection_available"])
        self.assertFalse(payload["external_anchor_configured"])
        self.assertFalse(payload["production_immutability"])
        self.assertTrue(payload["controlled_risk_required"])
        self.assertTrue(payload["production_blocking"])
        for key in [
            "audit_log_path",
            "checkpoint_path",
            "reason",
            "recommendation",
            "generated_at",
        ]:
            self.assertIn(key, payload)

    def test_generate_audit_verify_evidence_detects_tampering(self) -> None:
        output = self.root / "evidence" / "audit_verify.json"
        payload = generate_evidence(output=output)
        audit_log = Path(str(payload["audit_log_path"]))
        checkpoint = Path(str(payload["checkpoint_path"]))

        content = audit_log.read_text(encoding="utf-8")
        audit_log.write_text(content.replace("audit.evidence.verify", "audit.evidence.tamper"), encoding="utf-8")

        tampered = verify_local_audit_pair(audit_log, checkpoint)
        self.assertFalse(tampered["hash_chain_verified"])
        self.assertFalse(tampered["checkpoint_verified"])
        self.assertIn("hash", str(tampered["error"]))

    def test_pip_audit_empty_vulnerability_report_passes(self) -> None:
        report = convert_pip_audit_report({"dependencies": [{"name": "safe", "version": "1", "vulns": []}]}, input_file="raw.json")

        self.assertEqual(report["scanner_name"], "pip-audit")
        self.assertEqual(report["source"], "real_scanner")
        self.assertTrue(report["production_evidence"])
        self.assertEqual(report["policy_decision"], "pass")
        self.assertEqual(report["findings"], [])

    def test_pip_audit_vulnerability_report_fails(self) -> None:
        report = convert_pip_audit_report(
            {
                "dependencies": [
                    {
                        "name": "bad",
                        "version": "1",
                        "vulns": [
                            {
                                "id": "PYSEC-1",
                                "severity": "HIGH",
                                "description": "bad package",
                                "fix_versions": ["2"],
                            }
                        ],
                    }
                ]
            },
            input_file="raw.json",
        )

        self.assertEqual(report["policy_decision"], "fail")
        self.assertEqual(report["severity_summary"]["high"], 1)
        self.assertEqual(report["findings"][0]["id"], "PYSEC-1")

    def test_pip_audit_malformed_json_fails_closed(self) -> None:
        path = self.root / "pip_audit_raw.json"
        path.write_text("[]", encoding="utf-8")

        with self.assertRaises(ValueError):
            load_pip_audit_report(path)

        report = malformed_report(input_file=path, error="bad json")
        self.assertEqual(report["policy_decision"], "fail")
        self.assertFalse(report["production_evidence"])

    def _assert_drill_schema(self, payload: dict[str, object], drill_id: str) -> None:
        required = {
            "drill_id",
            "status",
            "checks",
            "reason",
            "recommendation",
            "production_blocking",
            "generated_at",
            "artifacts",
        }
        self.assertTrue(required.issubset(payload), payload)
        self.assertEqual(payload["drill_id"], drill_id)
        self.assertIn(payload["status"], {"pass", "failed", "missing", "skipped"})
        self.assertIsInstance(payload["checks"], dict)
        self.assertIsInstance(payload["production_blocking"], bool)

    def _fake_json_command(self, evidence_id: str, *_: object, **__: object) -> dict[str, object]:
        status = "pass"
        return {
            "status": status,
            "production_blocking": False,
            "reason": f"fake {evidence_id}",
            "generated_at": "2026-05-12T00:00:00+00:00",
        }

    def _audit_payload(self) -> dict[str, object]:
        return {
            "status": "pass",
            "hash_chain_verified": True,
            "checkpoint_verified": True,
            "external_anchor_configured": True,
            "production_immutability": True,
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

    def _production_bwrap_payload(self) -> dict[str, object]:
        return {
            "status": "pass",
            "mode": "production-required",
            "environment_class": "self_hosted",
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
