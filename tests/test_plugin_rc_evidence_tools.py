from __future__ import annotations

import argparse
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.plugin_system.release_gate import GO, NO_GO, GateInput, evaluate_release_gate
from scripts import collect_rc_evidence
from scripts.drill_quarantine import run_drill as run_quarantine_drill
from scripts.drill_registry_verify import run_drill as run_registry_drill
from scripts.drill_revocation import run_drill as run_revocation_drill
from scripts.drill_rollback import run_drill as run_rollback_drill


class RcEvidenceToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix=f"{self._testMethodName}-", dir=Path.cwd() / "data" / "test_runs"))

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
                bwrap={"status": "pass"},
                audit={"status": "pass", "checkpoint": {"status": "success"}},
                scan={"policy_decision": "pass"},
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


if __name__ == "__main__":
    unittest.main()
