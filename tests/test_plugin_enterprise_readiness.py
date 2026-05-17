from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from modules.plugin_system.audit import (
    AuditLogIntegrityError,
    AuditLogger,
    LocalCheckpointAnchor,
    create_audit_checkpoint,
    verify_audit_log,
)
from modules.plugin_system.doctor import doctor_report, run_doctor
from modules.plugin_system.engine import PluginEngine
from modules.plugin_system.loader import write_package_lock
from modules.plugin_system.models import PluginMetadata
from modules.plugin_system.policy import PolicyEngine, PolicyError, PluginPolicy
from modules.plugin_system.loader import PluginLoader, PluginPackageError
from modules.plugin_system.scanner import (
    OfflineLicenseScanner,
    OfflineVulnerabilityScanner,
    ScanPolicy,
    scanner_missing_report,
)
from modules.plugin_system.signing import generate_keypair, sign_package, verify_signature
from modules.plugin_system.sbom import write_sbom
from scripts.validate_bwrap_sandbox import (
    _evaluate_result,
    _make_malicious_plugin,
    _preflight_failure_checks,
    main as bwrap_validation_main,
    run_validation,
)
from modules.plugin_system.loader import PluginLoader
from modules.plugin_system.sandbox import scan_plugin_source
from tests.test_utils import make_test_root


class EnterpriseReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = make_test_root(self._testMethodName)
        self.plugins_dir = self.root / "plugins"
        self.plugins_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_doctor_dev_mode_allows_warnings(self) -> None:
        report = doctor_report(run_doctor(plugins_dir=self.plugins_dir, production_mode=False))
        self.assertIn(report["status"], {"pass", "warn"})
        self.assertFalse(report["production_blocking"])

    def test_doctor_production_missing_sandbox_backend_fails(self) -> None:
        with patch("modules.plugin_system.sandbox_backend.sys.platform", "linux"), patch(
            "modules.plugin_system.sandbox_backend.shutil.which", return_value=None
        ):
            report = doctor_report(run_doctor(plugins_dir=self.plugins_dir, production_mode=True))
        self.assertEqual(report["status"], "fail")
        self.assertTrue(report["production_blocking"])
        self.assertTrue(any(item["check_id"] == "sandbox.fail_closed" for item in report["checks"]))

    def test_doctor_windows_warns_job_object_is_not_strong_sandbox(self) -> None:
        with patch("modules.plugin_system.doctor.sys.platform", "win32"):
            report = doctor_report(run_doctor(plugins_dir=self.plugins_dir, production_mode=False))
        windows = [item for item in report["checks"] if item["check_id"] == "sandbox.windows.boundary"]
        self.assertTrue(windows)
        self.assertIn("not full", windows[0]["reason"])

    def test_doctor_simulated_windows_does_not_call_bwrap_which(self) -> None:
        with patch("modules.plugin_system.doctor.sys.platform", "win32"), patch(
            "modules.plugin_system.doctor.shutil.which",
            side_effect=AssertionError("bwrap lookup should not run on simulated Windows"),
        ):
            report = doctor_report(run_doctor(plugins_dir=self.plugins_dir, production_mode=True))
        windows = [item for item in report["checks"] if item["check_id"] == "sandbox.windows.boundary"]
        self.assertTrue(windows)
        self.assertTrue(windows[0]["production_blocking"])
        self.assertTrue(report["production_blocking"])

    def test_doctor_linux_checks_bwrap_with_safe_which(self) -> None:
        with patch("modules.plugin_system.doctor.sys.platform", "linux"), patch(
            "modules.plugin_system.doctor.platform.system",
            return_value="Linux",
        ), patch("modules.plugin_system.doctor.shutil.which", return_value="/usr/bin/bwrap") as which:
            report = doctor_report(run_doctor(plugins_dir=self.plugins_dir, production_mode=False))
        which.assert_any_call("bwrap")
        bwrap = [item for item in report["checks"] if item["check_id"] == "sandbox.bubblewrap.binary"]
        self.assertTrue(bwrap)
        self.assertIn("/usr/bin/bwrap", bwrap[0]["reason"])

    def test_doctor_json_fields_are_complete_and_cli_survives(self) -> None:
        result = subprocess.run(
            [sys.executable, "cli.py", "--plugins-dir", str(self.plugins_dir), "doctor", "--json"],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("checks", payload)
        required = {"check_id", "status", "reason", "recommendation", "severity", "production_blocking"}
        self.assertTrue(required <= set(payload["checks"][0]))

    def test_audit_checkpoint_detects_truncation_and_tampering(self) -> None:
        log_path = self.root / "audit.log"
        checkpoint_path = self.root / "audit.checkpoint.json"
        logger = AuditLogger(log_path)
        logger.record("plugin.verify", "success", plugin="audit_plugin", action="verify")
        logger.record("plugin.enable", "success", plugin="audit_plugin", action="enable")
        anchor = LocalCheckpointAnchor(checkpoint_path)
        anchor.write_checkpoint(create_audit_checkpoint(log_path))
        self.assertEqual(verify_audit_log(log_path, anchor=anchor)["checkpoint"]["status"], "success")

        lines = log_path.read_text(encoding="utf-8").splitlines()
        log_path.write_text(lines[0] + "\n", encoding="utf-8")
        with self.assertRaisesRegex(AuditLogIntegrityError, "rollback"):
            verify_audit_log(log_path, anchor=anchor)

    def test_audit_checkpoint_signature_error_fails_verify(self) -> None:
        log_path = self.root / "signed-audit.log"
        checkpoint_path = self.root / "signed-audit.checkpoint.json"
        private_key = self.root / "audit-private.pem"
        public_key = self.root / "audit-public.pem"
        generate_keypair(private_key, public_key)
        logger = AuditLogger(log_path)
        logger.record("plugin.verify", "success", plugin="signed_audit_plugin", action="verify")
        anchor = LocalCheckpointAnchor(checkpoint_path, private_key=private_key, public_key=public_key)
        anchor.write_checkpoint(create_audit_checkpoint(log_path))

        payload = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        payload["latest_hash"] = "0" * 64
        checkpoint_path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaises(AuditLogIntegrityError):
            verify_audit_log(log_path, anchor=LocalCheckpointAnchor(checkpoint_path, public_key=public_key))

    def test_scanner_clean_sbom_passes_and_cli_json_report(self) -> None:
        sbom = self.root / "clean.sbom.json"
        sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "clean", "version": "1.0.0"}]}))
        report = OfflineVulnerabilityScanner().scan_sbom(json.loads(sbom.read_text()))
        self.assertEqual(report.policy_decision, "pass")

        result = subprocess.run(
            [sys.executable, "cli.py", "scan", "sbom", str(sbom), "--json"],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["policy_decision"], "pass")

    def test_scanner_vulnerability_license_unknown_and_native_policy(self) -> None:
        sbom = {"components": [{"name": "badpkg", "version": "1.0.0"}]}
        fixture = {
            "vulnerabilities": {
                "badpkg==1.0.0": [{"id": "CVE-TEST", "severity": "critical"}],
            },
            "licenses": {"badpkg==1.0.0": "GPL-3.0"},
        }
        vuln_report = OfflineVulnerabilityScanner(fixture).scan_sbom(sbom)
        self.assertEqual(vuln_report.policy_decision, "fail")
        license_report = OfflineLicenseScanner(fixture).scan_sbom(sbom)
        self.assertEqual(license_report.policy_decision, "fail")

        unknown_report = OfflineLicenseScanner({}, ScanPolicy(unknown_license="warn")).scan_sbom(sbom)
        self.assertEqual(unknown_report.policy_decision, "warn")
        unknown_fail = OfflineLicenseScanner({}, ScanPolicy(unknown_license="fail")).scan_sbom(sbom)
        self.assertEqual(unknown_fail.policy_decision, "fail")

        native_package = self.root / "native.zip"
        with zipfile.ZipFile(native_package, "w") as archive:
            archive.writestr("src/native.so", b"x")
        native_report = OfflineVulnerabilityScanner(policy=ScanPolicy(native_extension="fail")).scan_package(native_package)
        self.assertEqual(native_report.policy_decision, "fail")

    def test_scanner_missing_production_policy_fails_closed(self) -> None:
        report = scanner_missing_report(production_mode=True, policy=ScanPolicy(scanner_required=True))
        self.assertEqual(report.policy_decision, "fail")

    def test_production_loader_default_policy_requires_scan_and_sbom(self) -> None:
        source = self._make_plugin("prod_default_policy_plugin")
        package = self._zip_plugin(source)
        private_key = self.root / "prod-default-private.pem"
        public_key = self.root / "prod-default-public.pem"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="policy@example.com")
        payload = verify_signature(package, signature, public_key=public_key)

        with self.assertRaisesRegex(Exception, "requires SBOM|requires passing scan"):
            PluginLoader(self.plugins_dir, production_mode=True).install(
                package,
                signature=payload,
            )

    def test_production_engine_api_uses_default_policy_not_only_cli(self) -> None:
        source = self._make_plugin("engine_default_policy_plugin")
        package = self._zip_plugin(source)
        private_key = self.root / "engine-policy-private.pem"
        public_key = self.root / "engine-policy-public.pem"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="policy@example.com")
        payload = verify_signature(package, signature, public_key=public_key)
        engine = PluginEngine(self.plugins_dir, production_mode=True)

        with self.assertRaisesRegex(Exception, "requires SBOM|requires passing scan"):
            engine.install(package, signature=payload)

    def test_production_engine_start_policy_checks_backend_capabilities(self) -> None:
        source = self._make_plugin("engine_start_policy_plugin")
        write_sbom(source)
        package = self._zip_plugin(source)
        private_key = self.root / "engine-start-policy-private.pem"
        public_key = self.root / "engine-start-policy-public.pem"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="policy@example.com")
        payload = verify_signature(package, signature, public_key=public_key)
        policy = PluginPolicy(
            require_admin_approval=set(),
            linux_required_for_third_party_production=False,
            require_audit_checkpoint=False,
        )
        engine = PluginEngine(
            self.plugins_dir,
            production_mode=True,
            sandbox_backend="python_guard",
            policy_engine=PolicyEngine(policy),
        )
        engine.install(
            package,
            signature=payload,
            scan_report=OfflineVulnerabilityScanner().scan_sbom({"components": []}).to_dict(),
        )
        engine.grant_permissions("engine_start_policy_plugin", reviewer="admin")

        with self.assertRaisesRegex(PolicyError, "requires enforced sandbox"):
            engine.start_plugin("engine_start_policy_plugin")

    def test_policy_denies_permissions_and_requires_admin_approval(self) -> None:
        metadata = PluginMetadata(
            name="policy_plugin",
            version="1.0.0",
            description="Policy test plugin",
            author="test",
            runtime={"mode": "sub_process", "trust": "third_party"},
            extensions=[{"type": "tool", "name": "run", "entry": "src.main:run"}],
            permissions=[{"compute": True}, {"memory.write": True}, {"fs.write": True}],
        )
        engine = PolicyEngine(PluginPolicy(deny_permissions={"memory.write"}))
        with self.assertRaises(PolicyError):
            engine.enforce(engine.evaluate_enable(metadata, {"compute", "memory.write"}, admin_approved=False))
        approval_engine = PolicyEngine(PluginPolicy(deny_permissions=set(), require_admin_approval={"fs.write"}))
        with self.assertRaises(PolicyError):
            approval_engine.enforce(approval_engine.evaluate_enable(metadata, {"compute", "fs.write"}, admin_approved=False))

    def test_policy_install_requires_sbom_lock_scan_and_rejects_prerelease(self) -> None:
        source = self._make_plugin("policy_install_plugin", version="1.0.0-alpha.1")
        engine = PolicyEngine()
        report = engine.check_source(source, production_mode=True)
        reasons = " ".join(item["reason"] for item in report["decisions"])
        self.assertEqual(report["status"], "fail")
        self.assertIn("pre-release", reasons)
        self.assertIn("SBOM", reasons)
        self.assertIn("scan", reasons)

    def test_policy_scan_report_tampered_expired_or_unknown_scanner_fails(self) -> None:
        engine = PolicyEngine(
            PluginPolicy(
                linux_required_for_third_party_production=False,
                require_admin_approval=set(),
            )
        )
        source = self._make_plugin("scan_policy_plugin")
        write_sbom(source)
        fresh = OfflineVulnerabilityScanner().scan_sbom({"components": []}).to_dict()
        report = engine.check_source(source, production_mode=True, signature={"ok": True}, scan_report=fresh)
        self.assertEqual(report["status"], "pass")

        tampered = dict(fresh)
        tampered["policy_decision"] = "fail"
        self.assertEqual(
            engine.check_source(source, production_mode=True, signature={"ok": True}, scan_report=tampered)["status"],
            "fail",
        )
        unknown = dict(fresh)
        unknown["scanner_name"] = "unknown"
        self.assertEqual(
            engine.check_source(source, production_mode=True, signature={"ok": True}, scan_report=unknown)["status"],
            "fail",
        )
        expired = dict(fresh)
        expired["generated_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
        self.assertEqual(
            engine.check_source(source, production_mode=True, signature={"ok": True}, scan_report=expired)["status"],
            "fail",
        )

    def test_cli_policy_check_and_engine_enable_are_consistent(self) -> None:
        source = self._make_plugin("policy_consistency_plugin")
        policy_file = self.root / "policy.yaml"
        policy_file.write_text("deny_permissions:\n  - memory.write\n", encoding="utf-8")
        (source / "plugin.yaml").write_text(
            (source / "plugin.yaml").read_text(encoding="utf-8").replace(
                "  - compute: true",
                "  - compute: true\n  - memory.write: true",
            ),
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "policy",
                "check",
                str(source),
                "--policy-file",
                str(policy_file),
                "--json",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        cli_payload = json.loads(result.stdout)
        engine = PolicyEngine.from_file(policy_file)
        metadata = PluginMetadata(
            name="policy_consistency_plugin",
            version="1.0.0",
            description="Policy test plugin",
            author="test",
            runtime={"mode": "sub_process", "trust": "third_party"},
            extensions=[{"type": "tool", "name": "run", "entry": "src.main:run"}],
            permissions=[{"compute": True}, {"memory.write": True}],
        )
        with self.assertRaises(PolicyError):
            engine.enforce(engine.evaluate_enable(metadata, {"compute", "memory.write"}, admin_approved=True))
        self.assertEqual(cli_payload["status"], "fail")
        self.assertTrue(
            any("permissions denied" in item.reason for item in engine.evaluate_enable(metadata, {"memory.write"}, admin_approved=True))
        )

    def test_cli_audit_status_fails_after_checkpoint_truncation(self) -> None:
        log_path = self.root / "cli-status.audit.log"
        checkpoint_path = self.root / "cli-status.checkpoint.json"
        logger = AuditLogger(log_path)
        logger.record("plugin.verify", "success", plugin="cli_status_plugin", action="verify")
        logger.record("plugin.enable", "success", plugin="cli_status_plugin", action="enable")
        cp = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "audit",
                "checkpoint",
                "--log",
                str(log_path),
                "--checkpoint",
                str(checkpoint_path),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        lines = log_path.read_text(encoding="utf-8").splitlines()
        log_path.write_text(lines[0] + "\n", encoding="utf-8")
        status = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "audit",
                "status",
                "--log",
                str(log_path),
                "--checkpoint",
                str(checkpoint_path),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(status.returncode, 0)
        self.assertIn("rollback", status.stderr)

    def test_workflow_readiness_self_check(self) -> None:
        workflow = Path(".github/workflows/ci.yml")
        self.assertTrue(workflow.exists())
        content = workflow.read_text(encoding="utf-8")
        for token in [
            "ubuntu-latest",
            "windows-latest",
            '"3.11"',
            '"3.12"',
            '"3.13"',
            'python -m pip install -e ".[dev]"',
            "python -m unittest discover -s tests",
            "python -m ruff check .",
            "python -m mypy",
            "python -m coverage run -m unittest discover -s tests",
        ]:
            self.assertIn(token, content)

    def test_pyproject_dev_tools_and_coverage_threshold(self) -> None:
        import tomllib

        payload = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        dev = payload["project"]["optional-dependencies"]["dev"]
        self.assertTrue(any(item.startswith("ruff") for item in dev))
        self.assertTrue(any(item.startswith("mypy") for item in dev))
        self.assertTrue(any(item.startswith("coverage") for item in dev))
        self.assertGreaterEqual(payload["tool"]["coverage"]["report"]["fail_under"], 70)
        ci_readiness = Path("CI_READINESS.md").read_text(encoding="utf-8")
        self.assertIn(f"{payload['tool']['coverage']['report']['fail_under']}%", ci_readiness)
        self.assertIn("modules/plugin_system", ci_readiness)
        self.assertIn("E9, F63, F7, F82", ci_readiness)
        self.assertNotIn("threshold is intentionally set to `0`", ci_readiness)

    def test_production_acceptance_evidence_template_exists(self) -> None:
        template = Path("PRODUCTION_ACCEPTANCE_EVIDENCE.md")
        self.assertTrue(template.exists())
        content = template.read_text(encoding="utf-8")
        for token in [
            "CI run URL",
            "Commit SHA",
            "acceptance_result.json",
            "plugin-cli doctor --production --json",
            "scripts/validate_bwrap_sandbox.py --json",
            "audit verify",
            "scanner report",
            "signed registry",
            "revoked key",
            "emergency quarantine",
            "final go/no-go decision",
            "Known Accepted Risks",
            "production-required",
        ]:
            self.assertIn(token, content)

    def test_bwrap_validation_harness_skip_behavior(self) -> None:
        with patch("scripts.validate_bwrap_sandbox.sys.platform", "win32"):
            report = run_validation(self.root / "validation")
        self.assertEqual(report["status"], "skipped")
        self.assertEqual(report["mode"], "production-required")
        self.assertTrue(report["production_blocking"])

    def test_bwrap_validation_production_required_fails_closed_before_sample(self) -> None:
        backend = {
            "name": "bubblewrap",
            "enforced": False,
            "platform": "linux",
            "details": {"probe": {"ok": False, "error": "operation not permitted"}},
            "warnings": ["bubblewrap probe failed"],
            "capabilities": {
                "process_containment": False,
                "resource_limits": False,
                "filesystem_isolation": False,
                "network_isolation": False,
            },
            "missing_capabilities": [
                "process_containment",
                "resource_limits",
                "filesystem_isolation",
                "network_isolation",
            ],
        }
        with (
            patch("scripts.validate_bwrap_sandbox.sys.platform", "linux"),
            patch("scripts.validate_bwrap_sandbox.shutil.which", return_value="/usr/bin/bwrap"),
            patch("scripts.validate_bwrap_sandbox._probe_backend_report", return_value=backend),
            patch("scripts.validate_bwrap_sandbox._run_sample_validation") as sample,
        ):
            report = run_validation(self.root / "validation", mode="production-required")

        sample.assert_not_called()
        self.assertEqual(report["status"], "fail")
        self.assertTrue(report["production_blocking"])
        self.assertEqual(report["result"]["status"], "not_run")

    def test_bwrap_validation_diagnostic_records_github_hosted_as_unsupported(self) -> None:
        sample_report = {
            "status": "pass",
            "checks": [],
            "sandbox_backend": {"enforced": True, "capabilities": {}},
        }
        with (
            patch("scripts.validate_bwrap_sandbox.sys.platform", "linux"),
            patch("scripts.validate_bwrap_sandbox.shutil.which", return_value="/usr/bin/bwrap"),
            patch("scripts.validate_bwrap_sandbox._detect_environment_class", return_value="github_hosted"),
            patch("scripts.validate_bwrap_sandbox._probe_backend_report", return_value={"enforced": True, "capabilities": {}}),
            patch("scripts.validate_bwrap_sandbox._run_sample_validation", return_value=sample_report),
        ):
            report = run_validation(self.root / "validation", mode="diagnostic")

        self.assertEqual(report["mode"], "diagnostic")
        self.assertEqual(report["environment_class"], "github_hosted")
        self.assertEqual(report["status"], "unsupported_environment")
        self.assertTrue(report["production_blocking"])

    def test_bwrap_validation_sample_passes_static_scan(self) -> None:
        source = _make_malicious_plugin(self.root, self.root / ".env", self.root / "home.secret")
        metadata = PluginLoader(self.root / "plugins").read_metadata(source / "plugin.yaml")
        self.assertEqual(scan_plugin_source(source, metadata), [])

    def test_bwrap_validation_requires_enforced_backend_details(self) -> None:
        class EmptyAudit:
            def read_records(self) -> list[object]:
                return [{}]

        result = {
            "status": "success",
            "data": {
                "home_readable": False,
                "env_readable": False,
                "core_readable": False,
                "code_writable": False,
                "host_tmp_write": True,
                "direct_network_available": False,
                "process_execution_available": False,
                "data_content": "data-ok",
            },
        }
        checks = _evaluate_result(  # type: ignore[arg-type]
            result,
            EmptyAudit(),
            {"sandbox_backend": {"enforced": False, "details": {}}},
            {"host_tmp_leaked": False},
        )
        statuses = {item["check_id"]: item["status"] for item in checks}
        self.assertEqual(statuses["bwrap_backend_enforced"], "fail")
        self.assertEqual(statuses["bwrap_wrapped_command"], "fail")

    def test_bwrap_validation_worker_failure_keeps_backend_pass_context(self) -> None:
        class EmptyAudit:
            def read_records(self) -> list[object]:
                return [{}]

        checks = _evaluate_result(  # type: ignore[arg-type]
            {"status": "error", "error_type": "WorkerNoOutput", "worker_started": False},
            EmptyAudit(),
            {
                "sandbox_backend": {
                    "enforced": True,
                    "details": {"wrapped_command": True, "network": "unshared", "tmp": "private_tmpfs"},
                }
            },
            {"host_tmp_leaked": False},
        )
        statuses = {item["check_id"]: item["status"] for item in checks}
        self.assertEqual(statuses["bwrap_backend_enforced"], "pass")
        self.assertEqual(statuses["bwrap_wrapped_command"], "pass")
        self.assertEqual(statuses["plugin_executed"], "fail")
        host_check = next(item for item in checks if item["check_id"] == "host_home_blocked")
        self.assertEqual(host_check["runtime_observation"], "missing")

    def test_bwrap_preflight_import_failure_checks_are_specific(self) -> None:
        backend = {
            "enforced": True,
            "details": {},
            "capabilities": {
                "filesystem_isolation": True,
                "network_isolation": True,
                "process_containment": True,
                "resource_limits": True,
            },
        }
        checks = _preflight_failure_checks(
            backend,
            {
                "import_runtime": "fail",
                "tmp_writable": "pass",
                "data_dir_writable": "pass",
                "code_dir_readonly": "pass",
                "host_home_blocked": "pass",
                "env_blocked": "pass",
                "core_blocked": "pass",
                "wrapped_command": ["/usr/bin/bwrap", "--unshare-net", "--tmpfs", "/tmp", "--", sys.executable],
            },
        )
        statuses = {item["check_id"]: item["status"] for item in checks}
        self.assertEqual(statuses["bwrap_backend_enforced"], "pass")
        self.assertEqual(statuses["bwrap_unshared_network"], "pass")
        self.assertEqual(statuses["runtime_import"], "fail")

    def test_bwrap_validation_output_argument_writes_json(self) -> None:
        output = self.root / "evidence" / "bwrap.json"
        with patch(
            "scripts.validate_bwrap_sandbox.run_validation",
            return_value={
                "status": "fail",
                "mode": "production-required",
                "environment_class": "unknown",
                "checks": [],
                "reason": "test",
            },
        ):
            exit_code = bwrap_validation_main(["--output", str(output)])

        self.assertEqual(exit_code, 1)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "fail")

    def test_rc1_docs_and_scripts_exist(self) -> None:
        expected = {
            "SCANNER_INTEGRATION.md": ["OfflineVulnerabilityScanner", "not be treated as real vulnerability"],
            "AUDIT_ANCHOR_INTEGRATION.md": ["LocalCheckpointAnchor", "tamper-evident, not tamper-proof"],
            "RELEASE_NOTES.md": ["v0.9.0-rc1", "Do not claim"],
            "scripts/run_production_acceptance.py": ["acceptance", "production_ready"],
            "scripts/release_gate.py": ["release_gate"],
            "modules/plugin_system/release_gate.py": ["CONTROLLED_GO", "NO_GO"],
        }
        for path, tokens in expected.items():
            content = Path(path).read_text(encoding="utf-8")
            for token in tokens:
                self.assertIn(token, content)

    def _make_plugin(self, name: str, version: str = "1.0.0") -> Path:
        source = self.root / name
        (source / "src").mkdir(parents=True)
        (source / "src" / "__init__.py").write_text("", encoding="utf-8")
        (source / "src" / "main.py").write_text("def run(args, api=None):\n    return {'ok': True}\n", encoding="utf-8")
        (source / "plugin.yaml").write_text(
            "\n".join(
                [
                    f"name: {name}",
                    f"version: {version}",
                    "description: Policy test plugin",
                    "author: test",
                    "license: MIT",
                    "runtime:",
                    "  mode: sub_process",
                    "  trust: third_party",
                    "extensions:",
                    "  - type: tool",
                    "    name: run",
                    "    entry: src.main:run",
                    "permissions:",
                    "  - compute: true",
                    "requires:",
                    '  python: ">=3.11"',
                    "  packages: []",
                ]
            ),
            encoding="utf-8",
        )
        write_package_lock(source)
        return source

    def _zip_plugin(self, source: Path) -> Path:
        package = self.root / f"{source.name}.zip"
        if (source / "manifest.lock").exists():
            write_package_lock(source)
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in source.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(source).as_posix())
        return package


if __name__ == "__main__":
    unittest.main()
