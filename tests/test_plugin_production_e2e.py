from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import yaml

from modules.plugin_system.audit import AuditLogger, LocalCheckpointAnchor, create_audit_checkpoint, verify_audit_log
from modules.plugin_system.engine import PluginEngine, PluginLifecycleError
from modules.plugin_system.gateway import PluginGateway
from modules.plugin_system.loader import PluginLoader, PluginPackageError, write_package_lock
from modules.plugin_system.marketplace import PluginRegistryClient, PluginRegistryError
from modules.plugin_system.policy import PluginPolicy, PolicyEngine
from modules.plugin_system.sandbox_backend import EXTERNAL_SANDBOX_ATTESTATION_ENV
from modules.plugin_system.scanner import OfflineVulnerabilityScanner
from modules.plugin_system.sbom import generate_sbom, write_sbom
from modules.plugin_system.signing import (
    TrustStore,
    generate_keypair,
    sha256_file,
    sign_package,
    verify_signature,
)
from tests.test_utils import make_test_root


class ProductionE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = make_test_root(self._testMethodName)
        self.plugins_dir = self.root / "plugins"
        self.packages_dir = self.root / "packages"
        self.plugins_dir.mkdir(parents=True)
        self.packages_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_rc1_production_flow_engine_and_cli_policy_are_consistent(self) -> None:
        source = self._make_plugin("rc_flow_plugin")
        write_sbom(source)
        write_package_lock(source)
        scan_report = OfflineVulnerabilityScanner().scan_sbom(generate_sbom(source)).to_dict()
        scan_path = self._write_json("rc_flow.scan.json", scan_report)
        package = self._zip_plugin(source)
        private_key, public_key = self._keys("rc-flow")
        trust_store = self.root / "trust-store.json"
        TrustStore(trust_store).add_key("rc@example.com", public_key)
        signature = sign_package(package, private_key=private_key, publisher="rc@example.com")
        signature_payload = verify_signature(package, signature, trust_store=trust_store)
        index = self._write_registry_index("rc_flow_plugin", package, signature, publisher="rc@example.com")
        index_signature = sign_package(index, private_key=private_key, publisher="rc@example.com")

        policy_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--production",
                "policy",
                "check",
                str(package),
                "--signature",
                str(signature),
                "--trust-store",
                str(trust_store),
                "--scan-report",
                str(scan_path),
                "--json",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(policy_result.returncode, 0, policy_result.stderr)
        cli_policy = json.loads(policy_result.stdout)
        self.assertEqual(cli_policy["status"], "fail")
        self.assertIn("admin approval required", json.dumps(cli_policy))

        audit_logger = AuditLogger(self.root / "rc-flow.audit.log")
        policy = PluginPolicy(linux_required_for_third_party_production=False, require_audit_checkpoint=False)
        engine = PluginEngine(
            self.plugins_dir,
            sandbox_backend="external_enforced",
            audit_logger=audit_logger,
            gateway=PluginGateway(
                data_dir=self.plugins_dir,
                memory_store={"rc-key": "rc-memory"},
                audit_logger=audit_logger,
            ),
            production_mode=True,
            policy_engine=PolicyEngine(policy, audit_logger=audit_logger),
        )
        registry_entries = PluginRegistryClient(index, index_signature=index_signature).list_plugins(
            trust_store=trust_store,
            require_signature=True,
        )
        self.assertEqual(registry_entries[0].name, "rc_flow_plugin")
        installed_metadata = engine.install(package, signature=signature_payload, scan_report=scan_report)
        self.assertEqual(installed_metadata.name, "rc_flow_plugin")
        review = engine.loader.get_installed("rc_flow_plugin")
        self.assertIsNotNone(review)
        self.assertTrue(review.permission_review["required"])

        engine.grant_permissions("rc_flow_plugin", reviewer="admin", review_reason="rc1_e2e")
        engine.enable_plugin("rc_flow_plugin", actor="admin", reason="rc1_e2e")
        with patch.dict(
            os.environ,
            {EXTERNAL_SANDBOX_ATTESTATION_ENV: "process_containment,resource_limits,filesystem_isolation,network_isolation"},
        ):
            engine.start_plugin("rc_flow_plugin")
            result = engine.call_tool("rc_flow_plugin", "run", {"path": "rc.txt"})
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["data"]["memory"], "rc-memory")
        self.assertEqual(result["data"]["file"], "rc-data")

        records = audit_logger.read_records()
        self.assertTrue(any(item.event == "plugin.installed" for item in records))
        self.assertTrue(any(item.event == "plugin.gateway_request" and item.action == "memory.read" for item in records))
        self.assertTrue(any(item.event == "plugin.gateway_request" and item.action == "fs.write" for item in records))
        self.assertTrue(any(item.event == "plugin.tool_call" for item in records))
        self.assertEqual(verify_audit_log(audit_logger.log_path)["records"], len(records))

        checkpoint = self.root / "rc-flow.checkpoint.json"
        anchor = LocalCheckpointAnchor(checkpoint)
        anchor.write_checkpoint(create_audit_checkpoint(audit_logger.log_path))
        self.assertEqual(verify_audit_log(audit_logger.log_path, anchor=anchor)["checkpoint"]["status"], "success")

        engine.disable_plugin("rc_flow_plugin", actor="admin", reason="rc1_disable")
        with self.assertRaises(PluginLifecycleError):
            engine.call_tool("rc_flow_plugin", "run", {})
        engine.quarantine_plugin("rc_flow_plugin", actor="admin", reason="rc1_quarantine")
        with self.assertRaises(PluginLifecycleError):
            engine.call_tool("rc_flow_plugin", "run", {})

    def test_rc1_production_negative_install_and_start_paths_fail_closed(self) -> None:
        source = self._make_plugin("rc_negative_plugin")
        write_sbom(source)
        scan_report = OfflineVulnerabilityScanner().scan_sbom(generate_sbom(source)).to_dict()
        package = self._zip_plugin(source)
        private_key, public_key = self._keys("rc-negative")
        signature = sign_package(package, private_key=private_key, publisher="rc@example.com")
        signature_payload = verify_signature(package, signature, public_key=public_key)
        policy = PluginPolicy(linux_required_for_third_party_production=False, require_audit_checkpoint=False)

        loader = PluginLoader(self.plugins_dir / "unsigned", production_mode=True)
        with self.assertRaisesRegex(PluginPackageError, "requires a verified signature"):
            loader.install(package, scan_report=scan_report)

        hmac_sig = sign_package(package, key="legacy")
        hmac_payload = verify_signature(package, hmac_sig, key="legacy")
        with self.assertRaisesRegex(PluginPackageError, "production mode requires"):
            PluginLoader(self.plugins_dir / "hmac", production_mode=True).install(
                package,
                signature=hmac_payload,
                scan_report=scan_report,
            )

        missing_sbom = self._make_plugin("rc_missing_sbom_plugin")
        missing_sbom_package = self._zip_plugin(missing_sbom)
        missing_sig = sign_package(missing_sbom_package, private_key=private_key, publisher="rc@example.com")
        missing_payload = verify_signature(missing_sbom_package, missing_sig, public_key=public_key)
        with self.assertRaisesRegex(Exception, "requires SBOM"):
            PluginLoader(self.plugins_dir / "missing-sbom", production_mode=True).install(
                missing_sbom_package,
                signature=missing_payload,
                scan_report=scan_report,
            )

        missing_lock = self._make_plugin("rc_missing_lock_plugin")
        write_sbom(missing_lock)
        (missing_lock / "manifest.lock").unlink()
        missing_lock_package = self._zip_plugin(missing_lock, refresh_lock=False)
        missing_lock_sig = sign_package(missing_lock_package, private_key=private_key, publisher="rc@example.com")
        missing_lock_payload = verify_signature(missing_lock_package, missing_lock_sig, public_key=public_key)
        with self.assertRaisesRegex(PluginPackageError, "requires manifest.lock"):
            PluginLoader(self.plugins_dir / "missing-lock", production_mode=True).install(
                missing_lock_package,
                signature=missing_lock_payload,
                scan_report=scan_report,
            )

        with self.assertRaisesRegex(Exception, "requires passing scan"):
            PluginLoader(self.plugins_dir / "missing-scan", production_mode=True).install(
                package,
                signature=signature_payload,
            )
        failing_scan = dict(scan_report)
        failing_scan["policy_decision"] = "fail"
        failing_scan["reason"] = "critical vulnerability"
        with self.assertRaisesRegex(Exception, "scan policy did not pass"):
            PluginLoader(self.plugins_dir / "scan-fail", production_mode=True).install(
                package,
                signature=signature_payload,
                scan_report=failing_scan,
            )

        trust_store = self.root / "revoked-trust.json"
        key_id = TrustStore(trust_store).add_key("rc@example.com", public_key)
        TrustStore(trust_store).revoke_key("rc@example.com", key_id)
        with self.assertRaises(Exception):
            verify_signature(package, signature, trust_store=trust_store)

        revoked_loader = PluginLoader(self.plugins_dir / "revoked-version", production_mode=True)
        revoked_loader.revoke_plugin_version("rc_negative_plugin", "1.0.0")
        with self.assertRaisesRegex(PluginPackageError, "version is revoked"):
            revoked_loader.install(package, signature=signature_payload, scan_report=scan_report)

        engine = PluginEngine(
            self.plugins_dir / "start-fail",
            sandbox_backend="python_guard",
            production_mode=True,
            policy_engine=PolicyEngine(policy),
        )
        engine.install(package, signature=signature_payload, scan_report=scan_report)
        engine.grant_permissions("rc_negative_plugin", reviewer="admin")
        with self.assertRaises(Exception):
            engine.start_plugin("rc_negative_plugin")
        engine.stop_all()

        with patch.dict(
            os.environ,
            {EXTERNAL_SANDBOX_ATTESTATION_ENV: "process_containment,resource_limits,filesystem_isolation,network_isolation"},
        ):
            gated = PluginEngine(
                self.plugins_dir / "lifecycle",
                sandbox_backend="external_enforced",
                production_mode=True,
                policy_engine=PolicyEngine(policy),
            )
            gated.install(package, signature=signature_payload, scan_report=scan_report)
            gated.grant_permissions("rc_negative_plugin", reviewer="admin")
            try:
                gated.start_plugin("rc_negative_plugin")
                gated.disable_plugin("rc_negative_plugin")
                with self.assertRaises(PluginLifecycleError):
                    gated.call_tool("rc_negative_plugin", "run", {})
                gated.quarantine_plugin("rc_negative_plugin")
                with self.assertRaises(PluginLifecycleError):
                    gated.call_tool("rc_negative_plugin", "run", {})
                gated.revoke_plugin("rc_negative_plugin")
                with self.assertRaises(PluginLifecycleError):
                    gated.call_tool("rc_negative_plugin", "run", {})
            finally:
                gated.stop_all()

    def _make_plugin(self, name: str) -> Path:
        source = self.root / name
        (source / "src").mkdir(parents=True)
        (source / "src" / "__init__.py").write_text("", encoding="utf-8")
        (source / "src" / "main.py").write_text(
            "\n".join(
                [
                    "def run(args, api):",
                    "    path = args.get('path', 'rc.txt')",
                    "    api.write_file(path, 'rc-data')",
                    "    return {'memory': api.read_memory('rc-key'), 'file': api.read_file(path)}",
                ]
            ),
            encoding="utf-8",
        )
        metadata = {
            "name": name,
            "version": "1.0.0",
            "description": "RC production flow plugin",
            "author": "test",
            "license": "MIT",
            "runtime": {
                "mode": "sub_process",
                "trust": "third_party",
                "memory_mb": 128,
                "timeout_seconds": 3,
                "cpu_seconds": 2,
            },
            "extensions": [{"type": "tool", "name": "run", "entry": "src.main:run"}],
            "permissions": [{"compute": True}, {"memory.read": True}, {"fs.read": True}, {"fs.write": True}],
            "requires": {"python": ">=3.11", "packages": []},
        }
        (source / "plugin.yaml").write_text(yaml.safe_dump(metadata, sort_keys=False), encoding="utf-8")
        write_package_lock(source)
        return source

    def _zip_plugin(self, source: Path, *, refresh_lock: bool = True) -> Path:
        if refresh_lock and (source / "manifest.lock").exists():
            write_package_lock(source)
        package = self.packages_dir / f"{source.name}.zip"
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in source.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(source).as_posix())
        return package

    def _keys(self, label: str) -> tuple[Path, Path]:
        private_key = self.root / f"{label}-private.pem"
        public_key = self.root / f"{label}-public.pem"
        generate_keypair(private_key, public_key)
        return private_key, public_key

    def _write_json(self, name: str, payload: dict[str, object]) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def _write_registry_index(self, name: str, package: Path, signature: Path, *, publisher: str) -> Path:
        registry_dir = self.root / "registry"
        registry_dir.mkdir(exist_ok=True)
        package_target = registry_dir / package.name
        signature_target = registry_dir / signature.name
        package_target.write_bytes(package.read_bytes())
        signature_target.write_bytes(signature.read_bytes())
        index = registry_dir / f"{name}-index.json"
        index.write_text(
            json.dumps(
                {
                    "version": 1,
                    "plugins": [
                        {
                            "name": name,
                            "version": "1.0.0",
                            "description": "RC registry plugin",
                            "package": package_target.name,
                            "sha256": sha256_file(package_target),
                            "signature": signature_target.name,
                            "publisher": publisher,
                        }
                    ],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return index


if __name__ == "__main__":
    unittest.main()
