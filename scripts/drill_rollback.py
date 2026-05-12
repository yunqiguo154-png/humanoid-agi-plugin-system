from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.plugin_system.audit import AuditLogger
from modules.plugin_system.engine import PluginEngine
from modules.plugin_system.loader import sha256_file
from modules.plugin_system.marketplace import PluginRegistryClient
from modules.plugin_system.policy import PluginPolicy, PolicyEngine
from modules.plugin_system.signing import sign_package
from scripts.drill_common import (
    PUBLISHER,
    drill_workspace,
    exception_text,
    make_keys,
    make_plugin_source,
    make_result,
    package_plugin,
    scan_report_for,
    sign_and_verify,
    write_json,
    write_registry_index,
)


PLUGIN_NAME = "drill_rollback_plugin"


def run_drill() -> dict[str, Any]:
    checks: dict[str, Any] = {}
    artifacts: dict[str, str] = {}
    with drill_workspace("rollback") as root:
        private_key, public_key = make_keys(root, "rollback")
        v1_source = make_plugin_source(root / "v1-source", PLUGIN_NAME, version="1.0.0", body=_body("v1"))
        v2_source = make_plugin_source(root / "v2-source", PLUGIN_NAME, version="2.0.0", body=_body("v2"))
        v2_same_source = make_plugin_source(
            root / "v2-same-source",
            PLUGIN_NAME,
            version="2.0.0",
            body=_body("v2-replacement"),
        )
        v1_package = package_plugin(v1_source, root / "packages")
        v2_package = package_plugin(v2_source, root / "packages-v2")
        v2_same_package = package_plugin(v2_same_source, root / "packages-v2-same")
        v1_scan = scan_report_for(v1_source)
        v2_scan = scan_report_for(v2_source)
        v2_same_scan = scan_report_for(v2_same_source)
        _v1_signature, v1_signature_payload = sign_and_verify(v1_package, private_key, public_key)
        _v2_signature, v2_signature_payload = sign_and_verify(v2_package, private_key, public_key)
        audit_logger = AuditLogger(root / "rollback.audit.log")
        engine = PluginEngine(
            root / "plugins",
            sandbox_backend="external_enforced",
            audit_logger=audit_logger,
            production_mode=True,
            policy_engine=PolicyEngine(
                PluginPolicy(linux_required_for_third_party_production=False, require_audit_checkpoint=False),
                audit_logger=audit_logger,
            ),
        )
        artifacts.update(
            {
                "v1_package": str(v1_package),
                "v2_package": str(v2_package),
                "audit_log": str(audit_logger.log_path),
            }
        )

        try:
            engine.install(v1_package, signature=v1_signature_payload, scan_report=v1_scan)
            installed_path = root / "plugins" / PLUGIN_NAME / "src" / "main.py"
            original_hash = sha256_file(installed_path)
            with patch("modules.plugin_system.loader.shutil.copytree", side_effect=RuntimeError("simulated update failure")):
                try:
                    engine.install(v2_package, signature=v2_signature_payload, scan_report=v2_scan)
                    checks["failed_update_can_rollback"] = False
                    checks["failed_update_error"] = "simulated update unexpectedly succeeded"
                except Exception as exc:
                    checks["failed_update_reason"] = exception_text(exc)
                    checks["failed_update_can_rollback"] = installed_path.exists() and sha256_file(installed_path) == original_hash
        except Exception as exc:
            checks["failed_update_can_rollback"] = False
            checks["rollback_setup_error"] = exception_text(exc)

        try:
            v2_sig = sign_package(v2_package, private_key=private_key, publisher=PUBLISHER)
            v2_index = write_registry_index(root / "registry-v2", PLUGIN_NAME, v2_package, v2_sig, version="2.0.0")
            v2_index_sig = sign_package(v2_index, private_key=private_key, publisher=PUBLISHER)
            PluginRegistryClient(v2_index, index_signature=v2_index_sig).install(
                PLUGIN_NAME,
                plugins_dir=root / "registry-install",
                public_key=public_key,
                require_signature=True,
                index_public_key=public_key,
                require_index_signature=True,
                scan_report=v2_scan,
            )
            v1_sig = sign_package(v1_package, private_key=private_key, publisher=PUBLISHER)
            v1_index = write_registry_index(root / "registry-v1", PLUGIN_NAME, v1_package, v1_sig, version="1.0.0")
            v1_index_sig = sign_package(v1_index, private_key=private_key, publisher=PUBLISHER)
            try:
                PluginRegistryClient(v1_index, index_signature=v1_index_sig).install(
                    PLUGIN_NAME,
                    plugins_dir=root / "registry-install",
                    public_key=public_key,
                    require_signature=True,
                    index_public_key=public_key,
                    require_index_signature=True,
                    scan_report=v1_scan,
                )
                checks["downgrade_rejected_unless_explicitly_allowed"] = False
            except Exception as exc:
                checks["downgrade_rejected_unless_explicitly_allowed"] = True
                checks["downgrade_rejected_reason"] = exception_text(exc)

            v2_same_sig = sign_package(v2_same_package, private_key=private_key, publisher=PUBLISHER)
            v2_same_index = write_registry_index(
                root / "registry-v2-same",
                PLUGIN_NAME,
                v2_same_package,
                v2_same_sig,
                version="2.0.0",
            )
            v2_same_index_sig = sign_package(v2_same_index, private_key=private_key, publisher=PUBLISHER)
            try:
                PluginRegistryClient(v2_same_index, index_signature=v2_same_index_sig).install(
                    PLUGIN_NAME,
                    plugins_dir=root / "registry-install",
                    public_key=public_key,
                    require_signature=True,
                    index_public_key=public_key,
                    require_index_signature=True,
                    scan_report=v2_same_scan,
                )
                checks["same_version_replacement_rejected"] = False
            except Exception as exc:
                checks["same_version_replacement_rejected"] = True
                checks["same_version_replacement_reason"] = exception_text(exc)
        except Exception as exc:
            checks["downgrade_rejected_unless_explicitly_allowed"] = False
            checks["same_version_replacement_rejected"] = False
            checks["registry_rollback_setup_error"] = exception_text(exc)

        records = audit_logger.read_records()
        checks["audit_event_written"] = any(
            item.event == "plugin.install_failed" and item.plugin is None for item in records
        )

    required = [
        "failed_update_can_rollback",
        "downgrade_rejected_unless_explicitly_allowed",
        "same_version_replacement_rejected",
        "audit_event_written",
    ]
    passed = all(checks.get(name) is True for name in required)
    return make_result(
        drill_id="rollback",
        status="pass" if passed else "failed",
        checks=checks,
        reason="rollback drill passed" if passed else "one or more rollback checks failed",
        recommendation="Archive evidence." if passed else "Fix update rollback and registry replacement controls before approval.",
        production_blocking=not passed,
        artifacts=artifacts,
    )


def _body(marker: str) -> str:
    return "\n".join(
        [
            "def run(args, api):",
            f"    return {{'marker': {marker!r}, 'args': args}}",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run update rollback and downgrade drill")
    parser.add_argument("--output", default="evidence/rollback_drill.json")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    report = run_drill()
    write_json(args.output, report)
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
