from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.plugin_system.audit import AuditLogger
from modules.plugin_system.engine import PluginEngine, PluginLifecycleError
from modules.plugin_system.marketplace import PluginRegistryClient
from modules.plugin_system.policy import PluginPolicy, PolicyEngine
from modules.plugin_system.sandbox_backend import EXTERNAL_SANDBOX_ATTESTATION_ENV
from modules.plugin_system.signing import TrustStore, sign_package, verify_signature
from scripts.drill_common import (
    ATTESTATION,
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


PLUGIN_NAME = "drill_revocation_plugin"


def run_drill() -> dict[str, Any]:
    checks: dict[str, Any] = {}
    artifacts: dict[str, str] = {}
    with drill_workspace("revocation") as root:
        source = make_plugin_source(root, PLUGIN_NAME)
        package = package_plugin(source, root / "packages")
        scan_report = scan_report_for(source)
        private_key, public_key = make_keys(root, "revocation")
        trust_store = root / "trust-store.json"
        key_id = TrustStore(trust_store).add_key(PUBLISHER, public_key)
        signature, signature_payload = sign_and_verify(package, private_key, public_key)
        artifacts.update(
            {
                "package": str(package),
                "signature": str(signature),
                "public_key": str(public_key),
                "trust_store": str(trust_store),
            }
        )

        TrustStore(trust_store).revoke_key(PUBLISHER, key_id)
        try:
            verify_signature(package, signature, trust_store=trust_store)
            checks["revoked_signer_key_rejected"] = False
        except Exception as exc:
            checks["revoked_signer_key_rejected"] = True
            checks["revoked_signer_key_reason"] = exception_text(exc)

        index = write_registry_index(
            root / "revoked-version",
            PLUGIN_NAME,
            package,
            signature,
            revoked_plugin_versions=[{"name": PLUGIN_NAME, "version": "1.0.0"}],
        )
        index_signature = sign_package(index, private_key=private_key, publisher=PUBLISHER)
        artifacts["revoked_version_index"] = str(index)
        try:
            PluginRegistryClient(index, index_signature=index_signature).install(
                PLUGIN_NAME,
                plugins_dir=root / "registry-install",
                public_key=public_key,
                require_signature=True,
                index_public_key=public_key,
                require_index_signature=True,
                scan_report=scan_report,
            )
            checks["revoked_plugin_version_rejected"] = False
        except Exception as exc:
            checks["revoked_plugin_version_rejected"] = True
            checks["revoked_plugin_version_reason"] = exception_text(exc)

        audit_logger = AuditLogger(root / "revocation.audit.log")
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
        artifacts["audit_log"] = str(audit_logger.log_path)
        try:
            engine.install(package, signature=signature_payload, scan_report=scan_report)
            engine.grant_permissions(PLUGIN_NAME, reviewer="admin", review_reason="revocation_drill")
            engine.enable_plugin(PLUGIN_NAME, actor="admin", reason="revocation_drill")
            with patch.dict(os.environ, {EXTERNAL_SANDBOX_ATTESTATION_ENV: ATTESTATION}):
                engine.start_plugin(PLUGIN_NAME)
                engine.revoke_plugin_version(
                    PLUGIN_NAME,
                    "1.0.0",
                    actor="admin",
                    reason="revocation_drill",
                )
                try:
                    engine.call_tool(PLUGIN_NAME, "run", {})
                    checks["already_installed_revoked_plugin_cannot_start_or_call"] = False
                except PluginLifecycleError as exc:
                    checks["already_installed_revoked_plugin_cannot_start_or_call"] = True
                    checks["already_installed_revoked_plugin_reason"] = exception_text(exc)
        except Exception as exc:
            checks["already_installed_revoked_plugin_cannot_start_or_call"] = False
            checks["already_installed_revoked_plugin_error"] = exception_text(exc)
        finally:
            engine.stop_all()

        records = audit_logger.read_records()
        checks["audit_event_written"] = any(
            item.event == "plugin.version_revoked" and item.plugin == PLUGIN_NAME for item in records
        ) and any(item.event in {"plugin.action_denied", "plugin.start_denied"} for item in records)

    required = [
        "revoked_signer_key_rejected",
        "revoked_plugin_version_rejected",
        "already_installed_revoked_plugin_cannot_start_or_call",
        "audit_event_written",
    ]
    passed = all(checks.get(name) is True for name in required)
    return make_result(
        drill_id="revocation",
        status="pass" if passed else "failed",
        checks=checks,
        reason="revocation drill passed" if passed else "one or more revocation checks failed",
        recommendation="Archive evidence." if passed else "Fix signer/version revocation enforcement before approval.",
        production_blocking=not passed,
        artifacts=artifacts,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run signer and plugin version revocation drill")
    parser.add_argument("--output", default="evidence/revocation_drill.json")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    report = run_drill()
    write_json(args.output, report)
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
