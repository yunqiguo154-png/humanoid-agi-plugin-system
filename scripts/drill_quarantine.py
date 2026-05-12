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
from modules.plugin_system.models import PluginStatus
from modules.plugin_system.policy import PluginPolicy, PolicyEngine
from modules.plugin_system.sandbox_backend import EXTERNAL_SANDBOX_ATTESTATION_ENV
from scripts.drill_common import (
    ATTESTATION,
    drill_workspace,
    exception_text,
    make_keys,
    make_plugin_source,
    make_result,
    package_plugin,
    scan_report_for,
    sign_and_verify,
    write_json,
)


PLUGIN_NAME = "drill_quarantine_plugin"


def run_drill() -> dict[str, Any]:
    checks: dict[str, Any] = {}
    artifacts: dict[str, str] = {}
    with drill_workspace("quarantine") as root:
        source = make_plugin_source(root, PLUGIN_NAME)
        package = package_plugin(source, root / "packages")
        scan_report = scan_report_for(source)
        private_key, public_key = make_keys(root, "quarantine")
        _signature, signature_payload = sign_and_verify(package, private_key, public_key)
        audit_logger = AuditLogger(root / "quarantine.audit.log")
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
        artifacts.update({"package": str(package), "audit_log": str(audit_logger.log_path)})
        try:
            engine.install(package, signature=signature_payload, scan_report=scan_report)
            engine.grant_permissions(PLUGIN_NAME, reviewer="admin", review_reason="quarantine_drill")
            engine.enable_plugin(PLUGIN_NAME, actor="admin", reason="quarantine_drill")
            with patch.dict(os.environ, {EXTERNAL_SANDBOX_ATTESTATION_ENV: ATTESTATION}):
                engine.start_plugin(PLUGIN_NAME)
                first = engine.call_tool(PLUGIN_NAME, "run", {})
                checks["plugin_started_and_callable_before_quarantine"] = first.get("status") == "success"
                quarantined = engine.quarantine_plugin(
                    PLUGIN_NAME,
                    actor="admin",
                    reason="quarantine_drill",
                )
                checks["admin_quarantine_succeeds"] = quarantined.status == PluginStatus.QUARANTINED
                checks["running_plugin_stops_or_future_calls_denied"] = PLUGIN_NAME not in engine.sandboxes
                try:
                    engine.call_tool(PLUGIN_NAME, "run", {})
                    checks["future_calls_denied_after_quarantine"] = False
                except PluginLifecycleError as exc:
                    checks["future_calls_denied_after_quarantine"] = True
                    checks["future_calls_denied_reason"] = exception_text(exc)
        except Exception as exc:
            checks["admin_quarantine_succeeds"] = False
            checks["quarantine_error"] = exception_text(exc)
        finally:
            engine.stop_all()

        installed = engine.loader.get_installed(PLUGIN_NAME)
        checks["visible_status_updated"] = installed is not None and installed.status == PluginStatus.QUARANTINED
        records = audit_logger.read_records()
        checks["audit_event_written"] = any(
            item.event == "plugin.quarantined" and item.plugin == PLUGIN_NAME for item in records
        ) and any(item.event in {"plugin.start_denied", "plugin.action_denied"} for item in records)

    required = [
        "admin_quarantine_succeeds",
        "running_plugin_stops_or_future_calls_denied",
        "future_calls_denied_after_quarantine",
        "audit_event_written",
        "visible_status_updated",
    ]
    passed = all(checks.get(name) is True for name in required)
    return make_result(
        drill_id="quarantine",
        status="pass" if passed else "failed",
        checks=checks,
        reason="quarantine drill passed" if passed else "one or more quarantine checks failed",
        recommendation="Archive evidence." if passed else "Fix quarantine enforcement before approval.",
        production_blocking=not passed,
        artifacts=artifacts,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run emergency quarantine drill")
    parser.add_argument("--output", default="evidence/quarantine_drill.json")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    report = run_drill()
    write_json(args.output, report)
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
