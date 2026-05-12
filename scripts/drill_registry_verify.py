from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.plugin_system.marketplace import PluginRegistryClient
from modules.plugin_system.signing import sha256_file, sign_package
from scripts.drill_common import (
    PUBLISHER,
    drill_workspace,
    exception_text,
    make_keys,
    make_plugin_source,
    make_result,
    package_plugin,
    sign_and_verify,
    write_json,
    write_registry_index,
)


def run_drill() -> dict[str, Any]:
    checks: dict[str, Any] = {}
    artifacts: dict[str, str] = {}
    with drill_workspace("registry-verify") as root:
        source = make_plugin_source(root, "drill_registry_plugin")
        package = package_plugin(source, root / "packages")
        private_key, public_key = make_keys(root, "registry")
        signature, _signature_payload = sign_and_verify(package, private_key, public_key)
        index = write_registry_index(root, "drill_registry_plugin", package, signature)
        index_signature = sign_package(index, private_key=private_key, publisher=PUBLISHER)
        artifacts.update(
            {
                "package": str(package),
                "index": str(index),
                "index_signature": str(index_signature),
                "public_key": str(public_key),
            }
        )

        try:
            entries = PluginRegistryClient(index, index_signature=index_signature).list_plugins(
                public_key=public_key,
                require_signature=True,
            )
            checks["signed_registry_index_verified"] = bool(entries and entries[0].name == "drill_registry_plugin")
        except Exception as exc:
            checks["signed_registry_index_verified"] = False
            checks["signed_registry_index_error"] = exception_text(exc)

        try:
            result = PluginRegistryClient(index, index_signature=index_signature).install(
                "drill_registry_plugin",
                plugins_dir=root / "installed",
                public_key=public_key,
                require_signature=True,
                index_public_key=public_key,
                require_index_signature=True,
                scan_report=None,
            )
            checks["plugin_sha256_verified"] = result.entry.sha256 == sha256_file(result.package_path)
        except Exception as exc:
            checks["plugin_sha256_verified"] = False
            checks["plugin_sha256_error"] = exception_text(exc)

        unsigned_index = write_registry_index(root / "unsigned", "drill_registry_plugin", package, signature)
        try:
            PluginRegistryClient(unsigned_index).list_plugins(public_key=public_key, require_signature=True)
            checks["unsigned_registry_rejected"] = False
        except Exception as exc:
            checks["unsigned_registry_rejected"] = True
            checks["unsigned_registry_reason"] = exception_text(exc)

        tampered_payload = json.loads(index.read_text(encoding="utf-8"))
        tampered_payload["plugins"][0]["description"] = "tampered"
        index.write_text(json.dumps(tampered_payload, indent=2, sort_keys=True), encoding="utf-8")
        try:
            PluginRegistryClient(index, index_signature=index_signature).list_plugins(
                public_key=public_key,
                require_signature=True,
            )
            checks["tampered_registry_rejected"] = False
        except Exception as exc:
            checks["tampered_registry_rejected"] = True
            checks["tampered_registry_reason"] = exception_text(exc)

    required = [
        "signed_registry_index_verified",
        "plugin_sha256_verified",
        "unsigned_registry_rejected",
        "tampered_registry_rejected",
    ]
    passed = all(checks.get(name) is True for name in required)
    return make_result(
        drill_id="registry_verify",
        status="pass" if passed else "failed",
        checks=checks,
        reason="registry verification drill passed" if passed else "one or more registry verification checks failed",
        recommendation="Archive evidence." if passed else "Fix registry signing/hash enforcement before approval.",
        production_blocking=not passed,
        artifacts=artifacts,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run signed registry verification drill")
    parser.add_argument("--output", default="evidence/registry_verify.json")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    report = run_drill()
    write_json(args.output, report)
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
