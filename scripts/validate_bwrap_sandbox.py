from __future__ import annotations

import argparse
import os
import json
import shutil
import sys
import tempfile
import textwrap
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.plugin_system.audit import AuditLogger
from modules.plugin_system.engine import PluginEngine
from modules.plugin_system.loader import PACKAGE_LOCK_FILE, write_package_lock
from modules.plugin_system.sandbox_backend import create_sandbox_backend, sandbox_capabilities


VALIDATION_MODE_DIAGNOSTIC = "diagnostic"
VALIDATION_MODE_PRODUCTION_REQUIRED = "production-required"
VALIDATION_MODES = {VALIDATION_MODE_DIAGNOSTIC, VALIDATION_MODE_PRODUCTION_REQUIRED}

PRODUCTION_REQUIRED_CAPABILITIES = (
    "process_containment",
    "resource_limits",
    "filesystem_isolation",
    "network_isolation",
)

PRODUCTION_REQUIRED_CHECKS = {
    "bwrap_backend_enforced",
    "bwrap_wrapped_command",
    "bwrap_unshared_network",
    "bwrap_private_tmp",
    "host_home_blocked",
    "env_blocked",
    "core_blocked",
    "code_readonly",
    "host_tmp_not_leaked",
    "direct_network_blocked",
    "data_write_allowed",
    "audit_records_present",
}


def run_validation(
    workdir: str | Path | None = None,
    *,
    mode: str = VALIDATION_MODE_PRODUCTION_REQUIRED,
) -> dict[str, Any]:
    if mode not in VALIDATION_MODES:
        raise ValueError(f"unsupported bwrap validation mode: {mode}")

    environment_class = _detect_environment_class()
    if sys.platform != "linux":
        return _finalize_report(
            {
                "status": "skipped",
                "reason": "bubblewrap validation requires Linux",
                "checks": [],
                "sandbox_backend": _empty_backend_report("bubblewrap validation requires Linux"),
                "recommendation": _target_linux_recommendation(mode, environment_class),
            },
            mode=mode,
            environment_class=environment_class,
        )
    if not shutil.which("bwrap"):
        return _finalize_report(
            {
                "status": "skipped",
                "reason": "bubblewrap executable is not available",
                "checks": [],
                "sandbox_backend": _empty_backend_report("bubblewrap executable is not available"),
                "recommendation": _target_linux_recommendation(mode, environment_class),
            },
            mode=mode,
            environment_class=environment_class,
        )

    preflight = _probe_backend_report()
    if mode == VALIDATION_MODE_PRODUCTION_REQUIRED and not _backend_has_required_capabilities(preflight):
        return _finalize_report(
            {
                "status": "fail",
                "reason": "bubblewrap backend is not enforced; production-required validation failed closed without running the sample plugin",
                "workdir": str(Path(workdir).resolve()) if workdir else None,
                "result": {
                    "status": "not_run",
                    "reason": "production-required mode does not run the validation sample without an enforced bwrap backend",
                },
                "checks": _preflight_checks(preflight),
                "audit_records": 0,
                "sandbox_backend": preflight,
                "observations": {"sample_executed": False},
                "recommendation": _target_linux_recommendation(mode, environment_class),
            },
            mode=mode,
            environment_class=environment_class,
        )

    report = _run_sample_validation(workdir, mode=mode)
    if not report.get("sandbox_backend"):
        report["sandbox_backend"] = preflight
    return _finalize_report(report, mode=mode, environment_class=environment_class)


def _run_sample_validation(
    workdir: str | Path | None = None,
    *,
    mode: str,
) -> dict[str, Any]:
    root = Path(workdir).resolve() if workdir else Path(tempfile.mkdtemp(prefix="humanoid-bwrap-"))
    root.mkdir(parents=True, exist_ok=True)
    plugins_dir = root / "plugins"
    packages_dir = root / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)
    project_env = Path.cwd() / ".env"
    previous_env = project_env.read_text(encoding="utf-8") if project_env.exists() else None
    home_secret = Path.home() / f".humanoid_agi_bwrap_validation_{uuid.uuid4().hex}"
    host_tmp_file = Path(tempfile.gettempdir()).resolve() / f"bwrap_escape_{uuid.uuid4().hex}.txt"
    try:
        project_env.write_text("bwrap-validation-env-secret", encoding="utf-8")
        home_secret.write_text("bwrap-validation-home-secret", encoding="utf-8")
        source = _make_malicious_plugin(root, project_env, home_secret)
        package = _zip_plugin(source, packages_dir)
        audit_logger = AuditLogger(root / "bwrap-validation.audit.log")
        engine = PluginEngine(
            plugins_dir,
            sandbox_backend="bubblewrap",
            audit_logger=audit_logger,
            require_enforced_sandbox=mode == VALIDATION_MODE_PRODUCTION_REQUIRED,
        )
        try:
            metadata = engine.install(package)
            engine.grant_permissions("bwrap_validation_plugin")
            sandbox = engine.start_plugin("bwrap_validation_plugin")
            backend_details = dict(sandbox.os_limits.get("sandbox_backend", {}).get("details", {}))
            result = sandbox.execute_with_timeout(
                "execute_tool",
                {
                    "tool_name": "run",
                    "args": {
                        "home_secret": str(home_secret),
                        "project_env": str(project_env),
                        "core_file": str((Path.cwd() / "SPECIFICATION").resolve()),
                        "code_file": str((plugins_dir / metadata.name / "src" / "blocked_write.txt").resolve()),
                        "host_tmp_file": str(host_tmp_file),
                        "wrapped_command": backend_details.get("wrapped_command"),
                        "network": backend_details.get("network"),
                        "tmp": backend_details.get("tmp"),
                    },
                },
                timeout=15.0,
                request_id=f"bwrap-validation-{uuid.uuid4().hex}",
            )
            os_limits = sandbox.os_limits
            sandbox_backend = sandbox.os_limits.get("sandbox_backend", {})
            result.setdefault("request_id", None)
            engine.audit_logger.record(
                "plugin.tool_call",
                "success" if result.get("status") == "success" else "error",
                request_id=str(result.get("request_id") or "bwrap-validation"),
                plugin="bwrap_validation_plugin",
                action="run",
                details={"arg_keys": ["code_file", "core_file", "home_secret", "host_tmp_file", "project_env"]},
            )
        except Exception as exc:
            result = {"status": "error", "error": str(exc), "error_type": type(exc).__name__}
            if "sandbox" in locals():
                os_limits = sandbox.os_limits
                sandbox_backend = sandbox.os_limits.get("sandbox_backend", {})
            else:
                os_limits = {}
                sandbox_backend = {}
        finally:
            engine.stop_all()
        observations = {"host_tmp_leaked": host_tmp_file.exists()}
        checks = _evaluate_result(result, audit_logger, os_limits, observations)
        status = "pass" if all(item["status"] in {"pass", "info"} for item in checks) else "fail"
        return {
            "status": status,
            "workdir": str(root),
            "result": result,
            "checks": checks,
            "audit_records": len(audit_logger.read_records()),
            "sandbox_backend": sandbox_backend,
            "observations": observations,
            "recommendation": _target_linux_recommendation(mode, _detect_environment_class()),
        }
    finally:
        if previous_env is None:
            try:
                project_env.unlink()
            except FileNotFoundError:
                pass
        else:
            project_env.write_text(previous_env, encoding="utf-8")
        try:
            home_secret.unlink()
        except FileNotFoundError:
            pass
        try:
            host_tmp_file.unlink()
        except FileNotFoundError:
            pass


def _probe_backend_report() -> dict[str, Any]:
    try:
        backend = create_sandbox_backend(128, 2, requested="bubblewrap")
        report = backend.report
        return {
            "name": report.name,
            "enforced": report.enforced,
            "platform": report.platform,
            "details": report.details,
            "warnings": report.warnings,
            "capabilities": report.capabilities,
            "missing_capabilities": report.missing_capabilities(),
        }
    except Exception as exc:
        return {
            "name": "bubblewrap",
            "enforced": False,
            "platform": sys.platform,
            "details": {},
            "warnings": [f"bubblewrap backend probe raised {type(exc).__name__}: {exc}"],
            "capabilities": sandbox_capabilities(),
            "missing_capabilities": list(PRODUCTION_REQUIRED_CAPABILITIES),
        }


def _empty_backend_report(reason: str) -> dict[str, Any]:
    return {
        "name": "bubblewrap",
        "enforced": False,
        "platform": sys.platform,
        "details": {},
        "warnings": [reason],
        "capabilities": sandbox_capabilities(),
        "missing_capabilities": list(PRODUCTION_REQUIRED_CAPABILITIES),
    }


def _backend_has_required_capabilities(backend: dict[str, Any]) -> bool:
    capabilities = backend.get("capabilities", {})
    if not isinstance(capabilities, dict):
        return False
    return bool(backend.get("enforced")) and all(
        capabilities.get(capability) is True for capability in PRODUCTION_REQUIRED_CAPABILITIES
    )


def _preflight_checks(backend: dict[str, Any]) -> list[dict[str, Any]]:
    details = backend.get("details", {}) if isinstance(backend.get("details"), dict) else {}
    capabilities = backend.get("capabilities", {}) if isinstance(backend.get("capabilities"), dict) else {}
    checks = [
        ("plugin_executed", False, "validation plugin must not execute without enforced bwrap in production-required mode"),
        ("bwrap_backend_enforced", bool(backend.get("enforced")), "bubblewrap backend must be enforced"),
        ("bwrap_wrapped_command", details.get("wrapped_command") is True, "plugin process must be launched through bwrap"),
        ("bwrap_unshared_network", details.get("network") == "unshared", "bwrap must unshare network namespace"),
        ("bwrap_private_tmp", details.get("tmp") == "private_tmpfs", "bwrap must provide a private /tmp"),
        ("filesystem_isolation", capabilities.get("filesystem_isolation") is True, "bwrap must provide filesystem isolation"),
        ("network_isolation", capabilities.get("network_isolation") is True, "bwrap must provide network isolation"),
        ("process_containment", capabilities.get("process_containment") is True, "bwrap must provide process containment"),
        ("resource_limits", capabilities.get("resource_limits") is True, "worker resource limits must be available"),
    ]
    return [
        {"check_id": check_id, "status": "pass" if passed else "fail", "reason": reason}
        for check_id, passed, reason in checks
    ]


def _detect_environment_class() -> str:
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        runner_environment = os.environ.get("RUNNER_ENVIRONMENT", "").strip().lower()
        labels = os.environ.get("RUNNER_LABELS", "").lower()
        if runner_environment == "self-hosted" or "self-hosted" in labels:
            return "self_hosted"
        return "github_hosted"
    return "unknown"


def _target_linux_recommendation(mode: str, environment_class: str) -> str:
    if mode == VALIDATION_MODE_DIAGNOSTIC:
        return (
            "Archive this as diagnostic evidence only. It does not satisfy Release Gate bwrap.validation; "
            "run production-required validation on a target Linux VM or a self-hosted runner labeled linux,bwrap."
        )
    if environment_class == "github_hosted":
        return (
            "GitHub-hosted runners are not target production Linux+bwrap evidence. Run production-required validation "
            "on a controlled Linux VM or a self-hosted runner labeled self-hosted,linux,bwrap."
        )
    return "Fix the target Linux+bwrap environment and rerun production-required validation."


def _finalize_report(
    report: dict[str, Any],
    *,
    mode: str,
    environment_class: str,
) -> dict[str, Any]:
    report["mode"] = mode
    report["environment_class"] = environment_class
    report.setdefault("sandbox_backend", _empty_backend_report("sandbox backend report missing"))
    report.setdefault("checks", [])
    report.setdefault("generated_at", datetime.now(UTC).isoformat())
    report.setdefault("recommendation", _target_linux_recommendation(mode, environment_class))

    if mode == VALIDATION_MODE_DIAGNOSTIC:
        report["production_blocking"] = True
        if environment_class == "github_hosted":
            current_status = str(report.get("status", "fail"))
            if current_status == "pass":
                report["status"] = "unsupported_environment"
                report["reason"] = (
                    "GitHub-hosted diagnostic completed, but hosted runner output is not target production "
                    "Linux+bwrap validation evidence"
                )
            else:
                report.setdefault(
                    "reason",
                    "GitHub-hosted bwrap diagnostic is unsupported as production validation evidence",
                )
        else:
            report.setdefault("reason", "diagnostic mode is not production validation evidence")
        return report

    status = str(report.get("status", "fail"))
    checks = report.get("checks", [])
    backend = report.get("sandbox_backend", {})
    critical_pass = _critical_checks_pass(checks) and _backend_has_required_capabilities(backend)
    if status == "pass" and critical_pass:
        report["production_blocking"] = False
        report.setdefault("reason", "production-required bwrap validation passed")
        return report

    report["status"] = "fail" if status != "skipped" else "skipped"
    report["production_blocking"] = True
    report.setdefault("reason", "production-required bwrap validation did not pass")
    return report


def _critical_checks_pass(checks: Any) -> bool:
    if not isinstance(checks, list):
        return False
    statuses = {
        str(item.get("check_id")): str(item.get("status"))
        for item in checks
        if isinstance(item, dict)
    }
    return all(statuses.get(check_id) == "pass" for check_id in PRODUCTION_REQUIRED_CHECKS)


def _make_malicious_plugin(root: Path, project_env: Path, home_secret: Path) -> Path:
    source = root / "bwrap_validation_plugin"
    (source / "src").mkdir(parents=True)
    (source / "src" / "__init__.py").write_text("", encoding="utf-8")
    code = """
import io

def _can_read(path):
    try:
        with io.open(path, "r", encoding="utf-8") as handle:
            handle.read(1)
        return True
    except Exception:
        return False

def _can_write(path):
    try:
        with io.open(path, "w", encoding="utf-8") as handle:
            handle.write("blocked")
        return True
    except Exception:
        return False

def _try_load_module(name):
    try:
        return __loader__.load_module(name)
    except Exception:
        return None

def _direct_network_available():
    socket_module = _try_load_module("_socket")
    if socket_module is None:
        return False
    try:
        sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
        sock.settimeout(0.2)
        sock.connect(("93.184.216.34", 80))
        sock.close()
        return True
    except Exception:
        return False

def _process_execution_available():
    subprocess_module = _try_load_module("subprocess")
    if subprocess_module is None:
        return False
    try:
        result = getattr(subprocess_module, "run")(["/bin/sh", "-c", "echo fork"], timeout=1, check=False)
        return getattr(result, "returncode", 1) == 0
    except Exception:
        return False

def run(args, api):
    api.write_file("allowed.txt", "data-ok")
    created = 0
    for index in range(100):
        try:
            api.write_file("many/%s.txt" % index, "x")
            created += 1
        except Exception:
            break
    return {
        "wrapped_command": args.get("wrapped_command"),
        "network_backend": args.get("network"),
        "tmp_backend": args.get("tmp"),
        "home_readable": _can_read(args["home_secret"]),
        "env_readable": _can_read(args["project_env"]),
        "core_readable": _can_read(args["core_file"]),
        "code_writable": _can_write(args["code_file"]),
        "host_tmp_write": _can_write(args["host_tmp_file"]),
        "direct_network_available": _direct_network_available(),
        "process_execution_available": _process_execution_available(),
        "many_files_created": created,
        "large_output_len": len("x" * (2 * 1024 * 1024)),
        "data_content": api.read_file("allowed.txt"),
    }
"""
    (source / "src" / "main.py").write_text(textwrap.dedent(code), encoding="utf-8")
    (source / "plugin.yaml").write_text(
        "\n".join(
            [
                "name: bwrap_validation_plugin",
                "version: 1.0.0",
                "description: Bubblewrap validation plugin",
                "author: test",
                "license: MIT",
                "runtime:",
                "  mode: sub_process",
                "  trust: third_party",
                "  memory_mb: 128",
                "  timeout_seconds: 5",
                "  cpu_seconds: 2",
                "extensions:",
                "  - type: tool",
                "    name: run",
                "    entry: src.main:run",
                "permissions:",
                "  - compute: true",
                "  - fs.read: true",
                "  - fs.write: true",
                "requires:",
                '  python: ">=3.11"',
                "  packages: []",
            ]
        ),
        encoding="utf-8",
    )
    write_package_lock(source)
    return source


def _zip_plugin(source: Path, packages_dir: Path) -> Path:
    if (source / PACKAGE_LOCK_FILE).exists():
        write_package_lock(source)
    package = packages_dir / f"{source.name}.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in source.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    return package


def _evaluate_result(
    result: dict[str, Any],
    audit_logger: AuditLogger,
    os_limits: dict[str, Any],
    observations: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    data = result.get("data") if result.get("status") == "success" else {}
    observations = observations or {}
    backend = os_limits.get("sandbox_backend", {})
    backend_details = backend.get("details", {}) if isinstance(backend, dict) else {}
    checks = [
        ("plugin_executed", result.get("status") == "success", "validation plugin should execute inside sandbox"),
        ("bwrap_backend_enforced", bool(backend.get("enforced")), "bubblewrap backend must be enforced"),
        ("bwrap_wrapped_command", backend_details.get("wrapped_command") is True, "plugin process must be launched through bwrap"),
        ("bwrap_unshared_network", backend_details.get("network") == "unshared", "bwrap must unshare network namespace"),
        ("bwrap_private_tmp", backend_details.get("tmp") == "private_tmpfs", "bwrap must provide a private /tmp"),
        ("host_home_blocked", not data.get("home_readable"), "host HOME must not be readable"),
        ("env_blocked", not data.get("env_readable"), ".env must not be readable"),
        ("core_blocked", not data.get("core_readable"), "project core must not be readable"),
        ("code_readonly", not data.get("code_writable"), "plugin code directory must be read-only"),
        ("private_tmp_writable", data.get("host_tmp_write") is True, "sandbox private /tmp should be writable"),
        ("host_tmp_not_leaked", not observations.get("host_tmp_leaked"), "sandbox private /tmp writes must not leak to host"),
        ("direct_network_blocked", not data.get("direct_network_available"), "direct network must be blocked"),
        ("data_write_allowed", data.get("data_content") == "data-ok", "plugin data directory should be writable via Gateway"),
        ("audit_records_present", len(audit_logger.read_records()) > 0, "audit records should be present"),
    ]
    results: list[dict[str, Any]] = [
        {"check_id": check_id, "status": "pass" if passed else "fail", "reason": reason}
        for check_id, passed, reason in checks
    ]
    results.append(
        {
            "check_id": "process_execution_observed",
            "status": "info",
            "reason": "bwrap provides process namespace/resource containment; child process availability is recorded separately",
            "observed": bool(data.get("process_execution_available")),
        }
    )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Linux bubblewrap plugin sandbox behavior")
    parser.add_argument("--workdir")
    parser.add_argument(
        "--mode",
        choices=sorted(VALIDATION_MODES),
        default=VALIDATION_MODE_PRODUCTION_REQUIRED,
        help="diagnostic records hosted-runner capability details; production-required fails closed before running samples if bwrap is not enforced",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    report = run_validation(args.workdir, mode=args.mode)
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "bwrap validation "
            f"mode={report.get('mode')} environment={report.get('environment_class')} "
            f"status={report['status']} reason={report.get('reason', '')}"
        )
        for item in report.get("checks", []):
            print(f"- [{item['status']}] {item['check_id']}: {item['reason']}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
