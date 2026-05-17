from __future__ import annotations

import argparse
import os
import json
import subprocess
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
from modules.plugin_system.sandbox import SandboxManager
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
    "private_tmp_writable",
    "host_tmp_not_leaked",
    "direct_network_blocked",
    "data_write_allowed",
    "audit_records_present",
}


def run_validation(
    workdir: str | Path | None = None,
    *,
    mode: str = VALIDATION_MODE_PRODUCTION_REQUIRED,
    debug: bool = False,
    keep_workdir: bool = False,
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
                "result": _default_result_diagnostics(
                    {
                        "status": "not_run",
                        "reason": "production-required mode does not run the validation sample without an enforced bwrap backend",
                    }
                ),
                "checks": _preflight_checks(preflight),
                "audit_records": 0,
                "sandbox_backend": preflight,
                "observations": {"sample_executed": False},
                "recommendation": _target_linux_recommendation(mode, environment_class),
            },
            mode=mode,
            environment_class=environment_class,
        )

    root = Path(workdir).resolve() if workdir else Path(tempfile.mkdtemp(prefix="humanoid-bwrap-"))
    root.mkdir(parents=True, exist_ok=True)
    should_cleanup = workdir is None and not keep_workdir
    try:
        if mode == VALIDATION_MODE_PRODUCTION_REQUIRED:
            preflight_result = _run_bwrap_preflight(root, preflight)
            if preflight_result.get("status") != "pass":
                return _finalize_report(
                    {
                        "status": "fail",
                        "reason": _preflight_failure_reason(preflight_result),
                        "workdir": str(root),
                        "result": _default_result_diagnostics(
                            {
                                "status": "not_run",
                                "reason": "production-required validation sample was not run because bwrap preflight failed",
                            }
                        ),
                        "checks": _preflight_failure_checks(preflight, preflight_result),
                        "audit_records": 0,
                        "sandbox_backend": preflight,
                        "preflight": preflight_result,
                        "observations": {"sample_executed": False},
                        "recommendation": _preflight_recommendation(preflight_result),
                    },
                    mode=mode,
                    environment_class=environment_class,
                )
        else:
            preflight_result = None

        report = _run_sample_validation(root, mode=mode)
        if preflight_result is not None:
            report["preflight"] = preflight_result
        if not report.get("sandbox_backend"):
            report["sandbox_backend"] = preflight
        if not debug:
            _trim_debug_paths(report)
        return _finalize_report(report, mode=mode, environment_class=environment_class)
    finally:
        if should_cleanup:
            shutil.rmtree(root, ignore_errors=True)


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
            installed = engine.grant_permissions("bwrap_validation_plugin")
            sandbox = SandboxManager(
                installed,
                plugins_dir=plugins_dir,
                gateway=engine.gateway,
                sandbox_backend="bubblewrap",
                require_enforced_sandbox=mode == VALIDATION_MODE_PRODUCTION_REQUIRED,
            )
            sandbox.start()
            engine.sandboxes["bwrap_validation_plugin"] = sandbox
            engine.gateway.register_sandbox(sandbox)
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
            result = _merge_result_diagnostics(result, sandbox.os_limits)
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
            diagnostics = getattr(exc, "diagnostics", {})
            result = _merge_result_diagnostics(
                {
                    "status": "error",
                    "error": str(exc),
                    "error_type": _diagnostic_error_type(type(exc).__name__, diagnostics),
                },
                diagnostics if diagnostics else (sandbox.os_limits if "sandbox" in locals() else {}),
            )
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


def _run_bwrap_preflight(root: Path, backend: dict[str, Any]) -> dict[str, Any]:
    plugin_dir = (root / "preflight_plugin").resolve()
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "src").mkdir(parents=True, exist_ok=True)
    (plugin_dir / "src" / "__init__.py").write_text("", encoding="utf-8")
    (plugin_dir / "plugin.yaml").write_text("name: preflight_plugin\n", encoding="utf-8")
    data_dir = (plugin_dir / "data").resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    code_write_probe = (plugin_dir / "src" / "preflight_write_probe.txt").resolve()
    project_env = (Path.cwd() / ".env").resolve()
    previous_env = project_env.read_text(encoding="utf-8") if project_env.exists() else None
    core_file = (Path.cwd() / "SPECIFICATION").resolve()
    home_secret = Path.home() / f".humanoid_agi_bwrap_preflight_{uuid.uuid4().hex}"
    wrapped: list[str] | None = None
    stderr = ""
    stdout = ""
    returncode: int | None = None
    backend_details = backend.get("details", {}) if isinstance(backend.get("details"), dict) else {}
    try:
        project_env.write_text("bwrap-preflight-env-secret", encoding="utf-8")
        home_secret.write_text("bwrap-preflight-home-secret", encoding="utf-8")
        script = _preflight_script(plugin_dir, data_dir, code_write_probe, home_secret.resolve(), project_env, core_file)
        command = [
            sys.executable,
            "-c",
            script,
        ]
        bwrap_backend = create_sandbox_backend(128, 2, requested="bubblewrap")
        wrapped = bwrap_backend.prepare_subprocess(
            command,
            plugin_dir=plugin_dir,
            project_root=PROJECT_ROOT,
        )
        backend_details = dict(bwrap_backend.report.details)
        completed = subprocess.run(
            wrapped,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=10,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stderr = str(exc)
        returncode = None
    except Exception as exc:
        stderr = f"{type(exc).__name__}: {exc}"
        returncode = None
        command = [sys.executable, "-c", ""]
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

    payload = _load_json_from_stdout(stdout)
    import_error = None
    if isinstance(payload, dict):
        import_error = payload.get("import_error")
    checks = _preflight_statuses(payload if isinstance(payload, dict) else {})
    failed = [name for name, status in checks.items() if status != "pass"]
    status = "pass" if returncode == 0 and isinstance(payload, dict) and not failed else "fail"
    return {
        "status": status,
        "python_start": checks.get("python_start", "fail"),
        "import_runtime": checks.get("import_runtime", "fail"),
        "import_error": import_error,
        "tmp_writable": checks.get("tmp_writable", "fail"),
        "data_dir_writable": checks.get("data_dir_writable", "fail"),
        "code_dir_readonly": checks.get("code_dir_readonly", "fail"),
        "host_home_blocked": checks.get("host_home_blocked", "fail"),
        "env_blocked": checks.get("env_blocked", "fail"),
        "core_blocked": checks.get("core_blocked", "fail"),
        "stdout": _excerpt(stdout),
        "stderr": _excerpt(stderr),
        "returncode": returncode,
        "wrapped_command": wrapped,
        "argv": command,
        "cwd": backend_details.get("cwd"),
        "executable": sys.executable,
        "python_version": sys.version,
        "env_keys": None,
        "import_probe": _import_probe_from_payload(payload),
        "runtime_probe": payload if isinstance(payload, dict) else None,
        "worker_started": returncode is not None,
        "json_result_received": isinstance(payload, dict),
    }


def _preflight_script(
    plugin_dir: Path,
    data_dir: Path,
    code_write_probe: Path,
    home_probe: Path,
    project_env: Path,
    core_file: Path,
) -> str:
    payload = {
        "plugin_dir": str(plugin_dir),
        "data_dir": str(data_dir),
        "code_write_probe": str(code_write_probe),
        "home_probe": str(home_probe),
        "project_env": str(project_env),
        "core_file": str(core_file),
    }
    return (
        "import importlib, json, pathlib, sys, tempfile\n"
        f"p = json.loads({json.dumps(payload)!r})\n"
        "def can_read(path):\n"
        "    try:\n"
        "        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:\n"
        "            handle.read(1)\n"
        "        return True\n"
        "    except Exception:\n"
        "        return False\n"
        "def can_write(path):\n"
        "    try:\n"
        "        target = pathlib.Path(path)\n"
        "        target.parent.mkdir(parents=True, exist_ok=True)\n"
        "        target.write_text('ok', encoding='utf-8')\n"
        "        return True\n"
        "    except Exception:\n"
        "        return False\n"
        "import_error = None\n"
        "modules_ok = True\n"
        "try:\n"
        "    importlib.import_module('modules.plugin_system')\n"
        "    importlib.import_module('modules.plugin_system.sandbox_stdio_worker')\n"
        "except Exception as exc:\n"
        "    modules_ok = False\n"
        "    import_error = type(exc).__name__ + ': ' + str(exc)\n"
        "tmp_target = pathlib.Path(tempfile.gettempdir()) / 'humanoid-preflight.tmp'\n"
        "data_target = pathlib.Path(p['data_dir']) / 'preflight-data.txt'\n"
        "result = {\n"
        "    'ok': True,\n"
        "    'executable': sys.executable,\n"
        "    'version': sys.version,\n"
        "    'sys_path': sys.path,\n"
        "    'editable_install': any(str(item).endswith('.egg-link') for item in sys.path),\n"
        "    'modules_plugin_system_imported': modules_ok,\n"
        "    'sandbox_stdio_worker_imported': modules_ok,\n"
        "    'import_error': import_error,\n"
        "    'tmp_writable': can_write(tmp_target),\n"
        "    'data_dir_writable': can_write(data_target),\n"
        "    'code_writable': can_write(p['code_write_probe']),\n"
        "    'home_readable': can_read(p['home_probe']),\n"
        "    'env_readable': can_read(p['project_env']),\n"
        "    'core_readable': can_read(p['core_file']),\n"
        "}\n"
        "print(json.dumps(result, sort_keys=True))\n"
        "raise SystemExit(0 if modules_ok and result['tmp_writable'] and result['data_dir_writable'] and not result['code_writable'] and not result['home_readable'] and not result['env_readable'] and not result['core_readable'] else 1)\n"
    )


def _load_json_from_stdout(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def _preflight_statuses(payload: dict[str, Any]) -> dict[str, str]:
    return {
        "python_start": "pass" if payload.get("ok") is True else "fail",
        "import_runtime": "pass" if payload.get("modules_plugin_system_imported") is True else "fail",
        "tmp_writable": "pass" if payload.get("tmp_writable") is True else "fail",
        "data_dir_writable": "pass" if payload.get("data_dir_writable") is True else "fail",
        "code_dir_readonly": "pass" if payload.get("code_writable") is False else "fail",
        "host_home_blocked": "pass" if payload.get("home_readable") is False else "fail",
        "env_blocked": "pass" if payload.get("env_readable") is False else "fail",
        "core_blocked": "pass" if payload.get("core_readable") is False else "fail",
    }


def _import_probe_from_payload(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    return {
        "editable_install": payload.get("editable_install"),
        "sys_path": payload.get("sys_path"),
        "modules_plugin_system_imported": payload.get("modules_plugin_system_imported"),
        "sandbox_stdio_worker_imported": payload.get("sandbox_stdio_worker_imported"),
        "import_error": payload.get("import_error"),
    }


def _preflight_failure_reason(preflight: dict[str, Any]) -> str:
    if preflight.get("import_runtime") != "pass":
        return "runtime import failed under bwrap"
    if preflight.get("tmp_writable") != "pass":
        return "private tmp is not writable under bwrap"
    if preflight.get("data_dir_writable") != "pass":
        return "plugin data directory is not writable under bwrap"
    if preflight.get("code_dir_readonly") != "pass":
        return "plugin code directory is writable under bwrap"
    if preflight.get("host_home_blocked") != "pass":
        return "host HOME is readable under bwrap"
    if preflight.get("env_blocked") != "pass":
        return "host .env is readable under bwrap"
    if preflight.get("core_blocked") != "pass":
        return "project core is readable under bwrap"
    return "bwrap runtime preflight failed"


def _preflight_recommendation(preflight: dict[str, Any]) -> str:
    reason = _preflight_failure_reason(preflight)
    if "import" in reason:
        return "Fix the trusted runtime bundle or Python environment mounted into bwrap, then rerun production-required validation."
    if "data directory" in reason:
        return "Fix writable plugin data bind mount configuration, then rerun production-required validation."
    if "tmp" in reason:
        return "Fix private /tmp bwrap mount configuration, then rerun production-required validation."
    return "Fix the bwrap mount policy reported by preflight, then rerun production-required validation."


def _preflight_failure_checks(backend: dict[str, Any], preflight: dict[str, Any]) -> list[dict[str, Any]]:
    details = backend.get("details", {}) if isinstance(backend.get("details"), dict) else {}
    capabilities = backend.get("capabilities", {}) if isinstance(backend.get("capabilities"), dict) else {}
    wrapped_command = preflight.get("wrapped_command")
    checks = [
        ("plugin_executed", False, "validation sample did not run because bwrap preflight failed"),
        ("bwrap_backend_enforced", bool(backend.get("enforced")), "bubblewrap backend must be enforced"),
        ("bwrap_wrapped_command", details.get("wrapped_command") is True or bool(wrapped_command), "preflight must be launched through bwrap"),
        ("bwrap_unshared_network", details.get("network") == "unshared" or _wrapped_command_has(wrapped_command, "--unshare-net"), "bwrap must unshare network namespace"),
        ("bwrap_private_tmp", details.get("tmp") == "private_tmpfs" or _wrapped_command_has_sequence(wrapped_command, "--tmpfs", "/tmp"), "bwrap must provide a private /tmp"),
        ("filesystem_isolation", capabilities.get("filesystem_isolation") is True, "bwrap must provide filesystem isolation"),
        ("network_isolation", capabilities.get("network_isolation") is True, "bwrap must provide network isolation"),
        ("process_containment", capabilities.get("process_containment") is True, "bwrap must provide process containment"),
        ("resource_limits", capabilities.get("resource_limits") is True, "worker resource limits must be available"),
        ("runtime_import", preflight.get("import_runtime") == "pass", "trusted runtime must import under bwrap"),
        ("private_tmp_writable", preflight.get("tmp_writable") == "pass", "sandbox private /tmp should be writable"),
        ("data_write_allowed", preflight.get("data_dir_writable") == "pass", "plugin data directory should be writable"),
        ("code_readonly", preflight.get("code_dir_readonly") == "pass", "plugin code directory must be read-only"),
        ("host_home_blocked", preflight.get("host_home_blocked") == "pass", "host HOME must not be readable"),
        ("env_blocked", preflight.get("env_blocked") == "pass", ".env must not be readable"),
        ("core_blocked", preflight.get("core_blocked") == "pass", "project core must not be readable"),
    ]
    return [
        {"check_id": check_id, "status": "pass" if passed else "fail", "reason": reason}
        for check_id, passed, reason in checks
    ]


def _wrapped_command_has(command: Any, token: str) -> bool:
    return isinstance(command, list) and token in command


def _wrapped_command_has_sequence(command: Any, first: str, second: str) -> bool:
    if not isinstance(command, list):
        return False
    return any(left == first and right == second for left, right in zip(command, command[1:]))


def _default_result_diagnostics(result: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(result or {})
    payload.setdefault("status", "error")
    payload.setdefault("error", None)
    payload.setdefault("error_type", None)
    payload.setdefault("returncode", None)
    payload.setdefault("stdout_excerpt", None)
    payload.setdefault("stderr_excerpt", None)
    payload.setdefault("stderr_path", None)
    payload.setdefault("stdout_path", None)
    payload.setdefault("wrapped_command", None)
    payload.setdefault("argv", None)
    payload.setdefault("cwd", None)
    payload.setdefault("executable", sys.executable)
    payload.setdefault("python_version", sys.version)
    payload.setdefault("env_keys", None)
    payload.setdefault("import_probe", None)
    payload.setdefault("runtime_probe", None)
    payload.setdefault("worker_started", False)
    payload.setdefault("json_result_received", False)
    return payload


def _merge_result_diagnostics(result: dict[str, Any], diagnostics_source: dict[str, Any]) -> dict[str, Any]:
    diagnostics = diagnostics_source.get("stdio_diagnostics", diagnostics_source)
    merged = _default_result_diagnostics(result)
    if isinstance(diagnostics, dict):
        for key in [
            "returncode",
            "stdout_excerpt",
            "stderr_excerpt",
            "stderr_path",
            "stdout_path",
            "wrapped_command",
            "argv",
            "cwd",
            "executable",
            "python_version",
            "env_keys",
            "import_probe",
            "runtime_probe",
            "worker_started",
            "json_result_received",
        ]:
            if diagnostics.get(key) is not None:
                merged[key] = diagnostics.get(key)
        if not merged.get("error_type") and diagnostics.get("error_type"):
            merged["error_type"] = diagnostics.get("error_type")
        if not merged.get("error") and diagnostics.get("error"):
            merged["error"] = diagnostics.get("error")
    if result.get("status") == "success":
        merged["worker_started"] = True
        merged["json_result_received"] = True
    return merged


def _diagnostic_error_type(fallback: str, diagnostics: Any) -> str:
    if isinstance(diagnostics, dict) and diagnostics.get("error_type"):
        return str(diagnostics["error_type"])
    return fallback


def _excerpt(text: str | None, limit: int = 4096) -> str:
    value = text or ""
    return value[-limit:]


def _trim_debug_paths(report: dict[str, Any]) -> None:
    result = report.get("result")
    if not isinstance(result, dict):
        return
    for key in ["stdout_excerpt", "stderr_excerpt"]:
        value = result.get(key)
        if isinstance(value, str) and len(value) > 1000:
            result[key] = value[-1000:]


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
    runtime_observation_missing = result.get("status") != "success"
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
        _check_result(check_id, passed, reason, runtime_observation_missing)
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


def _check_result(
    check_id: str,
    passed: bool,
    reason: str,
    runtime_observation_missing: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"check_id": check_id, "status": "pass" if passed else "fail", "reason": reason}
    if runtime_observation_missing and check_id in {
        "host_home_blocked",
        "env_blocked",
        "core_blocked",
        "code_readonly",
        "private_tmp_writable",
        "direct_network_blocked",
        "data_write_allowed",
    }:
        payload["runtime_observation"] = "missing"
        payload["reason"] = f"{reason}; runtime sample did not return data"
    return payload


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
    parser.add_argument("--debug", action="store_true", help="include full diagnostic excerpts and command fields")
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="keep the temporary validation workdir after failure for inspection",
    )
    parser.add_argument("--output", help="write JSON evidence directly to this path")
    args = parser.parse_args(argv)
    report = run_validation(args.workdir, mode=args.mode, debug=args.debug, keep_workdir=args.keep_workdir)
    rendered_json = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered_json + "\n", encoding="utf-8")
    if args.json_output:
        print(rendered_json)
    else:
        print(
            "bwrap validation "
            f"mode={report.get('mode')} environment={report.get('environment_class')} "
            f"status={report['status']} reason={report.get('reason', '')}"
        )
        if args.output:
            print(f"evidence: {args.output}")
        for item in report.get("checks", []):
            print(f"- [{item['status']}] {item['check_id']}: {item['reason']}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
