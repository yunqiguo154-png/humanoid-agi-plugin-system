from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import textwrap
import uuid
import zipfile
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.plugin_system.audit import AuditLogger
from modules.plugin_system.engine import PluginEngine
from modules.plugin_system.loader import PACKAGE_LOCK_FILE, write_package_lock


def run_validation(workdir: str | Path | None = None) -> dict[str, Any]:
    if sys.platform != "linux":
        return {"status": "skipped", "reason": "bubblewrap validation requires Linux", "checks": []}
    if not shutil.which("bwrap"):
        return {"status": "skipped", "reason": "bubblewrap executable is not available", "checks": []}
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
        engine = PluginEngine(plugins_dir, sandbox_backend="bubblewrap", audit_logger=audit_logger)
        try:
            metadata = engine.install(package)
            engine.grant_permissions("bwrap_validation_plugin")
            sandbox = engine.start_plugin("bwrap_validation_plugin")
            backend_details = dict(sandbox.os_limits.get("sandbox_backend", {}).get("details", {}))
            result = engine.call_tool(
                "bwrap_validation_plugin",
                "run",
                {
                    "home_secret": str(home_secret),
                    "project_env": str(project_env),
                    "core_file": str((Path.cwd() / "SPECIFICATION").resolve()),
                    "code_file": str((plugins_dir / metadata.name / "src" / "blocked_write.txt").resolve()),
                    "host_tmp_file": str(host_tmp_file),
                    "wrapped_command": backend_details.get("wrapped_command"),
                    "network": backend_details.get("network"),
                    "tmp": backend_details.get("tmp"),
                },
            )
            os_limits = sandbox.os_limits
            sandbox_backend = sandbox.os_limits.get("sandbox_backend", {})
        except Exception as exc:
            result = {"status": "error", "error": str(exc), "error_type": type(exc).__name__}
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
        sock.settimeout(1)
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
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    report = run_validation(args.workdir)
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"bwrap validation status={report['status']} reason={report.get('reason', '')}")
        for item in report.get("checks", []):
            print(f"- [{item['status']}] {item['check_id']}: {item['reason']}")
    return 0 if report["status"] in {"pass", "skipped"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
