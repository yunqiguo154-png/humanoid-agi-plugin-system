from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

import yaml

from modules.plugin_system.loader import write_package_lock
from modules.plugin_system.scanner import OfflineVulnerabilityScanner
from modules.plugin_system.sbom import generate_sbom, write_sbom
from modules.plugin_system.signing import generate_keypair, sha256_file, sign_package, verify_signature

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
DATA_RUNS_DIR = PROJECT_ROOT / "data" / "drill_runs"
PUBLISHER = "rc-drill@example.com"
ATTESTATION = "process_containment,resource_limits,filesystem_isolation,network_isolation"


@contextmanager
def drill_workspace(name: str) -> Iterator[Path]:
    DATA_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=DATA_RUNS_DIR))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def ensure_evidence_dir() -> Path:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def now() -> str:
    return datetime.now(UTC).isoformat()


def write_json(path: str | Path, payload: dict[str, Any]) -> Path:
    target = Path(path)
    if not target.is_absolute():
        target = PROJECT_ROOT / target
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return target


def make_result(
    *,
    drill_id: str,
    status: str,
    checks: dict[str, Any],
    reason: str,
    recommendation: str,
    production_blocking: bool,
    artifacts: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "drill_id": drill_id,
        "status": status,
        "checks": checks,
        "reason": reason,
        "recommendation": recommendation,
        "production_blocking": production_blocking,
        "artifacts": artifacts or {},
        "generated_at": now(),
    }


def make_plugin_source(root: Path, name: str, *, version: str = "1.0.0", body: str | None = None) -> Path:
    source = root / name
    (source / "src").mkdir(parents=True)
    (source / "src" / "__init__.py").write_text("", encoding="utf-8")
    (source / "src" / "main.py").write_text(
        body
        or "\n".join(
            [
                "def run(args, api):",
                "    return {'ok': True, 'args': args}",
            ]
        ),
        encoding="utf-8",
    )
    metadata = {
        "name": name,
        "version": version,
        "description": "RC drill plugin",
        "author": "drill",
        "license": "MIT",
        "runtime": {
            "mode": "sub_process",
            "trust": "third_party",
            "memory_mb": 128,
            "timeout_seconds": 3,
            "cpu_seconds": 2,
        },
        "extensions": [{"type": "tool", "name": "run", "entry": "src.main:run"}],
        "permissions": [{"compute": True}],
        "requires": {"python": ">=3.11", "packages": []},
    }
    (source / "plugin.yaml").write_text(yaml.safe_dump(metadata, sort_keys=False), encoding="utf-8")
    write_sbom(source)
    write_package_lock(source)
    return source


def package_plugin(source: Path, output_dir: Path) -> Path:
    write_package_lock(source)
    output_dir.mkdir(parents=True, exist_ok=True)
    package = output_dir / f"{source.name}.zip"
    if package.exists():
        package.unlink()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in source.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    return package


def make_keys(root: Path, label: str = "drill") -> tuple[Path, Path]:
    private_key = root / f"{label}-private.pem"
    public_key = root / f"{label}-public.pem"
    return generate_keypair(private_key, public_key)


def sign_and_verify(package: Path, private_key: Path, public_key: Path) -> tuple[Path, dict[str, Any]]:
    signature = sign_package(package, private_key=private_key, publisher=PUBLISHER)
    payload = verify_signature(package, signature, public_key=public_key)
    return signature, payload


def scan_report_for(source: Path) -> dict[str, Any]:
    return OfflineVulnerabilityScanner().scan_sbom(generate_sbom(source)).to_dict()


def write_registry_index(
    root: Path,
    name: str,
    package: Path,
    signature: Path | None,
    *,
    version: str = "1.0.0",
    publisher: str = PUBLISHER,
    revoked_keys: list[str] | None = None,
    revoked_plugin_versions: list[dict[str, str]] | None = None,
) -> Path:
    registry_dir = root / "registry"
    registry_dir.mkdir(parents=True, exist_ok=True)
    package_target = registry_dir / package.name
    shutil.copyfile(package, package_target)
    signature_name = None
    if signature is not None:
        signature_target = registry_dir / signature.name
        shutil.copyfile(signature, signature_target)
        signature_name = signature_target.name
    entry: dict[str, Any] = {
        "name": name,
        "version": version,
        "description": "RC drill registry plugin",
        "package": package_target.name,
        "sha256": sha256_file(package_target),
        "publisher": publisher,
    }
    if signature_name:
        entry["signature"] = signature_name
    payload: dict[str, Any] = {"version": 1, "plugins": [entry]}
    if revoked_keys:
        payload["revoked_keys"] = revoked_keys
    if revoked_plugin_versions:
        payload["revoked_plugin_versions"] = revoked_plugin_versions
    index = registry_dir / f"{name}-index.json"
    index.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return index


def exception_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"
