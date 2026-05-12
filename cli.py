from __future__ import annotations

import argparse
import os
import sys
import zipfile
from pathlib import Path
from typing import Any

import yaml

from modules.plugin_system.audit import (
    LocalCheckpointAnchor,
    create_audit_checkpoint,
    verify_audit_log,
)
from modules.plugin_system.dependency import lock_requirements
from modules.plugin_system.doctor import doctor_report, render_text, run_doctor
from modules.plugin_system.engine import PluginEngine
from modules.plugin_system.loader import PluginLoader, PluginPackageError, write_package_lock
from modules.plugin_system.marketplace import PluginRegistryClient
from modules.plugin_system.models import PluginMetadata, normalize_archive_path
from modules.plugin_system.policy import PolicyEngine
from modules.plugin_system.scanner import (
    OfflineLicenseScanner,
    OfflineVulnerabilityScanner,
    ScanPolicy,
    scan_lockfile,
    scan_package_file,
    scan_sbom_file,
)
from modules.plugin_system.sbom import write_sbom
from modules.plugin_system.signing import (
    TrustStore,
    generate_keypair,
    sign_package as create_signature,
    verify_signature as verify_package_signature,
)


def read_metadata(source_dir: Path) -> PluginMetadata:
    metadata_path = source_dir / "plugin.yaml"
    if not metadata_path.exists():
        raise PluginPackageError("missing plugin.yaml")
    raw = yaml.safe_load(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise PluginPackageError("plugin.yaml must contain a mapping")
    return PluginMetadata(**raw)


def build_plugin(source: str, output: str = ".") -> Path:
    source_dir = Path(source).resolve()
    if not source_dir.is_dir():
        raise PluginPackageError(f"source directory does not exist: {source_dir}")
    metadata = read_metadata(source_dir)
    if not (source_dir / "src").is_dir():
        raise PluginPackageError("plugin source must contain src/")
    write_package_lock(source_dir)

    output_dir = Path(output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    package_path = output_dir / f"{metadata.name}_v{metadata.version}.zip"

    with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [item for item in dirs if item not in {"__pycache__", ".git", ".venv", "venv"}]
            for filename in files:
                if should_skip_file(filename):
                    continue
                file_path = Path(root) / filename
                archive_name = normalize_archive_path(str(file_path.relative_to(source_dir)).replace("\\", "/"))
                archive.write(file_path, archive_name)
    print(f"Built {package_path}")
    return package_path


def lock_plugin_dependencies(
    source: str,
    wheelhouse: str,
    output: str | None = None,
    vendor: bool = False,
) -> Path:
    source_dir = Path(source).resolve()
    if not source_dir.is_dir():
        raise PluginPackageError(f"source directory does not exist: {source_dir}")
    metadata = read_metadata(source_dir)
    lockfile = lock_requirements(source_dir, metadata, wheelhouse, output=output, vendor=vendor)
    print(f"Locked {lockfile}")
    if vendor:
        print(f"Vendored wheels into {source_dir / 'wheels'}")
    return lockfile


def sbom_plugin(source: str, output: str | None = None) -> Path:
    source_dir = Path(source).resolve()
    if not source_dir.is_dir():
        raise PluginPackageError(f"plugin directory does not exist: {source_dir}")
    output_path = write_sbom(source_dir, output)
    print(f"SBOM {output_path}")
    return output_path


def create_keypair(private_key: str, public_key: str, overwrite: bool = False) -> tuple[Path, Path]:
    private_path, public_path = generate_keypair(private_key, public_key, overwrite=overwrite)
    print(f"Private key {private_path}")
    print(f"Public key {public_path}")
    return private_path, public_path


def sign_package(
    package: str,
    private_key: str | None = None,
    hmac_key: str | None = None,
    publisher: str | None = None,
    key_id: str | None = None,
) -> Path:
    package_path = Path(package).resolve()
    signature_path = create_signature(
        package_path,
        key=hmac_key,
        private_key=private_key,
        publisher=publisher,
        key_id=key_id,
    )
    print(f"Signed {package_path}")
    print(f"Signature {signature_path}")
    return signature_path


def verify_signature(
    package: str,
    signature: str | None = None,
    public_key: str | None = None,
    hmac_key: str | None = None,
    trust_store: str | None = None,
) -> bool:
    verify_package_signature(package, signature, key=hmac_key, public_key=public_key, trust_store=trust_store)
    return True


def install_plugin(
    package: str,
    plugins_dir: str = "data/plugins",
    require_signature: bool = False,
    signature: str | None = None,
    public_key: str | None = None,
    hmac_key: str | None = None,
    trust_store: str | None = None,
    install_dependencies: bool = False,
    production: bool = False,
    scan_report: str | None = None,
) -> None:
    package_path = Path(package).resolve()
    signature_payload = None
    if require_signature or production:
        signature_payload = verify_package_signature(
            str(package_path),
            signature,
            key=hmac_key,
            public_key=public_key,
            trust_store=trust_store,
        )
    loader = PluginLoader(plugins_dir, require_signatures=require_signature, production_mode=production)
    metadata = loader.install(
        package_path,
        signature=signature_payload,
        install_dependencies=install_dependencies,
        scan_report=read_scan_report(scan_report) if scan_report else None,
    )
    installed = loader.get_installed(metadata.name)
    status = installed.status.value if installed else "unknown"
    print(f"Installed {metadata.name} v{metadata.version} into {Path(plugins_dir).resolve()} status={status}")


def list_plugins(plugins_dir: str = "data/plugins") -> None:
    loader = PluginLoader(plugins_dir)
    plugins = loader.get_all_plugins()
    if not plugins:
        print("No plugins installed.")
        return
    for name, metadata in sorted(plugins.items()):
        installed = loader.get_installed(name)
        status = installed.status.value if installed else "unknown"
        granted = installed.granted_permission_names if installed else set()
        print(
            f"{name} v{metadata.version} "
            f"trust={metadata.runtime.trust.value} mode={metadata.effective_run_mode.value} "
            f"status={status} "
            f"requested={','.join(sorted(metadata.requested_permissions))} "
            f"granted={','.join(sorted(granted))}"
        )


def registry_list(
    index: str,
    index_signature: str | None = None,
    index_public_key: str | None = None,
    index_trust_store: str | None = None,
    require_index_signature: bool = False,
    production: bool = False,
) -> None:
    entries = PluginRegistryClient(index, index_signature=index_signature).list_plugins(
        public_key=index_public_key,
        trust_store=index_trust_store,
        require_signature=require_index_signature or production,
    )
    if not entries:
        print("No plugins in registry.")
        return
    for entry in sorted(entries, key=lambda item: (item.name, item.version)):
        publisher = entry.publisher or "unknown"
        signed = str(bool(entry.signature)).lower()
        print(
            f"{entry.name} v{entry.version} "
            f"publisher={publisher} signed={signed} sha256={entry.sha256} "
            f"description={entry.description}"
        )


def registry_install(
    index: str,
    name: str,
    plugins_dir: str = "data/plugins",
    version: str | None = None,
    public_key: str | None = None,
    trust_store: str | None = None,
    index_signature: str | None = None,
    index_public_key: str | None = None,
    index_trust_store: str | None = None,
    require_index_signature: bool = False,
    no_require_signature: bool = False,
    allow_downgrade: bool = False,
    allow_same_version_reinstall: bool = False,
    install_dependencies: bool = False,
    production: bool = False,
    scan_report: str | None = None,
) -> None:
    result = PluginRegistryClient(index, index_signature=index_signature).install(
        name,
        plugins_dir=plugins_dir,
        version=version,
        public_key=public_key,
        trust_store=trust_store,
        require_signature=not no_require_signature,
        index_public_key=index_public_key,
        index_trust_store=index_trust_store,
        require_index_signature=require_index_signature,
        allow_downgrade=allow_downgrade,
        allow_same_version_reinstall=allow_same_version_reinstall,
        install_dependencies=install_dependencies,
        production_mode=production,
        scan_report=read_scan_report(scan_report) if scan_report else None,
    )
    installed = PluginLoader(plugins_dir).get_installed(result.metadata.name)
    status = installed.status.value if installed else "unknown"
    publisher = result.entry.publisher or "unknown"
    print(
        f"Installed {result.metadata.name} v{result.metadata.version} "
        f"from registry publisher={publisher} status={status}"
    )


def trust_add_key(trust_store: str, publisher: str, public_key: str) -> str:
    key_id = TrustStore(trust_store).add_key(publisher, public_key)
    print(f"Trusted {publisher} key_id={key_id}")
    return key_id


def trust_revoke_key(trust_store: str, publisher: str, key_id: str) -> None:
    TrustStore(trust_store).revoke_key(publisher, key_id)
    print(f"Revoked {publisher} key_id={key_id}")


def trust_list_keys(trust_store: str) -> None:
    entries = TrustStore(trust_store).entries()
    if not entries:
        print("No trusted publishers.")
        return
    for publisher, publisher_entry in sorted(entries.items()):
        keys = publisher_entry.get("keys", {}) if isinstance(publisher_entry, dict) else {}
        for key_id, key_entry in sorted(keys.items()):
            status = key_entry.get("status", "unknown") if isinstance(key_entry, dict) else "invalid"
            print(f"{publisher} key_id={key_id} status={status}")


def review_plugin(plugins_dir: str, name: str) -> None:
    loader = PluginLoader(plugins_dir)
    installed = loader.get_installed(name)
    if not installed:
        raise PluginPackageError(f"plugin is not installed: {name}")
    review = installed.permission_review or {}
    print(f"{name} v{installed.metadata.version}")
    print(f"status={installed.status.value}")
    print(f"review_required={str(bool(review.get('required'))).lower()}")
    if review.get("reason"):
        print(f"reason={review['reason']}")
    print(f"requested={','.join(sorted(installed.metadata.requested_permissions))}")
    print(f"granted={','.join(sorted(installed.granted_permission_names))}")
    print(f"added={','.join(review.get('added_permissions') or [])}")
    print(f"changed={','.join(review.get('changed_permissions') or [])}")
    print(f"removed={','.join(review.get('removed_permissions') or [])}")
    print(f"denied={','.join(review.get('denied_permissions') or [])}")
    if review.get("reviewer"):
        print(f"reviewer={review['reviewer']}")
    if review.get("review_reason"):
        print(f"review_reason={review['review_reason']}")
    for item in review.get("requested_permission_risks") or []:
        print(
            f"risk {item['name']} level={item['level']} severity={item['risk']} "
            f"description={item['description']}"
        )
    if review.get("reviewed_at"):
        print(f"reviewed_at={review['reviewed_at']}")
    for item in review.get("history") or []:
        print(
            f"history reviewed_at={item.get('reviewed_at', '')} "
            f"reviewer={item.get('reviewer', '')} "
            f"granted={','.join(item.get('granted_permissions') or [])} "
            f"denied={','.join(item.get('denied_permissions') or [])} "
            f"reason={item.get('reason', '')}"
        )


def grant_plugin(
    plugins_dir: str,
    name: str,
    permissions: list[str] | None = None,
    reviewer: str | None = None,
    reason: str | None = None,
) -> None:
    loader = PluginLoader(plugins_dir)
    selected_permissions = parse_permission_args(permissions)
    installed = (
        loader.grant_permission_names(name, selected_permissions, reviewer=reviewer, review_reason=reason)
        if selected_permissions
        else loader.grant_permissions(name, reviewer=reviewer, review_reason=reason)
    )
    print(f"Granted {name}: {','.join(sorted(installed.granted_permission_names))}")


def approve_plugin(
    plugins_dir: str,
    name: str,
    permissions: list[str] | None = None,
    reviewer: str | None = None,
    reason: str | None = None,
) -> None:
    loader = PluginLoader(plugins_dir)
    selected_permissions = parse_permission_args(permissions)
    installed = (
        loader.grant_permission_names(name, selected_permissions, reviewer=reviewer, review_reason=reason)
        if selected_permissions
        else loader.grant_permissions(name, reviewer=reviewer, review_reason=reason)
    )
    print(f"Approved {name}: status={installed.status.value}")
    print(f"Granted permissions: {','.join(sorted(installed.granted_permission_names))}")


def parse_permission_args(values: list[str] | None) -> list[str]:
    if not values:
        return []
    permissions: list[str] = []
    for value in values:
        permissions.extend(item.strip() for item in value.split(",") if item.strip())
    return list(dict.fromkeys(permissions))


def read_scan_report(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    import json

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise PluginPackageError("scan report must be a JSON object")
    return payload


def set_plugin_enabled(plugins_dir: str, name: str, enabled: bool, production: bool = False) -> None:
    engine = PluginEngine(plugins_dir, production_mode=production)
    installed = engine.enable_plugin(name) if enabled else engine.disable_plugin(name)
    print(f"{name} status={installed.status.value}")


def quarantine_plugin(plugins_dir: str, name: str, production: bool = False) -> None:
    engine = PluginEngine(plugins_dir, production_mode=production)
    installed = engine.quarantine_plugin(name)
    print(f"{name} status={installed.status.value}")


def revoke_plugin(plugins_dir: str, name: str, production: bool = False) -> None:
    engine = PluginEngine(plugins_dir, production_mode=production)
    installed = engine.revoke_plugin(name)
    print(f"{name} status={installed.status.value}")


def revoke_plugin_version(plugins_dir: str, name: str, version: str, production: bool = False) -> None:
    engine = PluginEngine(plugins_dir, production_mode=production)
    engine.revoke_plugin_version(name, version)
    print(f"{name} v{version} status=revoked")


def audit_verify(log_path: str, checkpoint: str | None = None, public_key: str | None = None) -> None:
    anchor = LocalCheckpointAnchor(checkpoint, public_key=public_key) if checkpoint else None
    report = verify_audit_log(log_path, anchor=anchor, public_key=public_key)
    print(f"Audit log verified records={report['records']} last_hash={report['last_hash']}")


def audit_checkpoint(log_path: str, checkpoint: str, private_key: str | None = None, signer: str | None = None) -> None:
    anchor = LocalCheckpointAnchor(checkpoint, private_key=private_key, signer=signer)
    payload = create_audit_checkpoint(log_path)
    anchor.write_checkpoint(payload)
    latest = anchor.read_latest_checkpoint()
    print(f"Audit checkpoint sequence={latest.latest_sequence if latest else 0} hash={latest.latest_hash if latest else ''}")


def audit_status(log_path: str, checkpoint: str | None = None, public_key: str | None = None) -> None:
    anchor = LocalCheckpointAnchor(checkpoint, public_key=public_key) if checkpoint else None
    report = verify_audit_log(log_path, anchor=anchor, public_key=public_key)
    print(yaml.safe_dump(report, sort_keys=True, allow_unicode=True).strip())


def run_doctor_cli(
    plugins_dir: str,
    production: bool,
    json_output: bool,
    audit_log: str | None = None,
    scanner_configured: bool = False,
    audit_anchor_configured: bool = False,
) -> None:
    report = doctor_report(
        run_doctor(
            plugins_dir=plugins_dir,
            production_mode=production,
            audit_log=audit_log,
            scanner_configured=scanner_configured,
            audit_anchor_configured=audit_anchor_configured,
        )
    )
    if json_output:
        import json

        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))


def scan_cli(
    kind: str,
    target: str,
    fixture: str | None = None,
    json_output: bool = False,
    scanner_type: str = "vulnerability",
) -> None:
    scanner = (
        OfflineLicenseScanner(fixture, policy=ScanPolicy())
        if scanner_type == "license"
        else OfflineVulnerabilityScanner(fixture, policy=ScanPolicy())
    )
    if kind == "sbom":
        report = scan_sbom_file(target, scanner)
    elif kind == "package":
        report = scan_package_file(target, scanner)
    elif kind == "lock":
        report = scan_lockfile(target, scanner)
    else:
        raise PluginPackageError(f"unknown scan kind: {kind}")
    if json_output:
        import json

        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(yaml.safe_dump(report.to_dict(), sort_keys=True, allow_unicode=True).strip())


def policy_check_cli(
    source: str,
    policy_file: str | None,
    production: bool,
    json_output: bool,
    signature: str | None = None,
    public_key: str | None = None,
    hmac_key: str | None = None,
    trust_store: str | None = None,
    scan_report: str | None = None,
) -> None:
    engine = PolicyEngine.from_file(policy_file) if policy_file else PolicyEngine()
    signature_payload = (
        verify_package_signature(source, signature, key=hmac_key, public_key=public_key, trust_store=trust_store)
        if signature or public_key or hmac_key or trust_store
        else None
    )
    report = engine.check_source(
        source,
        production_mode=production,
        signature=signature_payload,
        scan_report=read_scan_report(scan_report) if scan_report else None,
    )
    if json_output:
        import json

        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(yaml.safe_dump(report, sort_keys=True, allow_unicode=True).strip())


def start_plugin(
    plugins_dir: str,
    name: str,
    sandbox_backend: str = "auto",
    strict_sandbox: bool = False,
    production: bool = False,
) -> None:
    engine = PluginEngine(
        plugins_dir,
        sandbox_backend=sandbox_backend,
        require_enforced_sandbox=strict_sandbox,
        production_mode=production,
    )
    try:
        sandbox = engine.start_plugin(name)
        report = sandbox.report()
        backend = report.os_limits.get("sandbox_backend", {})
        print(
            f"Started {name} "
            f"mode={report.run_mode.value} "
            f"backend={backend.get('name', 'none')} "
            f"enforced={str(bool(backend.get('enforced'))).lower()} "
            f"strict={str(strict_sandbox or production).lower()} "
            f"production={str(production).lower()}"
        )
        missing = backend.get("missing_capabilities") or []
        if missing:
            print(f"missing_capabilities={','.join(missing)}")
    finally:
        engine.stop_all()


def call_plugin_tool(
    plugins_dir: str,
    plugin_name: str,
    tool_name: str,
    args_json: str = "{}",
    sandbox_backend: str = "auto",
    strict_sandbox: bool = False,
    production: bool = False,
) -> None:
    args = parse_json_object(args_json, "tool args")
    engine = PluginEngine(
        plugins_dir,
        sandbox_backend=sandbox_backend,
        require_enforced_sandbox=strict_sandbox,
        production_mode=production,
    )
    try:
        result = engine.call_tool(plugin_name, tool_name, args)
        print(yaml.safe_dump(result, sort_keys=True, allow_unicode=True).strip())
    finally:
        engine.stop_all()


def parse_json_object(value: str, label: str) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(value)
    except yaml.YAMLError as exc:
        raise PluginPackageError(f"invalid {label}: {exc}") from exc
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise PluginPackageError(f"{label} must be an object")
    return payload


def should_skip_file(filename: str) -> bool:
    return filename.endswith((".pyc", ".pyo", ".swp", ".tmp", ".sig")) or filename in {
        ".DS_Store",
        "Thumbs.db",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="plugin-cli", description="Humanoid AGI plugin command line tool")
    parser.add_argument("--plugins-dir", default="data/plugins", help="plugin installation directory")
    parser.add_argument("--sandbox-backend", default="auto", help="sandbox backend for start/call commands")
    parser.add_argument(
        "--strict-sandbox",
        action="store_true",
        help="require production isolation capabilities for third-party subprocess plugins",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="enable production policy: Ed25519 signatures and enforced third-party sandboxing",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="validate and package a plugin directory")
    build.add_argument("source", help="plugin source directory")
    build.add_argument("-o", "--output", default=".", help="output directory")

    lock = subparsers.add_parser("lock", help="generate requirements.lock from a local wheelhouse")
    lock.add_argument("source", help="plugin source directory")
    lock.add_argument("--wheelhouse", required=True, help="directory containing prebuilt .whl artifacts")
    lock.add_argument(
        "-o",
        "--output",
        help="lockfile path; relative paths are resolved inside the plugin source directory",
    )
    lock.add_argument(
        "--vendor",
        action="store_true",
        help="copy locked wheel artifacts into the plugin source wheels/ directory",
    )

    sbom = subparsers.add_parser("sbom", help="generate a CycloneDX JSON SBOM for a plugin directory")
    sbom.add_argument("source", help="plugin source or installed plugin directory")
    sbom.add_argument("-o", "--output", help="output path; defaults to sbom.cdx.json in the plugin directory")

    keygen = subparsers.add_parser("keygen", help="generate an Ed25519 signing keypair")
    keygen.add_argument("--private-key", required=True, help="output private key PEM path")
    keygen.add_argument("--public-key", required=True, help="output public key PEM path")
    keygen.add_argument("--overwrite", action="store_true", help="overwrite existing key files")

    sign = subparsers.add_parser("sign", help="create a detached signature")
    sign.add_argument("package", help="plugin zip package")
    sign.add_argument("--private-key", help="Ed25519 private key PEM path")
    sign.add_argument("--hmac-key", help="legacy HMAC signing key; defaults to PLUGIN_SIGNING_KEY")
    sign.add_argument("--publisher", help="publisher identity to record in the signature payload")
    sign.add_argument("--key-id", help="explicit key id; defaults to the Ed25519 public key fingerprint")

    verify = subparsers.add_parser("verify", help="verify a detached signature")
    verify.add_argument("package", help="plugin zip package")
    verify.add_argument("--signature", help="signature file path")
    verify.add_argument("--public-key", help="Ed25519 public key PEM path")
    verify.add_argument("--hmac-key", help="legacy HMAC verification key")
    verify.add_argument("--trust-store", help="trusted publisher key store JSON path")

    install = subparsers.add_parser("install", help="install a plugin package")
    install.add_argument("package", help="plugin zip package")
    install.add_argument("--require-signature", action="store_true", help="require a valid .sig file")
    install.add_argument("--signature", help="signature file path")
    install.add_argument("--public-key", help="Ed25519 public key PEM path")
    install.add_argument("--hmac-key", help="legacy HMAC verification key")
    install.add_argument("--trust-store", help="trusted publisher key store JSON path")
    install.add_argument(
        "--install-dependencies",
        action="store_true",
        help="create a plugin venv and install declared packages",
    )
    install.add_argument("--scan-report", help="scanner JSON report required by production policy")

    grant = subparsers.add_parser("grant", help="grant a plugin its requested permissions and enable it")
    grant.add_argument("name", help="installed plugin name")
    grant.add_argument(
        "--permission",
        action="append",
        dest="permissions",
        help="permission name to grant; repeat to grant multiple permissions",
    )
    grant.add_argument("--reviewer", help="person or automation identity approving permissions")
    grant.add_argument("--reason", help="short approval reason")

    trust = subparsers.add_parser("trust", help="manage trusted plugin publisher keys")
    trust.add_argument("--store", required=True, help="trust store JSON path")
    trust_subparsers = trust.add_subparsers(dest="trust_command", required=True)
    trust_add = trust_subparsers.add_parser("add-key", help="trust a publisher public key")
    trust_add.add_argument("publisher", help="publisher identity")
    trust_add.add_argument("public_key", help="Ed25519 public key PEM path")
    trust_revoke = trust_subparsers.add_parser("revoke-key", help="revoke a trusted publisher key")
    trust_revoke.add_argument("publisher", help="publisher identity")
    trust_revoke.add_argument("key_id", help="trusted key id")
    trust_subparsers.add_parser("list", help="list trusted publisher keys")

    registry = subparsers.add_parser("registry", help="install plugins from a signed registry index")
    registry_subparsers = registry.add_subparsers(dest="registry_command", required=True)
    registry_list_parser = registry_subparsers.add_parser("list", help="list plugins in a registry index")
    registry_list_parser.add_argument("--index", required=True, help="registry index JSON path or URL")
    registry_list_parser.add_argument("--index-signature", help="detached signature for the registry index")
    registry_list_parser.add_argument("--index-public-key", help="Ed25519 public key PEM path for registry index")
    registry_list_parser.add_argument("--index-trust-store", help="trusted publisher key store JSON path for registry index")
    registry_list_parser.add_argument(
        "--require-index-signature",
        action="store_true",
        help="require a valid detached signature for the registry index",
    )
    registry_install_parser = registry_subparsers.add_parser("install", help="install a plugin from a registry index")
    registry_install_parser.add_argument("name", help="registry plugin name")
    registry_install_parser.add_argument("--index", required=True, help="registry index JSON path or URL")
    registry_install_parser.add_argument("--version", help="specific plugin version; defaults to latest")
    registry_install_parser.add_argument("--public-key", help="Ed25519 public key PEM path")
    registry_install_parser.add_argument("--trust-store", help="trusted publisher key store JSON path")
    registry_install_parser.add_argument("--index-signature", help="detached signature for the registry index")
    registry_install_parser.add_argument("--index-public-key", help="Ed25519 public key PEM path for registry index")
    registry_install_parser.add_argument("--index-trust-store", help="trusted publisher key store JSON path for registry index")
    registry_install_parser.add_argument(
        "--require-index-signature",
        action="store_true",
        help="require a valid detached signature for the registry index",
    )
    registry_install_parser.add_argument(
        "--no-require-signature",
        action="store_true",
        help="allow unsigned registry entries outside production mode",
    )
    registry_install_parser.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="allow installing an older plugin version from the registry",
    )
    registry_install_parser.add_argument(
        "--allow-same-version-reinstall",
        action="store_true",
        help="allow replacing the same plugin version with different package content",
    )
    registry_install_parser.add_argument(
        "--install-dependencies",
        action="store_true",
        help="create a plugin venv and install declared packages",
    )
    registry_install_parser.add_argument("--scan-report", help="scanner JSON report required by production policy")

    review = subparsers.add_parser("review", help="show permission review details for an installed plugin")
    review.add_argument("name", help="installed plugin name")

    approve = subparsers.add_parser("approve", help="approve requested permissions and enable a plugin")
    approve.add_argument("name", help="installed plugin name")
    approve.add_argument(
        "--permission",
        action="append",
        dest="permissions",
        help="permission name to approve; repeat to approve multiple permissions",
    )
    approve.add_argument("--reviewer", help="person or automation identity approving permissions")
    approve.add_argument("--reason", help="short approval reason")

    enable = subparsers.add_parser("enable", help="enable an installed plugin after permissions are granted")
    enable.add_argument("name", help="installed plugin name")

    disable = subparsers.add_parser("disable", help="disable an installed plugin")
    disable.add_argument("name", help="installed plugin name")

    quarantine = subparsers.add_parser("quarantine", help="quarantine an installed plugin")
    quarantine.add_argument("name", help="installed plugin name")

    revoke = subparsers.add_parser("revoke", help="revoke a plugin and clear granted permissions")
    revoke.add_argument("name", help="installed plugin name")

    revoke_version = subparsers.add_parser("revoke-version", help="revoke a plugin version")
    revoke_version.add_argument("name", help="plugin name")
    revoke_version.add_argument("version", help="plugin version")

    audit = subparsers.add_parser("audit", help="verify and checkpoint audit logs")
    audit_subparsers = audit.add_subparsers(dest="audit_command", required=True)
    audit_verify_parser = audit_subparsers.add_parser("verify", help="verify audit JSONL hash chain")
    audit_verify_parser.add_argument("--log", required=True, help="audit JSONL path")
    audit_verify_parser.add_argument("--checkpoint", help="local checkpoint file")
    audit_verify_parser.add_argument("--public-key", help="Ed25519 public key for signed checkpoint")
    audit_checkpoint_parser = audit_subparsers.add_parser("checkpoint", help="write a local audit checkpoint")
    audit_checkpoint_parser.add_argument("--log", required=True, help="audit JSONL path")
    audit_checkpoint_parser.add_argument("--checkpoint", required=True, help="local checkpoint output")
    audit_checkpoint_parser.add_argument("--private-key", help="Ed25519 private key for checkpoint signature")
    audit_checkpoint_parser.add_argument("--signer", help="checkpoint signer identity")
    audit_status_parser = audit_subparsers.add_parser("status", help="verify audit log and print status")
    audit_status_parser.add_argument("--log", required=True, help="audit JSONL path")
    audit_status_parser.add_argument("--checkpoint", help="local checkpoint file")
    audit_status_parser.add_argument("--public-key", help="Ed25519 public key for signed checkpoint")

    doctor = subparsers.add_parser("doctor", help="run production environment checks")
    doctor.add_argument("--json", action="store_true", dest="json_output", help="emit JSON")
    doctor.add_argument("--audit-log", help="audit log path")
    doctor.add_argument("--scanner-configured", action="store_true")
    doctor.add_argument("--audit-anchor-configured", action="store_true")

    scan = subparsers.add_parser("scan", help="run offline scanner adapters")
    scan_subparsers = scan.add_subparsers(dest="scan_command", required=True)
    for scan_kind in ["sbom", "package", "lock"]:
        scan_parser = scan_subparsers.add_parser(scan_kind, help=f"scan {scan_kind}")
        scan_parser.add_argument("target")
        scan_parser.add_argument("--fixture", help="offline scanner fixture JSON")
        scan_parser.add_argument(
            "--scanner",
            choices=["vulnerability", "license"],
            default="vulnerability",
            help="offline scanner adapter to use",
        )
        scan_parser.add_argument("--json", action="store_true", dest="json_output")

    policy = subparsers.add_parser("policy", help="run organization policy checks")
    policy_subparsers = policy.add_subparsers(dest="policy_command", required=True)
    policy_check = policy_subparsers.add_parser("check", help="check a plugin package or directory")
    policy_check.add_argument("source")
    policy_check.add_argument("--policy-file")
    policy_check.add_argument("--signature", help="detached package signature path")
    policy_check.add_argument("--public-key", help="Ed25519 public key PEM path")
    policy_check.add_argument("--hmac-key", help="legacy HMAC verification key")
    policy_check.add_argument("--trust-store", help="trusted publisher key store JSON path")
    policy_check.add_argument("--scan-report", help="scanner JSON report")
    policy_check.add_argument("--json", action="store_true", dest="json_output")

    start = subparsers.add_parser("start", help="start a plugin once and report sandbox enforcement")
    start.add_argument("name", help="installed plugin name")

    call = subparsers.add_parser("call", help="call an installed plugin tool")
    call.add_argument("plugin", help="installed plugin name")
    call.add_argument("tool", help="tool name")
    call.add_argument("--args", default="{}", help="tool arguments as a YAML/JSON object")

    subparsers.add_parser("list", help="list installed plugins")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            build_plugin(args.source, args.output)
        elif args.command == "lock":
            lock_plugin_dependencies(args.source, args.wheelhouse, args.output, args.vendor)
        elif args.command == "sbom":
            sbom_plugin(args.source, args.output)
        elif args.command == "keygen":
            create_keypair(args.private_key, args.public_key, args.overwrite)
        elif args.command == "sign":
            sign_package(args.package, args.private_key, args.hmac_key, args.publisher, args.key_id)
        elif args.command == "verify":
            verify_signature(args.package, args.signature, args.public_key, args.hmac_key, args.trust_store)
            print("Signature verified")
        elif args.command == "install":
            install_plugin(
                args.package,
                args.plugins_dir,
                args.require_signature,
                args.signature,
                args.public_key,
                args.hmac_key,
                args.trust_store,
                args.install_dependencies,
                args.production,
                args.scan_report,
            )
        elif args.command == "trust":
            if args.trust_command == "add-key":
                trust_add_key(args.store, args.publisher, args.public_key)
            elif args.trust_command == "revoke-key":
                trust_revoke_key(args.store, args.publisher, args.key_id)
            elif args.trust_command == "list":
                trust_list_keys(args.store)
        elif args.command == "registry":
            if args.registry_command == "list":
                registry_list(
                    args.index,
                    args.index_signature,
                    args.index_public_key,
                    args.index_trust_store,
                    args.require_index_signature,
                    args.production,
                )
            elif args.registry_command == "install":
                registry_install(
                    args.index,
                    args.name,
                    args.plugins_dir,
                    args.version,
                    args.public_key,
                    args.trust_store,
                    args.index_signature,
                    args.index_public_key,
                    args.index_trust_store,
                    args.require_index_signature,
                    args.no_require_signature,
                    args.allow_downgrade,
                    args.allow_same_version_reinstall,
                    args.install_dependencies,
                    args.production,
                    args.scan_report,
                )
        elif args.command == "grant":
            grant_plugin(args.plugins_dir, args.name, args.permissions, args.reviewer, args.reason)
        elif args.command == "review":
            review_plugin(args.plugins_dir, args.name)
        elif args.command == "approve":
            approve_plugin(args.plugins_dir, args.name, args.permissions, args.reviewer, args.reason)
        elif args.command == "enable":
            set_plugin_enabled(args.plugins_dir, args.name, enabled=True, production=args.production)
        elif args.command == "disable":
            set_plugin_enabled(args.plugins_dir, args.name, enabled=False, production=args.production)
        elif args.command == "quarantine":
            quarantine_plugin(args.plugins_dir, args.name, production=args.production)
        elif args.command == "revoke":
            revoke_plugin(args.plugins_dir, args.name, production=args.production)
        elif args.command == "revoke-version":
            revoke_plugin_version(args.plugins_dir, args.name, args.version, production=args.production)
        elif args.command == "audit":
            if args.audit_command == "verify":
                audit_verify(args.log, args.checkpoint, args.public_key)
            elif args.audit_command == "checkpoint":
                audit_checkpoint(args.log, args.checkpoint, args.private_key, args.signer)
            elif args.audit_command == "status":
                audit_status(args.log, args.checkpoint, args.public_key)
        elif args.command == "doctor":
            run_doctor_cli(
                args.plugins_dir,
                args.production,
                args.json_output,
                args.audit_log,
                args.scanner_configured,
                args.audit_anchor_configured,
            )
        elif args.command == "scan":
            scan_cli(args.scan_command, args.target, args.fixture, args.json_output, args.scanner)
        elif args.command == "policy":
            if args.policy_command == "check":
                policy_check_cli(
                    args.source,
                    args.policy_file,
                    args.production,
                    args.json_output,
                    args.signature,
                    args.public_key,
                    args.hmac_key,
                    args.trust_store,
                    args.scan_report,
                )
        elif args.command == "start":
            start_plugin(args.plugins_dir, args.name, args.sandbox_backend, args.strict_sandbox, args.production)
        elif args.command == "call":
            call_plugin_tool(
                args.plugins_dir,
                args.plugin,
                args.tool,
                args.args,
                args.sandbox_backend,
                args.strict_sandbox,
                args.production,
            )
        elif args.command == "list":
            list_plugins(args.plugins_dir)
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
