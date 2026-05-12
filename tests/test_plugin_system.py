from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import queue
import shutil
import subprocess
import threading
import textwrap
import time
import unittest
import uuid
import zipfile
import sys
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

from modules.plugin_system.audit import AuditLogIntegrityError, AuditLogger, verify_audit_log
from modules.plugin_system.config import CONFIG_EFFECTIVE_FILE, PluginConfigError
from modules.plugin_system.dependency import (
    DEPENDENCY_LOCK_FILE,
    DEPENDENCY_MANIFEST,
    DEPENDENCY_WHEELHOUSE_DIR,
    DependencyScanPolicy,
    DependencyManager,
    lock_requirements,
)
from modules.plugin_system.event_bus import EventBus
from modules.plugin_system.engine import PluginEngine, PluginLifecycleError, PluginMiddlewareError
from modules.plugin_system.gateway import PermissionDenied, PluginGateway
from modules.plugin_system.loader import MANIFEST_FILE, PluginLoader, PluginPackageError
from modules.plugin_system.loader import (
    MAX_PLUGIN_FILE_BYTES,
    MAX_PLUGIN_FILES,
    PACKAGE_LOCK_FILE,
    write_package_lock,
)
from modules.plugin_system.marketplace import PluginRegistryClient, PluginRegistryError, load_registry_index
from modules.plugin_system.models import InstalledPlugin, PluginMetadata, PluginStatus, permission_risk
from modules.plugin_system.sandbox import SandboxManager, SandboxStartupError, SandboxViolation
from modules.plugin_system.sandbox_backend import (
    EXTERNAL_SANDBOX_ATTESTATION_ENV,
    BubblewrapBackend,
    create_sandbox_backend,
)
from modules.plugin_system.signing import (
    LEGACY_SIGNATURE_ALGORITHM,
    SIGNATURE_ALGORITHM,
    PluginSignatureError,
    TrustStore,
    generate_keypair,
    sha256_file,
    sign_package,
    verify_signature,
)
from modules.plugin_system.sbom import generate_sbom
from modules.plugin_system.scanner import OfflineVulnerabilityScanner


class _FakeNetworkResponse:
    def __init__(self, status: int = 200, headers: dict[str, str] | None = None, body: bytes = b""):
        self.status = status
        self.headers = headers or {"Content-Type": "text/plain"}
        self._body = body

    def __enter__(self) -> "_FakeNetworkResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self._body
        return self._body[:size]


def _redirect_error(url: str, location: str) -> HTTPError:
    return HTTPError(url, 302, "Found", {"Location": location}, None)


class _AllowingDependencyScanner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def scan(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return {"status": "passed", "scanner": "test"}


class _FailingDependencyScanner:
    def scan(self, **kwargs: object) -> dict[str, object]:
        return {"status": "failed", "reason": "known vulnerable package"}


class PluginSystemTests(unittest.TestCase):
    def setUp(self) -> None:
        workspace_tmp = Path.cwd() / "data" / "test_runs" / f"{self._testMethodName}_{uuid.uuid4().hex}"
        workspace_tmp.mkdir(parents=True, exist_ok=True)
        self.root = workspace_tmp
        self.plugins_dir = self.root / "plugins"
        self.packages_dir = self.root / "packages"
        self.packages_dir.mkdir()

    def tearDown(self) -> None:
        self._remove_tree(self.root)

    def test_metadata_rejects_third_party_in_process(self) -> None:
        with self.assertRaises(ValueError):
            PluginMetadata(
                name="bad_plugin",
                version="1.0.0",
                description="Bad runtime declaration",
                author="test",
                runtime={"mode": "in_process", "trust": "third_party"},
                extensions=[{"type": "tool", "name": "run", "entry": "src.main:run"}],
            )

    def test_production_loader_rejects_third_party_directory_load(self) -> None:
        source = self._make_plugin(
            "production_directory_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        loader = PluginLoader(self.plugins_dir, production_mode=True)

        with self.assertRaisesRegex(PluginPackageError, "signed package install"):
            loader.load_from_directory(source)

    def test_permission_risk_metadata_maps_levels_and_descriptions(self) -> None:
        compute = permission_risk("compute", True)
        fs_write = permission_risk("fs.write", True)
        output_send = permission_risk("output.send", True)

        self.assertEqual(compute["level"], "L0")
        self.assertEqual(compute["risk"], "low")
        self.assertEqual(fs_write["level"], "L3")
        self.assertEqual(fs_write["risk"], "high")
        self.assertEqual(output_send["level"], "L4")
        self.assertEqual(output_send["risk"], "critical")
        self.assertIn("Write files", fs_write["description"])

    def test_loader_rejects_zip_slip(self) -> None:
        package = self.packages_dir / "evil.zip"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("../escape.txt", "owned")
            archive.writestr("plugin.yaml", self._metadata_yaml("evil_plugin"))
            archive.writestr("src/__init__.py", "")
            archive.writestr("src/main.py", "def run(args, api=None): return args\n")

        loader = PluginLoader(self.plugins_dir)
        with self.assertRaises(PluginPackageError):
            loader.install(package)

    def test_loader_rejects_archive_bomb_by_total_unpacked_size(self) -> None:
        package = self.packages_dir / "bomb.zip"
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("plugin.yaml", self._metadata_yaml("bomb_plugin"))
            archive.writestr("src/__init__.py", "")
            archive.writestr("src/main.py", "def run(args, api=None): return {'ok': True}\n")
            archive.writestr("assets/zeros.bin", b"\0" * (2 * 1024 * 1024))

        with self.assertRaisesRegex(PluginPackageError, "compression ratio"):
            PluginLoader(self.plugins_dir).install(package)

    def test_loader_rejects_archive_with_too_many_files(self) -> None:
        package = self.packages_dir / "too_many_files.zip"
        with zipfile.ZipFile(package, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("plugin.yaml", self._metadata_yaml("many_files_plugin"))
            archive.writestr("src/__init__.py", "")
            archive.writestr("src/main.py", "def run(args, api=None): return {'ok': True}\n")
            for index in range(MAX_PLUGIN_FILES + 1):
                archive.writestr(f"assets/{index}.txt", "x")

        with self.assertRaisesRegex(PluginPackageError, "too many files"):
            PluginLoader(self.plugins_dir).install(package)

    def test_loader_rejects_archive_member_declared_as_symlink(self) -> None:
        package = self.packages_dir / "symlink_member.zip"
        with zipfile.ZipFile(package, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("plugin.yaml", self._metadata_yaml("zip_symlink_plugin"))
            archive.writestr("src/__init__.py", "")
            archive.writestr("src/main.py", "def run(args, api=None): return {'ok': True}\n")
            info = zipfile.ZipInfo("assets/link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "target")

        with self.assertRaisesRegex(PluginPackageError, "not allowed|not a regular file"):
            PluginLoader(self.plugins_dir).install(package)

    def test_loader_rejects_archive_member_declared_too_large(self) -> None:
        package = self.packages_dir / "large_member.zip"
        with zipfile.ZipFile(package, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("plugin.yaml", self._metadata_yaml("large_member_plugin"))
            archive.writestr("src/__init__.py", "")
            archive.writestr("src/main.py", "def run(args, api=None): return {'ok': True}\n")
            archive.writestr("assets/large.bin", b"x" * (MAX_PLUGIN_FILE_BYTES + 1))

        with self.assertRaisesRegex(PluginPackageError, "file size limit"):
            PluginLoader(self.plugins_dir).install(package)

    def test_engine_calls_official_in_process_tool(self) -> None:
        source = self._make_plugin(
            "hello_plugin",
            runtime={"mode": "in_process", "trust": "official"},
            code="def run(args, api=None):\n    return {'message': 'hi ' + args.get('name', 'world')}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        engine = PluginEngine(self.plugins_dir)
        engine.install(package)

        result = engine.call_tool("hello_plugin", "run", {"name": "Ada"})
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["data"]["message"], "hi Ada")
        engine.stop_all()

    def test_file_writer_is_limited_to_plugin_data(self) -> None:
        source = self._make_plugin(
            "writer_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.read": True}, {"fs.write": True}],
            code=textwrap.dedent(
                """
                def run(args, api):
                    api.write_file(args.get('path', 'note.txt'), 'safe')
                    return {'ok': True}
                """
            ),
        )
        package = self._zip_plugin(source, include_sbom=True)
        engine = PluginEngine(self.plugins_dir)
        engine.install(package)
        engine.grant_permissions("writer_plugin")

        ok = engine.call_tool("writer_plugin", "run", {"path": "note.txt"})
        self.assertEqual(ok["status"], "success")
        denied = engine.call_tool("writer_plugin", "run", {"path": "../escape.txt"})
        self.assertEqual(denied["status"], "error")
        self.assertIn("unsafe plugin data path", denied["error"])
        engine.stop_all()

    def test_sandbox_gateway_channel_ignores_spoofed_plugin_identity(self) -> None:
        privileged_source = self._make_plugin(
            "privileged_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"memory.read": True}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        attacker_source = self._make_plugin(
            "identity_spoof_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}],
            code=textwrap.dedent(
                """
                def run(args, api=None):
                    api._conn.send({
                        'kind': 'gateway_request',
                        'plugin': 'privileged_plugin',
                        'request_type': 'memory.read',
                        'request_id': 'spoofed-request',
                        'payload': {'key': 'secret'},
                    })
                    response = api._conn.recv()
                    return response
                """
            ),
        )
        audit_logger = AuditLogger(self.root / "identity_spoof.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(self._zip_plugin(privileged_source))
        engine.install(self._zip_plugin(attacker_source))
        engine.grant_permissions("privileged_plugin")
        engine.grant_permissions("identity_spoof_plugin")
        engine.gateway.memory_store["secret"] = "classified"
        try:
            result = engine.call_tool("identity_spoof_plugin", "run", {})
            self.assertEqual(result["status"], "success")
            spoofed_response = result["data"]
            self.assertEqual(spoofed_response["status"], "error")
            self.assertIn("identity_spoof_plugin does not have memory.read", spoofed_response["error"])
            self.assertIn("security_warnings", spoofed_response)
            self.assertEqual(engine.gateway.memory_store["secret"], "classified")
            spoof_records = [
                item
                for item in audit_logger.read_records()
                if item.event == "plugin.gateway_identity_spoofed"
                and item.plugin == "identity_spoof_plugin"
            ]
            self.assertEqual(spoof_records[-1].details["claimed_plugin"], "privileged_plugin")
        finally:
            engine.stop_all()

    def test_sandbox_rejects_oversized_pipe_ipc_message(self) -> None:
        source = self._make_plugin(
            "oversized_ipc_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code=textwrap.dedent(
                """
                def run(args, api=None):
                    api._conn.send({'kind': 'result', 'status': 'success', 'data': 'x' * (3 * 1024 * 1024)})
                    return {'unreachable': True}
                """
            ),
        )
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(self._zip_plugin(source))
        engine.grant_permissions("oversized_ipc_plugin")
        try:
            result = engine.call_tool("oversized_ipc_plugin", "run", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("IPC message exceeds", result["error"])
        finally:
            engine.stop_all()

    def test_sandbox_rejects_malformed_pipe_ipc_message(self) -> None:
        source = self._make_plugin(
            "malformed_ipc_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code=textwrap.dedent(
                """
                def run(args, api=None):
                    api._conn.send(['not', 'an', 'object'])
                    return {'unreachable': True}
                """
            ),
        )
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(self._zip_plugin(source))
        engine.grant_permissions("malformed_ipc_plugin")
        try:
            result = engine.call_tool("malformed_ipc_plugin", "run", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("child IPC message must be an object", result["error"])
        finally:
            engine.stop_all()

    def test_sandbox_rejects_oversized_stdio_ipc_message(self) -> None:
        source = self._make_plugin(
            "oversized_stdio_ipc_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        loader = PluginLoader(self.plugins_dir)
        loader.install(self._zip_plugin(source))
        installed = loader.grant_permissions("oversized_stdio_ipc_plugin")
        sandbox = SandboxManager(installed, self.plugins_dir, sandbox_backend="python_guard")
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('x' * (3 * 1024 * 1024) + '\\n'); sys.stdout.flush()",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
        sandbox.process = process
        sandbox._stdio_queue = queue.Queue()
        try:
            sandbox._stdio_reader()
            with self.assertRaisesRegex(Exception, "stdio IPC message exceeds"):
                sandbox._stdio_read(timeout=0.1)
        finally:
            if process.stdout:
                process.stdout.close()
            process.kill()
            process.wait(timeout=2)

    def test_gateway_rejects_plugin_data_symlink_escape(self) -> None:
        if not hasattr(Path, "symlink_to"):
            self.skipTest("symlinks are not supported by pathlib on this platform")
        metadata = PluginMetadata(
            name="symlink_plugin",
            version="1.0.0",
            description="Symlink escape test plugin",
            author="test",
            runtime={"mode": "sub_process", "trust": "third_party"},
            extensions=[{"type": "tool", "name": "run", "entry": "src.main:run"}],
            permissions=[{"compute": True}, {"fs.read": True}, {"fs.write": True}],
        )
        source = self._make_plugin(
            "symlink_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.read": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        loader = PluginLoader(self.plugins_dir)
        loader.load_from_directory(source)
        loader.grant_permissions("symlink_plugin")
        gateway = PluginGateway(data_dir=self.plugins_dir)
        gateway.register_plugin(loader.get_installed("symlink_plugin"))
        outside = self.root / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        data_dir = self.plugins_dir / "symlink_plugin" / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        symlink_path = data_dir / "escape.txt"
        try:
            symlink_path.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlinks are not available: {exc}")

        with self.assertRaisesRegex(PermissionDenied, "symlink"):
            gateway.read_plugin_file(metadata, "escape.txt")
        with self.assertRaisesRegex(PermissionDenied, "symlink"):
            gateway.write_plugin_file(metadata, "escape.txt", "overwrite")
        self.assertEqual(outside.read_text(encoding="utf-8"), "secret")

    def test_gateway_rejects_plugin_data_hardlink_escape(self) -> None:
        if not hasattr(os, "link"):
            self.skipTest("hardlinks are not supported on this platform")
        metadata = PluginMetadata(
            name="hardlink_plugin",
            version="1.0.0",
            description="Hardlink escape test plugin",
            author="test",
            runtime={"mode": "sub_process", "trust": "third_party"},
            extensions=[{"type": "tool", "name": "run", "entry": "src.main:run"}],
            permissions=[{"compute": True}, {"fs.read": True}, {"fs.write": True}],
        )
        source = self._make_plugin(
            "hardlink_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.read": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        loader = PluginLoader(self.plugins_dir)
        loader.load_from_directory(source)
        loader.grant_permissions("hardlink_plugin")
        gateway = PluginGateway(data_dir=self.plugins_dir)
        gateway.register_plugin(loader.get_installed("hardlink_plugin"))
        outside = self.root / "outside-hardlink.txt"
        outside.write_text("secret", encoding="utf-8")
        data_dir = self.plugins_dir / "hardlink_plugin" / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        hardlink_path = data_dir / "escape.txt"
        try:
            os.link(outside, hardlink_path)
        except OSError as exc:
            self.skipTest(f"hardlinks are not available: {exc}")

        with self.assertRaisesRegex(PermissionDenied, "hardlink"):
            gateway.read_plugin_file(metadata, "escape.txt")
        with self.assertRaisesRegex(PermissionDenied, "hardlink"):
            gateway.write_plugin_file(metadata, "escape.txt", "overwrite")
        self.assertEqual(outside.read_text(encoding="utf-8"), "secret")

    def test_runtime_guard_rejects_direct_open_symlink_escape(self) -> None:
        source = self._make_plugin(
            "open_symlink_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.read": True}],
            code=textwrap.dedent(
                """
                def run(args, api=None):
                    with open('escape.txt', 'r', encoding='utf-8') as handle:
                        return {'content': handle.read()}
                """
            ),
        )
        package = self._zip_plugin(source, include_sbom=True)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("open_symlink_plugin")
        outside = self.root / "outside-open.txt"
        outside.write_text("secret", encoding="utf-8")
        data_dir = self.plugins_dir / "open_symlink_plugin" / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            (data_dir / "escape.txt").symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlinks are not available: {exc}")

        try:
            result = engine.call_tool("open_symlink_plugin", "run", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("symlink", result["error"])
        finally:
            engine.stop_all()

    def test_static_scan_blocks_import_os_escape(self) -> None:
        source = self._make_plugin(
            "escape_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="import os\n\ndef run(args, api=None):\n    return os.listdir('.')\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        loader = PluginLoader(self.plugins_dir)
        meta = loader.install(package)
        sandbox = SandboxManager(meta, self.plugins_dir)

        with self.assertRaises(SandboxViolation):
            sandbox.start()

    def test_runtime_guard_blocks_dynamic_import_escape(self) -> None:
        source = self._make_plugin(
            "dynamic_import_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code=textwrap.dedent(
                """
                def run(args, api=None):
                    importer = globals()['_' + '_builtins_' + '_']['_' + '_import_' + '_']
                    return importer('o' + 's').listdir('.')
                """
            ),
        )
        package = self._zip_plugin(source, include_sbom=True)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("dynamic_import_plugin")
        try:
            result = engine.call_tool("dynamic_import_plugin", "run", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("dynamic import of os is not allowed", result["error"])
        finally:
            engine.stop_all()

    def test_runtime_guard_blocks_compile(self) -> None:
        source = self._make_plugin(
            "compile_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code=textwrap.dedent(
                """
                def run(args, api=None):
                    compiler = globals()['_' + '_builtins_' + '_']['compile']
                    return compiler('1 + 1', '<x>', 'eval')
                """
            ),
        )
        package = self._zip_plugin(source, include_sbom=True)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("compile_plugin")
        try:
            result = engine.call_tool("compile_plugin", "run", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("compile is blocked", result["error"])
        finally:
            engine.stop_all()

    def test_static_scan_blocks_host_module_import(self) -> None:
        source = self._make_plugin(
            "host_import_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code=textwrap.dedent(
                """
                from modules.plugin_system.gateway import global_gateway

                def run(args, api=None):
                    return {'plugins': list(global_gateway.plugins)}
                """
            ),
        )
        package = self._zip_plugin(source, include_sbom=True)
        loader = PluginLoader(self.plugins_dir)
        meta = loader.install(package)
        sandbox = SandboxManager(meta, self.plugins_dir)

        with self.assertRaisesRegex(SandboxViolation, "host module"):
            sandbox.start()

    def test_load_guard_blocks_dynamic_host_module_import_before_runtime_guards(self) -> None:
        source = self._make_plugin(
            "host_dynamic_import_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code=textwrap.dedent(
                """
                builtins_obj = globals()['_' + '_builtins_' + '_']
                importer = (
                    builtins_obj['_' + '_import_' + '_']
                    if isinstance(builtins_obj, dict)
                    else builtins_obj.__dict__['_' + '_import_' + '_']
                )
                gateway = importer('modules.plugin_system.gateway', fromlist=['global_gateway'])

                def run(args, api=None):
                    return {'plugins': list(gateway.global_gateway.plugins)}
                """
            ),
        )
        package = self._zip_plugin(source, include_sbom=True)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("host_dynamic_import_plugin")
        try:
            with self.assertRaisesRegex(Exception, "host module import is not allowed"):
                engine.call_tool("host_dynamic_import_plugin", "run", {})
        finally:
            engine.stop_all()

    def test_gateway_blocks_private_network_targets_even_when_whitelisted(self) -> None:
        metadata = PluginMetadata(
            name="net_plugin",
            version="1.0.0",
            description="Network test plugin",
            author="test",
            runtime={"mode": "sub_process", "trust": "third_party"},
            extensions=[{"type": "tool", "name": "run", "entry": "src.main:run"}],
            permissions=[{"compute": True}, {"network.outbound": "http://127.0.0.1/*"}],
        )
        loader = PluginLoader(self.plugins_dir)
        installed = loader.load_from_directory(self._make_plugin(
            "net_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"network.outbound": "http://127.0.0.1/*"}],
            code="def run(args, api):\n    return api.network_request(args['url'])\n",
        ))
        loader.grant_permissions(installed.name)
        gateway = PluginGateway(data_dir=self.plugins_dir)
        gateway.register_plugin(loader.get_installed("net_plugin"))

        with self.assertRaises(PermissionDenied):
            gateway.network_request(metadata, {"url": "http://127.0.0.1/status"})

    def test_gateway_rejects_unsafe_network_request_shape_before_connecting(self) -> None:
        metadata = PluginMetadata(
            name="net_policy_plugin",
            version="1.0.0",
            description="Network policy test plugin",
            author="test",
            runtime={"mode": "sub_process", "trust": "third_party"},
            extensions=[{"type": "tool", "name": "run", "entry": "src.main:run"}],
            permissions=[{"compute": True}, {"network.outbound": "https://api.example.com/*"}],
        )
        loader = PluginLoader(self.plugins_dir)
        loader.load_from_directory(self._make_plugin(
            "net_policy_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"network.outbound": "https://api.example.com/*"}],
            code="def run(args, api):\n    return api.network_request(args['url'])\n",
        ))
        loader.grant_permissions("net_policy_plugin")
        gateway = PluginGateway(data_dir=self.plugins_dir)
        gateway.register_plugin(loader.get_installed("net_policy_plugin"))

        denied_requests = [
            (
                {"url": "https://user:pass@api.example.com/status"},
                "credentials",
            ),
            (
                {"url": "https://api.example.com/status", "timeout": 120},
                "timeout",
            ),
            (
                {"url": "https://api.example.com/status", "headers": {"Authorization": "secret"}},
                "custom network headers",
            ),
            (
                {"url": "https://api.example.com/status", "method": "GET", "body": {"x": 1}},
                "bodies are only allowed for POST",
            ),
            (
                {"url": "https://api.example.com/status", "method": "POST", "body": {"x": "y" * (65 * 1024)}},
                "body exceeds size limit",
            ),
        ]
        for payload, message in denied_requests:
            with self.subTest(message=message):
                with self.assertRaisesRegex(PermissionDenied, message):
                    gateway.network_request(metadata, payload)

    def test_gateway_does_not_expand_path_scoped_network_whitelist_to_whole_host(self) -> None:
        metadata = PluginMetadata(
            name="net_path_plugin",
            version="1.0.0",
            description="Network path policy test plugin",
            author="test",
            runtime={"mode": "sub_process", "trust": "third_party"},
            extensions=[{"type": "tool", "name": "run", "entry": "src.main:run"}],
            permissions=[{"compute": True}, {"network.outbound": "https://api.example.com/v1/*"}],
        )
        loader = PluginLoader(self.plugins_dir)
        loader.load_from_directory(self._make_plugin(
            "net_path_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"network.outbound": "https://api.example.com/v1/*"}],
            code="def run(args, api):\n    return api.network_request(args['url'])\n",
        ))
        loader.grant_permissions("net_path_plugin")
        gateway = PluginGateway(data_dir=self.plugins_dir)
        gateway.register_plugin(loader.get_installed("net_path_plugin"))

        self.assertFalse(gateway._url_allowed(metadata, "https://api.example.com/admin"))
        self.assertTrue(gateway._url_allowed(metadata, "https://api.example.com/v1/status"))

    def test_gateway_allows_authorized_network_target_through_gateway(self) -> None:
        metadata, gateway = self._gateway_for_network_plugin(
            "net_allowed_plugin",
            "https://api.example.com/*",
        )
        with patch.object(
            gateway,
            "_resolve_host_addresses",
            return_value={ipaddress.ip_address("93.184.216.34")},
        ), patch.object(gateway, "_open_network_request", return_value=_FakeNetworkResponse(body=b"ok")):
            result = gateway.network_request(
                metadata,
                {"url": "https://api.example.com/status", "method": "GET"},
                request_id="net-allow-1",
            )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["body"], "ok")
        records = [
            item
            for item in gateway.audit_logger.read_records()
            if item.event == "plugin.network_decision" and item.request_id == "net-allow-1"
        ]
        self.assertEqual(records[-1].details["plugin_id"], "net_allowed_plugin")
        self.assertEqual(records[-1].details["url"], "https://api.example.com/status")
        self.assertEqual(records[-1].details["resolved_ips"], ["93.184.216.34"])
        self.assertEqual(records[-1].details["decision"], "allow")
        self.assertEqual(records[-1].details["reason"], "allowed")
        self.assertEqual(records[-1].details["request_id"], "net-allow-1")

    def test_gateway_rejects_network_target_without_manifest_or_grant(self) -> None:
        metadata, gateway = self._gateway_for_network_plugin(
            "net_no_decl_plugin",
            "https://api.example.com/*",
            declared=False,
        )
        with self.assertRaisesRegex(PermissionDenied, "has not declared"):
            gateway.network_request(metadata, {"url": "https://api.example.com/status"})

        metadata, gateway = self._gateway_for_network_plugin(
            "net_no_grant_plugin",
            "https://api.example.com/*",
            granted=False,
        )
        with self.assertRaisesRegex(PermissionDenied, "does not have network.outbound"):
            gateway.network_request(metadata, {"url": "https://api.example.com/status"})

    def test_gateway_rejects_unapproved_network_domain(self) -> None:
        metadata, gateway = self._gateway_for_network_plugin(
            "net_unapproved_domain_plugin",
            "https://api.example.com/*",
        )
        with self.assertRaisesRegex(PermissionDenied, "not whitelisted"):
            gateway.network_request(metadata, {"url": "https://evil.example.net/status"})

    def test_gateway_rejects_broad_true_network_rule(self) -> None:
        metadata, gateway = self._gateway_for_network_plugin(
            "net_broad_true_plugin",
            True,
        )
        with self.assertRaisesRegex(PermissionDenied, "not whitelisted"):
            gateway.network_request(metadata, {"url": "https://api.example.com/status"})

    def test_gateway_enforces_structured_network_method_policy(self) -> None:
        metadata, gateway = self._gateway_for_network_plugin(
            "net_method_policy_plugin",
            {"url": "https://api.example.com:443/v1/*", "methods": ["POST"]},
        )
        with self.assertRaisesRegex(PermissionDenied, "not whitelisted"):
            gateway.network_request(metadata, {"url": "https://api.example.com:443/v1/status", "method": "GET"})

        with patch.object(
            gateway,
            "_resolve_host_addresses",
            return_value={ipaddress.ip_address("93.184.216.34")},
        ), patch.object(gateway, "_open_network_request", return_value=_FakeNetworkResponse(body=b"created")):
            result = gateway.network_request(
                metadata,
                {"url": "https://api.example.com:443/v1/status", "method": "POST", "body": {"ok": True}},
            )
        self.assertEqual(result["body"], "created")

    def test_gateway_rejects_ssrf_network_targets(self) -> None:
        cases = [
            ("localhost", "http://localhost/status", "127.0.0.1"),
            ("private", "http://private.example/status", "10.0.0.5"),
            ("link_local", "http://linklocal.example/status", "169.254.1.10"),
            ("metadata", "http://metadata.example/status", "169.254.169.254"),
            ("multicast", "http://multicast.example/status", "224.0.0.1"),
            ("unspecified", "http://zero.example/status", "0.0.0.0"),
        ]
        for label, url, address in cases:
            with self.subTest(label=label):
                metadata, gateway = self._gateway_for_network_plugin(
                    f"net_ssrf_{label}_plugin",
                    "http://*/*",
                )
                with patch.object(
                    gateway,
                    "_resolve_host_addresses",
                    return_value={ipaddress.ip_address(address)},
                ):
                    with self.assertRaisesRegex(PermissionDenied, "blocked address"):
                        gateway.network_request(metadata, {"url": url})

    def test_gateway_rejects_ip_literal_network_targets_by_default(self) -> None:
        metadata, gateway = self._gateway_for_network_plugin(
            "net_ip_literal_plugin",
            "https://93.184.216.34/*",
        )
        with self.assertRaisesRegex(PermissionDenied, "IP literal"):
            gateway.network_request(metadata, {"url": "https://93.184.216.34/status"})

    def test_gateway_rejects_userinfo_url_confusion(self) -> None:
        metadata, gateway = self._gateway_for_network_plugin(
            "net_userinfo_plugin",
            "https://allowed.example/*",
        )
        with self.assertRaisesRegex(PermissionDenied, "credentials"):
            gateway.network_request(metadata, {"url": "https://allowed.example@evil.example/status"})

    def test_gateway_rejects_redirect_to_unapproved_or_internal_target(self) -> None:
        cases = [
            ("unapproved", "https://evil.example/status"),
            ("internal", "http://metadata.example/status"),
        ]
        for label, location in cases:
            with self.subTest(label=label):
                metadata, gateway = self._gateway_for_network_plugin(
                    f"net_redirect_{label}_plugin",
                    "https://api.example.com/*",
                )
                address_map = {
                    "api.example.com": {ipaddress.ip_address("93.184.216.34")},
                    "evil.example": {ipaddress.ip_address("93.184.216.35")},
                    "metadata.example": {ipaddress.ip_address("169.254.169.254")},
                }
                with patch.object(
                    gateway,
                    "_resolve_host_addresses",
                    side_effect=lambda host: address_map[host],
                ), patch.object(
                    gateway,
                    "_open_network_request",
                    side_effect=_redirect_error("https://api.example.com/start", location),
                ):
                    with self.assertRaisesRegex(PermissionDenied, "redirect denied"):
                        gateway.network_request(metadata, {"url": "https://api.example.com/start"})

    def test_gateway_rejects_dns_rebinding_between_validation_and_response(self) -> None:
        metadata, gateway = self._gateway_for_network_plugin(
            "net_rebinding_plugin",
            "https://api.example.com/*",
        )
        with patch.object(
            gateway,
            "_resolve_host_addresses",
            side_effect=[
                {ipaddress.ip_address("93.184.216.34")},
                {ipaddress.ip_address("10.0.0.9")},
            ],
        ), patch.object(gateway, "_open_network_request", return_value=_FakeNetworkResponse(body=b"ok")):
            with self.assertRaisesRegex(PermissionDenied, "blocked address"):
                gateway.network_request(
                    metadata,
                    {"url": "https://api.example.com/status"},
                    request_id="net-rebind-1",
                )

        records = [
            item
            for item in gateway.audit_logger.read_records()
            if item.event == "plugin.network_decision" and item.request_id == "net-rebind-1"
        ]
        self.assertEqual(records[-1].details["decision"], "deny")
        self.assertIn("blocked_address", records[-1].details["reason"])

    def test_third_party_plugin_requires_permission_grant_before_start(self) -> None:
        source = self._make_plugin(
            "approval_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        engine = PluginEngine(self.plugins_dir)
        engine.install(package)

        with self.assertRaisesRegex(Exception, "pending_approval"):
            engine.call_tool("approval_plugin", "run", {})

        engine.grant_permissions("approval_plugin")
        result = engine.call_tool("approval_plugin", "run", {})
        self.assertEqual(result["status"], "success")
        engine.stop_all()

    def test_production_start_rejects_dev_installed_third_party_plugin(self) -> None:
        source = self._make_plugin(
            "production_unsigned_start_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        dev_engine = PluginEngine(self.plugins_dir)
        dev_engine.install(package)
        dev_engine.grant_permissions("production_unsigned_start_plugin")

        production_engine = PluginEngine(
            self.plugins_dir,
            sandbox_backend="external_enforced",
            production_mode=True,
        )
        with self.assertRaisesRegex(PluginPackageError, "signature record"):
            production_engine.call_tool("production_unsigned_start_plugin", "run", {})

    def test_legacy_hmac_signing_requires_explicit_key_and_detects_tampering(self) -> None:
        source = self._make_plugin(
            "signed_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)

        with self.assertRaises(PluginSignatureError):
            sign_package(package)

        signature = sign_package(package, key="test-signing-key")
        payload = verify_signature(package, signature, key="test-signing-key")
        self.assertEqual(payload["algorithm"], LEGACY_SIGNATURE_ALGORITHM)

        with zipfile.ZipFile(package, "a", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("tampered.txt", "changed")

        with self.assertRaises(PluginSignatureError):
            verify_signature(package, signature, key="test-signing-key")

    def test_ed25519_signing_verifies_and_detects_tampering(self) -> None:
        source = self._make_plugin(
            "ed25519_signed_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        private_key = self.root / "keys" / "plugin-signing-private.pem"
        public_key = self.root / "keys" / "plugin-signing-public.pem"
        generate_keypair(private_key, public_key)

        signature = sign_package(package, private_key=private_key, publisher="security@example.com")
        payload = verify_signature(package, signature, public_key=public_key)
        self.assertEqual(payload["algorithm"], SIGNATURE_ALGORITHM)
        self.assertEqual(payload["publisher"], "security@example.com")

        with zipfile.ZipFile(package, "a", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("tampered.txt", "changed")

        with self.assertRaises(PluginSignatureError):
            verify_signature(package, signature, public_key=public_key)

    def test_loader_can_require_signatures_for_third_party_plugins(self) -> None:
        source = self._make_plugin(
            "signature_required_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        loader = PluginLoader(self.plugins_dir, require_signatures=True)

        with self.assertRaisesRegex(PluginPackageError, "requires a verified signature"):
            loader.install(package)

        signature_path = sign_package(package, key="test-signing-key")
        signature_payload = verify_signature(package, signature_path, key="test-signing-key")
        metadata = loader.install(package, signature=signature_payload)
        self.assertEqual(metadata.name, "signature_required_plugin")

    def test_loader_accepts_required_ed25519_signature_for_third_party_plugin(self) -> None:
        source = self._make_plugin(
            "ed25519_required_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        private_key = self.root / "keys" / "private.pem"
        public_key = self.root / "keys" / "public.pem"
        generate_keypair(private_key, public_key)
        signature_path = sign_package(package, private_key=private_key, publisher="trusted@example.com")
        signature_payload = verify_signature(package, signature_path, public_key=public_key)
        loader = PluginLoader(self.plugins_dir, require_signatures=True)

        metadata = loader.install(package, signature=signature_payload)
        self.assertEqual(metadata.name, "ed25519_required_plugin")

    def test_loader_production_mode_requires_ed25519_for_third_party_plugins(self) -> None:
        source = self._make_plugin(
            "production_signature_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir, production_mode=True)

        with self.assertRaisesRegex(PluginPackageError, "requires a verified signature"):
            loader.install(package)

        hmac_signature = sign_package(package, key="test-signing-key")
        hmac_payload = verify_signature(package, hmac_signature, key="test-signing-key")
        with self.assertRaisesRegex(PluginPackageError, "production mode requires"):
            loader.install(package, signature=hmac_payload)

        private_key = self.root / "production-private.pem"
        public_key = self.root / "production-public.pem"
        generate_keypair(private_key, public_key)
        ed25519_signature = sign_package(package, private_key=private_key, publisher="prod@example.com")
        ed25519_payload = verify_signature(package, ed25519_signature, public_key=public_key)
        package = self._zip_plugin(source, include_sbom=True)
        ed25519_signature = sign_package(package, private_key=private_key, publisher="prod@example.com")
        ed25519_payload = verify_signature(package, ed25519_signature, public_key=public_key)
        metadata = loader.install(
            package,
            signature=ed25519_payload,
            scan_report=self._passing_scan_report(source),
        )
        self.assertEqual(metadata.name, "production_signature_plugin")

    def test_trust_store_verifies_and_revokes_publisher_keys(self) -> None:
        source = self._make_plugin(
            "trust_store_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        private_key = self.root / "keys" / "trust-private.pem"
        public_key = self.root / "keys" / "trust-public.pem"
        trust_store = self.root / "trust-store.json"
        generate_keypair(private_key, public_key)
        key_id = TrustStore(trust_store).add_key("trusted@example.com", public_key)
        signature_path = sign_package(package, private_key=private_key, publisher="trusted@example.com")

        payload = verify_signature(package, signature_path, trust_store=trust_store)
        self.assertEqual(payload["publisher"], "trusted@example.com")
        self.assertEqual(payload["key_id"], key_id)

        TrustStore(trust_store).revoke_key("trusted@example.com", key_id)
        with self.assertRaisesRegex(PluginSignatureError, "not trusted"):
            verify_signature(package, signature_path, trust_store=trust_store)

    def test_registry_loads_index_and_installs_signed_plugin(self) -> None:
        source = self._make_plugin(
            "registry_signed_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        private_key = self.root / "registry-private.pem"
        public_key = self.root / "registry-public.pem"
        trust_store = self.root / "registry-trust-store.json"
        generate_keypair(private_key, public_key)
        TrustStore(trust_store).add_key("registry@example.com", public_key)
        signature = sign_package(package, private_key=private_key, publisher="registry@example.com")
        index = self._write_registry_index(
            "registry_signed_plugin",
            package,
            signature,
            publisher="registry@example.com",
        )
        index_signature = sign_package(index, private_key=private_key, publisher="registry@example.com")

        loaded = load_registry_index(index)
        self.assertEqual(loaded.entries[0].name, "registry_signed_plugin")

        result = PluginRegistryClient(index, index_signature=index_signature).install(
            "registry_signed_plugin",
            plugins_dir=self.plugins_dir,
            trust_store=trust_store,
            production_mode=True,
            scan_report=self._passing_scan_report(source),
        )

        self.assertEqual(result.metadata.name, "registry_signed_plugin")
        installed = PluginLoader(self.plugins_dir).get_installed("registry_signed_plugin")
        self.assertIsNotNone(installed)
        self.assertEqual(installed.status.value, "pending_approval")

    def test_registry_install_rejects_sha256_mismatch_before_install(self) -> None:
        source = self._make_plugin(
            "registry_hash_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        private_key = self.root / "registry-hash-private.pem"
        public_key = self.root / "registry-hash-public.pem"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="registry@example.com")
        index = self._write_registry_index(
            "registry_hash_plugin",
            package,
            signature,
            publisher="registry@example.com",
            digest="0" * 64,
        )

        with self.assertRaisesRegex(PluginRegistryError, "sha256 mismatch"):
            PluginRegistryClient(index).install(
                "registry_hash_plugin",
                plugins_dir=self.plugins_dir,
                public_key=public_key,
            )
        self.assertIsNone(PluginLoader(self.plugins_dir).get_installed("registry_hash_plugin"))

    def test_registry_install_rejects_untrusted_publisher_signature(self) -> None:
        source = self._make_plugin(
            "registry_untrusted_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        private_key = self.root / "registry-untrusted-private.pem"
        public_key = self.root / "registry-untrusted-public.pem"
        trust_store = self.root / "registry-untrusted-store.json"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="untrusted@example.com")
        index = self._write_registry_index(
            "registry_untrusted_plugin",
            package,
            signature,
            publisher="untrusted@example.com",
        )

        with self.assertRaisesRegex(PluginRegistryError, "not trusted"):
            PluginRegistryClient(index).install(
                "registry_untrusted_plugin",
                plugins_dir=self.plugins_dir,
                trust_store=trust_store,
            )

    def test_registry_rejects_local_artifact_path_escape(self) -> None:
        source = self._make_plugin(
            "registry_escape_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        index_dir = self.root / "registry"
        index_dir.mkdir()
        index = index_dir / "index.json"
        index.write_text(
            json.dumps(
                {
                    "version": 1,
                    "plugins": [
                        {
                            "name": "registry_escape_plugin",
                            "version": "1.0.0",
                            "description": "Path escape test plugin",
                            "package": "../packages/registry_escape_plugin.zip",
                            "sha256": sha256_file(package),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(PluginRegistryError, "escapes registry directory"):
            PluginRegistryClient(index).install(
                "registry_escape_plugin",
                plugins_dir=self.plugins_dir,
                require_signature=False,
            )

    def test_cli_registry_list_and_install_signed_plugin(self) -> None:
        source = self._make_plugin(
            "cli_registry_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        private_key = self.root / "cli-registry-private.pem"
        public_key = self.root / "cli-registry-public.pem"
        trust_store = self.root / "cli-registry-trust-store.json"
        generate_keypair(private_key, public_key)
        TrustStore(trust_store).add_key("cli-registry@example.com", public_key)
        signature = sign_package(package, private_key=private_key, publisher="cli-registry@example.com")
        index = self._write_registry_index(
            "cli_registry_plugin",
            package,
            signature,
            publisher="cli-registry@example.com",
        )
        index_signature = sign_package(index, private_key=private_key, publisher="cli-registry@example.com")

        list_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "registry",
                "list",
                "--index",
                str(index),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(list_result.returncode, 0, list_result.stderr)
        self.assertIn("cli_registry_plugin v1.0.0", list_result.stdout)
        self.assertIn("signed=true", list_result.stdout)

        install_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "--production",
                "registry",
                "install",
                "cli_registry_plugin",
                "--index",
                str(index),
                "--index-signature",
                str(index_signature),
                "--trust-store",
                str(trust_store),
                "--scan-report",
                str(self._write_scan_report(source, "cli_registry_plugin")),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(install_result.returncode, 0, install_result.stderr)
        self.assertIn("Installed cli_registry_plugin v1.0.0 from registry", install_result.stdout)

    def test_registry_production_install_requires_signed_index(self) -> None:
        source = self._make_plugin(
            "registry_unsigned_index_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        private_key = self.root / "registry-unsigned-index-private.pem"
        public_key = self.root / "registry-unsigned-index-public.pem"
        trust_store = self.root / "registry-unsigned-index-store.json"
        generate_keypair(private_key, public_key)
        TrustStore(trust_store).add_key("registry-prod@example.com", public_key)
        package_signature = sign_package(package, private_key=private_key, publisher="registry-prod@example.com")
        index = self._write_registry_index(
            "registry_unsigned_index_plugin",
            package,
            package_signature,
            publisher="registry-prod@example.com",
        )

        with self.assertRaisesRegex(PluginRegistryError, "index signature is required"):
            PluginRegistryClient(index).install(
                "registry_unsigned_index_plugin",
                plugins_dir=self.plugins_dir,
                trust_store=trust_store,
                production_mode=True,
            )

    def test_registry_production_install_verifies_signed_index_and_records_source(self) -> None:
        source = self._make_plugin(
            "registry_signed_index_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        private_key = self.root / "registry-signed-index-private.pem"
        public_key = self.root / "registry-signed-index-public.pem"
        trust_store = self.root / "registry-signed-index-store.json"
        generate_keypair(private_key, public_key)
        TrustStore(trust_store).add_key("registry-index@example.com", public_key)
        package_signature = sign_package(package, private_key=private_key, publisher="registry-index@example.com")
        index = self._write_registry_index(
            "registry_signed_index_plugin",
            package,
            package_signature,
            publisher="registry-index@example.com",
        )
        index_signature = sign_package(index, private_key=private_key, publisher="registry-index@example.com")

        result = PluginRegistryClient(index, index_signature=index_signature).install(
            "registry_signed_index_plugin",
            plugins_dir=self.plugins_dir,
            trust_store=trust_store,
            production_mode=True,
            scan_report=self._passing_scan_report(source),
        )

        self.assertEqual(result.metadata.name, "registry_signed_index_plugin")
        manifest = json.loads(
            (self.plugins_dir / "registry_signed_index_plugin" / MANIFEST_FILE).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["registry"]["index"], str(index.resolve()))
        self.assertTrue(manifest["registry"]["index_signed"])
        self.assertEqual(manifest["registry"]["index_signature"]["publisher"], "registry-index@example.com")

    def test_registry_signed_index_detects_tampering(self) -> None:
        source = self._make_plugin(
            "registry_tampered_index_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        private_key = self.root / "registry-tampered-index-private.pem"
        public_key = self.root / "registry-tampered-index-public.pem"
        trust_store = self.root / "registry-tampered-index-store.json"
        generate_keypair(private_key, public_key)
        TrustStore(trust_store).add_key("registry-tamper@example.com", public_key)
        package_signature = sign_package(package, private_key=private_key, publisher="registry-tamper@example.com")
        index = self._write_registry_index(
            "registry_tampered_index_plugin",
            package,
            package_signature,
            publisher="registry-tamper@example.com",
        )
        index_signature = sign_package(index, private_key=private_key, publisher="registry-tamper@example.com")
        payload = json.loads(index.read_text(encoding="utf-8"))
        payload["plugins"][0]["description"] = "Tampered registry entry"
        index.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(PluginRegistryError, "hash does not match"):
            PluginRegistryClient(index, index_signature=index_signature).install(
                "registry_tampered_index_plugin",
                plugins_dir=self.plugins_dir,
                trust_store=trust_store,
                production_mode=True,
            )

    def test_registry_install_rejects_revoked_key(self) -> None:
        source = self._make_plugin(
            "registry_revoked_key_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        private_key = self.root / "registry-revoked-key-private.pem"
        public_key = self.root / "registry-revoked-key-public.pem"
        trust_store = self.root / "registry-revoked-key-store.json"
        generate_keypair(private_key, public_key)
        key_id = TrustStore(trust_store).add_key("registry-revoked@example.com", public_key)
        package_signature = sign_package(package, private_key=private_key, publisher="registry-revoked@example.com")
        index = self._write_registry_index(
            "registry_revoked_key_plugin",
            package,
            package_signature,
            publisher="registry-revoked@example.com",
        )
        payload = json.loads(index.read_text(encoding="utf-8"))
        payload["revoked_keys"] = [key_id]
        index.write_text(json.dumps(payload), encoding="utf-8")
        index_signature = sign_package(index, private_key=private_key, publisher="registry-revoked@example.com")

        with self.assertRaisesRegex(PluginRegistryError, "publisher key is revoked"):
            PluginRegistryClient(index, index_signature=index_signature).install(
                "registry_revoked_key_plugin",
                plugins_dir=self.plugins_dir,
                trust_store=trust_store,
                production_mode=True,
            )

    def test_registry_install_rejects_revoked_plugin_version(self) -> None:
        source = self._make_plugin(
            "registry_revoked_version_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        private_key = self.root / "registry-revoked-version-private.pem"
        public_key = self.root / "registry-revoked-version-public.pem"
        trust_store = self.root / "registry-revoked-version-store.json"
        generate_keypair(private_key, public_key)
        TrustStore(trust_store).add_key("registry-version-revoke@example.com", public_key)
        package_signature = sign_package(package, private_key=private_key, publisher="registry-version-revoke@example.com")
        index = self._write_registry_index(
            "registry_revoked_version_plugin",
            package,
            package_signature,
            publisher="registry-version-revoke@example.com",
        )
        payload = json.loads(index.read_text(encoding="utf-8"))
        payload["revoked_plugin_versions"] = [
            {"name": "registry_revoked_version_plugin", "version": "1.0.0"}
        ]
        index.write_text(json.dumps(payload), encoding="utf-8")
        index_signature = sign_package(index, private_key=private_key, publisher="registry-version-revoke@example.com")

        with self.assertRaisesRegex(PluginRegistryError, "plugin version is revoked"):
            PluginRegistryClient(index, index_signature=index_signature).install(
                "registry_revoked_version_plugin",
                plugins_dir=self.plugins_dir,
                trust_store=trust_store,
                production_mode=True,
            )

    def test_registry_install_rejects_downgrade_and_same_version_replacement(self) -> None:
        source_v2 = self._make_plugin(
            "registry_version_plugin_v2_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'version': 2}\n",
        )
        (source_v2 / "plugin.yaml").write_text(
            self._metadata_yaml(
                "registry_version_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
            ).replace("version: 1.0.0", "version: 2.0.0"),
            encoding="utf-8",
        )
        package_v2 = self._zip_plugin(source_v2)
        PluginLoader(self.plugins_dir).install(package_v2)

        source_v1 = self._make_plugin(
            "registry_version_plugin_v1_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'version': 1}\n",
        )
        (source_v1 / "plugin.yaml").write_text(
            self._metadata_yaml(
                "registry_version_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
            ),
            encoding="utf-8",
        )
        package_v1 = self._zip_plugin(source_v1)
        downgrade_index = self._write_registry_index(
            "registry_version_plugin",
            package_v1,
            version="1.0.0",
        )

        with self.assertRaisesRegex(PluginRegistryError, "would downgrade"):
            PluginRegistryClient(downgrade_index).install(
                "registry_version_plugin",
                plugins_dir=self.plugins_dir,
                require_signature=False,
            )

        source_v2_replacement = self._make_plugin(
            "registry_version_plugin_v2_replacement_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'version': 'replacement'}\n",
        )
        (source_v2_replacement / "plugin.yaml").write_text(
            self._metadata_yaml(
                "registry_version_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
            ).replace("version: 1.0.0", "version: 2.0.0"),
            encoding="utf-8",
        )
        package_v2_replacement = self._zip_plugin(source_v2_replacement)
        replacement_index = self._write_registry_index(
            "registry_version_plugin",
            package_v2_replacement,
            version="2.0.0",
        )

        with self.assertRaisesRegex(PluginRegistryError, "same version"):
            PluginRegistryClient(replacement_index).install(
                "registry_version_plugin",
                plugins_dir=self.plugins_dir,
                require_signature=False,
            )

    def test_cli_registry_production_install_requires_index_signature(self) -> None:
        source = self._make_plugin(
            "cli_registry_index_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source, include_sbom=True)
        private_key = self.root / "cli-registry-index-private.pem"
        public_key = self.root / "cli-registry-index-public.pem"
        trust_store = self.root / "cli-registry-index-store.json"
        generate_keypair(private_key, public_key)
        TrustStore(trust_store).add_key("cli-registry-index@example.com", public_key)
        package_signature = sign_package(package, private_key=private_key, publisher="cli-registry-index@example.com")
        index = self._write_registry_index(
            "cli_registry_index_plugin",
            package,
            package_signature,
            publisher="cli-registry-index@example.com",
        )

        missing_index_signature = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "--production",
                "registry",
                "install",
                "cli_registry_index_plugin",
                "--index",
                str(index),
                "--trust-store",
                str(trust_store),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(missing_index_signature.returncode, 0)
        self.assertIn("index signature is required", missing_index_signature.stderr)

        index_signature = sign_package(index, private_key=private_key, publisher="cli-registry-index@example.com")
        signed_index_install = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "--production",
                "registry",
                "install",
                "cli_registry_index_plugin",
                "--index",
                str(index),
                "--index-signature",
                str(index_signature),
                "--trust-store",
                str(trust_store),
                "--scan-report",
                str(self._write_scan_report(source, "cli_registry_index_plugin")),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(signed_index_install.returncode, 0, signed_index_install.stderr)
        self.assertIn("Installed cli_registry_index_plugin", signed_index_install.stdout)

    def test_cli_keygen_sign_and_verify_ed25519_signature(self) -> None:
        source = self._make_plugin(
            "cli_ed25519_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        private_key = self.root / "cli-private.pem"
        public_key = self.root / "cli-public.pem"

        keygen_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "keygen",
                "--private-key",
                str(private_key),
                "--public-key",
                str(public_key),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(keygen_result.returncode, 0, keygen_result.stderr)

        sign_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "sign",
                str(package),
                "--private-key",
                str(private_key),
                "--publisher",
                "cli@example.com",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(sign_result.returncode, 0, sign_result.stderr)

        verify_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "verify",
                str(package),
                "--public-key",
                str(public_key),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(verify_result.returncode, 0, verify_result.stderr)
        self.assertIn("Signature verified", verify_result.stdout)

    def test_cli_trust_store_can_verify_publisher_signature(self) -> None:
        source = self._make_plugin(
            "cli_trust_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        private_key = self.root / "cli-trust-private.pem"
        public_key = self.root / "cli-trust-public.pem"
        trust_store = self.root / "cli-trust-store.json"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="cli-trusted@example.com")

        add_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "trust",
                "--store",
                str(trust_store),
                "add-key",
                "cli-trusted@example.com",
                str(public_key),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(add_result.returncode, 0, add_result.stderr)
        self.assertIn("Trusted cli-trusted@example.com", add_result.stdout)

        verify_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "verify",
                str(package),
                "--signature",
                str(signature),
                "--trust-store",
                str(trust_store),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(verify_result.returncode, 0, verify_result.stderr)
        self.assertIn("Signature verified", verify_result.stdout)

    def test_cli_production_install_rejects_hmac_and_accepts_ed25519(self) -> None:
        source = self._make_plugin(
            "cli_production_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        hmac_signature = sign_package(package, key="test-signing-key")

        hmac_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "--production",
                "install",
                str(package),
                "--signature",
                str(hmac_signature),
                "--hmac-key",
                "test-signing-key",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(hmac_result.returncode, 0)
        self.assertIn("production mode requires", hmac_result.stderr)

        private_key = self.root / "cli-production-private.pem"
        public_key = self.root / "cli-production-public.pem"
        generate_keypair(private_key, public_key)
        package = self._zip_plugin(source, include_sbom=True)
        ed25519_signature = sign_package(package, private_key=private_key, publisher="cli-prod@example.com")
        ed25519_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "--production",
                "install",
                str(package),
                "--signature",
                str(ed25519_signature),
                "--public-key",
                str(public_key),
                "--scan-report",
                str(self._write_scan_report(source, "cli_production_plugin")),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(ed25519_result.returncode, 0, ed25519_result.stderr)
        self.assertIn("Installed cli_production_plugin", ed25519_result.stdout)

    def test_signature_policy_does_not_force_official_plugin_signatures(self) -> None:
        source = self._make_plugin(
            "official_unsigned_plugin",
            runtime={"mode": "in_process", "trust": "official"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir, require_signatures=True)

        metadata = loader.install(package)
        self.assertEqual(metadata.name, "official_unsigned_plugin")

    def test_engine_can_require_signatures_on_install(self) -> None:
        source = self._make_plugin(
            "engine_signature_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "signature_policy.log")
        engine = PluginEngine(
            self.plugins_dir,
            audit_logger=audit_logger,
            require_signatures=True,
        )

        with self.assertRaisesRegex(PluginPackageError, "requires a verified signature"):
            engine.install(package)

        signature_path = sign_package(package, key="test-signing-key")
        signature_payload = verify_signature(package, signature_path, key="test-signing-key")
        metadata = engine.install(package, signature=signature_payload)
        self.assertEqual(metadata.name, "engine_signature_plugin")
        install_records = [
            item
            for item in audit_logger.read_records()
            if item.event == "plugin.installed" and item.plugin == "engine_signature_plugin"
        ]
        self.assertTrue(install_records[-1].details["signed"])
        self.assertTrue(install_records[-1].details["require_signatures"])

    def test_engine_production_mode_enforces_signature_policy_and_strict_sandbox(self) -> None:
        source = self._make_plugin(
            "engine_production_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "engine_production.log")
        engine = PluginEngine(
            self.plugins_dir,
            sandbox_backend="python_guard",
            audit_logger=audit_logger,
            production_mode=True,
        )

        self.assertTrue(engine.loader.require_signatures)
        self.assertTrue(engine.loader.production_mode)
        self.assertTrue(engine.require_enforced_sandbox)
        with self.assertRaisesRegex(PluginPackageError, "requires a verified signature"):
            engine.install(package)

        hmac_signature = sign_package(package, key="test-signing-key")
        hmac_payload = verify_signature(package, hmac_signature, key="test-signing-key")
        with self.assertRaisesRegex(PluginPackageError, "production mode requires"):
            engine.install(package, signature=hmac_payload)

        private_key = self.root / "engine-production-private.pem"
        public_key = self.root / "engine-production-public.pem"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="engine-prod@example.com")
        payload = verify_signature(package, signature, public_key=public_key)
        package = self._zip_plugin(source, include_sbom=True)
        signature = sign_package(package, private_key=private_key, publisher="engine-prod@example.com")
        payload = verify_signature(package, signature, public_key=public_key)
        engine.install(package, signature=payload, scan_report=self._passing_scan_report(source))
        install_records = [
            item
            for item in audit_logger.read_records()
            if item.event == "plugin.installed" and item.plugin == "engine_production_plugin"
        ]
        self.assertTrue(install_records[-1].details["production_mode"])

    def test_upgrade_preserves_granted_permissions_when_still_requested(self) -> None:
        source_v1 = self._make_plugin(
            "upgrade_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'version': 1}\n",
        )
        package_v1 = self._zip_plugin(source_v1)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package_v1)
        loader.grant_permissions("upgrade_plugin")

        source_v2 = self._make_plugin(
            "upgrade_plugin_v2_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'version': 2}\n",
        )
        (source_v2 / "plugin.yaml").write_text(
            self._metadata_yaml(
                "upgrade_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
                permissions=[{"compute": True}, {"fs.write": True}],
            ),
            encoding="utf-8",
        )
        package_v2 = self._zip_plugin(source_v2)
        loader.install(package_v2)

        installed = loader.get_installed("upgrade_plugin")
        self.assertIsNotNone(installed)
        self.assertEqual(installed.status.value, "enabled")
        self.assertEqual(installed.granted_permission_names, {"compute", "fs.write"})
        self.assertFalse(installed.permission_review["required"])

    def test_upgrade_with_added_permission_requires_reapproval(self) -> None:
        source_v1 = self._make_plugin(
            "upgrade_added_permission_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}],
            code="def run(args, api=None):\n    return {'version': 1}\n",
        )
        package_v1 = self._zip_plugin(source_v1)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package_v1)
        loader.grant_permissions("upgrade_added_permission_plugin")

        source_v2 = self._make_plugin(
            "upgrade_added_permission_plugin_v2_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'version': 2}\n",
        )
        (source_v2 / "plugin.yaml").write_text(
            self._metadata_yaml(
                "upgrade_added_permission_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
                permissions=[{"compute": True}, {"fs.write": True}],
            ),
            encoding="utf-8",
        )
        package_v2 = self._zip_plugin(source_v2)
        loader.install(package_v2)

        installed = loader.get_installed("upgrade_added_permission_plugin")
        self.assertIsNotNone(installed)
        self.assertEqual(installed.status.value, "pending_approval")
        self.assertEqual(installed.granted_permission_names, {"compute"})
        self.assertEqual(installed.permission_review["reason"], "permission_expansion")
        self.assertEqual(installed.permission_review["added_permissions"], ["fs.write"])

        manifest = json.loads(
            (self.plugins_dir / "upgrade_added_permission_plugin" / MANIFEST_FILE).read_text(encoding="utf-8")
        )
        self.assertTrue(manifest["permission_review"]["required"])
        self.assertEqual(manifest["permission_review"]["added_permissions"], ["fs.write"])

    def test_enable_cannot_bypass_pending_permission_review_after_upgrade(self) -> None:
        source_v1 = self._make_plugin(
            "enable_review_bypass_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}],
            code="def run(args, api=None):\n    return {'version': 1}\n",
        )
        package_v1 = self._zip_plugin(source_v1)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package_v1)
        loader.grant_permissions("enable_review_bypass_plugin")

        source_v2 = self._make_plugin(
            "enable_review_bypass_plugin_v2_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'version': 2}\n",
        )
        (source_v2 / "plugin.yaml").write_text(
            self._metadata_yaml(
                "enable_review_bypass_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
                permissions=[{"compute": True}, {"fs.write": True}],
            ),
            encoding="utf-8",
        )
        package_v2 = self._zip_plugin(source_v2)
        loader.install(package_v2)

        with self.assertRaisesRegex(PluginPackageError, "requires permission review"):
            loader.enable_plugin("enable_review_bypass_plugin")

        installed = loader.get_installed("enable_review_bypass_plugin")
        self.assertIsNotNone(installed)
        self.assertEqual(installed.status.value, "pending_approval")

    def test_engine_refuses_upgraded_plugin_until_new_permissions_are_granted(self) -> None:
        source_v1 = self._make_plugin(
            "engine_upgrade_permission_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}],
            code="def run(args, api=None):\n    return {'version': 1}\n",
        )
        package_v1 = self._zip_plugin(source_v1)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package_v1)
        engine.grant_permissions("engine_upgrade_permission_plugin")

        source_v2 = self._make_plugin(
            "engine_upgrade_permission_plugin_v2_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'version': 2}\n",
        )
        (source_v2 / "plugin.yaml").write_text(
            self._metadata_yaml(
                "engine_upgrade_permission_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
                permissions=[{"compute": True}, {"fs.write": True}],
            ),
            encoding="utf-8",
        )
        package_v2 = self._zip_plugin(source_v2)
        engine.install(package_v2)

        with self.assertRaisesRegex(PluginLifecycleError, "pending_approval"):
            engine.call_tool("engine_upgrade_permission_plugin", "run", {})

        engine.grant_permissions("engine_upgrade_permission_plugin")
        result = engine.call_tool("engine_upgrade_permission_plugin", "run", {})
        self.assertEqual(result["data"]["version"], 2)
        engine.stop_all()

    def test_upgrade_with_permission_value_change_requires_reapproval(self) -> None:
        source_v1 = self._make_plugin(
            "upgrade_changed_permission_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"network.outbound": "https://api.example.com/*"}],
            code="def run(args, api=None):\n    return {'version': 1}\n",
        )
        package_v1 = self._zip_plugin(source_v1)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package_v1)
        loader.grant_permissions("upgrade_changed_permission_plugin")

        source_v2 = self._make_plugin(
            "upgrade_changed_permission_plugin_v2_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"network.outbound": "https://*.example.com/*"}],
            code="def run(args, api=None):\n    return {'version': 2}\n",
        )
        (source_v2 / "plugin.yaml").write_text(
            self._metadata_yaml(
                "upgrade_changed_permission_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
                permissions=[{"compute": True}, {"network.outbound": "https://*.example.com/*"}],
            ),
            encoding="utf-8",
        )
        package_v2 = self._zip_plugin(source_v2)
        loader.install(package_v2)

        installed = loader.get_installed("upgrade_changed_permission_plugin")
        self.assertIsNotNone(installed)
        self.assertEqual(installed.status.value, "pending_approval")
        self.assertEqual(installed.granted_permission_value("network.outbound"), "https://api.example.com/*")
        self.assertEqual(installed.permission_review["changed_permissions"], ["network.outbound"])

    def test_upgrade_with_removed_permission_drops_old_grant_without_reapproval(self) -> None:
        source_v1 = self._make_plugin(
            "upgrade_removed_permission_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'version': 1}\n",
        )
        package_v1 = self._zip_plugin(source_v1)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package_v1)
        loader.grant_permissions("upgrade_removed_permission_plugin")

        source_v2 = self._make_plugin(
            "upgrade_removed_permission_plugin_v2_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}],
            code="def run(args, api=None):\n    return {'version': 2}\n",
        )
        (source_v2 / "plugin.yaml").write_text(
            self._metadata_yaml(
                "upgrade_removed_permission_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
                permissions=[{"compute": True}],
            ),
            encoding="utf-8",
        )
        package_v2 = self._zip_plugin(source_v2)
        loader.install(package_v2)

        installed = loader.get_installed("upgrade_removed_permission_plugin")
        self.assertIsNotNone(installed)
        self.assertEqual(installed.status.value, "enabled")
        self.assertEqual(installed.granted_permission_names, {"compute"})
        self.assertFalse(installed.permission_review["required"])
        self.assertEqual(installed.permission_review["removed_permissions"], ["fs.write"])

    def test_grant_marks_permission_review_as_reviewed(self) -> None:
        source = self._make_plugin(
            "reviewed_grant_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)
        installed = loader.grant_permissions("reviewed_grant_plugin")

        self.assertFalse(installed.permission_review["required"])
        self.assertTrue(installed.permission_review["reviewed"])
        self.assertEqual(installed.permission_review["granted_permissions"], ["compute"])

        manifest = json.loads(
            (self.plugins_dir / "reviewed_grant_plugin" / MANIFEST_FILE).read_text(encoding="utf-8")
        )
        self.assertFalse(manifest["permission_review"]["required"])
        self.assertTrue(manifest["permission_review"]["reviewed"])

    def test_permission_review_records_reviewer_reason_and_history(self) -> None:
        source = self._make_plugin(
            "approval_history_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)
        installed = loader.grant_permission_names(
            "approval_history_plugin",
            ["compute"],
            reviewer="alice@example.com",
            review_reason="initial limited rollout",
        )

        self.assertEqual(installed.permission_review["reviewer"], "alice@example.com")
        self.assertEqual(installed.permission_review["review_reason"], "initial limited rollout")
        self.assertEqual(len(installed.permission_review["history"]), 1)
        self.assertEqual(installed.permission_review["history"][0]["granted_permissions"], ["compute"])
        self.assertEqual(installed.permission_review["history"][0]["denied_permissions"], ["fs.write"])

        installed = loader.grant_permissions(
            "approval_history_plugin",
            reviewer="bob@example.com",
            review_reason="approved after security review",
        )
        self.assertEqual(installed.permission_review["reviewer"], "bob@example.com")
        self.assertEqual(installed.permission_review["history"][0]["reviewer"], "alice@example.com")
        self.assertEqual(installed.permission_review["history"][1]["reviewer"], "bob@example.com")
        self.assertEqual(installed.permission_review["denied_permissions"], [])

        manifest = json.loads(
            (self.plugins_dir / "approval_history_plugin" / MANIFEST_FILE).read_text(encoding="utf-8")
        )
        self.assertEqual(len(manifest["permission_review"]["history"]), 2)

    def test_grant_permission_names_allows_least_privilege_approval(self) -> None:
        source = self._make_plugin(
            "least_privilege_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}, {"network.outbound": "https://api.example.com/*"}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)
        installed = loader.grant_permission_names("least_privilege_plugin", ["compute"])

        self.assertEqual(installed.status.value, "enabled")
        self.assertEqual(installed.granted_permission_names, {"compute"})
        self.assertFalse(installed.permission_review["required"])
        self.assertEqual(
            installed.permission_review["denied_permissions"],
            ["fs.write", "network.outbound"],
        )
        denied_risks = {
            item["name"]: item
            for item in installed.permission_review["denied_permission_risks"]
        }
        self.assertEqual(denied_risks["fs.write"]["level"], "L3")
        self.assertEqual(denied_risks["network.outbound"]["risk"], "medium")

        with self.assertRaisesRegex(PluginPackageError, "not requested"):
            loader.grant_permission_names("least_privilege_plugin", ["compute", "memory.write"])

    def test_cli_review_and_approve_permission_review_flow(self) -> None:
        source = self._make_plugin(
            "cli_review_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        install_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "install",
                str(package),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(install_result.returncode, 0, install_result.stderr)

        review_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "review",
                "cli_review_plugin",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(review_result.returncode, 0, review_result.stderr)
        self.assertIn("review_required=true", review_result.stdout)
        self.assertIn("added=compute,fs.write", review_result.stdout)
        self.assertIn("risk fs.write level=L3 severity=high", review_result.stdout)

        approve_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "approve",
                "cli_review_plugin",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(approve_result.returncode, 0, approve_result.stderr)
        self.assertIn("Approved cli_review_plugin: status=enabled", approve_result.stdout)

        review_after_approve = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "review",
                "cli_review_plugin",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(review_after_approve.returncode, 0, review_after_approve.stderr)
        self.assertIn("review_required=false", review_after_approve.stdout)

    def test_cli_approve_can_grant_selected_permissions_only(self) -> None:
        source = self._make_plugin(
            "cli_least_privilege_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        install_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "install",
                str(package),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(install_result.returncode, 0, install_result.stderr)

        approve_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "approve",
                "cli_least_privilege_plugin",
                "--permission",
                "compute",
                "--reviewer",
                "security-team",
                "--reason",
                "least privilege rollout",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(approve_result.returncode, 0, approve_result.stderr)
        self.assertIn("Granted permissions: compute", approve_result.stdout)

        review_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "review",
                "cli_least_privilege_plugin",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(review_result.returncode, 0, review_result.stderr)
        self.assertIn("granted=compute", review_result.stdout)
        self.assertIn("denied=fs.write", review_result.stdout)
        self.assertIn("reviewer=security-team", review_result.stdout)
        self.assertIn("review_reason=least privilege rollout", review_result.stdout)
        self.assertIn("history ", review_result.stdout)

    def test_engine_permission_grant_audit_includes_reviewer_and_denied_permissions(self) -> None:
        source = self._make_plugin(
            "engine_approval_audit_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "approval_audit.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions(
            "engine_approval_audit_plugin",
            [{"compute": True}],
            reviewer="platform-admin",
            review_reason="approve compute only",
        )

        records = [
            item
            for item in audit_logger.read_records()
            if item.event == "plugin.permissions_granted" and item.plugin == "engine_approval_audit_plugin"
        ]
        self.assertEqual(records[-1].details["reviewer"], "platform-admin")
        self.assertEqual(records[-1].details["review_reason"], "approve compute only")
        self.assertEqual(records[-1].details["permissions"], ["compute"])
        self.assertEqual(records[-1].details["denied_permissions"], ["fs.write"])

    def test_legacy_manifest_without_permission_review_is_inferred_as_pending(self) -> None:
        source = self._make_plugin(
            "legacy_review_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)
        manifest_path = self.plugins_dir / "legacy_review_plugin" / MANIFEST_FILE
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.pop("permission_review")
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        reloaded = PluginLoader(self.plugins_dir)
        installed = reloaded.get_installed("legacy_review_plugin")
        self.assertIsNotNone(installed)
        self.assertTrue(installed.permission_review["required"])
        self.assertEqual(installed.permission_review["reason"], "legacy_install_pending_review")
        self.assertEqual(installed.permission_review["added_permissions"], ["compute", "fs.write"])

    def test_failed_upgrade_rolls_back_existing_plugin_directory(self) -> None:
        source_v1 = self._make_plugin(
            "rollback_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'version': 1}\n",
        )
        package_v1 = self._zip_plugin(source_v1)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package_v1)
        original_code = (self.plugins_dir / "rollback_plugin" / "src" / "main.py").read_text(encoding="utf-8")

        source_v2 = self._make_plugin(
            "rollback_plugin_v2_source",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'version': 2}\n",
        )
        (source_v2 / "plugin.yaml").write_text(
            self._metadata_yaml(
                "rollback_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
            ),
            encoding="utf-8",
        )
        package_v2 = self._zip_plugin(source_v2)

        real_copytree = __import__("shutil").copytree

        def fail_target_copytree(src: Path, dst: Path, *args: object, **kwargs: object) -> object:
            if Path(dst).name == "rollback_plugin":
                raise OSError("simulated copy failure")
            return real_copytree(src, dst, *args, **kwargs)

        with patch("modules.plugin_system.loader.shutil.copytree", side_effect=fail_target_copytree):
            with self.assertRaises(OSError):
                loader.install(package_v2)

        restored_code = (self.plugins_dir / "rollback_plugin" / "src" / "main.py").read_text(encoding="utf-8")
        self.assertEqual(restored_code, original_code)

    def test_install_manifest_records_file_integrity_hashes(self) -> None:
        source = self._make_plugin(
            "integrity_manifest_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)

        manifest = json.loads(
            (self.plugins_dir / "integrity_manifest_plugin" / MANIFEST_FILE).read_text(encoding="utf-8")
        )
        integrity = manifest["file_integrity"]
        self.assertEqual(integrity["algorithm"], "sha256")
        self.assertIn("plugin.yaml", integrity["files"])
        self.assertIn("src/main.py", integrity["files"])
        self.assertNotIn(MANIFEST_FILE, integrity["files"])

    def test_engine_refuses_to_start_tampered_plugin_file(self) -> None:
        source = self._make_plugin(
            "tamper_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "tamper_audit.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions("tamper_plugin")
        (self.plugins_dir / "tamper_plugin" / "src" / "main.py").write_text(
            "def run(args, api=None):\n    return {'tampered': True}\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(PluginPackageError, "integrity check failed"):
            engine.call_tool("tamper_plugin", "run", {})

        records = audit_logger.read_records()
        integrity_records = [
            item
            for item in records
            if item.event == "plugin.integrity_check" and item.plugin == "tamper_plugin"
        ]
        self.assertEqual(integrity_records[-1].result, "error")
        self.assertIn("changed", integrity_records[-1].details["error"])

    def test_runtime_data_files_do_not_break_integrity_check(self) -> None:
        source = self._make_plugin(
            "runtime_data_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("runtime_data_plugin")
        data_path = self.plugins_dir / "runtime_data_plugin" / "data" / "state.json"
        data_path.parent.mkdir(parents=True, exist_ok=True)
        data_path.write_text("{}", encoding="utf-8")
        try:
            result = engine.call_tool("runtime_data_plugin", "run", {})
            self.assertEqual(result["status"], "success")
        finally:
            engine.stop_all()

    def test_manifest_lock_is_recorded_and_tamper_is_rejected(self) -> None:
        source = self._make_plugin(
            "lock_manifest_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        write_package_lock(source)
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)

        self.assertEqual(loader.verify_package_lock("lock_manifest_plugin")["status"], "success")
        (self.plugins_dir / "lock_manifest_plugin" / "src" / "main.py").write_text(
            "def run(args, api=None):\n    return {'tampered': True}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PluginPackageError, "manifest.lock verification failed"):
            loader.verify_package_lock("lock_manifest_plugin")

    def test_production_install_requires_manifest_lock_for_third_party_plugin(self) -> None:
        source = self.root / "prod_missing_lock_plugin"
        (source / "src").mkdir(parents=True)
        (source / "src" / "__init__.py").write_text("", encoding="utf-8")
        (source / "src" / "main.py").write_text("def run(args, api=None):\n    return {'ok': True}\n", encoding="utf-8")
        (source / "plugin.yaml").write_text(
            self._metadata_yaml(
                "prod_missing_lock_plugin",
                runtime={"mode": "sub_process", "trust": "third_party"},
            ),
            encoding="utf-8",
        )
        package = self._zip_plugin(source)
        private_key = self.root / "prod-lock-private.pem"
        public_key = self.root / "prod-lock-public.pem"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="prod-lock@example.com")
        payload = verify_signature(package, signature, public_key=public_key)

        with self.assertRaisesRegex(PluginPackageError, "requires manifest.lock"):
            PluginLoader(self.plugins_dir, production_mode=True).install(package, signature=payload)

    def test_production_install_rejects_manifest_lock_hash_mismatch(self) -> None:
        source = self._make_plugin(
            "prod_bad_lock_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        write_package_lock(source)
        (source / "src" / "main.py").write_text(
            "def run(args, api=None):\n    return {'changed': True}\n",
            encoding="utf-8",
        )
        package = self.packages_dir / "prod_bad_lock_plugin.zip"
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in source.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(source).as_posix())
        private_key = self.root / "prod-bad-lock-private.pem"
        public_key = self.root / "prod-bad-lock-public.pem"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="prod-bad-lock@example.com")
        payload = verify_signature(package, signature, public_key=public_key)

        with self.assertRaisesRegex(PluginPackageError, "manifest.lock verification failed"):
            PluginLoader(self.plugins_dir, production_mode=True).install(package, signature=payload)

    def test_sandbox_backend_factory_reports_requested_backend(self) -> None:
        backend = create_sandbox_backend(128, 2, requested="python_guard")
        self.assertEqual(backend.report.name, "python_guard")
        self.assertFalse(backend.report.enforced)
        self.assertEqual(backend.report.details["memory_mb"], 128)
        self.assertTrue(backend.report.capabilities["language_runtime_guards"])
        self.assertIn("filesystem_isolation", backend.report.missing_capabilities())

    def test_bubblewrap_backend_reports_requested_backend_and_wraps_command_when_available(self) -> None:
        probe = {"ok": True}
        with patch("modules.plugin_system.sandbox_backend.sys.platform", "linux"), patch(
            "modules.plugin_system.sandbox_backend.shutil.which",
            return_value="/usr/bin/bwrap",
        ), patch("modules.plugin_system.sandbox_backend._probe_bubblewrap", return_value=probe):
            backend = create_sandbox_backend(128, 2, requested="bubblewrap")

        self.assertIsInstance(backend, BubblewrapBackend)
        self.assertEqual(backend.report.name, "bubblewrap")
        self.assertTrue(backend.requires_subprocess_launcher)
        self.assertTrue(backend.report.enforced)
        self.assertTrue(backend.report.capabilities["filesystem_isolation"])
        self.assertTrue(backend.report.capabilities["network_isolation"])

        plugin_dir = self.root / "plugins" / "bwrap_plugin"
        (plugin_dir / "data").mkdir(parents=True)
        command = ["python", "-m", "modules.plugin_system.sandbox_stdio_worker"]
        wrapped = backend.prepare_subprocess(command, plugin_dir=plugin_dir, project_root=Path.cwd())

        self.assertEqual(wrapped[0], "/usr/bin/bwrap")
        self.assertIn("--unshare-net", wrapped)
        self.assertIn("--clearenv", wrapped)
        self.assertIn("--tmpfs", wrapped)
        self.assertIn("--ro-bind", wrapped)
        self.assertIn("--bind", wrapped)
        self.assertEqual(wrapped[-len(command) :], command)
        self.assertIn(str(plugin_dir / "data"), backend.report.details["writable_binds"])
        self.assertEqual(backend.report.details["home"], str(plugin_dir / "data"))
        self.assertIn("_sandbox_runtime", backend.report.details["pythonpath"])
        self.assertNotIn(str(Path.cwd()), backend.report.details["readonly_binds"])

    def test_auto_backend_prefers_bubblewrap_on_linux(self) -> None:
        with patch("modules.plugin_system.sandbox_backend.sys.platform", "linux"), patch(
            "modules.plugin_system.sandbox_backend.shutil.which",
            return_value="/usr/bin/bwrap",
        ), patch("modules.plugin_system.sandbox_backend._probe_bubblewrap", return_value={"ok": True}):
            backend = create_sandbox_backend(128, 2, requested="auto")

        self.assertEqual(backend.report.name, "bubblewrap")
        self.assertTrue(backend.report.enforced)

    def test_auto_backend_fails_closed_when_linux_bubblewrap_is_unavailable(self) -> None:
        source = self._make_plugin(
            "auto_bwrap_required_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, require_enforced_sandbox=True)
        engine.install(package)
        engine.grant_permissions("auto_bwrap_required_plugin")

        with patch("modules.plugin_system.sandbox_backend.sys.platform", "linux"), patch(
            "modules.plugin_system.sandbox_backend.shutil.which",
            return_value=None,
        ):
            with self.assertRaisesRegex(SandboxStartupError, "bubblewrap"):
                engine.call_tool("auto_bwrap_required_plugin", "run", {})
        engine.stop_all()

    def test_bubblewrap_backend_missing_binary_is_not_strict_capable(self) -> None:
        with patch("modules.plugin_system.sandbox_backend.sys.platform", "linux"), patch(
            "modules.plugin_system.sandbox_backend.shutil.which",
            return_value=None,
        ):
            backend = create_sandbox_backend(128, 2, requested="bubblewrap")

        self.assertEqual(backend.report.name, "bubblewrap")
        self.assertFalse(backend.report.enforced)
        self.assertIn("filesystem_isolation", backend.report.missing_capabilities())
        self.assertTrue(backend.report.warnings)

    def test_external_enforced_backend_requires_complete_attestation(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            backend = create_sandbox_backend(128, 2, requested="external_enforced")
        self.assertEqual(backend.report.name, "external_enforced")
        self.assertFalse(backend.report.enforced)
        self.assertIn("filesystem_isolation", backend.report.missing_capabilities())
        self.assertTrue(backend.report.warnings)

        with patch.dict(
            os.environ,
            {
                EXTERNAL_SANDBOX_ATTESTATION_ENV: (
                    "process_containment,resource_limits,filesystem_isolation,network_isolation"
                )
            },
        ):
            backend = create_sandbox_backend(128, 2, requested="external_enforced")
        self.assertTrue(backend.report.enforced)
        self.assertEqual(backend.report.missing_capabilities(), [])
        self.assertTrue(backend.report.capabilities["filesystem_isolation"])
        self.assertTrue(backend.report.capabilities["network_isolation"])

    def test_sandbox_report_includes_backend_details(self) -> None:
        source = self._make_plugin(
            "backend_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)
        installed = loader.grant_permissions("backend_plugin")
        sandbox = SandboxManager(installed, self.plugins_dir, sandbox_backend="python_guard")
        try:
            self.assertTrue(sandbox.start())
            report = sandbox.report()
            self.assertIn("sandbox_backend", report.os_limits)
            self.assertEqual(report.os_limits["sandbox_backend"]["name"], "python_guard")
            self.assertIn("capabilities", report.os_limits["sandbox_backend"])
            self.assertIn("missing_capabilities", report.os_limits["sandbox_backend"])
        finally:
            sandbox.stop()

    def test_strict_sandbox_rejects_non_enforced_backend_for_third_party_plugin(self) -> None:
        source = self._make_plugin(
            "strict_backend_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "strict_backend.log")
        engine = PluginEngine(
            self.plugins_dir,
            sandbox_backend="python_guard",
            audit_logger=audit_logger,
            require_enforced_sandbox=True,
        )
        engine.install(package)
        engine.grant_permissions("strict_backend_plugin")

        with self.assertRaisesRegex(SandboxStartupError, "production isolation capabilities"):
            engine.call_tool("strict_backend_plugin", "run", {})

        self.assertNotIn("strict_backend_plugin", engine.sandboxes)
        start_failures = [
            item
            for item in audit_logger.read_records()
            if item.event == "plugin.start_failed" and item.plugin == "strict_backend_plugin"
        ]
        self.assertTrue(start_failures)
        self.assertTrue(start_failures[-1].details["require_enforced_sandbox"])
        self.assertEqual(start_failures[-1].details["sandbox_backend"], "python_guard")
        engine.stop_all()

    def test_cli_strict_start_rejects_non_enforced_backend(self) -> None:
        source = self._make_plugin(
            "cli_strict_backend_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        install_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "install",
                str(package),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(install_result.returncode, 0, install_result.stderr)
        approve_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "approve",
                "cli_strict_backend_plugin",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(approve_result.returncode, 0, approve_result.stderr)

        start_result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "--plugins-dir",
                str(self.plugins_dir),
                "--sandbox-backend",
                "python_guard",
                "--strict-sandbox",
                "start",
                "cli_strict_backend_plugin",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(start_result.returncode, 0)
        self.assertIn("production isolation capabilities", start_result.stderr)
        self.assertIn("filesystem_isolation", start_result.stderr)

    def test_strict_sandbox_allows_official_in_process_plugin(self) -> None:
        source = self._make_plugin(
            "strict_official_plugin",
            runtime={"mode": "in_process", "trust": "official"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(
            self.plugins_dir,
            sandbox_backend="python_guard",
            require_enforced_sandbox=True,
        )
        engine.install(package)

        result = engine.call_tool("strict_official_plugin", "run", {})
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["data"], {"ok": True})
        engine.stop_all()

    def test_strict_sandbox_allows_attested_external_backend(self) -> None:
        source = self._make_plugin(
            "strict_external_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        with patch.dict(
            os.environ,
            {
                EXTERNAL_SANDBOX_ATTESTATION_ENV: (
                    "process_containment,resource_limits,filesystem_isolation,network_isolation"
                )
            },
        ):
            engine = PluginEngine(
                self.plugins_dir,
                sandbox_backend="external_enforced",
                require_enforced_sandbox=True,
            )
            engine.install(package)
            engine.grant_permissions("strict_external_plugin")
            try:
                result = engine.call_tool("strict_external_plugin", "run", {})
                self.assertEqual(result["status"], "success")
                report = engine.sandboxes["strict_external_plugin"].report()
                backend = report.os_limits["sandbox_backend"]
                self.assertEqual(backend["name"], "external_enforced")
                self.assertTrue(backend["enforced"])
                self.assertEqual(backend["missing_capabilities"], [])
            finally:
                engine.stop_all()

    def test_bubblewrap_backend_uses_stdio_launcher_and_fails_strict_when_unavailable(self) -> None:
        source = self._make_plugin(
            "strict_bubblewrap_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(
            self.plugins_dir,
            sandbox_backend="bubblewrap",
            require_enforced_sandbox=True,
        )
        engine.install(package)
        engine.grant_permissions("strict_bubblewrap_plugin")

        with patch("modules.plugin_system.sandbox_backend.sys.platform", "linux"), patch(
            "modules.plugin_system.sandbox_backend.shutil.which",
            return_value=None,
        ):
            with self.assertRaisesRegex(SandboxStartupError, "bubblewrap"):
                engine.call_tool("strict_bubblewrap_plugin", "run", {})
        engine.stop_all()

    def test_bubblewrap_os_sandbox_blocks_host_and_allows_plugin_data(self) -> None:
        if sys.platform != "linux":
            self.skipTest("bubblewrap OS sandbox integration test requires Linux")
        if not shutil.which("bwrap"):
            self.skipTest("bubblewrap executable is not available")
        backend = create_sandbox_backend(128, 2, requested="bubblewrap")
        if not backend.report.enforced:
            self.skipTest("; ".join(backend.report.warnings) or "bubblewrap is not usable")

        home_secret = Path.home() / f".humanoid_agi_sandbox_secret_{uuid.uuid4().hex}"
        project_env = Path.cwd() / ".env"
        previous_env = project_env.read_text(encoding="utf-8") if project_env.exists() else None
        home_secret.write_text("home-secret", encoding="utf-8")
        project_env.write_text("env-secret", encoding="utf-8")
        self.addCleanup(lambda: home_secret.exists() and home_secret.unlink())
        if previous_env is None:
            self.addCleanup(lambda: project_env.exists() and project_env.unlink())
        else:
            self.addCleanup(lambda: project_env.write_text(previous_env, encoding="utf-8"))

        code = f"""
import _socket
import io

def _can_read(path):
    try:
        handle = io.open(path, "r", encoding="utf-8")
        try:
            handle.read()
        finally:
            handle.close()
        return True
    except Exception:
        return False

def _can_write(path):
    try:
        handle = io.open(path, "w", encoding="utf-8")
        try:
            handle.write("blocked")
        finally:
            handle.close()
        return True
    except Exception:
        return False

def _direct_network_available():
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(("93.184.216.34", 80))
        sock.close()
        return True
    except Exception:
        return False

def run(args, api=None):
    api.write_file("allowed.txt", "data-ok")
    return {{
        "host_env_readable": _can_read({str(project_env)!r}),
        "host_home_readable": _can_read({str(home_secret)!r}),
        "core_readable": _can_read({str((Path.cwd() / "SPECIFICATION").resolve())!r}),
        "code_writable": _can_write(__file__.replace("main.py", "blocked_write.txt")),
        "direct_network_available": _direct_network_available(),
        "data_content": api.read_file("allowed.txt"),
    }}
"""
        source = self._make_plugin(
            "bwrap_isolation_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.read": True}, {"fs.write": True}],
            code=textwrap.dedent(code),
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="bubblewrap")
        engine.install(package)
        engine.grant_permissions("bwrap_isolation_plugin")
        try:
            result = engine.call_tool("bwrap_isolation_plugin", "run", {})
            self.assertEqual(result["status"], "success", result)
            data = result["data"]
            self.assertFalse(data["host_env_readable"])
            self.assertFalse(data["host_home_readable"])
            self.assertFalse(data["core_readable"])
            self.assertFalse(data["code_writable"])
            self.assertFalse(data["direct_network_available"])
            self.assertEqual(data["data_content"], "data-ok")
        finally:
            engine.stop_all()

    def test_engine_passes_configured_sandbox_backend_to_plugin_sandbox(self) -> None:
        source = self._make_plugin(
            "engine_backend_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("engine_backend_plugin")
        try:
            result = engine.call_tool("engine_backend_plugin", "run", {})
            self.assertEqual(result["status"], "success")
            report = engine.sandboxes["engine_backend_plugin"].report()
            self.assertEqual(report.os_limits["sandbox_backend"]["name"], "python_guard")
        finally:
            engine.stop_all()

    def test_plugin_concurrency_limit_rejects_overlapping_calls(self) -> None:
        source = self._make_plugin(
            "concurrency_plugin",
            runtime={
                "mode": "sub_process",
                "trust": "third_party",
                "max_concurrency": 1,
                "failure_threshold": 5,
            },
            code=textwrap.dedent(
                """
                import time

                def run(args, api=None):
                    time.sleep(0.4)
                    return {'ok': True}
                """
            ),
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "concurrency.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions("concurrency_plugin")
        first_result: dict[str, object] = {}

        def call_first() -> None:
            first_result.update(engine.call_tool("concurrency_plugin", "run", {}))

        thread = threading.Thread(target=call_first)
        thread.start()
        time.sleep(0.1)
        try:
            second_result = engine.call_tool("concurrency_plugin", "run", {})
            self.assertEqual(second_result["status"], "error")
            self.assertIn("concurrency limit", second_result["error"])
        finally:
            thread.join(timeout=2)
            engine.stop_all()

        self.assertEqual(first_result["status"], "success")
        records = [
            item
            for item in audit_logger.read_records()
            if item.event == "plugin.concurrency_rejected" and item.plugin == "concurrency_plugin"
        ]
        self.assertEqual(records[-1].details["max_concurrency"], 1)

    def test_failure_threshold_auto_disables_plugin(self) -> None:
        source = self._make_plugin(
            "breaker_plugin",
            runtime={
                "mode": "sub_process",
                "trust": "third_party",
                "failure_threshold": 2,
            },
            code="def run(args, api=None):\n    raise RuntimeError('boom')\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "breaker.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions("breaker_plugin")
        try:
            first = engine.call_tool("breaker_plugin", "run", {})
            self.assertEqual(first["status"], "error")
            installed = engine.loader.get_installed("breaker_plugin")
            self.assertIsNotNone(installed)
            self.assertEqual(installed.status.value, "enabled")

            second = engine.call_tool("breaker_plugin", "run", {})
            self.assertEqual(second["status"], "error")
            installed = engine.loader.get_installed("breaker_plugin")
            self.assertIsNotNone(installed)
            self.assertEqual(installed.status.value, "disabled")

            with self.assertRaisesRegex(Exception, "disabled"):
                engine.call_tool("breaker_plugin", "run", {})
        finally:
            engine.stop_all()

        records = [
            item
            for item in audit_logger.read_records()
            if item.event == "plugin.circuit_opened" and item.plugin == "breaker_plugin"
        ]
        self.assertEqual(records[-1].details["failure_threshold"], 2)

    def test_success_resets_consecutive_failure_count(self) -> None:
        source = self._make_plugin(
            "failure_reset_plugin",
            runtime={
                "mode": "sub_process",
                "trust": "third_party",
                "failure_threshold": 2,
            },
            code=textwrap.dedent(
                """
                def run(args, api=None):
                    if args.get('fail'):
                        raise RuntimeError('boom')
                    return {'ok': True}
                """
            ),
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "failure_reset.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions("failure_reset_plugin")
        try:
            self.assertEqual(engine.call_tool("failure_reset_plugin", "run", {"fail": True})["status"], "error")
            self.assertEqual(engine.call_tool("failure_reset_plugin", "run", {"fail": False})["status"], "success")
            self.assertEqual(engine.call_tool("failure_reset_plugin", "run", {"fail": True})["status"], "error")
            installed = engine.loader.get_installed("failure_reset_plugin")
            self.assertIsNotNone(installed)
            self.assertEqual(installed.status.value, "enabled")
        finally:
            engine.stop_all()

    def test_install_records_dependency_environment_without_implicit_downloads(self) -> None:
        source = self._make_plugin(
            "deps_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)

        manifest_path = self.plugins_dir / "deps_plugin" / DEPENDENCY_MANIFEST
        self.assertTrue(manifest_path.exists())
        environment = DependencyManager(self.plugins_dir).read_environment(self.plugins_dir / "deps_plugin")
        self.assertIsNotNone(environment)
        self.assertEqual(environment.backend, "venv")
        self.assertFalse(environment.installed)
        self.assertEqual(environment.packages, ["idna==3.7"])

    def test_dependency_install_requires_hashed_lockfile_for_third_party_plugins(self) -> None:
        source = self._make_plugin(
            "deps_no_lock_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)

        with self.assertRaisesRegex(Exception, "requires requirements.lock"):
            loader.install(package, install_dependencies=True)

    def test_production_install_rejects_unlocked_dependencies_even_without_install(self) -> None:
        source = self._make_plugin(
            "prod_deps_no_lock_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        write_package_lock(source)
        package = self._zip_plugin(source)
        private_key = self.root / "prod-deps-private.pem"
        public_key = self.root / "prod-deps-public.pem"
        generate_keypair(private_key, public_key)
        signature = sign_package(package, private_key=private_key, publisher="prod-deps@example.com")
        payload = verify_signature(package, signature, public_key=public_key)

        with self.assertRaisesRegex(Exception, "requires requirements.lock"):
            PluginLoader(self.plugins_dir, production_mode=True).install(package, signature=payload)

    def test_dependency_install_uses_hash_pinned_lockfile(self) -> None:
        source = self._make_plugin(
            "deps_lock_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        wheelhouse = source / DEPENDENCY_WHEELHOUSE_DIR
        wheelhouse.mkdir()
        wheel_bytes = b"install fake wheel bytes"
        wheel_digest = hashlib.sha256(wheel_bytes).hexdigest()
        (wheelhouse / "idna-3.7-py3-none-any.whl").write_bytes(wheel_bytes)
        (source / DEPENDENCY_LOCK_FILE).write_text(
            f"idna==3.7 --hash=sha256:{wheel_digest}\n",
            encoding="utf-8",
        )
        write_package_lock(source)
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)

        with patch("modules.plugin_system.dependency.subprocess.run") as run:
            run.return_value.returncode = 0
            loader.install(package, install_dependencies=True)

        command = run.call_args.args[0]
        self.assertIn("--no-index", command)
        self.assertIn("--find-links", command)
        self.assertIn(str(self.plugins_dir / "deps_lock_plugin" / DEPENDENCY_WHEELHOUSE_DIR), command)
        self.assertIn("--require-hashes", command)
        self.assertIn("--only-binary", command)
        self.assertIn(":all:", command)
        self.assertIn("--no-build-isolation", command)
        self.assertIn("-r", command)
        self.assertIn(str(self.plugins_dir / "deps_lock_plugin" / DEPENDENCY_LOCK_FILE), command)
        environment = DependencyManager(self.plugins_dir).read_environment(self.plugins_dir / "deps_lock_plugin")
        self.assertIsNotNone(environment)
        self.assertTrue(environment.installed)
        self.assertTrue(environment.hash_required)
        self.assertEqual(environment.lockfile, DEPENDENCY_LOCK_FILE)

    def test_dependency_install_rejects_unhashed_lockfile(self) -> None:
        source = self._make_plugin(
            "deps_unhashed_lock_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        (source / DEPENDENCY_LOCK_FILE).write_text("idna==3.7\n", encoding="utf-8")
        write_package_lock(source)
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)

        with self.assertRaisesRegex(Exception, "missing --hash=sha256"):
            loader.install(package, install_dependencies=True)

    def test_dependency_install_requires_vendored_wheelhouse(self) -> None:
        source = self._make_plugin(
            "deps_missing_wheels_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        (source / DEPENDENCY_LOCK_FILE).write_text(
            "idna==3.7 --hash=sha256:" + "a" * 64 + "\n",
            encoding="utf-8",
        )
        write_package_lock(source)
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)

        with self.assertRaisesRegex(Exception, "vendored wheels"):
            loader.install(package, install_dependencies=True)

    def test_dependency_install_rejects_wheelhouse_hash_mismatch(self) -> None:
        source = self._make_plugin(
            "deps_bad_wheel_hash_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        wheelhouse = source / DEPENDENCY_WHEELHOUSE_DIR
        wheelhouse.mkdir()
        (wheelhouse / "idna-3.7-py3-none-any.whl").write_bytes(b"actual wheel bytes")
        (source / DEPENDENCY_LOCK_FILE).write_text(
            "idna==3.7 --hash=sha256:" + "a" * 64 + "\n",
            encoding="utf-8",
        )
        write_package_lock(source)
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)

        with self.assertRaisesRegex(Exception, "wheel hash does not match"):
            loader.install(package, install_dependencies=True)

    def test_dependency_install_rejects_lockfile_version_mismatch(self) -> None:
        source = self._make_plugin(
            "deps_mismatched_lock_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        (source / DEPENDENCY_LOCK_FILE).write_text(
            "idna==3.8 --hash=sha256:" + "a" * 64 + "\n",
            encoding="utf-8",
        )
        write_package_lock(source)
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)

        with self.assertRaisesRegex(Exception, "version mismatch"):
            loader.install(package, install_dependencies=True)

    def test_dependency_policy_rejects_native_wheel_by_default(self) -> None:
        source = self._make_plugin(
            "deps_native_wheel_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["fastjson==1.0.0"],
        )
        wheelhouse = source / DEPENDENCY_WHEELHOUSE_DIR
        wheelhouse.mkdir()
        wheel_bytes = b"native wheel bytes"
        digest = hashlib.sha256(wheel_bytes).hexdigest()
        (wheelhouse / "fastjson-1.0.0-cp311-cp311-win_amd64.whl").write_bytes(wheel_bytes)
        (source / DEPENDENCY_LOCK_FILE).write_text(
            f"fastjson==1.0.0 --hash=sha256:{digest}\n",
            encoding="utf-8",
        )
        write_package_lock(source)
        package = self._zip_plugin(source)

        with self.assertRaisesRegex(Exception, "native extension wheel"):
            PluginLoader(self.plugins_dir).install(package)

    def test_dependency_scanner_adapter_can_block_install(self) -> None:
        source = self._make_plugin(
            "deps_scanner_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        wheelhouse = source / DEPENDENCY_WHEELHOUSE_DIR
        wheelhouse.mkdir()
        wheel_bytes = b"scanner wheel bytes"
        digest = hashlib.sha256(wheel_bytes).hexdigest()
        (wheelhouse / "idna-3.7-py3-none-any.whl").write_bytes(wheel_bytes)
        (source / DEPENDENCY_LOCK_FILE).write_text(
            f"idna==3.7 --hash=sha256:{digest}\n",
            encoding="utf-8",
        )
        write_package_lock(source)
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.dependency_manager.scan_policy = DependencyScanPolicy(
            vulnerability_scanner=_FailingDependencyScanner(),
        )

        with self.assertRaisesRegex(Exception, "vulnerability scanner failed policy"):
            loader.install(package)

    def test_dependency_scanner_adapter_records_passed_reports(self) -> None:
        source = self._make_plugin(
            "deps_scanner_pass_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        wheelhouse = source / DEPENDENCY_WHEELHOUSE_DIR
        wheelhouse.mkdir()
        wheel_bytes = b"scanner pass wheel bytes"
        digest = hashlib.sha256(wheel_bytes).hexdigest()
        (wheelhouse / "idna-3.7-py3-none-any.whl").write_bytes(wheel_bytes)
        (source / DEPENDENCY_LOCK_FILE).write_text(
            f"idna==3.7 --hash=sha256:{digest}\n",
            encoding="utf-8",
        )
        write_package_lock(source)
        package = self._zip_plugin(source)
        scanner = _AllowingDependencyScanner()
        loader = PluginLoader(self.plugins_dir)
        loader.dependency_manager.scan_policy = DependencyScanPolicy(
            vulnerability_scanner=scanner,
            license_scanner=scanner,
        )

        loader.install(package)

        environment = DependencyManager(self.plugins_dir).read_environment(
            self.plugins_dir / "deps_scanner_pass_plugin"
        )
        self.assertIsNotNone(environment)
        self.assertEqual(len(scanner.calls), 4)
        self.assertEqual(
            [item["type"] for item in environment.scan_reports],
            ["vulnerability", "license"],
        )

    def test_lock_requirements_writes_hash_pinned_lockfile_from_wheelhouse(self) -> None:
        source = self._make_plugin(
            "deps_lock_gen_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        wheelhouse = self.root / "wheelhouse"
        wheelhouse.mkdir()
        wheel_bytes = b"fake wheel bytes"
        (wheelhouse / "idna-3.7-py3-none-any.whl").write_bytes(wheel_bytes)

        metadata = PluginLoader(self.plugins_dir).read_metadata(source / "plugin.yaml")
        lockfile = lock_requirements(source, metadata, wheelhouse)

        digest = hashlib.sha256(wheel_bytes).hexdigest()
        self.assertEqual(source / DEPENDENCY_LOCK_FILE, lockfile)
        self.assertEqual(
            f"idna==3.7 --hash=sha256:{digest}\n",
            lockfile.read_text(encoding="utf-8"),
        )

    def test_lock_requirements_can_vendor_wheels_into_plugin_source(self) -> None:
        source = self._make_plugin(
            "deps_vendor_lock_gen_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        wheelhouse = self.root / "vendor-wheelhouse"
        wheelhouse.mkdir()
        wheel_bytes = b"vendored fake wheel bytes"
        (wheelhouse / "idna-3.7-py3-none-any.whl").write_bytes(wheel_bytes)

        metadata = PluginLoader(self.plugins_dir).read_metadata(source / "plugin.yaml")
        lock_requirements(source, metadata, wheelhouse, vendor=True)

        self.assertEqual(
            wheel_bytes,
            (source / DEPENDENCY_WHEELHOUSE_DIR / "idna-3.7-py3-none-any.whl").read_bytes(),
        )

    def test_lock_requirements_rejects_unpinned_declared_package(self) -> None:
        source = self._make_plugin(
            "deps_unpinned_lock_gen_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna>=3.7"],
        )
        wheelhouse = self.root / "wheelhouse-unpinned"
        wheelhouse.mkdir()
        metadata = PluginLoader(self.plugins_dir).read_metadata(source / "plugin.yaml")

        with self.assertRaisesRegex(Exception, "exact package pins"):
            lock_requirements(source, metadata, wheelhouse)

    def test_sbom_generation_includes_plugin_files_and_dependencies(self) -> None:
        source = self._make_plugin(
            "sbom_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        wheelhouse = source / DEPENDENCY_WHEELHOUSE_DIR
        wheelhouse.mkdir()
        wheel_bytes = b"sbom wheel bytes"
        digest = hashlib.sha256(wheel_bytes).hexdigest()
        (wheelhouse / "idna-3.7-py3-none-any.whl").write_bytes(wheel_bytes)
        (source / DEPENDENCY_LOCK_FILE).write_text(
            f"idna==3.7 --hash=sha256:{digest}\n",
            encoding="utf-8",
        )
        write_package_lock(source)

        sbom = generate_sbom(source)

        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["metadata"]["component"]["name"], "sbom_plugin")
        self.assertEqual(sbom["metadata"]["component"]["version"], "1.0.0")
        file_components = {item["name"]: item for item in sbom["components"] if item["type"] == "file"}
        dependency_components = {item["name"]: item for item in sbom["components"] if item["type"] == "library"}
        self.assertIn("plugin.yaml", file_components)
        self.assertIn("src/main.py", file_components)
        self.assertEqual(dependency_components["idna"]["version"], "3.7")
        self.assertEqual(dependency_components["idna"]["hashes"][0]["content"], digest)

    def test_cli_sbom_writes_cyclonedx_json(self) -> None:
        source = self._make_plugin(
            "cli_sbom_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        output = self.root / "cli-sbom.json"

        result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "sbom",
                str(source),
                "--output",
                str(output),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["bomFormat"], "CycloneDX")
        self.assertEqual(payload["metadata"]["component"]["name"], "cli_sbom_plugin")

    def test_cli_lock_writes_requirements_lock(self) -> None:
        source = self._make_plugin(
            "cli_lock_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        wheelhouse = self.root / "cli-wheelhouse"
        wheelhouse.mkdir()
        wheel_bytes = b"cli fake wheel bytes"
        (wheelhouse / "idna-3.7-py3-none-any.whl").write_bytes(wheel_bytes)

        result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "lock",
                str(source),
                "--wheelhouse",
                str(wheelhouse),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )

        digest = hashlib.sha256(wheel_bytes).hexdigest()
        lockfile = source / DEPENDENCY_LOCK_FILE
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Locked", result.stdout)
        self.assertEqual(
            f"idna==3.7 --hash=sha256:{digest}\n",
            lockfile.read_text(encoding="utf-8"),
        )

    def test_cli_lock_vendor_copies_wheels(self) -> None:
        source = self._make_plugin(
            "cli_vendor_lock_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        wheelhouse = self.root / "cli-vendor-wheelhouse"
        wheelhouse.mkdir()
        wheel_bytes = b"cli vendored fake wheel bytes"
        (wheelhouse / "idna-3.7-py3-none-any.whl").write_bytes(wheel_bytes)

        result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "lock",
                str(source),
                "--wheelhouse",
                str(wheelhouse),
                "--vendor",
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Vendored wheels", result.stdout)
        self.assertEqual(
            wheel_bytes,
            (source / DEPENDENCY_WHEELHOUSE_DIR / "idna-3.7-py3-none-any.whl").read_bytes(),
        )

    def test_sandbox_uses_dependency_python_when_environment_is_installed(self) -> None:
        source = self._make_plugin(
            "runtime_deps_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            packages=["idna==3.7"],
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)
        installed = loader.grant_permissions("runtime_deps_plugin")
        plugin_dir = self.plugins_dir / "runtime_deps_plugin"
        environment = DependencyManager(self.plugins_dir).read_environment(plugin_dir)
        self.assertIsNotNone(environment)
        fake_python = Path(environment.python)
        fake_python.parent.mkdir(parents=True, exist_ok=True)
        fake_python.write_text("", encoding="utf-8")
        environment.installed = True
        DependencyManager(self.plugins_dir).write_environment(plugin_dir, environment)

        sandbox = SandboxManager(installed, self.plugins_dir, sandbox_backend="python_guard")
        self.assertEqual(sandbox.runtime_python, str(fake_python))
        self.assertNotEqual(sandbox.runtime_python, sys.executable)

    def test_plugin_config_schema_defaults_are_available_through_gateway(self) -> None:
        source = self._make_plugin(
            "config_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"config.read": True}],
            code=textwrap.dedent(
                """
                def run(args, api):
                    return {'api_key': api.read_config('api_key'), 'units': api.read_config('units')}
                """
            ),
        )
        self._write_config_schema(
            source,
            {
                "type": "object",
                "required": ["api_key"],
                "properties": {
                    "api_key": {"type": "string"},
                    "units": {"type": "string", "default": "metric"},
                },
            },
            {"api_key": "secret"},
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("config_plugin")

        effective_path = self.plugins_dir / "config_plugin" / CONFIG_EFFECTIVE_FILE
        self.assertTrue(effective_path.exists())
        try:
            result = engine.call_tool("config_plugin", "run", {})
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["data"], {"api_key": "secret", "units": "metric"})
        finally:
            engine.stop_all()

    def test_config_read_requires_granted_permission(self) -> None:
        source = self._make_plugin(
            "config_denied_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"config.read": True}],
            code="def run(args, api):\n    return api.read_config('api_key')\n",
        )
        self._write_config_schema(
            source,
            {
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "default": "secret"},
                },
            },
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("config_denied_plugin", [{"compute": True}])
        try:
            result = engine.call_tool("config_denied_plugin", "run", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("config.read", result["error"])
        finally:
            engine.stop_all()

    def test_output_send_requires_granted_permission_and_records_message(self) -> None:
        source = self._make_plugin(
            "output_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"output.send": True}],
            code=textwrap.dedent(
                """
                def run(args, api):
                    return api.send_output(
                        {'text': args.get('text', 'hello')},
                        channel='assistant',
                        content_type='application/json',
                    )
                """
            ),
        )
        package = self._zip_plugin(source)
        output_store: list[dict[str, object]] = []
        gateway = PluginGateway(data_dir=self.plugins_dir, output_store=output_store)
        engine = PluginEngine(self.plugins_dir, gateway=gateway, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("output_plugin")
        try:
            result = engine.call_tool("output_plugin", "run", {"text": "ready"})
            self.assertEqual(result["status"], "success")
            self.assertEqual(len(output_store), 1)
            self.assertEqual(output_store[0]["plugin"], "output_plugin")
            self.assertEqual(output_store[0]["channel"], "assistant")
            self.assertEqual(output_store[0]["content"], {"text": "ready"})
            self.assertEqual(result["data"], output_store[0])
        finally:
            engine.stop_all()

    def test_output_send_denied_without_granted_permission(self) -> None:
        source = self._make_plugin(
            "output_denied_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"output.send": True}],
            code="def run(args, api):\n    return api.send_output('blocked')\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "output_denied.log")
        output_store: list[dict[str, object]] = []
        gateway = PluginGateway(
            data_dir=self.plugins_dir,
            output_store=output_store,
            audit_logger=audit_logger,
        )
        engine = PluginEngine(
            self.plugins_dir,
            gateway=gateway,
            sandbox_backend="python_guard",
            audit_logger=audit_logger,
        )
        engine.install(package)
        engine.grant_permissions("output_denied_plugin", [{"compute": True}])
        try:
            result = engine.call_tool("output_denied_plugin", "run", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("output.send", result["error"])
            self.assertEqual(output_store, [])
            denied_records = [
                item
                for item in audit_logger.read_records()
                if item.event == "plugin.gateway_request"
                and item.plugin == "output_denied_plugin"
                and item.action == "output.send"
            ]
            self.assertEqual(denied_records[-1].result, "error")
            self.assertEqual(denied_records[-1].details["error_type"], "PermissionDenied")
        finally:
            engine.stop_all()

    def test_invalid_plugin_config_rejects_install(self) -> None:
        source = self._make_plugin(
            "bad_config_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        self._write_config_schema(
            source,
            {
                "type": "object",
                "required": ["api_key"],
                "properties": {
                    "api_key": {"type": "string"},
                },
            },
            {},
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        with self.assertRaises(PluginConfigError):
            loader.install(package)

    def test_event_listener_extension_receives_published_events(self) -> None:
        source = self._make_plugin(
            "event_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code=textwrap.dedent(
                """
                def on_user_message(event, api):
                    api.write_file('last_event.txt', event['data']['text'])
                    return {'handled': event['name'], 'source': event['source']}
                """
            ),
            extensions=[
                {"type": "event_listener", "events": ["user.message"], "entry": "src.main:on_user_message"}
            ],
        )
        package = self._zip_plugin(source)
        event_bus = EventBus()
        engine = PluginEngine(self.plugins_dir, event_bus=event_bus, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("event_plugin")
        self.assertEqual(
            engine.event_listeners()["event_plugin"],
            {"user.message": ["src.main:on_user_message"]},
        )
        engine.start_plugin("event_plugin")

        try:
            results = event_bus.publish("user.message", {"text": "hello"}, source="test")
            self.assertEqual(results[0]["status"], "success")
            self.assertEqual(results[0]["data"][0]["handled"], "user.message")
            self.assertEqual(
                (self.plugins_dir / "event_plugin" / "data" / "last_event.txt").read_text(encoding="utf-8"),
                "hello",
            )
        finally:
            engine.stop_all()

    def test_event_listeners_are_unregistered_when_plugin_stops(self) -> None:
        source = self._make_plugin(
            "event_stop_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def on_event(event, api=None):\n    return {'ok': True}\n",
            extensions=[
                {"type": "event_listener", "events": ["user.message"], "entry": "src.main:on_event"}
            ],
        )
        package = self._zip_plugin(source)
        event_bus = EventBus()
        engine = PluginEngine(self.plugins_dir, event_bus=event_bus, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("event_stop_plugin")
        engine.start_plugin("event_stop_plugin")
        self.assertEqual(event_bus.listener_count("user.message"), 1)

        engine.stop_plugin("event_stop_plugin")
        self.assertEqual(event_bus.listener_count("user.message"), 0)

    def test_event_listener_requires_entry(self) -> None:
        with self.assertRaises(ValueError):
            PluginMetadata(
                name="bad_event_plugin",
                version="1.0.0",
                description="Bad event listener plugin",
                author="test",
                extensions=[{"type": "event_listener", "events": ["user.message"]}],
            )

    def test_middleware_extension_transforms_context(self) -> None:
        source = self._make_plugin(
            "middleware_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code=textwrap.dedent(
                """
                def enrich(context, api=None):
                    context = dict(context)
                    context['text'] = context.get('text', '').strip().upper()
                    context['middleware'] = 'enrich'
                    return context
                """
            ),
            extensions=[
                {"type": "middleware", "name": "enrich", "entry": "src.main:enrich"}
            ],
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("middleware_plugin")
        try:
            self.assertEqual(
                engine.middlewares()["middleware_plugin"],
                {"enrich": "src.main:enrich"},
            )
            result = engine.run_middlewares({"text": " hello "})
            self.assertEqual(result, {"text": "HELLO", "middleware": "enrich"})
        finally:
            engine.stop_all()

    def test_middleware_must_return_dict(self) -> None:
        source = self._make_plugin(
            "bad_middleware_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def bad(context, api=None):\n    return 'not a dict'\n",
            extensions=[
                {"type": "middleware", "name": "bad", "entry": "src.main:bad"}
            ],
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("bad_middleware_plugin")
        try:
            with self.assertRaises(PluginMiddlewareError):
                engine.run_middlewares({"text": "hello"})
        finally:
            engine.stop_all()

    def test_loader_rejects_missing_middleware_entry_module(self) -> None:
        source = self._make_plugin(
            "missing_middleware_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            extensions=[
                {"type": "middleware", "name": "missing", "entry": "src.missing:run"}
            ],
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        with self.assertRaises(PluginPackageError):
            loader.install(package)

    def test_memory_provider_extension_handles_operations(self) -> None:
        source = self._make_plugin(
            "memory_provider_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"memory.read": True}, {"memory.write": True}],
            code=textwrap.dedent(
                """
                def kv_memory(request, api):
                    operation = request.get('operation')
                    payload = request.get('payload') or {}
                    if operation == 'store':
                        api.write_memory(payload['key'], payload['value'])
                        return {'stored': payload['key']}
                    if operation == 'retrieve':
                        return {'value': api.read_memory(payload['key'])}
                    return {'operation': operation}
                """
            ),
            extensions=[
                {"type": "memory_provider", "name": "kv", "entry": "src.main:kv_memory"}
            ],
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("memory_provider_plugin")
        try:
            self.assertEqual(
                engine.memory_providers()["memory_provider_plugin"],
                {"kv": "src.main:kv_memory"},
            )
            stored = engine.call_memory_provider(
                "memory_provider_plugin",
                "kv",
                "store",
                {"key": "city", "value": {"name": "Shanghai"}},
            )
            self.assertEqual(stored["status"], "success")
            self.assertEqual(stored["data"], {"stored": "city"})

            retrieved = engine.call_memory_provider(
                "memory_provider_plugin",
                "kv",
                "retrieve",
                {"key": "city"},
            )
            self.assertEqual(retrieved["status"], "success")
            self.assertEqual(retrieved["data"], {"value": {"name": "Shanghai"}})
        finally:
            engine.stop_all()

    def test_memory_provider_gateway_requires_granted_memory_permission(self) -> None:
        source = self._make_plugin(
            "memory_denied_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"memory.read": True}],
            code="def memory(request, api):\n    return api.read_memory('secret')\n",
            extensions=[
                {"type": "memory_provider", "name": "reader", "entry": "src.main:memory"}
            ],
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("memory_denied_plugin", [{"compute": True}])
        try:
            result = engine.call_memory_provider("memory_denied_plugin", "reader", "retrieve", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("memory.read", result["error"])
        finally:
            engine.stop_all()

    def test_memory_provider_unknown_name_returns_error(self) -> None:
        source = self._make_plugin(
            "memory_unknown_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def memory(request, api=None):\n    return {'ok': True}\n",
            extensions=[
                {"type": "memory_provider", "name": "known", "entry": "src.main:memory"}
            ],
        )
        package = self._zip_plugin(source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(package)
        engine.grant_permissions("memory_unknown_plugin")
        try:
            result = engine.call_memory_provider("memory_unknown_plugin", "missing", "retrieve", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("not declared", result["error"])
        finally:
            engine.stop_all()

    def test_loader_rejects_missing_memory_provider_entry_module(self) -> None:
        source = self._make_plugin(
            "missing_memory_provider_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
            extensions=[
                {"type": "memory_provider", "name": "missing", "entry": "src.missing:memory"}
            ],
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        with self.assertRaises(PluginPackageError):
            loader.install(package)

    def test_audit_log_records_tool_call_and_gateway_request_with_same_request_id(self) -> None:
        source = self._make_plugin(
            "audit_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code=textwrap.dedent(
                """
                def run(args, api):
                    api.write_file('audit.txt', args.get('message', 'ok'))
                    return {'ok': True}
                """
            ),
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "audit.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions("audit_plugin")
        try:
            result = engine.call_tool("audit_plugin", "run", {"message": "hello"})
            self.assertEqual(result["status"], "success")
            self.assertIn("request_id", result)

            records = audit_logger.read_records()
            tool_records = [
                item
                for item in records
                if item.event == "plugin.tool_call" and item.plugin == "audit_plugin"
            ]
            gateway_records = [
                item
                for item in records
                if item.event == "plugin.gateway_request"
                and item.plugin == "audit_plugin"
                and item.action == "fs.write"
            ]
            self.assertEqual(tool_records[-1].request_id, result["request_id"])
            self.assertEqual(gateway_records[-1].request_id, result["request_id"])
            self.assertEqual(gateway_records[-1].details["path"], "audit.txt")
        finally:
            engine.stop_all()

    def test_audit_log_records_permission_denied_gateway_request(self) -> None:
        source = self._make_plugin(
            "audit_denied_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api):\n    api.write_file('denied.txt', 'x')\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "audit_denied.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions("audit_denied_plugin", [{"compute": True}])
        try:
            result = engine.call_tool("audit_denied_plugin", "run", {})
            self.assertEqual(result["status"], "error")
            self.assertIn("request_id", result)

            denied_records = [
                item
                for item in audit_logger.read_records()
                if item.event == "plugin.gateway_request"
                and item.plugin == "audit_denied_plugin"
                and item.action == "fs.write"
            ]
            self.assertEqual(denied_records[-1].result, "error")
            self.assertEqual(denied_records[-1].request_id, result["request_id"])
            self.assertEqual(denied_records[-1].details["error_type"], "PermissionDenied")
        finally:
            engine.stop_all()

    def test_disabled_plugin_cannot_start(self) -> None:
        source = self._make_plugin(
            "governance_disabled_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "governance_disabled.audit.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions("governance_disabled_plugin")
        engine.disable_plugin("governance_disabled_plugin", actor="admin", reason="policy")

        with self.assertRaisesRegex(PluginLifecycleError, "disabled"):
            engine.call_tool("governance_disabled_plugin", "run", {})

        records = audit_logger.read_records()
        self.assertTrue(
            any(
                item.event == "plugin.disabled"
                and item.plugin == "governance_disabled_plugin"
                and item.actor == "admin"
                for item in records
            )
        )
        self.assertTrue(
            any(
                item.event == "plugin.start_denied"
                and item.plugin == "governance_disabled_plugin"
                and item.decision == "deny"
                for item in records
            )
        )

    def test_quarantined_plugin_cannot_be_called(self) -> None:
        source = self._make_plugin(
            "governance_quarantine_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "governance_quarantine.audit.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions("governance_quarantine_plugin")
        first = engine.call_tool("governance_quarantine_plugin", "run", {})
        self.assertEqual(first["status"], "success")

        engine.quarantine_plugin("governance_quarantine_plugin", actor="admin", reason="incident")
        self.assertNotIn("governance_quarantine_plugin", engine.sandboxes)

        with self.assertRaisesRegex(PluginLifecycleError, "quarantined"):
            engine.call_tool("governance_quarantine_plugin", "run", {})

        records = audit_logger.read_records()
        self.assertTrue(
            any(
                item.event == "plugin.quarantined"
                and item.plugin == "governance_quarantine_plugin"
                and item.reason == "incident"
                for item in records
            )
        )

    def test_revoked_plugin_version_cannot_install_or_start(self) -> None:
        source = self._make_plugin(
            "governance_revoked_version_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        loader = PluginLoader(self.plugins_dir)
        loader.revoke_plugin_version("governance_revoked_version_plugin", "1.0.0")

        with self.assertRaisesRegex(PluginPackageError, "version is revoked"):
            loader.install(package)

        active_source = self._make_plugin(
            "governance_active_revoke_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        active_package = self._zip_plugin(active_source)
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard")
        engine.install(active_package)
        engine.grant_permissions("governance_active_revoke_plugin")
        engine.revoke_plugin_version("governance_active_revoke_plugin", "1.0.0")

        with self.assertRaisesRegex(PluginLifecycleError, "revoked"):
            engine.call_tool("governance_active_revoke_plugin", "run", {})

    def test_revoked_signer_key_not_trusted(self) -> None:
        source = self._make_plugin(
            "governance_revoked_key_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        private_key = self.root / "revoked-private.pem"
        public_key = self.root / "revoked-public.pem"
        trust_store = self.root / "revoked-trust-store.json"
        generate_keypair(private_key, public_key)
        key_id = TrustStore(trust_store).add_key("revoked@example.com", public_key)
        signature = sign_package(package, private_key=private_key, publisher="revoked@example.com")
        TrustStore(trust_store).revoke_key("revoked@example.com", key_id)

        with self.assertRaisesRegex(PluginSignatureError, "not trusted"):
            verify_signature(package, signature, trust_store=trust_store)

    def test_illegal_status_transition_is_rejected_and_audited(self) -> None:
        source = self._make_plugin(
            "governance_transition_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            code="def run(args, api=None):\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "governance_transition.audit.log")
        loader = PluginLoader(self.plugins_dir)
        loader.install(package)

        with self.assertRaisesRegex(PluginPackageError, "illegal plugin status transition"):
            loader.transition_status(
                "governance_transition_plugin",
                PluginStatus.RUNNING,
                actor="admin",
                reason="bad_transition",
                audit_logger=audit_logger,
            )

        records = audit_logger.read_records()
        self.assertEqual(records[-1].event, "plugin.status_transition")
        self.assertEqual(records[-1].result, "error")
        self.assertEqual(records[-1].plugin_id, "governance_transition_plugin")
        self.assertEqual(records[-1].decision, "deny")
        self.assertEqual(records[-1].actor, "admin")

    def test_audit_log_contains_governance_fields(self) -> None:
        source = self._make_plugin(
            "governance_audit_fields_plugin",
            runtime={"mode": "sub_process", "trust": "third_party"},
            permissions=[{"compute": True}, {"fs.write": True}],
            code="def run(args, api):\n    api.write_file('field.txt', 'x')\n    return {'ok': True}\n",
        )
        package = self._zip_plugin(source)
        audit_logger = AuditLogger(self.root / "governance_fields.audit.log")
        engine = PluginEngine(self.plugins_dir, sandbox_backend="python_guard", audit_logger=audit_logger)
        engine.install(package)
        engine.grant_permissions("governance_audit_fields_plugin", reviewer="secops", review_reason="approved")
        try:
            result = engine.call_tool("governance_audit_fields_plugin", "run", {})
            self.assertEqual(result["status"], "success")
        finally:
            engine.stop_all()

        records = audit_logger.read_records()
        fs_write = [
            item
            for item in records
            if item.event == "plugin.gateway_request"
            and item.plugin == "governance_audit_fields_plugin"
            and item.action == "fs.write"
        ][-1]
        self.assertIsNotNone(fs_write.timestamp)
        self.assertIsNotNone(fs_write.request_id)
        self.assertEqual(fs_write.plugin_id, "governance_audit_fields_plugin")
        self.assertEqual(fs_write.plugin_version, "1.0.0")
        self.assertEqual(fs_write.action, "fs.write")
        self.assertEqual(fs_write.resource, "field.txt")
        self.assertEqual(fs_write.permission, "fs.write")
        self.assertEqual(fs_write.decision, "allow")
        self.assertEqual(fs_write.actor, "system")

    def test_audit_hash_chain_verifies_and_detects_tampering(self) -> None:
        log_path = self.root / "governance_hash.audit.log"
        audit_logger = AuditLogger(log_path)
        audit_logger.record(
            "plugin.verify",
            "success",
            plugin="hash_chain_plugin",
            action="verify",
            details={"version": "1.0.0", "reason": "ok"},
        )
        audit_logger.record(
            "plugin.enable",
            "success",
            plugin="hash_chain_plugin",
            action="enable",
            details={"version": "1.0.0", "actor": "admin"},
        )

        report = verify_audit_log(log_path)
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["records"], 2)

        lines = log_path.read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[0])
        payload["action"] = "tampered"
        lines[0] = json.dumps(payload, sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with self.assertRaises(AuditLogIntegrityError):
            verify_audit_log(log_path)

    def test_cli_audit_verify_command(self) -> None:
        log_path = self.root / "cli_audit_verify.audit.log"
        AuditLogger(log_path).record("plugin.verify", "success", plugin="cli_audit_plugin", action="verify")

        result = subprocess.run(
            [
                sys.executable,
                "cli.py",
                "audit",
                "verify",
                "--log",
                str(log_path),
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Audit log verified records=1", result.stdout)

    def _make_plugin(
        self,
        name: str,
        runtime: dict[str, object],
        code: str,
        permissions: list[dict[str, object]] | None = None,
        packages: list[str] | None = None,
        extensions: list[dict[str, object]] | None = None,
    ) -> Path:
        source = self.root / name
        (source / "src").mkdir(parents=True)
        (source / "src" / "__init__.py").write_text("", encoding="utf-8")
        (source / "src" / "main.py").write_text(code, encoding="utf-8")
        metadata = self._metadata_yaml(
            name,
            runtime=runtime,
            permissions=permissions,
            packages=packages,
            extensions=extensions,
        )
        (source / "plugin.yaml").write_text(metadata, encoding="utf-8")
        write_package_lock(source)
        return source

    def _metadata_yaml(
        self,
        name: str,
        runtime: dict[str, object] | None = None,
        permissions: list[dict[str, object]] | None = None,
        packages: list[str] | None = None,
        extensions: list[dict[str, object]] | None = None,
    ) -> str:
        runtime = runtime or {"mode": "sub_process", "trust": "third_party"}
        permissions = permissions or [{"compute": True}]
        packages = packages or []
        lines = [
            f"name: {name}",
            "version: 1.0.0",
            "description: Test plugin for plugin system",
            "author: test",
            "license: MIT",
            "runtime:",
            f"  mode: {runtime['mode']}",
            f"  trust: {runtime['trust']}",
            f"  memory_mb: {runtime.get('memory_mb', 128)}",
            f"  timeout_seconds: {runtime.get('timeout_seconds', 3)}",
            f"  cpu_seconds: {runtime.get('cpu_seconds', 2)}",
            f"  max_concurrency: {runtime.get('max_concurrency', 1)}",
            f"  failure_threshold: {runtime.get('failure_threshold', 3)}",
            f"  disable_on_failure_threshold: {str(runtime.get('disable_on_failure_threshold', True)).lower()}",
            "extensions:",
        ]
        if extensions:
            for extension in extensions:
                lines.append(f"  - type: {extension['type']}")
                if "name" in extension:
                    lines.append(f"    name: {extension['name']}")
                if "entry" in extension:
                    lines.append(f"    entry: {extension['entry']}")
                if "events" in extension:
                    events = ", ".join(f'"{event}"' for event in extension["events"])
                    lines.append(f"    events: [{events}]")
        else:
            lines.extend(
                [
                    "  - type: tool",
                    "    name: run",
                    "    entry: src.main:run",
                ]
            )
        lines.append("permissions:")
        for item in permissions:
            for key, value in item.items():
                rendered = str(value).lower() if isinstance(value, bool) else value
                lines.append(f"  - {key}: {rendered}")
        lines.extend(
            [
                "requires:",
                '  python: ">=3.11"',
                "  packages:",
            ]
        )
        if packages:
            for package in packages:
                lines.append(f"    - {package}")
        else:
            lines[-1] = "  packages: []"
        return "\n".join(lines)

    def _zip_plugin(self, source: Path, *, include_sbom: bool = False) -> Path:
        if (source / PACKAGE_LOCK_FILE).exists():
            write_package_lock(source)
        if include_sbom:
            from modules.plugin_system.sbom import write_sbom

            write_sbom(source)
            write_package_lock(source)
        package = self.packages_dir / f"{source.name}.zip"
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in source.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(source).as_posix())
        return package

    def _passing_scan_report(self, source: Path) -> dict[str, object]:
        return OfflineVulnerabilityScanner().scan_sbom(generate_sbom(source)).to_dict()

    def _write_scan_report(self, source: Path, name: str) -> Path:
        report_path = self.root / f"{name}.scan.json"
        report_path.write_text(json.dumps(self._passing_scan_report(source), sort_keys=True), encoding="utf-8")
        return report_path

    def _write_registry_index(
        self,
        name: str,
        package: Path,
        signature: Path | None = None,
        *,
        version: str = "1.0.0",
        publisher: str | None = None,
        digest: str | None = None,
    ) -> Path:
        registry_dir = self.root / "registry"
        registry_dir.mkdir(exist_ok=True)
        package_target = registry_dir / package.name
        package_target.write_bytes(package.read_bytes())
        signature_name = None
        if signature is not None:
            signature_target = registry_dir / signature.name
            signature_target.write_bytes(signature.read_bytes())
            signature_name = signature_target.name
        index = registry_dir / f"{name}-index.json"
        entry: dict[str, object] = {
            "name": name,
            "version": version,
            "description": "Registry test plugin",
            "package": package_target.name,
            "sha256": digest or sha256_file(package_target),
        }
        if signature_name is not None:
            entry["signature"] = signature_name
        if publisher is not None:
            entry["publisher"] = publisher
        index.write_text(json.dumps({"version": 1, "plugins": [entry]}), encoding="utf-8")
        return index

    def _write_config_schema(
        self,
        source: Path,
        schema: dict[str, object],
        config: dict[str, object] | None = None,
    ) -> None:
        import json

        (source / "config_schema.json").write_text(json.dumps(schema), encoding="utf-8")
        if config is not None:
            (source / "config.json").write_text(json.dumps(config), encoding="utf-8")

    def _gateway_for_network_plugin(
        self,
        name: str,
        rule: object,
        *,
        declared: bool = True,
        granted: bool = True,
    ) -> tuple[PluginMetadata, PluginGateway]:
        permissions = [{"compute": True}]
        if declared:
            permissions.append({"network.outbound": rule})
        metadata = PluginMetadata(
            name=name,
            version="1.0.0",
            description="Network gateway policy test plugin",
            author="test",
            runtime={"mode": "sub_process", "trust": "third_party"},
            extensions=[{"type": "tool", "name": "run", "entry": "src.main:run"}],
            permissions=permissions,
        )
        granted_permissions = [{"compute": True}]
        if granted:
            granted_permissions.append({"network.outbound": rule})
        gateway = PluginGateway(
            data_dir=self.plugins_dir,
            audit_logger=AuditLogger(self.root / f"{name}.audit.log"),
        )
        gateway.register_plugin(
            InstalledPlugin(
                metadata=metadata,
                path=str(self.plugins_dir / name),
                status=PluginStatus.ENABLED,
                granted_permissions=granted_permissions,
            )
        )
        return metadata, gateway

    def _remove_tree(self, path: Path) -> None:
        if not path.exists():
            return
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
        path.rmdir()


if __name__ == "__main__":
    unittest.main()
