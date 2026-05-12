from __future__ import annotations

import re
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
PLUGIN_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
PYTHON_REQ_PATTERN = re.compile(r"^(>=|<=|==|~=|>|<)\s*\d+\.\d+(?:\.\d+)?$")
ENTRY_PATTERN = re.compile(r"^[a-zA-Z_][\w.]*:[a-zA-Z_]\w*$")


class PluginValidationError(ValueError):
    """Raised when a plugin package violates the plugin specification."""


class ExtensionType(str, Enum):
    TOOL = "tool"
    MIDDLEWARE = "middleware"
    EVENT_LISTENER = "event_listener"
    MEMORY_PROVIDER = "memory_provider"


class RunMode(str, Enum):
    IN_PROCESS = "in_process"
    SUB_PROCESS = "sub_process"
    AUTO = "auto"


class TrustLevel(str, Enum):
    OFFICIAL = "official"
    TRUSTED = "trusted"
    THIRD_PARTY = "third_party"


class PluginStatus(str, Enum):
    DISCOVERED = "discovered"
    VERIFIED = "verified"
    INSTALLED = "installed"
    CONFIGURED = "configured"
    PENDING_APPROVAL = "pending_approval"
    PERMISSION_PENDING = "permission_pending"
    ENABLED = "enabled"
    RUNNING = "running"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    UNINSTALLED = "uninstalled"


class PermissionName(str, Enum):
    COMPUTE = "compute"
    MEMORY_READ = "memory.read"
    CONFIG_READ = "config.read"
    NETWORK_OUTBOUND = "network.outbound"
    FS_READ = "fs.read"
    FS_WRITE = "fs.write"
    MEMORY_WRITE = "memory.write"
    OUTPUT_SEND = "output.send"


PERMISSION_LEVELS: dict[PermissionName, str] = {
    PermissionName.COMPUTE: "L0",
    PermissionName.MEMORY_READ: "L1",
    PermissionName.CONFIG_READ: "L1",
    PermissionName.NETWORK_OUTBOUND: "L2",
    PermissionName.FS_READ: "L3",
    PermissionName.FS_WRITE: "L3",
    PermissionName.MEMORY_WRITE: "L4",
    PermissionName.OUTPUT_SEND: "L4",
}

PERMISSION_RISK_LABELS: dict[str, str] = {
    "L0": "low",
    "L1": "low",
    "L2": "medium",
    "L3": "high",
    "L4": "critical",
}

PERMISSION_DESCRIPTIONS: dict[PermissionName, str] = {
    PermissionName.COMPUTE: "Local computation only; no external system access.",
    PermissionName.MEMORY_READ: "Read memory records exposed by the host gateway.",
    PermissionName.CONFIG_READ: "Read approved plugin configuration values.",
    PermissionName.NETWORK_OUTBOUND: "Send outbound HTTP requests to approved targets.",
    PermissionName.FS_READ: "Read files from the plugin sandbox data directory.",
    PermissionName.FS_WRITE: "Write files inside the plugin sandbox data directory.",
    PermissionName.MEMORY_WRITE: "Modify memory records exposed by the host gateway.",
    PermissionName.OUTPUT_SEND: "Send output messages through host-controlled channels.",
}


def permission_risk(permission: PermissionName | str, value: Any = None) -> dict[str, Any]:
    permission_name = PermissionName(permission)
    level = PERMISSION_LEVELS[permission_name]
    return {
        "name": permission_name.value,
        "level": level,
        "risk": PERMISSION_RISK_LABELS[level],
        "description": PERMISSION_DESCRIPTIONS[permission_name],
        "value": value,
    }


def permission_risks(permissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        permission_risk(next(iter(item.keys())), next(iter(item.values())))
        for item in permissions
    ]


def validate_permission_decls(value: list[dict[str, Any]], *, default_compute: bool) -> list[dict[str, Any]]:
    if not value:
        return [{"compute": True}] if default_compute else []
    allowed = {permission.value for permission in PermissionName}
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError("each permission must be a single-key mapping")
        key, permission_value = next(iter(item.items()))
        if key not in allowed:
            raise ValueError(f"unknown permission: {key}")
        normalized.append({key: permission_value})
    return normalized


DANGEROUS_IMPORTS = {
    "aiohttp",
    "builtins",
    "ctypes",
    "ftplib",
    "http",
    "httpx",
    "importlib",
    "inspect",
    "marshal",
    "multiprocessing",
    "os",
    "pathlib",
    "pickle",
    "pkgutil",
    "pty",
    "resource",
    "requests",
    "shutil",
    "signal",
    "site",
    "socket",
    "ssl",
    "subprocess",
    "sys",
    "urllib",
}

DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "input",
}


class ExtensionDecl(BaseModel):
    """A single extension point exported by a plugin."""

    type: ExtensionType
    entry: str | None = Field(default=None, description="Python entry point, for example src.main:run")
    events: list[str] = Field(default_factory=list)
    name: str | None = Field(default=None, description="Public tool or middleware name")

    @model_validator(mode="after")
    def validate_shape(self) -> "ExtensionDecl":
        if self.type in {
            ExtensionType.TOOL,
            ExtensionType.MIDDLEWARE,
            ExtensionType.MEMORY_PROVIDER,
        }:
            if not self.entry:
                raise ValueError(f"{self.type.value} extension requires an entry")
            if not ENTRY_PATTERN.match(self.entry):
                raise ValueError(f"invalid entry point: {self.entry}")
        if self.type == ExtensionType.EVENT_LISTENER:
            if not self.events:
                raise ValueError("event_listener extension requires events")
            if not self.entry:
                raise ValueError("event_listener extension requires an entry")
            if not ENTRY_PATTERN.match(self.entry):
                raise ValueError(f"invalid entry point: {self.entry}")
        return self

    @field_validator("events")
    @classmethod
    def validate_events(cls, value: list[str]) -> list[str]:
        for event in value:
            if not re.match(r"^[a-zA-Z0-9_.:-]{1,128}$", event):
                raise ValueError(f"invalid event name: {event}")
        return value


class RequirementsDecl(BaseModel):
    python: str = Field(default=">=3.11")
    packages: list[str] = Field(default_factory=list)

    @field_validator("python")
    @classmethod
    def validate_python_requirement(cls, value: str) -> str:
        if not PYTHON_REQ_PATTERN.match(value.strip()):
            raise ValueError("python requirement must look like '>=3.11'")
        return value.strip()

    @field_validator("packages")
    @classmethod
    def validate_packages(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for package in value:
            package = package.strip()
            if not package:
                continue
            if any(token in package for token in [";", "&", "|", "`", "$", "\n", "\r"]):
                raise ValueError(f"unsafe package requirement: {package}")
            normalized.append(package)
        return normalized


class RuntimeDecl(BaseModel):
    mode: RunMode = RunMode.AUTO
    trust: TrustLevel = TrustLevel.THIRD_PARTY
    memory_mb: int = Field(default=256, ge=16, le=2048)
    timeout_seconds: float = Field(default=5.0, gt=0, le=120)
    cpu_seconds: int = Field(default=5, ge=1, le=120)
    max_concurrency: int = Field(default=1, ge=1, le=64)
    failure_threshold: int = Field(default=3, ge=1, le=100)
    disable_on_failure_threshold: bool = True


class PluginMetadata(BaseModel):
    name: str
    version: str
    description: str = Field(min_length=5)
    author: str
    license: str = "MIT"
    extensions: list[ExtensionDecl] = Field(default_factory=list)
    permissions: list[dict[str, Any]] = Field(default_factory=lambda: [{"compute": True}])
    requires: RequirementsDecl = Field(default_factory=RequirementsDecl)
    runtime: RuntimeDecl = Field(default_factory=RuntimeDecl)
    signature: str | None = Field(default=None, description="Detached package signature")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not PLUGIN_NAME_PATTERN.match(value):
            raise ValueError("plugin name must use lowercase letters, numbers, and underscores")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not SEMVER_PATTERN.match(value):
            raise ValueError("version must be semantic version, for example 1.2.0")
        return value

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return validate_permission_decls(value, default_compute=True)

    @model_validator(mode="after")
    def validate_runtime_policy(self) -> "PluginMetadata":
        if self.runtime.trust == TrustLevel.OFFICIAL and self.runtime.mode == RunMode.SUB_PROCESS:
            return self
        if self.runtime.trust == TrustLevel.THIRD_PARTY and self.runtime.mode == RunMode.IN_PROCESS:
            raise ValueError("third-party plugins cannot force in_process runtime")
        return self

    @property
    def requested_permissions(self) -> set[str]:
        return {next(iter(item.keys())) for item in self.permissions}

    @property
    def effective_run_mode(self) -> RunMode:
        if self.runtime.mode != RunMode.AUTO:
            return self.runtime.mode
        if self.runtime.trust in {TrustLevel.OFFICIAL, TrustLevel.TRUSTED}:
            return RunMode.IN_PROCESS
        return RunMode.SUB_PROCESS

    def has_permission(self, permission: PermissionName | str) -> bool:
        key = permission.value if isinstance(permission, PermissionName) else permission
        return key in self.requested_permissions

    def permission_value(self, permission: PermissionName | str, default: Any = None) -> Any:
        key = permission.value if isinstance(permission, PermissionName) else permission
        for item in self.permissions:
            if key in item:
                return item[key]
        return default

    def tool_entries(self) -> dict[str, str]:
        entries: dict[str, str] = {}
        for extension in self.extensions:
            if extension.type == ExtensionType.TOOL and extension.entry:
                tool_name = extension.name or extension.entry.rsplit(":", 1)[-1]
                entries[tool_name] = extension.entry
        return entries

    def event_listener_entries(self) -> dict[str, list[str]]:
        entries: dict[str, list[str]] = {}
        for extension in self.extensions:
            if extension.type == ExtensionType.EVENT_LISTENER and extension.entry:
                for event in extension.events:
                    entries.setdefault(event, []).append(extension.entry)
        return entries

    def middleware_entries(self) -> dict[str, str]:
        entries: dict[str, str] = {}
        for extension in self.extensions:
            if extension.type == ExtensionType.MIDDLEWARE and extension.entry:
                middleware_name = extension.name or extension.entry.rsplit(":", 1)[-1]
                entries[middleware_name] = extension.entry
        return entries

    def memory_provider_entries(self) -> dict[str, str]:
        entries: dict[str, str] = {}
        for extension in self.extensions:
            if extension.type == ExtensionType.MEMORY_PROVIDER and extension.entry:
                provider_name = extension.name or extension.entry.rsplit(":", 1)[-1]
                entries[provider_name] = extension.entry
        return entries


class InstalledPlugin(BaseModel):
    metadata: PluginMetadata
    path: str
    package_hash: str | None = None
    installed_at: str | None = None
    status: PluginStatus = PluginStatus.PENDING_APPROVAL
    granted_permissions: list[dict[str, Any]] = Field(default_factory=list)
    permission_review: dict[str, Any] = Field(default_factory=dict)

    @field_validator("granted_permissions")
    @classmethod
    def validate_granted_permissions(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return validate_permission_decls(value, default_compute=False)

    @property
    def granted_permission_names(self) -> set[str]:
        return {next(iter(item.keys())) for item in self.granted_permissions}

    def has_granted_permission(self, permission: PermissionName | str) -> bool:
        key = permission.value if isinstance(permission, PermissionName) else permission
        return key in self.granted_permission_names

    def granted_permission_value(self, permission: PermissionName | str, default: Any = None) -> Any:
        key = permission.value if isinstance(permission, PermissionName) else permission
        for item in self.granted_permissions:
            if key in item:
                return item[key]
        return default


def normalize_archive_path(path: str) -> str:
    """Return a safe POSIX archive path or raise PluginValidationError."""

    candidate = PurePosixPath(path.replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise PluginValidationError(f"archive contains unsafe path: {path}")
    return str(candidate)
