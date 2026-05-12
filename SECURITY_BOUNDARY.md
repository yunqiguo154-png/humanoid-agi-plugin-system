# Security Boundary

This document defines what the plugin system currently treats as a security boundary and what is only defense in depth.

## Trusted Boundary

The trusted boundary for third-party plugins in production is an OS-enforced sandbox, container, or microVM boundary. On Linux, the preferred backend is `bubblewrap` (`bwrap`) with filesystem namespaces, network namespace isolation, process isolation, private `/tmp`, read-only plugin code mounts, and a writable per-plugin data directory.

The Gateway is the only supported entry point for plugin access to host resources. Third-party plugins must not access memory, output, files, network, configuration, or event capabilities directly. Production deployments must run third-party plugins out of process and require an enforced sandbox backend.

## Not A Security Boundary

Python static scanning, import blocking, monkey patching, AST checks, and disabling `eval` or `exec` are not a complete security boundary. They are useful as policy checks and early rejection controls, but they cannot safely contain arbitrary malicious Python code.

The `python_guard` backend is not an OS sandbox. It is suitable for development compatibility and policy tests, not production isolation for untrusted plugins.

Windows Job Object support is currently a resource limiting mechanism. It does not provide complete filesystem isolation, network isolation, or syscall filtering. Windows production deployments need an external container, VM, or platform sandbox with explicit attestation before treating third-party plugins as strongly isolated.

## Linux Production Recommendation

Linux production deployments should use:

- `production_mode=True`.
- Third-party plugins running in `sub_process` mode only.
- `sandbox_backend="auto"` or `sandbox_backend="bubblewrap"` with `bwrap` installed and usable.
- `require_enforced_sandbox=True` if not already implied by production mode.
- Ed25519 package signatures.
- Signed registry indexes.
- Manifest lockfiles and dependency lockfiles with hashes.
- Gateway-only outbound network access.
- Audit logs stored on append-only or centrally collected infrastructure.

If `bwrap` is unavailable or not usable, production startup for third-party plugins must fail closed.

## Plugin Output

Plugin output is untrusted data. The host must validate, encode, rate-limit, and sanitize plugin output before displaying it, passing it to tools, writing it to memory, or sending it to external systems.

## Gateway Responsibilities

The Gateway enforces declared and approved permissions for:

- `memory.read` and `memory.write`.
- `config.read`.
- `network.outbound`.
- `fs.read` and `fs.write`.
- `output.send`.
- Event publication.

Network requests must go through the Gateway. The Gateway rejects internal addresses, link-local addresses, metadata service addresses, unsafe URL forms, unauthorized methods, unauthorized hosts, and unsafe redirects.

## Remaining Risks

- Local audit hash chains detect tampering but do not prevent deletion or rollback of the entire log file.
- Local checkpoint anchors are testable rollback-detection mechanisms, not true append-only audit storage unless checkpoints are stored outside attacker control.
- Registry support is a secure local/signed distribution path, not a full public marketplace with abuse review, malware analysis, billing, or publisher onboarding.
- Native dependency policy exists, but production deployments still need an external vulnerability and license scanner.
- OS sandbox behavior depends on kernel, distribution, `bwrap` installation, and deployment configuration.

## Production Evidence

Run these commands on production-like hosts before launch:

```bash
plugin-cli doctor --production --json
python scripts/validate_bwrap_sandbox.py --json
```

The doctor and validation harness provide deployment evidence. They do not replace architecture review or manual host hardening.
