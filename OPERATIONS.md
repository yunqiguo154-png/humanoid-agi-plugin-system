# Operations

## Production Mode

Enable production policy through the engine or CLI:

```python
engine = PluginEngine(
    "data/plugins",
    production_mode=True,
    sandbox_backend="auto",
)
```

```bash
plugin-cli --production --sandbox-backend auto start plugin_name
```

Production mode enforces fail-closed behavior for third-party plugins:

- Subprocess execution only.
- Enforced sandbox required.
- Ed25519 signatures required.
- HMAC signatures are not trusted.
- Signed registry index required for registry installs.
- Permission expansion requires reapproval.

## Sandbox Backend Requirements

Linux production should install and verify `bubblewrap`:

```bash
bwrap --version
```

The production startup path fails closed if an enforced backend is unavailable. Integration tests skip the live bwrap test when Linux or `bwrap` is unavailable, but fail-closed policy tests always run.

Validate bubblewrap in one of two explicit modes:

```bash
python scripts/validate_bwrap_sandbox.py --mode diagnostic --json
python scripts/validate_bwrap_sandbox.py --mode production-required --json
```

`diagnostic` is for GitHub-hosted runners or local troubleshooting. It records backend capabilities and may return
`fail` or `unsupported_environment`; it never satisfies release-gate production bwrap evidence. `production-required`
is for a user-controlled Linux VM or a GitHub self-hosted runner labeled `self-hosted`, `linux`, `bwrap`. If the bwrap
probe is not enforced in production-required mode, the script fails closed and does not run the validation sample plugin
outside the sandbox.

GitHub-hosted Ubuntu runners can fail bwrap probing with namespace or loopback errors such as
`Failed RTM_NEWADDR: Operation not permitted`. That is a host capability limitation, not a reason to relax policy.
Do not treat hosted diagnostic output as target production Linux+bwrap validation.

Windows currently supports Job Object resource limits only. Treat Windows production as requiring an external container, VM, or other attested sandbox for third-party plugins.

## Registry Requirements

Production registry installs require:

- Signed registry index.
- Registry entries with package `sha256`.
- Ed25519 package signatures.
- No revoked publisher key.
- No revoked plugin version.
- No downgrade or same-version replacement unless explicitly allowed outside production policy.

## Audit Logs

The default engine audit path is:

```text
data/plugins/audit.log
```

Custom deployments should pass an explicit `AuditLogger` path and ship logs to centralized, append-only storage.

Verify a local audit hash chain:

```bash
plugin-cli audit verify --log data/plugins/audit.log
python scripts/generate_audit_verify_evidence.py --output evidence/audit_verify.json
```

Create and verify a local checkpoint:

```bash
plugin-cli audit checkpoint --log data/plugins/audit.log --checkpoint data/plugins/audit.checkpoint.json
plugin-cli audit verify --log data/plugins/audit.log --checkpoint data/plugins/audit.checkpoint.json
plugin-cli audit status --log data/plugins/audit.log --checkpoint data/plugins/audit.checkpoint.json
```

The local hash chain detects line tampering. A local checkpoint can detect truncation or rollback when the checkpoint is preserved separately. Neither provides real immutable audit storage by itself. Production should use append-only storage, SIEM, WORM buckets, transparency logs, or a centralized audit service.

## Production Doctor

Run:

```bash
plugin-cli doctor --production --json
```

Production-blocking findings must be resolved before enabling third-party plugins.

## RC Acceptance Evidence

For local RC evidence collection, run:

```bash
python scripts/collect_rc_evidence.py --json --output-dir evidence
```

This helper writes `evidence/index.json` and the local evidence files. It does not fabricate GitHub Actions,
Linux+bwrap, real scanner, or external audit anchor results. On Windows or hosts without `bwrap`, bwrap validation is
recorded as skipped and production-blocking for third-party production approval.

For RC or production approval, run the acceptance orchestrator from the repository root:

```bash
python scripts/run_production_acceptance.py --json --output acceptance_result.json
```

Pass explicit paths for deployment evidence when available, for example:

```bash
python scripts/run_production_acceptance.py \
  --json \
  --output acceptance_result.json \
  --audit-log data/plugins/audit.log \
  --audit-checkpoint data/plugins/audit.checkpoint.json \
  --policy-source dist/plugin.zip \
  --policy-signature dist/plugin.zip.sig \
  --policy-trust-store trust-store.json \
  --scan-report scan-report.json \
  --sample-sbom sbom.cdx.json \
  --registry-index registry/index.json \
  --registry-index-signature registry/index.json.sig \
  --registry-trust-store trust-store.json \
  --revocation-drill-json revocation-drill.json
```

Skipped steps are not pass results. If Linux bwrap validation skips because the host is not Linux or `bwrap` is missing, the environment is not ready for full third-party production approval.

Run local governance and supply-chain drills:

```bash
python scripts/drill_registry_verify.py --json --output evidence/registry_verify.json
python scripts/drill_revocation.py --json --output evidence/revocation_drill.json
python scripts/drill_quarantine.py --json --output evidence/quarantine_drill.json
python scripts/drill_rollback.py --json --output evidence/rollback_drill.json
```

Then evaluate the release gate:

```bash
python scripts/release_gate.py \
  --doctor evidence/doctor.json \
  --bwrap evidence/bwrap_validation.json \
  --audit evidence/audit_verify.json \
  --scan evidence/scanner_report.json \
  --ci evidence/ci_result.json \
  --registry evidence/registry_verify.json \
  --revocation evidence/revocation_drill.json \
  --quarantine evidence/quarantine_drill.json \
  --rollback evidence/rollback_drill.json \
  --json
```

Missing registry, revocation, quarantine, or rollback drill evidence is production-blocking. Passing local drills does not
replace target Linux+bwrap validation, real scanner evidence, or external immutable audit anchoring.

Next external acceptance steps for `v0.9.0-rc2`:

1. Push the RC commit and tag to GitHub.
2. Run GitHub Actions and archive the workflow run URL, head SHA, matrix jobs, ruff, mypy, unittest, and coverage result.
3. On the target Linux+bwrap host, run `plugin-cli doctor --production --json` and `python scripts/validate_bwrap_sandbox.py --mode production-required --json`.
4. Connect a real scanner such as pip-audit, OSV, Safety, Grype, or enterprise SCA; otherwise record a formal accepted risk for a controlled pilot.
5. Connect an external append-only/SIEM/WORM audit anchor; otherwise record a formal accepted risk for a controlled pilot.
6. Re-run `scripts/collect_rc_evidence.py` and `scripts/release_gate.py` with the external evidence paths.

Target Linux+bwrap validation commands:

Note: `scripts/generate_audit_verify_evidence.py` was added after the existing `v0.9.0-rc2` tag. Do not move that tag.
Use current `main` after this documentation/tooling commit, or create a later RC tag, if the local audit evidence helper
must be part of the tagged validation run.

```bash
git clone https://github.com/yunqiguo154-png/humanoid-agi-plugin-system.git
cd humanoid-agi-plugin-system
git checkout v0.9.0-rc2

git rev-parse HEAD
git branch --show-current
python3 --version
uname -a

python3 -m pip install -e ".[dev]"
sudo apt-get update
sudo apt-get install -y bubblewrap
bwrap --version
python3 -m unittest discover -s tests
python3 -m ruff check .
python3 -m mypy .
python3 -m coverage run -m unittest discover -s tests
python3 -m coverage report

mkdir -p evidence
plugin-cli doctor --production --json > evidence/doctor.json
python3 scripts/validate_bwrap_sandbox.py --mode production-required --json > evidence/bwrap_validation.json
python3 scripts/run_production_acceptance.py --json --output evidence/acceptance_result.json
python3 scripts/generate_audit_verify_evidence.py --output evidence/audit_verify.json  # requires post-RC2 main or a later RC tag
python3 scripts/release_gate.py --json > evidence/release_gate.json
```

If `bubblewrap` is missing on Debian or Ubuntu hosts:

```bash
sudo apt-get update
sudo apt-get install -y bubblewrap
```

Record the Linux distribution, kernel, `bwrap --version`, Python version, commit SHA, and tag in the acceptance archive.
Windows local evidence cannot replace this target Linux+bwrap validation. GitHub Actions hosted Ubuntu diagnostic output
also does not replace validation on the target production Linux host class. A skipped, unsupported, or diagnostic bwrap
validation is not a pass. Release Gate only clears `bwrap.validation` with `mode=production-required`, a target or
self-hosted Linux environment, enforced backend capabilities, and all critical sandbox checks passing.
Scanner evidence and an external append-only/SIEM/WORM audit anchor still require real external evidence or formal risk
acceptance before a controlled production pilot.

## Self-Hosted Linux Bwrap Runner

Use a self-hosted runner only for controlled branches or tags; do not attach an untrusted self-hosted runner to run
unreviewed public pull requests.

On the target Linux VM:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-pip python3-venv bubblewrap
```

In GitHub, open `Settings -> Actions -> Runners -> New self-hosted runner`, choose Linux, then run the commands GitHub
shows on the VM. Add labels:

```text
self-hosted
linux
bwrap
```

Trigger the workflow manually with `workflow_dispatch`. The `target linux bwrap production validation` job runs on
`[self-hosted, linux, bwrap]` and uploads `target-linux-bwrap-production-evidence-${{ github.sha }}` containing:

- `evidence/doctor.json`
- `evidence/bwrap_validation.json`
- `evidence/acceptance_result.json`
- `evidence/audit_verify.json`
- `evidence/release_gate.json`

The legacy compatibility layer is not a production plugin execution path. Legacy `plugins/<name>/metadata.json + plugin.py` loading is development-only and is rejected in production mode. Migrate legacy plugins using `MIGRATION_GUIDE.md`.

## Governance Workflows

Disable a plugin:

```bash
plugin-cli disable plugin_name
```

Quarantine a plugin after an incident:

```bash
plugin-cli quarantine plugin_name
```

Revoke an installed plugin:

```bash
plugin-cli revoke plugin_name
```

Revoke a plugin version:

```bash
plugin-cli revoke-version plugin_name 1.0.0
```

Revoke a signer key:

```bash
plugin-cli trust --store trust-store.json revoke-key publisher@example.com <key_id>
```

Disabled, quarantined, and revoked plugins must not start. A running plugin is stopped when quarantine or revoke is performed through the engine.

## Troubleshooting

- `production isolation capabilities`: the selected backend is not enforced or lacks required capabilities.
- `registry index signature is required`: provide `--index-signature` or a colocated `.sig` file and a trusted public key.
- `production mode requires Ed25519`: HMAC signatures are legacy/dev only.
- `permission review before starting`: approve requested permissions after install or upgrade.
- `manifest.lock verification failed`: rebuild the package lock and package.
- Network denials are audited as `plugin.network_decision` with resolved IPs and reasons.
