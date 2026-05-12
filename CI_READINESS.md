# CI Readiness

## Workflow

GitHub Actions workflow:

```text
.github/workflows/ci.yml
```

Trigger it by pushing the RC branch or tag to GitHub, or by opening a pull request. After it completes, copy the run URL
and head SHA into `PRODUCTION_ACCEPTANCE_EVIDENCE.md` or the external evidence archive.

It runs on:

- `ubuntu-latest`
- `windows-latest`
- Python `3.11`, `3.12`, `3.13`

## Commands

CI installs the package with development tools:

```bash
python -m pip install -e ".[dev]"
```

Then runs:

```bash
python -m ruff check .
python -m mypy
python -m unittest discover -s tests
python -m coverage run -m unittest discover -s tests
python -m coverage report
```

## Local Equivalent

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m mypy
python -m unittest discover -s tests
python -m coverage run -m unittest discover -s tests
python -m coverage report
```

If `ruff`, `mypy`, or `coverage` are missing locally, install the `dev` extra. Do not remove CI checks to make a local environment pass.

## Lint And Type Baseline

`ruff` is enabled with a conservative baseline focused on syntax/runtime-critical rules:

```text
E9, F63, F7, F82
```

This is intentionally not a full style gate yet. It still catches parse errors, undefined names in common cases, and invalid Python constructs.

`mypy` currently checks:

```text
modules/plugin_system
cli.py
```

The configuration keeps legacy compatibility overrides for existing dynamic code paths. Do not remove the type-check job; tighten the scope and disabled error codes as modules stabilize.

## Integration Tests

The Linux bubblewrap OS sandbox integration test is allowed to skip when:

- The runner is not Linux.
- The `bwrap` executable is not installed.
- The `bwrap` smoke probe fails due to host kernel or namespace restrictions.

Production fail-closed policy tests are not allowed to skip. They validate that third-party production startup fails when enforced sandbox capabilities are unavailable.

Skipped tests are not production pass evidence. Target Linux+bwrap validation must still be run on the deployment host class.

## Coverage

Coverage is collected with:

```bash
python -m coverage run -m unittest discover -s tests
python -m coverage report
```

The current threshold is `70%` in `pyproject.toml`. This is a conservative production-candidate baseline, not a final quality target. Raise it after reviewing stable coverage baselines.

## Workflow Self-Check

The test suite includes workflow self-checks verifying that CI contains:

- Linux and Windows matrix entries.
- Python 3.11, 3.12, 3.13.
- unittest discovery.
- ruff.
- mypy.
- coverage.

Core unittest execution does not require real external network access.
