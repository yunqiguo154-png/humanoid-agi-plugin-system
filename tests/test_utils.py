from __future__ import annotations

import tempfile
from pathlib import Path


def make_test_root(test_name: str) -> Path:
    base = Path.cwd() / "data" / "test_runs"
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f"{test_name}-", dir=base))
