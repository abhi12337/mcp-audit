"""Shared helpers. Fake secrets are assembled at runtime so that no secret-shaped
string is ever committed to this repository (keeps secret scanners quiet)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

FAKE = {
    "github": "ghp" + "_" + "FAKEfakeFAKEfake0123456789abcdefABCD",
    "openai": "sk-" + "proj-" + "FAKEfakeFAKEfake0123456789abcdefABCDEF",
    "anthropic": "sk-" + "ant-" + "api03-FAKEfakeFAKEfake0123456789abcdef",
    "slack": "xox" + "b-" + "000000000000-FAKEfakeFAKE",
    "generic": "Zq8" + "vN2pLr5Tx9WmK4c",
    "db_password": "hun" + "ter2-but-longer",
}


@pytest.fixture
def fake():
    return FAKE


@pytest.fixture
def make_repo(tmp_path):
    """make_repo({"rel/path": "content" | dict, ...}) -> Path. dict values are written as JSON."""

    def _make(files: dict) -> Path:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, (dict, list)):
                content = json.dumps(content, indent=2)
            p.write_text(content, encoding="utf-8")
        return root

    return _make


@pytest.fixture
def copy_fixture(tmp_path):
    def _copy(name: str) -> Path:
        dst = tmp_path / name
        shutil.copytree(FIXTURES / name, dst)
        return dst

    return _copy
