"""Walks a folder (or takes a single file) and dispatches to the config / Python / JS checks.
Reads local files only. Never imports, runs or connects to anything it scans."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from .config_scan import looks_like_mcp_config, scan_config_text
from .findings import Finding
from .js_scan import is_mcp_js, scan_js
from .py_scan import is_mcp_python, scan_python

MAX_BYTES_DEFAULT = 2 * 1024 * 1024
SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "dist", "build", "out", ".next", ".nuxt", ".venv", "venv", "env",
             "__pycache__", "site-packages", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage",
             ".turbo", ".cache", ".idea", "target", "vendor", ".gradle"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "__fixtures__", "testdata", "e2e"}
PY_EXT = {".py"}
JS_EXT = {".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"}


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    config_files: list[str] = field(default_factory=list)
    servers_configured: int = 0
    server_files: list[str] = field(default_factory=list)


def _is_test_file(name: str) -> bool:
    n = name.lower()
    return n.startswith("test_") or n.endswith(("_test.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js",
                                                ".test.mjs", ".spec.mjs", ".test.tsx", ".spec.tsx"))


def _read(p: Path, max_bytes: int) -> str | None:
    try:
        if p.stat().st_size > max_bytes:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_file(path: Path, rel: str, res: ScanResult, max_bytes: int, force_config: bool = False) -> None:
    text = _read(path, max_bytes)
    if text is None:
        return
    name = path.name
    suffix = path.suffix.lower()
    if suffix == ".json" or name.endswith(".jsonc"):
        if force_config or looks_like_mcp_config(name, text):
            cr = scan_config_text(rel, text)
            if cr.parsed and (cr.servers or force_config or name in ("claude_desktop_config.json", ".mcp.json")):
                res.files_scanned += 1
                res.config_files.append(rel)
                res.servers_configured += cr.servers
                res.findings += cr.findings
        return
    if suffix in PY_EXT:
        res.files_scanned += 1
        if is_mcp_python(text):
            res.server_files.append(rel)
            res.findings += scan_python(rel, text)
    elif suffix in JS_EXT and not name.endswith((".d.ts", ".min.js")):
        res.files_scanned += 1
        if is_mcp_js(text):
            res.server_files.append(rel)
            res.findings += scan_js(rel, text)


def scan_path(target: str, *, excludes: list[str] | None = None, include_tests: bool = False,
              max_bytes: int = MAX_BYTES_DEFAULT) -> ScanResult:
    excludes = excludes or []
    root = Path(target)
    if root.is_file():
        res = ScanResult(str(root.resolve().parent))
        scan_file(root, target.replace("\\", "/"), res, max_bytes,
                  force_config=root.suffix.lower() in (".json", ".jsonc"))
        return res
    res = ScanResult(str(root.resolve()))
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        keep = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS or (not include_tests and d.lower() in TEST_DIRS):
                continue
            if d.startswith(".") and d not in (".cursor", ".vscode", ".roo", ".windsurf", ".codeium", ".claude",
                                               ".gemini", ".kiro", ".continue", ".zed", ".github"):
                continue
            if any(fnmatch.fnmatch(rel_dir + d, pat) or fnmatch.fnmatch(rel_dir + d + "/", pat) for pat in excludes):
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            rel = rel_dir + fn
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                continue
            if not include_tests and _is_test_file(fn):
                continue
            scan_file(Path(dirpath) / fn, rel, res, max_bytes)
    return res


def user_config_paths(home: Path | None = None) -> list[Path]:
    """Well-known per-user MCP client config locations (only existing files are returned)."""
    home = home or Path.home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    cands = [
        home / "Library/Application Support/Claude/claude_desktop_config.json",
        appdata / "Claude/claude_desktop_config.json",
        home / ".config/Claude/claude_desktop_config.json",
        home / ".claude.json",
        home / ".cursor/mcp.json",
        home / ".codeium/windsurf/mcp_config.json",
        home / ".gemini/settings.json",
        home / ".config/zed/settings.json",
    ]
    for code_dir in (home / "Library/Application Support/Code/User", appdata / "Code/User",
                     home / ".config/Code/User"):
        cands.append(code_dir / "mcp.json")
        cands.append(code_dir / "globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json")
        cands.append(code_dir / "globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json")
    seen, out = set(), []
    for c in cands:
        if c.is_file() and str(c) not in seen:
            seen.add(str(c))
            out.append(c)
    return out


def scan_user_configs(home: Path | None = None, max_bytes: int = MAX_BYTES_DEFAULT) -> ScanResult:
    home = home or Path.home()
    res = ScanResult(str(home))
    for p in user_config_paths(home):
        try:
            rel = "~/" + p.relative_to(home).as_posix()
        except ValueError:
            rel = str(p)
        scan_file(p, rel, res, max_bytes, force_config=True)
    return res
