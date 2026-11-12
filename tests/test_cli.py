import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_audit import scanner
from mcp_audit.cli import main
from mcp_audit.findings import RULES, SEVERITIES, mask_secret

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_scan_vulnerable_text_report(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "py_vulnerable"), "--no-color")
    assert code == 1
    assert "CRITICAL MCP101" in out and "server.py:20" in out
    assert "why:" in out and "fix:" in out and "shell=False" in out
    assert "Exit code: 1" in out


def test_scan_clean_exits_0(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "py_clean"), str(FIX / "ts_clean"), "--no-color")
    assert code == 0
    assert "No findings" in out and "2 MCP server source file(s)" in out


def test_json_report_shape(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "ts_vulnerable"), "--json")
    doc = json.loads(out)
    assert code == 1 and doc["exit_code"] == 1 and doc["tool"] == "mcp-audit"
    assert doc["server_source_files"] == ["src/index.ts"]
    assert set(doc["summary"]) == set(SEVERITIES)
    first = doc["findings"][0]
    assert first["severity"] == "critical"
    assert {"rule_id", "severity", "message", "file", "line", "evidence", "title", "why", "fix"} <= set(first)


def test_fail_on_min_severity_and_disable(capsys):
    assert run(capsys, "scan", str(FIX / "py_vulnerable"), "--fail-on", "never")[0] == 0
    code, out, _ = run(capsys, "scan", str(FIX / "py_vulnerable"), "--json", "--min-severity", "critical")
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"critical"}
    code, out, _ = run(capsys, "scan", str(FIX / "py_vulnerable"), "--json", "--disable", "MCP101",
                       "--disable", "mcp108", "--disable", "MCP102")
    ids = {f["rule_id"] for f in json.loads(out)["findings"]}
    assert not ids & {"MCP101", "MCP102", "MCP108"} and code == 1   # MCP103/104/107 are still high


def test_fail_on_info_counts_info(capsys, make_repo):
    root = make_repo({"s.py": "from mcp.server.fastmcp import FastMCP\nimport httpx\nmcp = FastMCP('x')\n"
                              "@mcp.tool()\ndef news():\n    return httpx.get('https://n.example.com/').text\n"})
    assert run(capsys, "scan", str(root))[0] == 0
    assert run(capsys, "scan", str(root), "--fail-on", "info")[0] == 1


def test_unknown_rule_and_missing_path(capsys, tmp_path):
    code, _, err = run(capsys, "scan", str(tmp_path / "nope"))
    assert code == 2 and "does not exist" in err
    code, _, err = run(capsys, "scan", str(tmp_path), "--disable", "MCP999")
    assert code == 2 and "unknown rule" in err


def test_scan_single_config_file(capsys, make_repo, fake):
    root = make_repo({"my-config.json": {"mcpServers": {"gh": {"command": "npx", "args": ["-y", "x@1.0.0"],
                                                               "env": {"GITHUB_TOKEN": fake["github"]}}}}})
    code, out, _ = run(capsys, "scan", str(root / "my-config.json"), "--json")
    doc = json.loads(out)
    assert code == 1 and [f["rule_id"] for f in doc["findings"]] == ["MCP001"]


def test_output_never_contains_secrets(capsys, make_repo, fake):
    servers = {"a": {"command": "node", "args": ["s.js", "--token", fake["generic"]],
                     "env": {"OPENAI_API_KEY": fake["openai"], "SLACK_BOT_TOKEN": fake["slack"]}},
               "b": {"url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer " + fake["anthropic"]}},
               "c": {"command": "npx", "args": ["-y", "pg-mcp",
                                                f"postgresql://u:{fake['db_password']}@db:5432/x"]}}
    root = make_repo({".mcp.json": {"mcpServers": servers}})
    for fmt in ([], ["--json"]):
        code, out, _ = run(capsys, "scan", str(root), "--no-color", *fmt)
        assert code == 1
        for name, secret in fake.items():
            if name == "github":
                continue
            assert secret not in out, name
            assert secret[:8] not in out, name      # never more than 4 leading characters


def test_mask_secret_shows_at_most_four_chars():
    assert mask_secret("abcdefghijklmnopqrstuvwxyz") == "abcd**** (26 chars)"
    assert mask_secret("abcdefgh") == "ab**** (8 chars)"
    assert mask_secret("abc") == "**** (3 chars)"


def test_tests_folders_skipped_unless_included(capsys, make_repo):
    vuln = (FIX / "py_vulnerable" / "server.py").read_text()
    root = make_repo({"tests/server.py": vuln, "test_server.py": vuln})
    code, out, _ = run(capsys, "scan", str(root), "--json")
    assert code == 0 and json.loads(out)["findings"] == []
    code, out, _ = run(capsys, "scan", str(root), "--json", "--include-tests")
    assert code == 1 and len(json.loads(out)["findings"]) == 24


def test_exclude_glob(capsys, copy_fixture):
    root = copy_fixture("ts_vulnerable")
    code, out, _ = run(capsys, "scan", str(root), "--exclude", "src/*", "--json")
    assert code == 0 and json.loads(out)["files_scanned"] == 0


def test_user_configs(capsys, tmp_path, monkeypatch, fake):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps(
        {"mcpServers": {"gh": {"command": "npx", "args": ["-y", "server-github"],
                               "env": {"GITHUB_TOKEN": fake["github"]}}}}))
    (home / ".claude.json").write_text(json.dumps({"numStartups": 3}))
    monkeypatch.setattr(scanner.Path, "home", lambda: home)
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    code, out, _ = run(capsys, "scan", "--user-configs", "--json")
    doc = json.loads(out)
    assert code == 1
    assert sorted(f["rule_id"] for f in doc["findings"]) == ["MCP001", "MCP002"]
    assert doc["findings"][0]["file"] == "~/.cursor/mcp.json"
    assert "~/.claude.json" in doc["config_files"]


def test_rules_lists_every_rule(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    for rid in RULES:
        assert rid in out
    assert "<" not in out.replace("<version>", "").replace("<digest>", "").replace("<untrusted_content", "") \
        .replace("</untrusted_content>", "")


def test_every_rule_has_title_why_fix():
    for r in RULES.values():
        assert r.title and len(r.why) > 40 and len(r.fix) > 40


def test_module_entry_point():
    res = subprocess.run([sys.executable, "-m", "mcp_audit", "scan", str(FIX / "ts_clean"), "--brief"],
                         capture_output=True, text=True, env={"PYTHONPATH": str(ROOT / "src"), "SYSTEMROOT": "C:\\Windows",
                                                               "PATH": ""} if sys.platform == "win32" else
                         {"PYTHONPATH": str(ROOT / "src")})
    assert res.returncode == 0, res.stderr
    assert "No findings" in res.stdout


def test_no_network_imports():
    """The scanner must never be able to contact anything."""
    src = ROOT / "src" / "mcp_audit"
    for p in src.glob("*.py"):
        text = p.read_text()
        for mod in ("urllib.request", "http.client", "socket", "requests", "httpx"):
            assert f"import {mod}" not in text and f"from {mod} import" not in text, (p.name, mod)


@pytest.mark.parametrize("name", ["py_vulnerable", "ts_vulnerable"])
def test_every_finding_has_location_evidence_and_fix(capsys, name):
    _, out, _ = run(capsys, "scan", str(FIX / name), "--json")
    for f in json.loads(out)["findings"]:
        assert f["file"] and f["line"] and f["evidence"] and f["fix"]
