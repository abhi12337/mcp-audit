import json

import pytest

from mcp_audit.config_scan import parse_npm_spec, parse_py_spec, scan_config_text, strip_jsonc
from mcp_audit.scanner import scan_path


def cfg(servers: dict, key: str = "mcpServers") -> str:
    return json.dumps({key: servers}, indent=2)


def run(servers: dict, rel: str = ".cursor/mcp.json", key: str = "mcpServers"):
    return scan_config_text(rel, cfg(servers, key)).findings


def only(findings, rule):
    return [f for f in findings if f.rule_id == rule]


# ---------------------------------------------------------------- MCP001 secrets
def test_known_token_in_env_is_critical_and_masked(fake):
    fs = run({"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"],
                         "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": fake["github"]}}})
    [f] = only(fs, "MCP001")
    assert f.severity == "critical"
    assert f.file == ".cursor/mcp.json" and f.line == 10
    assert fake["github"] not in f.evidence and fake["github"][4:12] not in f.evidence
    assert "ghp_****" in f.evidence and "(40 chars)" in f.evidence
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in f.fix


@pytest.mark.parametrize("key", ["openai", "anthropic", "slack"])
def test_known_tokens_anywhere_in_args(fake, key):
    fs = run({"s": {"command": "node", "args": ["server.js", "--key", fake[key]]}})
    [f] = only(fs, "MCP001")
    assert f.severity == "critical" and fake[key] not in f.evidence


def test_generic_secret_by_key_name_is_high(fake):
    fs = run({"s": {"command": "node", "args": ["s.js"], "env": {"MY_SERVICE_API_KEY": fake["generic"]}}})
    [f] = only(fs, "MCP001")
    assert f.severity == "high"
    assert f.evidence.startswith("env.MY_SERVICE_API_KEY = Zq8v****")


@pytest.mark.parametrize("value", ["${GITHUB_TOKEN}", "${env:GITHUB_TOKEN}", "${input:github-token}", "$GITHUB_TOKEN",
                                   "%GITHUB_TOKEN%", "your-token-here", "<YOUR_TOKEN>", "xxxxxxxxxxxx", "", "changeme"])
def test_env_references_and_placeholders_are_not_secrets(value):
    assert only(run({"s": {"command": "node", "args": ["s.js"], "env": {"GITHUB_TOKEN": value}}}), "MCP001") == []


def test_non_secret_keys_are_ignored():
    env = {"LOG_LEVEL": "debug", "AUTH_TYPE": "oauth-device-flow", "TOKEN_URL": "https://auth.example.com/token",
           "SECRETS_FILE": "/etc/app/secrets.json", "PASSWORD_MIN_LENGTH": "12", "OAUTH_CLIENT_ID": "abc123def456"}
    assert only(run({"s": {"command": "node", "args": ["s.js"], "env": env}}), "MCP001") == []


def test_authorization_header(fake):
    fs = run({"r": {"type": "http", "url": "https://mcp.example.com/mcp",
                    "headers": {"Authorization": "Bearer " + fake["generic"]}}})
    [f] = only(fs, "MCP001")
    assert f.severity == "high" and fake["generic"] not in f.evidence
    ok = run({"r": {"type": "http", "url": "https://mcp.example.com/mcp",
                    "headers": {"Authorization": "Bearer ${MCP_TOKEN}"}}})
    assert only(ok, "MCP001") == []


def test_secret_flag_in_args(fake):
    fs = run({"s": {"command": "node", "args": ["s.js", "--api-key=" + fake["generic"]]}})
    [f] = only(fs, "MCP001")
    assert f.severity == "high" and fake["generic"] not in f.evidence
    fs = run({"s": {"command": "node", "args": ["s.js", "--token", fake["generic"]]}})
    assert len(only(fs, "MCP001")) == 1


def test_mcp_remote_header_arg(fake):
    fs = run({"s": {"command": "npx", "args": ["-y", "mcp-remote@0.1.18", "https://mcp.example.com/sse",
                                                 "--header", "Authorization: Bearer " + fake["generic"]]}})
    assert len(only(fs, "MCP001")) == 1


def test_database_url_password_in_args_is_masked_everywhere(fake):
    url = f"postgresql://app:{fake['db_password']}@db.internal:5432/app"
    text = json.dumps({"mcpServers": {"db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres",
                                                                          url]}}})  # one line: compact config
    fs = scan_config_text(".mcp.json", text).findings
    [s] = only(fs, "MCP001")
    assert s.severity == "high" and s.extra["key"] == "DATABASE_URL"
    assert only(fs, "MCP002")
    for f in fs:
        assert fake["db_password"] not in (f.evidence or "")
        assert fake["db_password"] not in f.message


def test_disabled_server_secret_still_reported(fake):
    fs = run({"s": {"command": "npx", "args": ["-y", "some-server"], "disabled": True,
                    "env": {"GITHUB_TOKEN": fake["github"]}}})
    assert len(only(fs, "MCP001")) == 1
    assert only(fs, "MCP002") == []


# ---------------------------------------------------------------- MCP002 / MCP003 versions
@pytest.mark.parametrize("args,rule", [
    (["-y", "@modelcontextprotocol/server-memory"], "MCP002"),
    (["@modelcontextprotocol/server-memory"], "MCP002"),
    (["-y", "some-mcp"], "MCP002"),
    (["-y", "some-mcp@^1.2.0"], "MCP002"),
    (["-y", "some-mcp@1.x"], "MCP002"),
    (["-y", "@modelcontextprotocol/server-memory@latest"], "MCP003"),
    (["-y", "some-mcp@next"], "MCP003"),
    (["-y", "-p", "some-mcp", "some-mcp-bin"], "MCP002"),
    (["--yes", "--package=some-mcp@latest", "bin"], "MCP003"),
])
def test_npx_unpinned(args, rule):
    fs = run({"s": {"command": "npx", "args": args}})
    found = [f for f in fs if f.rule_id in ("MCP002", "MCP003")]
    assert [f.rule_id for f in found] == [rule]
    assert found[0].severity == "medium"
    assert "@<version>" in found[0].fix


@pytest.mark.parametrize("args", [
    ["-y", "@modelcontextprotocol/server-memory@2025.4.25"],
    ["-y", "some-mcp@1.2.3"],
    ["-y", "./local-server"],
    ["-y", "C:\\work\\server"],
    ["-y", "github:owner/repo#abc123"],
])
def test_npx_pinned_or_local_is_fine(args):
    assert [f for f in run({"s": {"command": "npx", "args": args}}) if f.rule_id in ("MCP002", "MCP003")] == []


def test_windows_cmd_wrapper_and_full_path():
    fs = run({"a": {"command": "cmd", "args": ["/c", "npx", "-y", "some-mcp"]},
              "b": {"command": "C:\\Program Files\\nodejs\\npx.cmd", "args": ["-y", "other-mcp@latest"]},
              "c": {"command": "npx -y third-mcp", "args": []}})
    got = sorted((f.extra["server"], f.rule_id) for f in fs)
    assert got == [("a", "MCP002"), ("b", "MCP003"), ("c", "MCP002")]


@pytest.mark.parametrize("command,args,rule", [
    ("uvx", ["mcp-server-fetch"], "MCP002"),
    ("uvx", ["--python", "3.12", "mcp-server-git"], "MCP002"),
    ("uvx", ["mcp-server-fetch@latest"], "MCP003"),
    ("uvx", ["mcp-server-fetch>=1.0"], "MCP002"),
    ("uv", ["tool", "run", "mcp-server-time"], "MCP002"),
    ("pipx", ["run", "mcp-server-time"], "MCP002"),
    ("uvx", ["mcp-server-fetch==2025.1.17"], None),
    ("uvx", ["mcp-server-fetch@2025.1.17"], None),
    ("uvx", ["--from", "mcp-server-git==0.6.2", "mcp-server-git", "--repository", "."], None),
    ("uvx", ["--from", "git+https://github.com/o/r@v1.0", "srv"], None),
    ("uv", ["run", "--directory", "/srv/app", "server.py"], None),
    ("python", ["-m", "my_server"], None),
])
def test_python_launchers(command, args, rule):
    got = [f.rule_id for f in run({"s": {"command": command, "args": args}}) if f.rule_id in ("MCP002", "MCP003")]
    assert got == ([rule] if rule else [])


def test_spec_parsers():
    assert parse_npm_spec("@scope/pkg@1.2.3") == ("@scope/pkg", "1.2.3")
    assert parse_npm_spec("@scope/pkg") == ("@scope/pkg", None)
    assert parse_npm_spec("pkg@latest") == ("pkg", "latest")
    assert parse_py_spec("pkg[extra]==1.0") == ("pkg[extra]", "1.0", True)
    assert parse_py_spec("pkg>=1.0")[2] is False


# ---------------------------------------------------------------- MCP005 docker
def docker(*args):
    return run({"d": {"command": "docker", "args": ["run", "-i", "--rm", *args]}})


def test_docker_privileged_socket_and_root_mount():
    fs = docker("--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", "/:/host", "img:1.0")
    sev = sorted(f.severity for f in only(fs, "MCP005"))
    assert sev == ["critical", "critical", "critical"]


def test_docker_home_and_sensitive_mounts():
    fs = docker("-v", "/Users/alice:/data", "--mount", "type=bind,source=/home/bob/.ssh,target=/k", "img:1.0")
    assert sorted(f.severity for f in only(fs, "MCP005")) == ["high", "high"]
    fs = docker("-v", "C:\\Users\\alice:/data", "img:1.0")
    assert [f.severity for f in only(fs, "MCP005")] == ["high"]


def test_docker_host_network_and_caps():
    fs = docker("--network", "host", "--cap-add=SYS_ADMIN", "img:1.0")
    assert sorted(f.severity for f in only(fs, "MCP005")) == ["high", "medium"]


def test_docker_image_tags():
    assert [f.rule_id for f in docker("ghcr.io/github/github-mcp-server")] == ["MCP002"]
    assert [f.rule_id for f in docker("mcp/fetch:latest")] == ["MCP003"]
    assert docker("mcp/fetch:1.2.0") == []
    assert docker("mcp/fetch@sha256:" + "a" * 64) == []
    assert docker("localhost:5000/mcp/fetch:1.2") == []


def test_docker_clean_setup_has_no_findings():
    fs = docker("-e", "GITHUB_TOKEN", "-v", "/srv/project:/workspace:ro", "--cap-drop", "ALL",
                "ghcr.io/github/github-mcp-server:v0.6.0")
    assert fs == []


# ---------------------------------------------------------------- MCP004 roots
@pytest.mark.parametrize("root", ["/", "~", "$HOME", "C:\\", "C:/", "D:\\", "/Users/alice", "/home/bob/",
                                  "C:\\Users\\alice", "%USERPROFILE%"])
def test_broad_filesystem_roots(root):
    fs = run({"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.7.1", root]}})
    [f] = only(fs, "MCP004")
    assert f.severity == "high"


@pytest.mark.parametrize("root", ["/Users/alice/projects/app", "C:\\work\\repo", "./data", "/srv/notes"])
def test_narrow_roots_are_fine(root):
    fs = run({"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.7.1", root]}})
    assert fs == []


def test_root_flag_form():
    fs = run({"s": {"command": "node", "args": ["srv.js", "--allowed-dirs=/srv/a,/"]}})
    assert len(only(fs, "MCP004")) == 1


# ---------------------------------------------------------------- MCP006 transport
def test_plain_http_remote():
    fs = run({"r": {"type": "sse", "url": "http://mcp.example.com/sse"}})
    [f] = only(fs, "MCP006")
    assert f.severity == "high" and "https://mcp.example.com/sse" in f.fix


@pytest.mark.parametrize("url", ["http://localhost:3000/mcp", "http://127.0.0.1:8080/sse", "https://mcp.example.com",
                                 "http://host.docker.internal:9000/mcp"])
def test_local_or_https_remote_is_fine(url):
    assert run({"r": {"url": url}}) == []


def test_mcp_remote_http_arg():
    fs = run({"r": {"command": "npx", "args": ["-y", "mcp-remote@0.1.18", "http://mcp.example.com/sse"]}})
    assert [f.rule_id for f in fs] == ["MCP006"]


# ---------------------------------------------------------------- formats
def test_vscode_jsonc_with_comments_and_trailing_commas(fake):
    text = """{
  // VS Code workspace MCP config
  "inputs": [{"type": "promptString", "id": "gh", "password": true}],
  "servers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"], /* unpinned */
      "env": {"GITHUB_TOKEN": "${input:gh}", "URL": "https://x.example.com//path"},
    },
  },
}"""
    res = scan_config_text(".vscode/mcp.json", text)
    assert res.parsed and res.servers == 1
    assert [(f.rule_id, f.line) for f in res.findings] == [("MCP002", 7)]


def test_strip_jsonc_keeps_strings():
    assert strip_jsonc('{"a": "http://x//y", "b": "/* no */"} // c') .startswith('{"a": "http://x//y", "b": "/* no */"}')


def test_claude_code_user_config_projects_nesting(fake):
    data = {"projects": {"/home/me/app": {"mcpServers": {"gh": {"command": "npx", "args": ["-y", "x@1.0.0"],
                                                                 "env": {"GITHUB_TOKEN": fake["github"]}}}}}}
    res = scan_config_text(".claude.json", json.dumps(data, indent=2))
    assert [f.rule_id for f in res.findings] == ["MCP001"]


def test_ignore_comment_in_jsonc(fake):
    text = '{"mcpServers": {"s": {\n"command": "npx",\n"args": ["-y", "some-mcp"] // mcp-audit: ignore\n}}}'
    assert scan_config_text(".mcp.json", text).findings == []


def test_unrelated_json_is_not_treated_as_config(make_repo):
    root = make_repo({"package.json": {"name": "x", "servers": {"a": {"command": "npx", "args": ["-y", "pkg"]}}},
                      "data/servers.json": {"servers": {"a": {"command": "npx", "args": ["-y", "pkg"]}}}})
    res = scan_path(str(root))
    assert res.findings == [] and res.config_files == []


def test_config_file_discovery(make_repo, fake):
    srv = {"mcpServers": {"s": {"command": "npx", "args": ["-y", "pkg"]}}}
    root = make_repo({".cursor/mcp.json": srv, ".vscode/mcp.json": {"servers": srv["mcpServers"]}, ".mcp.json": srv,
                      "claude_desktop_config.json": srv, "windsurf/mcp_config.json": srv,
                      "cline_mcp_settings.json": srv, "any/other-name.json": srv,
                      "node_modules/x/.mcp.json": srv})
    res = scan_path(str(root))
    assert sorted(res.config_files) == sorted([".cursor/mcp.json", ".vscode/mcp.json", ".mcp.json",
                                               "claude_desktop_config.json", "windsurf/mcp_config.json",
                                               "cline_mcp_settings.json", "any/other-name.json"])
    assert len(res.findings) == 7


def test_invalid_json_does_not_crash():
    res = scan_config_text(".mcp.json", '{"mcpServers": {')
    assert res.findings == [] and not res.parsed
