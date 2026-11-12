import textwrap
from pathlib import Path

import pytest

from mcp_audit.py_scan import scan_python

FIX = Path(__file__).parent / "fixtures"
HEADER = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"


def scan(body: str, header: str = HEADER):
    return scan_python("server.py", header + textwrap.dedent(body))


def rules(findings):
    return sorted(f.rule_id for f in findings)


def test_vulnerable_fixture_exact_findings():
    text = (FIX / "py_vulnerable" / "server.py").read_text()
    got = sorted((f.rule_id, f.severity, f.line) for f in scan_python("server.py", text))
    assert got == sorted([
        ("MCP101", "critical", 20),   # subprocess.run(command, shell=True)
        ("MCP101", "critical", 27),   # os.popen(f"git log {branch}")
        ("MCP102", "high", 34),       # open(os.path.join(NOTES_DIR, name))
        ("MCP102", "critical", 41),   # Path(NOTES_DIR, name).write_text
        ("MCP102", "critical", 53),   # os.remove in a helper called by delete_note
        ("MCP103", "high", 60),       # f-string SQL
        ("MCP103", "high", 68),       # concatenated SQL via a variable
        ("MCP104", "high", 75),       # client.get(url)
        ("MCP105", "info", 76),       # return resp.text
        ("MCP106", "low", 45),        # delete_note without annotations
        ("MCP107", "high", 88),       # returns OPENAI_API_KEY
        ("MCP108", "critical", 82),   # eval(expression)
    ])


def test_clean_fixture_has_no_findings():
    text = (FIX / "py_clean" / "server.py").read_text()
    assert scan_python("server.py", text) == []


def test_non_mcp_file_is_ignored():
    assert scan_python("x.py", "import os\ndef tool(cmd):\n    os.system(cmd)\n") == []


def test_fix_names_the_parameter():
    [f] = scan("""
        import os
        @mcp.tool()
        def run(cmd: str) -> str:
            line = "echo " + cmd
            return os.popen(line).read()
    """)
    assert f.rule_id == "MCP101" and f.extra["param"] == "cmd"
    assert "cmd" in f.fix and "'cmd'" in f.message


# ---------------------------------------------------------------- shell
@pytest.mark.parametrize("code,expected", [
    ("os.system(cmd)", ["MCP101"]),
    ("subprocess.call(cmd, shell=True)", ["MCP101"]),
    ("subprocess.check_output('ls ' + cmd, shell=True)", ["MCP101"]),
    ("subprocess.getoutput(f'cat {cmd}')", ["MCP101"]),
    ("subprocess.run([cmd, '--version'])", ["MCP101"]),
    ("subprocess.run(cmd.split())", ["MCP101"]),
    ("subprocess.run(['git', 'show', cmd])", []),
    ("subprocess.run(f'ls {shlex.quote(cmd)}', shell=True)", []),
    ("subprocess.run('ls -la', shell=True)", []),
    ("os.system('uptime')", []),
    ("subprocess.run(cmd, shell=False)", ["MCP101"]),
])
def test_shell_patterns(code, expected):
    fs = scan(f"""
        import os, shlex, subprocess
        @mcp.tool()
        def t(cmd: str) -> str:
            {code}
            return "ok"
    """)
    assert rules(fs) == expected


def test_program_choice_is_high_shell_true_is_critical():
    fs = scan("""
        import subprocess
        @mcp.tool()
        def a(cmd: str): subprocess.run([cmd])
        @mcp.tool()
        def b(cmd: str): subprocess.run(cmd, shell=True)
    """)
    assert sorted(f.severity for f in fs) == ["critical", "high"]


def test_asyncio_shell_and_aliases():
    fs = scan("""
        import asyncio
        from subprocess import run as sh
        @mcp.tool()
        async def a(cmd: str):
            p = await asyncio.create_subprocess_shell(cmd)
        @mcp.tool()
        def b(cmd: str):
            sh(cmd, shell=True)
    """)
    assert rules(fs) == ["MCP101", "MCP101"]


def test_lowlevel_call_tool_handler():
    fs = scan("""
        import subprocess
        from mcp.server import Server
        server = Server("x")
        @server.call_tool()
        async def handle(name: str, arguments: dict):
            if name == "run":
                cmd = arguments["command"]
                return subprocess.check_output(cmd, shell=True)
    """)
    assert rules(fs) == ["MCP101"]


def test_add_tool_registration():
    fs = scan("""
        import os
        def run_it(command: str) -> str:
            return os.popen(command).read()
        mcp.add_tool(run_it, name="run")
    """)
    assert rules(fs) == ["MCP101"]


def test_untainted_params_and_context_are_ignored():
    fs = scan("""
        import os
        from mcp.server.fastmcp import Context
        @mcp.tool()
        def t(n: int, ctx: Context) -> str:
            os.system(ctx.request_id)
            return "x"
    """)
    assert fs == []


def test_helper_depth_two():
    fs = scan("""
        import os
        def _inner(c):
            os.system(c)
        def _outer(c):
            _inner("x " + c)
        @mcp.tool()
        def t(cmd: str):
            _outer(cmd)
    """)
    assert rules(fs) == ["MCP101"]


def test_ignore_comment():
    fs = scan("""
        import os
        @mcp.tool()
        def t(cmd: str):
            os.system(cmd)  # mcp-audit: ignore
    """)
    assert fs == []


# ---------------------------------------------------------------- eval
def test_eval_and_exec():
    fs = scan("""
        @mcp.tool()
        def a(code: str): exec(code)
        @mcp.tool()
        def b(expr: str): return eval(expr, {"__builtins__": {}})
        @mcp.tool()
        def c(n: int): return eval("1+1")
    """)
    assert rules(fs) == ["MCP108", "MCP108"]


# ---------------------------------------------------------------- paths
@pytest.mark.parametrize("code,expected", [
    ("open(path).read()", ["MCP102"]),
    ("open(path, 'w').write('x')", ["MCP102"]),
    ("Path(path).read_text()", ["MCP102"]),
    ("(BASE / path).read_bytes()", ["MCP102"]),
    ("shutil.rmtree(path)", ["MCP102", "MCP106"]),  # deleting tool without annotations
    ("os.listdir(path)", ["MCP102"]),
    ("path.replace('a', 'b')", []),             # str.replace, not Path.replace
    ("open(os.path.join(BASE, os.path.basename(path))).read()", []),
    ("open('/etc/hostname').read()", []),
])
def test_path_patterns(code, expected):
    fs = scan(f"""
        import os, shutil
        from pathlib import Path
        BASE = Path("/srv/data")
        @mcp.tool()
        def t(path: str):
            return {code}
    """)
    assert rules(fs) == expected


def test_write_is_critical_read_is_high():
    fs = scan("""
        from pathlib import Path
        @mcp.tool()
        def r(p: str): return open(p).read()
        @mcp.tool()
        def w(p: str, body: str): Path(p).write_text(body)
    """)
    assert sorted(f.severity for f in fs) == ["critical", "high"]


@pytest.mark.parametrize("check", [
    "if not target.is_relative_to(BASE): raise ValueError()",
    "if os.path.commonpath([BASE, target]) != str(BASE): raise ValueError()",
    "target.relative_to(BASE)",
])
def test_containment_checks_suppress(check):
    fs = scan(f"""
        import os
        from pathlib import Path
        BASE = Path("/srv").resolve()
        @mcp.tool()
        def t(p: str):
            target = (BASE / p).resolve()
            {check}
            return target.read_text()
    """)
    assert fs == []


def test_containment_helper_by_body():
    fs = scan("""
        import os
        BASE = "/srv"
        def inside_root(p):
            full = os.path.realpath(os.path.join(BASE, p))
            if not full.startswith(BASE + os.sep):
                raise ValueError()
            return full
        @mcp.tool()
        def t(p: str):
            return open(inside_root(p)).read()
    """)
    assert fs == []


# ---------------------------------------------------------------- SQL
@pytest.mark.parametrize("code,expected", [
    ("cur.execute(f\"SELECT * FROM t WHERE name = '{q}'\")", ["MCP103"]),
    ("cur.execute(\"SELECT * FROM t WHERE name = '%s'\" % q)", ["MCP103"]),
    ("cur.execute(\"SELECT * FROM t WHERE name = '{}'\".format(q))", ["MCP103"]),
    ("conn.execute(text(f\"DELETE FROM t WHERE id = {q}\"))", ["MCP103"]),
    ("await pool.fetch(f\"SELECT * FROM {q}\")", ["MCP103"]),
    ("cur.execute(\"SELECT * FROM t WHERE name = ?\", (q,))", []),
    ("cur.execute(\"SELECT * FROM t WHERE name = %s\", (q,))", []),
    ("cur.execute(f\"SELECT * FROM t LIMIT {int(q)}\")", []),
    ("cur.execute(f\"SELECT * FROM t WHERE id = {CONST}\")", []),
    ("log.info(f\"select {q}\")", []),
])
def test_sql_patterns(code, expected):
    fs = scan(f"""
        from sqlalchemy import text
        CONST = 5
        @mcp.tool()
        async def t(q: str):
            {code}
    """)
    assert rules(fs) == expected


def test_sql_built_incrementally():
    fs = scan("""
        @mcp.tool()
        def t(name: str, db=None):
            sql = "SELECT * FROM users"
            sql += f" WHERE name = '{name}'"
            return db.execute(sql)
    """)
    assert rules(fs) == ["MCP103"]


# ---------------------------------------------------------------- SSRF / raw content
@pytest.mark.parametrize("code,expected", [
    ("requests.get(url).json()", ["MCP104"]),
    ("httpx.post(url, json={}).json()", ["MCP104"]),
    ("urllib.request.urlopen(url).read()", ["MCP104", "MCP105"]),
    ("requests.request('GET', url).json()", ["MCP104"]),
    ("requests.get(f'https://api.example.com/v1/{url}').json()", []),
    ("requests.get('https://api.example.com/v1/' + url).json()", []),
    ("requests.get(BASE + url).json()", []),
    ("requests.get('https://api.example.com/x', params={'q': url}).json()", []),
])
def test_ssrf_patterns(code, expected):
    fs = scan(f"""
        import requests, httpx, urllib.request
        BASE = "https://api.example.com/"
        @mcp.tool()
        def t(url: str):
            return {code}
    """)
    assert rules(fs) == expected


def test_ssrf_fixed_host_variable_and_session():
    fs = scan("""
        import requests
        @mcp.tool()
        def a(path: str):
            endpoint = f"https://api.example.com/{path}"
            return requests.get(endpoint).json()
        @mcp.tool()
        def b(url: str):
            s = requests.Session()
            return s.get(url).json()
    """)
    assert [(f.rule_id, f.extra["param"]) for f in fs] == [("MCP104", "url")]


def test_ssrf_allowlist_suppresses():
    fs = scan("""
        import httpx
        from urllib.parse import urlparse
        ALLOWED = {"example.com"}
        @mcp.tool()
        def t(url: str):
            if urlparse(url).hostname not in ALLOWED:
                raise ValueError()
            return httpx.get(url).json()
    """)
    assert fs == []


def test_raw_content_is_info():
    fs = scan("""
        import httpx
        @mcp.tool()
        def news() -> str:
            r = httpx.get("https://news.example.com/")
            html = r.text
            return html[:5000]
    """)
    assert [(f.rule_id, f.severity) for f in fs] == [("MCP105", "info")]


# ---------------------------------------------------------------- annotations
def test_destructive_tool_annotations():
    fs = scan("""
        import os
        @mcp.tool()
        def drop_table(name: str) -> str: return "x"
        @mcp.tool(name="purgeCache")
        def pc() -> str: return "x"
        @mcp.tool(annotations={"destructiveHint": True})
        def delete_user(uid: int) -> str: return "x"
        @mcp.tool()
        def list_users() -> str: return "x"
        @mcp.tool()
        def cleanup(n: int) -> str:
            os.remove("/tmp/cache")
            return "x"
    """)
    assert sorted(f.extra["tool"] for f in fs) == ["cleanup", "drop_table", "purgeCache"]
    assert {f.severity for f in fs} == {"low"}


def test_lowlevel_tool_definition_annotations():
    fs = scan("""
        from mcp import types
        TOOLS = [
            types.Tool(name="delete_repo", description="x", inputSchema={}),
            types.Tool(name="remove_file", description="x", inputSchema={},
                       annotations=types.ToolAnnotations(destructiveHint=True)),
            types.Tool(name="get_repo", description="x", inputSchema={}),
        ]
    """)
    assert [f.extra["tool"] for f in fs] == ["delete_repo"]


# ---------------------------------------------------------------- secrets in results
@pytest.mark.parametrize("ret,expected", [
    ("return os.environ['STRIPE_SECRET_KEY']", ["MCP107"]),
    ("return {'key': os.getenv('API_KEY')}", ["MCP107"]),
    ("return f'token={TOKEN}'", ["MCP107"]),
    ("return json.dumps(dict(os.environ))", ["MCP107"]),
    ("return str(os.environ)", ["MCP107"]),
    ("return {k: v for k, v in os.environ.items()}", ["MCP107"]),
    ("return os.environ.get('HOME')", []),
    ("return {'configured': bool(TOKEN)}", []),
    ("return {'configured': TOKEN is not None}", []),
    ("return call_api(TOKEN)", []),
    ("return len(os.environ['API_KEY'])", []),
])
def test_secret_echo(ret, expected):
    fs = scan(f"""
        import os, json
        TOKEN = os.environ["GITHUB_TOKEN"]
        def call_api(t): return "ok"
        @mcp.tool()
        def t():
            {ret}
    """)
    assert rules(fs) == expected


def test_syntax_error_does_not_crash():
    assert scan_python("bad.py", "from mcp import types\ndef (:\n") == []
