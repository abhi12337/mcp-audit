import textwrap
from pathlib import Path

import pytest

from mcp_audit.js_scan import lex, scan_js

FIX = Path(__file__).parent / "fixtures"
HEADER = ('import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
          'import { z } from "zod";\n'
          'const server = new McpServer({ name: "t", version: "1.0.0" });\n')


def scan(body: str, header: str = HEADER):
    return scan_js("index.ts", header + textwrap.dedent(body))


def rules(findings):
    return sorted(f.rule_id for f in findings)


def tool(body: str, params: str = "{ input }") -> str:
    return f"""
server.tool("t", "test tool", {{ input: z.string() }}, async ({params}) => {{
  {body}
  return {{ content: [{{ type: "text", text: "ok" }}] }};
}});
"""


def test_vulnerable_fixture_exact_findings():
    text = (FIX / "ts_vulnerable" / "src" / "index.ts").read_text()
    got = sorted((f.rule_id, f.severity, f.line) for f in scan_js("src/index.ts", text))
    assert got == sorted([
        ("MCP101", "critical", 19),   # execAsync(`npm test --workspace ${pkg}`)
        ("MCP101", "high", 27),       # spawn(program, args)
        ("MCP102", "high", 34),       # fs.readFile(full)
        ("MCP102", "critical", 39),   # fs.rm(path.join(WORKSPACE, file))
        ("MCP103", "high", 44),       # db.query(`... '${email}'`)
        ("MCP104", "high", 49),       # fetch(url)
        ("MCP105", "info", 50),       # res.text() returned
        ("MCP106", "low", 38),        # delete_file without annotations
        ("MCP107", "high", 55),       # GITHUB_TOKEN in tool result
    ])
    by_line = {f.line: f for f in scan_js("src/index.ts", text)}
    assert by_line[34].extra["param"] == "file"        # reported as the tool parameter, not the temp var


def test_clean_fixture_has_no_findings():
    text = (FIX / "ts_clean" / "src" / "index.ts").read_text()
    assert scan_js("src/index.ts", text) == []


def test_non_mcp_file_is_ignored():
    assert scan_js("x.ts", "import { exec } from 'child_process';\nexport const f = (c) => exec(c);\n") == []


def test_lexer_blanks_strings_and_comments_but_keeps_template_expressions():
    src = 'const a = "exec(x)"; // exec(y)\nconst b = `run ${cmd} now`; /* fetch(u) */ const r = /["\'`]/;'
    clean, code = lex(src)
    assert len(clean) == len(code) == len(src)
    assert "exec(y)" not in clean and "fetch(u)" not in clean and "exec(x)" in clean
    assert "exec(x)" not in code and "${cmd}" in code and "run" not in code


# ---------------------------------------------------------------- shell
CP = 'import { exec, execSync, spawn, execFile } from "node:child_process";\n'


@pytest.mark.parametrize("body,expected", [
    ("exec(`ls ${input}`);", ["MCP101"]),
    ("execSync('git log ' + input);", ["MCP101"]),
    ("const cmd = `grep ${input} *.log`; execSync(cmd);", ["MCP101"]),
    ("spawn('sh', ['-c', input], { shell: true });", ["MCP101"]),
    ("execFile('git', ['log', input]);", []),
    ("spawn(input, []);", ["MCP101"]),
    ("exec('ls -la');", []),
    ("const m = /a(b)/.exec(input);", []),
    ("// exec(`rm -rf ${input}`)", []),
    ("const s = \"exec(`${input}`)\";", []),
    ("exec(`ls ${Number(input)}`);", []),
])
def test_shell_patterns(body, expected):
    assert rules(scan(tool(body), HEADER + CP)) == expected


def test_shell_via_require_namespace_and_promisify():
    header = HEADER + 'const cp = require("child_process");\nconst util = require("util");\n' \
                      'const run = util.promisify(cp.exec);\n'
    fs = scan(tool("cp.exec(`echo ${input}`);\n  await run(`cat ${input}`);"), header)
    assert rules(fs) == ["MCP101", "MCP101"]


def test_execa_shell_true():
    header = HEADER + 'import { execa, execaCommand } from "execa";\n'
    assert rules(scan(tool("await execa(input, { shell: true });"), header)) == ["MCP101"]
    assert rules(scan(tool("await execaCommand(input);"), header)) == ["MCP101"]
    assert rules(scan(tool("await execa('git', ['log', input]);"), header)) == []


# ---------------------------------------------------------------- low-level server + helpers
LOWLEVEL = """
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import * as fs from "fs";
import { execSync } from "child_process";

const server = new Server({ name: "x", version: "1" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "read_file", description: "Read", inputSchema: { type: "object" } },
    { name: "delete_file", description: "Delete", inputSchema: { type: "object" } },
    { name: "remove_dir", description: "Rm", inputSchema: { type: "object" },
      annotations: { destructiveHint: true } },
  ],
}));

function runCommand(cmd: string): string {
  return execSync(cmd).toString();
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  switch (name) {
    case "read_file": {
      const { path } = args as { path: string };
      return { content: [{ type: "text", text: fs.readFileSync(path, "utf8") }] };
    }
    case "run":
      return { content: [{ type: "text", text: runCommand(String(args?.command)) }] };
  }
});
"""


def test_lowlevel_server_with_helper_dispatch():
    fs = scan_js("index.ts", LOWLEVEL)
    got = sorted((f.rule_id, f.line) for f in fs)
    assert got == [("MCP101", 19), ("MCP102", 27), ("MCP106", 12)]


# ---------------------------------------------------------------- fs
FSH = 'import fs from "node:fs/promises";\nimport { readFileSync, writeFileSync } from "fs";\n' \
      'import path from "node:path";\nconst ROOT = path.resolve("/srv");\n'


@pytest.mark.parametrize("body,expected", [
    ("await fs.readFile(input, 'utf8');", ["MCP102"]),
    ("readFileSync(path.join(ROOT, input));", ["MCP102"]),
    ("writeFileSync(input, 'x');", ["MCP102"]),
    ("await fs.readFile(path.join(ROOT, path.basename(input)));", []),
    ("await fs.readFile('/etc/hostname');", []),
    ("const p = path.resolve(ROOT, input); if (!p.startsWith(ROOT + path.sep)) throw new Error('no');"
     " await fs.readFile(p);", []),
    ("const rel = path.relative(ROOT, path.resolve(ROOT, input)); if (rel.startsWith('..')) throw 1;"
     " await fs.readFile(path.join(ROOT, rel));", []),
])
def test_fs_patterns(body, expected):
    assert rules(scan(tool(body), HEADER + FSH)) == expected


def test_fs_write_is_critical():
    [f] = scan(tool("await fs.writeFile(input, 'x');"), HEADER + FSH)
    assert f.severity == "critical"


# ---------------------------------------------------------------- SQL
@pytest.mark.parametrize("body,expected", [
    ("await db.query(`SELECT * FROM t WHERE a = '${input}'`);", ["MCP103"]),
    ("await db.query(\"SELECT * FROM t WHERE a = '\" + input + \"'\");", ["MCP103"]),
    ("db.prepare(`DELETE FROM t WHERE id = ${input}`).run();", ["MCP103"]),
    ("await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE a = ${input}`);", ["MCP103"]),
    ("const q = `SELECT * FROM t WHERE a = '${input}'`; await pool.query(q);", ["MCP103"]),
    ("await db.query('SELECT * FROM t WHERE a = $1', [input]);", []),
    ("await prisma.$queryRaw`SELECT * FROM t WHERE a = ${input}`;", []),
    ("await sql`SELECT * FROM t WHERE a = ${input}`;", []),
    ("await db.query(`SELECT * FROM t LIMIT ${Number(input)}`);", []),
    ("cache.get(`user:${input}`);", []),
])
def test_sql_patterns(body, expected):
    assert rules(scan(tool(body))) == expected


# ---------------------------------------------------------------- SSRF / raw content
@pytest.mark.parametrize("body,expected", [
    ("const r = await fetch(input); await r.json();", ["MCP104"]),
    ("const r = await fetch(new URL(input)); await r.json();", ["MCP104"]),
    ("const r = await fetch(`${input}`); await r.json();", ["MCP104"]),
    ("await axios.get(input);", ["MCP104"]),
    ("const r = await fetch(`https://api.example.com/v1/${input}`); await r.json();", []),
    ("const r = await fetch('https://api.example.com/v1/' + input); await r.json();", []),
    ("const r = await fetch(`${BASE}/items/${input}`); await r.json();", []),
    ("const u = `https://api.example.com/${input}`; const r = await fetch(u); await r.json();", []),
    ("const u = new URL(input); if (!ALLOWED_HOSTS.includes(u.hostname)) throw 1; await fetch(u);", []),
])
def test_ssrf_patterns(body, expected):
    header = HEADER + 'import axios from "axios";\nconst BASE = "https://api.example.com";\n'
    assert rules(scan(tool(body), header)) == expected


def test_raw_content_info():
    fs = scan("""
server.tool("news", "Latest news", {}, async () => {
  const res = await fetch("https://news.example.com/");
  return { content: [{ type: "text", text: await res.text() }] };
});
""")
    assert [(f.rule_id, f.severity) for f in fs] == [("MCP105", "info")]


# ---------------------------------------------------------------- annotations
def test_annotations_registerTool_and_addTool():
    fs = scan("""
server.registerTool("delete_issue", { description: "x", inputSchema: {} }, async () => ({ content: [] }));
server.registerTool("drop_index", { description: "x", annotations: { destructiveHint: true } },
  async () => ({ content: [] }));
server.tool("list_issues", "x", {}, async () => ({ content: [] }));
server.tool("killProcess", "x", { pid: z.number() }, { destructiveHint: true }, async () => ({ content: [] }));
server.tool("removeLabel", "x", {}, async () => ({ content: [] }));
""")
    assert sorted(f.extra["tool"] for f in fs) == ["delete_issue", "removeLabel"]


def test_fastmcp_ts_addTool():
    header = 'import { FastMCP } from "fastmcp";\nimport { exec } from "child_process";\n' \
             'const server = new FastMCP({ name: "x", version: "1.0.0" });\n'
    fs = scan("""
server.addTool({
  name: "run",
  description: "run a command",
  parameters: z.object({ cmd: z.string() }),
  execute: async (args) => {
    exec(`bash -c "${args.cmd}"`);
    return "ok";
  },
});
""", header)
    assert rules(fs) == ["MCP101"]


# ---------------------------------------------------------------- secrets in results
@pytest.mark.parametrize("text_expr,expected", [
    ("`key: ${API_KEY}`", ["MCP107"]),
    ("process.env.OPENAI_API_KEY", ["MCP107"]),
    ("JSON.stringify(process.env)", ["MCP107"]),
    ("'token ' + TOKEN", ["MCP107"]),
    ("`configured: ${Boolean(API_KEY)}`", []),
    ("await callApi(API_KEY)", []),
    ("process.env.NODE_ENV", []),
    ("`home: ${process.env.HOME}`", []),
])
def test_secret_echo(text_expr, expected):
    header = HEADER + 'const API_KEY = process.env.API_KEY;\nconst { TOKEN } = process.env;\n'
    fs = scan(f"""
server.tool("info", "x", {{}}, async () => {{
  return {{ content: [{{ type: "text", text: {text_expr} }}] }};
}});
""", header)
    assert rules(fs) == expected


def test_eval_and_new_function():
    fs = scan(tool("eval(input);\n  const f = new Function('a', input);\n  vm.runInNewContext(input);"),
              HEADER + 'import vm from "node:vm";\n')
    assert rules(fs) == ["MCP108", "MCP108", "MCP108"]


def test_ignore_comment():
    assert scan(tool("exec(`ls ${input}`); // mcp-audit: ignore"), HEADER + CP) == []
