# mcp-audit

A static security audit for MCP (Model Context Protocol) setups. It reads two kinds of
files and tells you what an attacker could do with them:

1. **MCP client configs**: `claude_desktop_config.json`, `.mcp.json` (Claude Code),
   `.cursor/mcp.json`, `.vscode/mcp.json`, Windsurf `mcp_config.json`, Cline / Roo
   settings, Gemini CLI and Zed settings. It finds hard-coded tokens, servers launched with
   `npx -y` / `uvx` and no version, `@latest`, filesystem servers given `/` or your home
   directory, privileged docker servers, and remote servers over plain http.
2. **MCP server source code** in TypeScript/JavaScript (`@modelcontextprotocol/sdk`,
   `fastmcp`) and Python (`mcp`, FastMCP). It follows tool arguments, which the model writes
   and a prompt injection can control, into shell commands, file paths, SQL, outgoing HTTP
   requests, `eval`, and tool results that leak secrets.

Every finding has a rule id, a severity, `file:line`, the offending line (secrets
masked), and a concrete fix written for that finding's language and names.

Zero dependencies (Python 3.10+ standard library only). **Static only:** it never starts,
imports or connects to any MCP server and makes no network requests. CI-friendly exit codes.

---

## Quick start

```bash
pipx install git+https://github.com/abhi12337/mcp-audit   # straight from GitHub
pipx install .                          # from a clone of this repo (or: pip install .)

mcp-audit scan                          # current folder: configs + server code
mcp-audit scan path/to/repo path/to/other-repo
mcp-audit scan ~/.cursor/mcp.json       # a single config file
mcp-audit scan --user-configs           # this machine's MCP client configs (see below)
mcp-audit scan . --json > report.json   # machine-readable output
mcp-audit rules                         # every rule, why it matters, how to fix it
```

Try it on the deliberately broken demo project (a config plus two vulnerable servers
copied from `tests/fixtures`):

```bash
python examples/make_demo.py demo-mcp
mcp-audit scan demo-mcp
```

Exit codes: `0` = nothing at or above `--fail-on` (default `high`), `1` = findings at or above
it, `2` = usage error. Use `--fail-on critical|high|medium|low|info|never` to tune CI.

## Example output

All output below was produced by running this version of the tool on the demo project and the test fixtures in this repository (nothing is hand-edited).

`mcp-audit scan demo-mcp/.cursor/mcp.json --brief` (the config alone):

```text
mcp-audit 0.1.1
Scanned demo-mcp/.cursor/mcp.json
1 file(s): 1 MCP config file(s) with 7 server(s), 0 MCP server source file(s)

CRITICAL MCP001  Hard-coded secret in MCP config
      at: demo-mcp/.cursor/mcp.json:10
      GitHub token hard-coded in env.GITHUB_PERSONAL_ACCESS_TOKEN of server 'github'. Anyone with
      this file has it.
      code: env.GITHUB_PERSONAL_ACCESS_TOKEN = ghp_**** (40 chars)

CRITICAL MCP005  Docker MCP server with privileged or host access
      at: demo-mcp/.cursor/mcp.json:39
      Server 'browser' runs a --privileged container: it has full access to the host devices and
      kernel.
      code: "--privileged",

CRITICAL MCP005  Docker MCP server with privileged or host access
      at: demo-mcp/.cursor/mcp.json:41
      Server 'browser' mounts the docker socket: the container can start privileged containers and
      take over the host.
      code: "/var/run/docker.sock:/var/run/docker.sock",

HIGH     MCP004  Filesystem MCP server given a broad root
      at: demo-mcp/.cursor/mcp.json:18
      Server 'filesystem' is given /Users/alice (your home directory) as an accessible root: the
      model can read (and possibly write) everything under it.
      code: "/Users/alice"

HIGH     MCP006  Remote MCP server over plain http
      at: demo-mcp/.cursor/mcp.json:47
      Server 'team-wiki' connects to http://wiki.internal.example.com:8080/sse over plain http:
      tool calls, results and tokens travel unencrypted.
      code: http://wiki.internal.example.com:8080/sse

MEDIUM   MCP002  MCP server launched without a pinned version
      at: demo-mcp/.cursor/mcp.json:7
      Server 'github' runs @modelcontextprotocol/server-github with no version: whatever the
      registry serves at launch time is executed.
      code: "@modelcontextprotocol/server-github"

MEDIUM   MCP002  MCP server launched without a pinned version
      at: demo-mcp/.cursor/mcp.json:24
      Server 'fetch' runs mcp-server-fetch with no version: whatever the registry serves at launch
      time is executed.
      code: "mcp-server-fetch"

MEDIUM   MCP003  MCP server pinned to a moving tag (@latest / :latest)
      at: demo-mcp/.cursor/mcp.json:17
      Server 'filesystem' runs @modelcontextprotocol/server-filesystem at the moving tag 'latest':
      every client start can pull new, unreviewed code.
      code: "@modelcontextprotocol/server-filesystem@latest",

MEDIUM   MCP003  MCP server pinned to a moving tag (@latest / :latest)
      at: demo-mcp/.cursor/mcp.json:42
      Server 'browser' runs docker image mcp/browser:latest: ':latest' moves with every release.
      code: "mcp/browser:latest"

Summary: 3 critical, 2 high, 4 medium, 0 low, 0 info
Exit code: 1
```

A full finding (without `--brief`), with the fix written for the language and variable
name of the code it was found in:

```text
HIGH     MCP104  Tool fetches arbitrary URLs (SSRF)
      at: server.py:75
      Tool input 'url' is used as the URL in client.get() with no host allowlist or private-
      address check: SSRF (http://169.254.169.254/, localhost).
      code: resp = await client.get(url)
      why: A fetch tool that requests any URL the model gives it can be steered to internal
           services: cloud metadata (http://169.254.169.254/ returns instance credentials),
           localhost admin ports, and private network hosts the user's machine can reach.
      fix:
        Validate the URL before fetching:

          1. Allow only https (and http only if you must).
          2. Prefer an allowlist of hosts when the tool has a known purpose:
               if urlparse(url).hostname not in ALLOWED_HOSTS: raise ValueError("host not allowed")
          3. Otherwise resolve the hostname and reject private, loopback, link-local and
             metadata addresses (ipaddress.ip_address(addr).is_private / is_loopback / is_link_local).
          4. Disable redirects or re-check every redirect target.
```

<details>
<summary>The whole demo project: <code>mcp-audit scan demo-mcp --brief</code> (config + Python server + TypeScript server)</summary>

```text
mcp-audit 0.1.1
Scanned demo-mcp
3 file(s): 1 MCP config file(s) with 7 server(s), 2 MCP server source file(s)

CRITICAL MCP001  Hard-coded secret in MCP config
      at: .cursor/mcp.json:10
      GitHub token hard-coded in env.GITHUB_PERSONAL_ACCESS_TOKEN of server 'github'. Anyone with
      this file has it.
      code: env.GITHUB_PERSONAL_ACCESS_TOKEN = ghp_**** (40 chars)

CRITICAL MCP005  Docker MCP server with privileged or host access
      at: .cursor/mcp.json:39
      Server 'browser' runs a --privileged container: it has full access to the host devices and
      kernel.
      code: "--privileged",

CRITICAL MCP005  Docker MCP server with privileged or host access
      at: .cursor/mcp.json:41
      Server 'browser' mounts the docker socket: the container can start privileged containers and
      take over the host.
      code: "/var/run/docker.sock:/var/run/docker.sock",

CRITICAL MCP101  Shell command built from tool input
      at: server-python/server.py:20
      Tool input 'command' reaches subprocess.run(..., shell=True): a prompt injection can run any
      shell command.
      code: out = subprocess.run(command, shell=True, capture_output=True, text=True)

CRITICAL MCP101  Shell command built from tool input
      at: server-python/server.py:27
      Tool input 'branch' reaches os.popen(): a prompt injection can run any shell command.
      code: return os.popen(f"git log --oneline {branch}").read()

CRITICAL MCP101  Shell command built from tool input
      at: server-ts/src/index.ts:19
      Tool input 'pkg' is interpolated into a shell command run by execAsync(): a prompt injection
      can run any command.
      code: const { stdout } = await execAsync(`npm test --workspace ${pkg}`);

CRITICAL MCP102  File access without path containment
      at: server-python/server.py:41
      Tool input 'name' is used as a path in Path.write_text() (write/delete) with no check that
      it stays inside an allowed directory: path traversal (../../.ssh/id_rsa).
      code: Path(NOTES_DIR, name).write_text(body)

CRITICAL MCP102  File access without path containment
      at: server-python/server.py:53
      Tool input 'name' is used as a path in os.remove() (write/delete) with no check that it
      stays inside an allowed directory: path traversal (../../.ssh/id_rsa).
      code: os.remove(os.path.join(NOTES_DIR, name))

CRITICAL MCP102  File access without path containment
      at: server-ts/src/index.ts:39
      Tool input 'file' is used as a path in fs.rm() (write/delete) with no check that it stays
      inside an allowed directory: path traversal (../../.ssh/id_rsa).
      code: await fs.rm(path.join(WORKSPACE, file), { force: true });

CRITICAL MCP108  Code evaluation of tool input
      at: server-python/server.py:82
      Tool input 'expression' is passed to eval(): remote code execution.
      code: return str(eval(expression))

HIGH     MCP004  Filesystem MCP server given a broad root
      at: .cursor/mcp.json:18
      Server 'filesystem' is given /Users/alice (your home directory) as an accessible root: the
      model can read (and possibly write) everything under it.
      code: "/Users/alice"

HIGH     MCP006  Remote MCP server over plain http
      at: .cursor/mcp.json:47
      Server 'team-wiki' connects to http://wiki.internal.example.com:8080/sse over plain http:
      tool calls, results and tokens travel unencrypted.
      code: http://wiki.internal.example.com:8080/sse

HIGH     MCP101  Shell command built from tool input
      at: server-ts/src/index.ts:27
      Tool input 'program' chooses the program run by spawn(): the model can run any executable.
      code: const child = spawn(program, args);

HIGH     MCP102  File access without path containment
      at: server-python/server.py:34
      Tool input 'name' is used as a path in open() (read) with no check that it stays inside an
      allowed directory: path traversal (../../.ssh/id_rsa).
      code: with open(path) as f:

HIGH     MCP102  File access without path containment
      at: server-ts/src/index.ts:34
      Tool input 'file' is used as a path in fs.readFile() (read) with no check that it stays
      inside an allowed directory: path traversal (../../.ssh/id_rsa).
      code: const text = await fs.readFile(full, "utf8");

HIGH     MCP103  SQL built from tool input
      at: server-python/server.py:60
      SQL is built from tool input 'term' with string formatting and run via execute(): SQL
      injection.
      code: cur.execute(f"SELECT id, title FROM notes WHERE title LIKE '%{term}%'")

HIGH     MCP103  SQL built from tool input
      at: server-python/server.py:68
      SQL is built from tool input 'tag' with string formatting and run via execute(): SQL
      injection.
      code: return DB.execute(sql).fetchall()

HIGH     MCP103  SQL built from tool input
      at: server-ts/src/index.ts:44
      SQL is built from tool input 'email' with string interpolation and run via query(): SQL
      injection.
      code: const result = await db.query(`SELECT id, name FROM users WHERE email = '${email}'`);

HIGH     MCP104  Tool fetches arbitrary URLs (SSRF)
      at: server-python/server.py:75
      Tool input 'url' is used as the URL in client.get() with no host allowlist or private-
      address check: SSRF (http://169.254.169.254/, localhost).
      code: resp = await client.get(url)

HIGH     MCP104  Tool fetches arbitrary URLs (SSRF)
      at: server-ts/src/index.ts:49
      Tool input 'url' is used as the URL in fetch() with no host allowlist or private-address
      check: SSRF (http://169.254.169.254/, localhost).
      code: const res = await fetch(url);

HIGH     MCP107  Secret from environment returned in tool result
      at: server-python/server.py:88
      Tool result includes the secret env var 'OPENAI_API_KEY' (via OPENAI_KEY): it ends up in the
      model context and transcript.
      code: return {"notes_dir": NOTES_DIR, "openai_key": OPENAI_KEY}

HIGH     MCP107  Secret from environment returned in tool result
      at: server-ts/src/index.ts:55
      Tool result includes the secret env var 'GITHUB_TOKEN' (via GITHUB_TOKEN): it ends up in the
      model context and transcript.
      code: return { content: [{ type: "text", text: `token: ${GITHUB_TOKEN}` }] };

MEDIUM   MCP002  MCP server launched without a pinned version
      at: .cursor/mcp.json:7
      Server 'github' runs @modelcontextprotocol/server-github with no version: whatever the
      registry serves at launch time is executed.
      code: "@modelcontextprotocol/server-github"

MEDIUM   MCP002  MCP server launched without a pinned version
      at: .cursor/mcp.json:24
      Server 'fetch' runs mcp-server-fetch with no version: whatever the registry serves at launch
      time is executed.
      code: "mcp-server-fetch"

MEDIUM   MCP003  MCP server pinned to a moving tag (@latest / :latest)
      at: .cursor/mcp.json:17
      Server 'filesystem' runs @modelcontextprotocol/server-filesystem at the moving tag 'latest':
      every client start can pull new, unreviewed code.
      code: "@modelcontextprotocol/server-filesystem@latest",

MEDIUM   MCP003  MCP server pinned to a moving tag (@latest / :latest)
      at: .cursor/mcp.json:42
      Server 'browser' runs docker image mcp/browser:latest: ':latest' moves with every release.
      code: "mcp/browser:latest"

LOW      MCP106  Destructive tool without annotations
      at: server-python/server.py:45
      Tool 'delete_note' looks destructive but declares no annotations (destructiveHint /
      readOnlyHint), so clients cannot tell it apart from a read-only tool.
      code: @mcp.tool()

LOW      MCP106  Destructive tool without annotations
      at: server-ts/src/index.ts:38
      Tool 'delete_file' looks destructive but declares no annotations (destructiveHint /
      readOnlyHint), so clients cannot tell it apart from a read-only tool.
      code: server.tool("delete_file", "Delete a file", { file: z.string() }, async ({ file }) => {

INFO     MCP105  Raw web content returned to the model
      at: server-python/server.py:76
      Tool 'fetch_page' returns fetched web content to the model as-is: prompt-injection exposure.
      code: return resp.text

INFO     MCP105  Raw web content returned to the model
      at: server-ts/src/index.ts:50
      Tool 'fetch_url' returns fetched web content to the model as-is: prompt-injection exposure.
      code: const body = await res.text();

Summary: 10 critical, 12 high, 4 medium, 2 low, 2 info
Exit code: 1
```

</details>

The same servers written safely (`tests/fixtures/py_clean`, `tests/fixtures/ts_clean`)
produce no findings:

```text
mcp-audit 0.1.1
Scanned tests/fixtures/py_clean, tests/fixtures/ts_clean
2 file(s): 0 MCP config file(s) with 0 server(s), 2 MCP server source file(s)

No findings. (This is not a guarantee: see 'What it does not check' in the README.)
Summary: 0 critical, 0 high, 0 medium, 0 low, 0 info
Exit code: 0
```

## What it checks

### MCP client configs

| Rule | Severity | What it finds |
|---|---|---|
| MCP001 | Critical / High | Hard-coded secrets in a server's `env`, `headers`, `args` or URL. Known token formats (GitHub, OpenAI, Anthropic, AWS, Slack, GitLab, Stripe live, Google, npm, Hugging Face, Supabase, Notion, Linear, ...) are Critical; values of secret-named keys (`*_TOKEN`, `*_API_KEY`, `*PASSWORD*`, `Authorization`), `--api-key=...` style args, `user:password@` in connection strings and `?api_key=` query params are High. References such as `${VAR}`, `${env:VAR}`, `${input:id}`, `$VAR`, `%VAR%` and obvious placeholders are ignored. Values are shown as at most the first 4 characters. |
| MCP002 | Medium | Servers started with `npx` / `bunx` / `pnpm dlx` / `npm exec`, `uvx` / `uv tool run` / `pipx run` without a version, with a version range (`^1.2`, `>=1`), or docker images without a tag. Windows `cmd /c npx ...` wrappers are unwrapped. Local paths are ignored. |
| MCP003 | Medium | Packages or images pinned to a moving tag: `@latest`, `@next`, `:latest`, ... |
| MCP004 | High | Filesystem roots that are too broad: `/`, a whole drive (`C:\`), `~`, `$HOME`, `%USERPROFILE%`, `/Users/<name>`, `/home/<name>`, `C:\Users\<name>`. |
| MCP005 | Critical / High / Medium | Docker servers with `--privileged`, the docker socket mounted, `/` mounted (Critical); home directory, `/etc`, `~/.ssh`, `~/.aws` mounts, `--cap-add SYS_ADMIN`/`ALL`, seccomp/apparmor disabled (High); `--network host`, `--pid host` (Medium). |
| MCP006 | High | Remote (`sse` / `http`) servers or `mcp-remote` targets on `http://` to anything other than localhost. |

Servers with `"disabled": true` are still checked for secrets (the token is still in the file)
but not for the other rules.

### MCP server source code

Tool handlers are found from `@mcp.tool()`, `@server.call_tool()` and `mcp.add_tool(fn)` in
Python, and `server.tool(...)`, `server.registerTool(...)`, `server.addTool(...)` and
`setRequestHandler(CallToolRequestSchema, ...)` in TypeScript/JavaScript. Their parameters are
treated as attacker-controlled and followed through assignments, destructuring, string
building and up to two levels of same-file helper functions. Code that is not reachable from
a tool is not reported.

| Rule | Severity | What it finds |
|---|---|---|
| MCP101 | Critical / High | Tool input in a shell command: `subprocess.*(..., shell=True)`, `os.system`, `os.popen`, `asyncio.create_subprocess_shell`, `child_process.exec`/`execSync` (including `promisify(exec)`), `spawn`/`execFile`/`execa` with `shell: true` (Critical). Tool input choosing the program itself: `subprocess.run([cmd, ...])`, `spawn(cmd, args)` (High). `shlex.quote`, `Number(...)` and argv lists with a fixed program are not reported. |
| MCP102 | Critical (write/delete) / High (read) | Tool input used as a path in `open`, `pathlib.Path` methods, `os.remove`, `shutil.*`, `fs.readFile`, `fs.writeFile`, `fs.rm`, ... with no containment check. A check is recognised when the code (or a same-file helper it calls) resolves the path and compares it with a root (`is_relative_to`, `commonpath`, `relative_to`, `resolve`/`realpath` + `startswith`, `path.resolve` + `startsWith`, `path.relative`), or calls a helper named like `safe_path` / `validatePath` / `isWithinRoot`. `basename(...)` counts as safe. |
| MCP103 | High | SQL built from tool input with f-strings, `%`, `.format`, `+` or template literals and passed to `execute`, `executemany`, `fetch`, `text()`, `query`, `prepare`, `$queryRawUnsafe`, ... Only strings that contain SQL keywords are considered. Bound parameters, tagged templates (`` sql`...` ``, `` $queryRaw`...` ``) and `int(...)`/`Number(...)` values are not reported. |
| MCP104 | High | Tool input used as the URL of `requests`, `httpx` (incl. clients), `aiohttp`, `urllib`, `fetch`, `axios`, `got`, `undici`, ... without a host allowlist or private-address check. URLs whose host is fixed (`f"https://api.example.com/{x}"`, `BASE + x`) are not reported. |
| MCP105 | Info | A tool that fetches over HTTP and returns the response text (`resp.text`, `await res.text()`) to the model: prompt-injection exposure. Informational, because fetch tools exist to do this. |
| MCP106 | Low | Tools whose name says they are destructive (`delete`, `remove`, `drop`, `purge`, `kill`, `reset`, `overwrite`, ...) or whose body deletes files, declared without `annotations` (`destructiveHint` / `readOnlyHint`). Also checks low-level `types.Tool(...)` and `ListTools` definitions. |
| MCP107 | High | Tool results that include a secret-named environment variable (`os.environ["API_KEY"]`, `process.env.GITHUB_TOKEN`, or a variable assigned from one) or the whole environment (`dict(os.environ)`, `JSON.stringify(process.env)`). `bool(...)`, comparisons and passing the key into another call are not reported. |
| MCP108 | Critical | Tool input passed to `eval`, `exec`, `compile`, `new Function`, `vm.runIn*Context`. |

Files are only analysed as servers if they import the MCP SDK (`mcp`, `fastmcp`,
`@modelcontextprotocol/sdk`). `node_modules`, `.git`, virtualenvs, build output and test
folders/files are skipped (use `--include-tests` to scan tests, `--exclude GLOB` to skip more).

## What it does not check

Be clear about the limits before relying on it:

- **It is not a penetration test** and gives **no guarantee**. A clean report means "none of
  these known patterns were found", nothing more.
- **No cross-file data flow.** Tool input is followed inside one file only (through up to two
  levels of helper functions). A tool that passes its argument to a function in another
  module is not followed, so the sink there is missed.
- **TypeScript/JavaScript is analysed without a full parser** (comments and strings are
  lexed out, then patterns are matched). Unusual code shapes, dynamic property access,
  class-based tool registries and handlers defined far from their registration may be
  missed. Python uses the real `ast` module and is more precise.
- **Sanitisation is recognised by pattern**, not proven. A containment check that is
  present but wrong (for example `startswith` without resolving `..` first, or checking a
  different variable) is treated as safe. A host allowlist anywhere in the tool counts.
- It does not look at what the server does at runtime: authentication of remote servers,
  OAuth scopes, rate limits, tool-description poisoning, or which tools a client
  auto-approves.
- Secret detection is pattern- and name-based. Custom token formats in oddly named keys are
  missed. Only MCP config files are checked for secrets, not the rest of the repository.
- Other languages (Go, Rust, Java, C#) and other MCP frameworks are not supported yet.
- `--user-configs` covers the common default config locations on macOS, Windows and Linux;
  portable or custom installs need the path passed explicitly.

## How to fix each finding

`mcp-audit rules` prints all of this. Every finding in a report carries its own fix with the
real parameter, tool, package, path or env var name filled in.

**MCP001 - secret in config.** Rotate the token first. Then reference it instead of writing
it into the file: `"${GITHUB_TOKEN}"` in Claude Code `.mcp.json`, `"${env:GITHUB_TOKEN}"` in
Cursor, `"${input:github-token}"` plus an `inputs` entry with `"password": true` in VS Code.
Claude Desktop has no variable syntax: keep that file out of git and anything you share.

**MCP002 / MCP003 - unpinned server.** `npx -y @modelcontextprotocol/server-github@<version>`,
`uvx mcp-server-fetch==<version>`, `ghcr.io/org/image:<version>` or `image@sha256:<digest>`.
Update versions deliberately.

**MCP004 - broad filesystem root.** Pass only the project folders the model needs.

**MCP005 - privileged docker.** Drop `--privileged`, the docker socket and host-root/home
mounts; mount one folder (`-v /path/to/project:/workspace:ro`), add `--cap-drop ALL`.

**MCP006 - plain http.** Use the server's `https://` URL.

**MCP101 - shell injection.** No shell. Use an argv list with a fixed program
(`subprocess.run(["git", "log", "--end-of-options", branch, "--"])`,
`execFile("git", ["log", "--end-of-options", branch, "--"])`), validate the value against a strict
pattern and reject anything starting with `-`, and map model-chosen actions to an allowlist.

**MCP102 - path traversal.**
```python
ROOT = Path(ALLOWED_DIR).resolve()
target = (ROOT / name).resolve()
if not target.is_relative_to(ROOT):
    raise ValueError("path outside allowed directory")
```
```ts
const root = fs.realpathSync(path.resolve(ALLOWED_DIR));
const target = path.resolve(root, file);
if (target !== root && !target.startsWith(root + path.sep)) throw new Error("denied");
```

**MCP103 - SQL injection.** Bound parameters: `cur.execute("... WHERE name = ?", (name,))`,
`client.query("... WHERE email = $1", [email])`. Allowlist table/column names.

**MCP104 - SSRF.** Allow only https and an allowlist of hosts; otherwise resolve the host and
reject private, loopback, link-local and metadata addresses; do not follow redirects blindly.

**MCP105 - raw web content.** Strip markup, truncate, wrap as untrusted content, and keep
destructive tools behind client confirmation.

**MCP106 - missing annotations.**
`@mcp.tool(annotations={"destructiveHint": True, "readOnlyHint": False})` or
`registerTool(name, { ..., annotations: { destructiveHint: true } }, handler)`.

**MCP107 - secret in tool result.** Return `bool(os.environ.get("API_KEY"))` (a status), never
the value. Rotate any key that was returned.

**MCP108 - eval.** Remove it. Parse data with `json.loads` / `JSON.parse` /
`ast.literal_eval`.

## Suppressing a finding

Add `mcp-audit: ignore` as a comment on the reported line (works in Python, JS/TS and
JSONC configs such as `.vscode/mcp.json`):

```python
os.system(cmd)  # mcp-audit: ignore  (cmd is validated against ALLOWED above)
```

To turn a rule off for a whole run: `--disable MCP105` (repeatable).

## Scanning this machine's client configs

`mcp-audit scan --user-configs` reads (only if they exist) the Claude Desktop config,
`~/.claude.json` (Claude Code, including per-project servers), `~/.cursor/mcp.json`,
`~/.codeium/windsurf/mcp_config.json`, the VS Code user `mcp.json`, the Cline and Roo Code
settings files, `~/.gemini/settings.json` and Zed's `settings.json`. Secrets in them are
masked in the output like everywhere else. Combine it with a path to scan both:
`mcp-audit scan . --user-configs`.

## Use in CI

See [`examples/github-actions/mcp-audit.yml`](examples/github-actions/mcp-audit.yml). It runs
on every pull request, fails the build on Critical/High findings, and uploads the JSON
report as an artifact.

## JSON output

`--json` prints (one finding shown, from the demo project):

```json
{
  "tool": "mcp-audit",
  "version": "0.1.1",
  "targets": [
    "/abs/path/demo-mcp"
  ],
  "files_scanned": 3,
  "config_files": [
    ".cursor/mcp.json"
  ],
  "servers_configured": 7,
  "server_source_files": [
    "server-python/server.py",
    "server-ts/src/index.ts"
  ],
  "skipped": [],
  "exit_code": 1,
  "summary": {
    "critical": 10,
    "high": 12,
    "medium": 4,
    "low": 2,
    "info": 2
  },
  "findings": [
    {
      "rule_id": "MCP001",
      "severity": "critical",
      "message": "GitHub token hard-coded in env.GITHUB_PERSONAL_ACCESS_TOKEN of server 'github'. Anyone with this file has it.",
      "file": ".cursor/mcp.json",
      "line": 10,
      "evidence": "env.GITHUB_PERSONAL_ACCESS_TOKEN = ghp_**** (40 chars)",
      "heuristic": false,
      "extra": {
        "server": "github",
        "key": "GITHUB_PERSONAL_ACCESS_TOKEN"
      },
      "title": "Hard-coded secret in MCP config",
      "why": "MCP client configs (claude_desktop_config.json, .cursor/mcp.json, .vscode/mcp.json, .mcp.json) are copied between machines, pasted into issues and committed to repos. A token written into `env`, `args` or `headers` travels with the file, and every MCP server process (and anything it spawns) can read it.",
      "fix": "1. Rotate GITHUB_PERSONAL_ACCESS_TOKEN now in the provider's dashboard; assume the old value is public.\n2. Reference it instead of writing it into the file:\n     Claude Code / .mcp.json:   \"env\": { \"GITHUB_PERSONAL_ACCESS_TOKEN\": \"${GITHUB_PERSONAL_ACCESS_TOKEN}\" }\n     VS Code (.vscode/mcp.json): \"env\": { \"GITHUB_PERSONAL_ACCESS_TOKEN\": \"${input:github-personal-access-token}\" } plus an\n                                 \"inputs\" entry with \"password\": true\n     Cursor:                     \"env\": { \"GITHUB_PERSONAL_ACCESS_TOKEN\": \"${env:GITHUB_PERSONAL_ACCESS_TOKEN}\" }\n   and export GITHUB_PERSONAL_ACCESS_TOKEN in your shell profile or a secrets manager. Claude Desktop has no\n   variable syntax: keep that file out of git and out of anything you share.\n3. If the file was committed, remove it from git history (git filter-repo / BFG)."
    }
  ]
}
```

`"skipped"` lists Python files that could not be parsed (`{"path": ..., "reason": "syntax error
line 12"}`). Such files are never treated as clean: each is also reported on stderr
(`warning: server.py: syntax error line 12; file not scanned`) and counted in the text header.
They do not change the exit code.

## Development

```bash
pip install -e ".[test]"
pytest
```

Test fixtures never contain real or real-looking secrets in the repository: fake keys are
assembled at runtime in `tests/conftest.py` and `examples/make_demo.py`. Every rule has
tests for code that must be reported and for safe code that must not be.

## License

MIT, Copyright (c) 2026 Abheesht Tripathi. See [LICENSE](LICENSE).

---

Questions, or want a review of your MCP server before you publish it? abheeshttripathi890@gmail.com
