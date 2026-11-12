"""Static checks for Python MCP servers (the official `mcp` SDK, FastMCP).

Uses the standard-library `ast` module. Tool functions are found by their decorators
(`@mcp.tool()`, `@server.call_tool()`) or `add_tool(fn)` calls; their parameters are
treated as model-controlled ("tainted") and followed through simple assignments and
one or two levels of same-file helper calls into dangerous sinks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .config_scan import NOT_SECRET_KEY_RE, SECRET_KEY_RE
from .findings import Finding, redact_line

MCP_IMPORT_RE = re.compile(r"^\s*(?:from\s+(?:mcp|fastmcp)(?:\.[\w.]+)?\s+import\b|import\s+(?:mcp|fastmcp)\b)", re.M)

GENERIC_SANITIZERS = {"int", "float", "bool", "len", "ord", "abs", "round", "hash", "isinstance", "type", "id",
                      "uuid.UUID", "datetime.fromisoformat", "re.escape"}
SHELL_SANITIZERS = {"shlex.quote", "shlex.join", "pipes.quote"}
PATH_SANITIZERS = {"os.path.basename", "werkzeug.utils.secure_filename", "secure_filename", "pathlib.PurePath.name"}

SHELL_ALWAYS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput",
                "asyncio.create_subprocess_shell"}
SUBPROCESS_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                    "subprocess.Popen"}
EVAL_FUNCS = {"eval", "exec", "compile"}

PATH_READ_FUNCS = {"open", "io.open", "codecs.open", "aiofiles.open", "os.listdir", "os.scandir", "os.walk",
                   "glob.glob", "glob.iglob", "os.open", "anyio.open_file"}
PATH_WRITE_FUNCS = {"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.rename", "os.replace", "os.makedirs",
                    "os.mkdir", "os.chmod", "os.truncate", "shutil.rmtree", "shutil.move", "shutil.copy",
                    "shutil.copyfile", "shutil.copy2", "shutil.copytree", "aiofiles.os.remove", "aiofiles.os.rename"}
PATH_DELETE_FUNCS = {"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree", "aiofiles.os.remove"}
PATH_METHODS_READ = {"read_text", "read_bytes", "iterdir", "open", "stat"}
PATH_METHODS_WRITE = {"write_text", "write_bytes", "unlink", "rmdir", "touch", "mkdir", "rename", "replace", "chmod"}
PATH_CTORS = ("Path", "PurePath", "PosixPath", "WindowsPath", "anyio.Path", "trio.Path", "AsyncPath")

SQL_METHODS = {"execute", "executemany", "executescript", "exec_driver_sql", "mogrify", "fetch", "fetchrow",
               "fetchval", "raw", "read_sql", "read_sql_query"}
SQL_FUNCS = {"sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text", "pandas.read_sql",
             "pandas.read_sql_query"}
SQL_KEYWORDS_RE = re.compile(r"(?i)\b(select|insert\s+into|update|delete\s+from|where|from|pragma|drop\s+table|"
                             r"order\s+by|values)\b")

HTTP_FUNCS = {f"{lib}.{m}" for lib in ("requests", "httpx") for m in
              ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream")}
HTTP_FUNCS |= {"urllib.request.urlopen", "urllib.request.Request", "aiohttp.request", "urllib3.request"}
HTTP_CLIENT_CTORS = {"httpx.Client", "httpx.AsyncClient", "requests.Session", "requests.session",
                     "aiohttp.ClientSession", "urllib3.PoolManager"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "stream", "fetch"}
HTTP_RECEIVER_RE = re.compile(r"(?i)^_?(client|http|http_client|httpx|session|async_client|http_session)$")
FIXED_HOST_RE = re.compile(r"^[A-Za-z][\w+.\-]*://[^/{}\s]+/")

CONTAIN_HELPER_RE = re.compile(r"(?i)(safe_?path|safe_?join|validate_?path|valid_?path|allowed_?path|within|inside|"
                               r"contain|sanitiz|jail|sandbox|check_?path|resolve_?safe|safe_?resolve|ensure_?path|"
                               r"assert_?path|secure_?path|secure_?filename|confine|resolve_?path|normali[sz]e_?path|"
                               r"is_?allowed)")
ALLOW_HELPER_RE = re.compile(r"(?i)(allow|safe|valid|check_?url|is_public|is_private|ssrf|whitelist|permitted)")
DESTRUCTIVE_WORDS = {"delete", "remove", "drop", "destroy", "purge", "truncate", "kill", "terminate", "wipe", "erase",
                     "rm", "unlink", "revoke", "uninstall", "overwrite", "reset", "shutdown", "rmdir"}
SAFE_RESULT_CALLS = {"str", "repr", "dict", "list", "tuple", "json.dumps", "TextContent", "mcp.types.TextContent",
                     "types.TextContent", "format", "join", "dumps"}
CTX_ANNOTATIONS = ("Context", "RequestContext", "ServerSession")


def is_mcp_python(text: str) -> bool:
    return bool(MCP_IMPORT_RE.search(text))


def name_words(name: str) -> set[str]:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return {w.lower() for w in re.split(r"[_\-\s.]+", s) if w}


def is_destructive_name(name: str) -> bool:
    return bool(name_words(name) & DESTRUCTIVE_WORDS)


@dataclass
class Tool:
    func: ast.FunctionDef | ast.AsyncFunctionDef
    name: str | None
    params: list[str]
    decorator: ast.expr | None = None
    has_annotations: bool = False


@dataclass
class _Ctx:
    """Analysis context passed from a tool into the helpers it calls."""
    tool: Tool
    sources: list[str] = field(default_factory=list)      # source of every function on the call chain
    depth: int = 0


class PyModule:
    def __init__(self, rel: str, text: str):
        self.rel, self.text = rel, text
        self.lines = text.splitlines()
        self.tree = ast.parse(text)
        self.aliases: dict[str, str] = {}
        self.funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()
        self.module_secret_vars: dict[str, str] = {}
        self.http_client_vars: set[str] = set()
        self.module_pathlike: set[str] = set()
        self.module_fixed_urls: set[str] = set()     # BASE = "https://api.example.com/"
        self._collect()
        # same-file functions that resolve a path and check it against a root: calls to them sanitise paths
        self.contain_funcs = {n for n, f in self.funcs.items() if has_containment(self.src(f))}

    # ---------------------------------------------------------- setup
    def _collect(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs.setdefault(node.name, node)
        for node in self.tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                env = self.secret_env_name(node.value)
                for t in targets:
                    if isinstance(t, ast.Name):
                        if env:
                            self.module_secret_vars[t.id] = env
                        if isinstance(node.value, ast.Call) and self.callname(node.value) in HTTP_CLIENT_CTORS:
                            self.http_client_vars.add(t.id)
                        value = node.value
                        if isinstance(value, ast.Constant) and isinstance(value.value, str) and \
                                FIXED_HOST_RE.match(value.value):
                            self.module_fixed_urls.add(t.id)
                        v = node.value
                        while isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr in (
                                "resolve", "absolute", "expanduser"):
                            v = v.func.value
                        if isinstance(v, ast.Call) and self.callname(v).rsplit(".", 1)[-1] in PATH_CTORS:
                            self.module_pathlike.add(t.id)

    def dotted(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            base = self.dotted(node.func)
            return f"{base}()" if base else None
        return None

    def callname(self, call: ast.Call) -> str:
        return self.dotted(call.func) or ""

    def src(self, node: ast.AST) -> str:
        return ast.get_source_segment(self.text, node) or ""

    # ---------------------------------------------------------- tools
    def tools(self) -> list[Tool]:
        found: dict[int, Tool] = {}
        added: dict[str, str | None] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_tool":
                if node.args and isinstance(node.args[0], ast.Name):
                    nm = next((k.value.value for k in node.keywords if k.arg == "name"
                               and isinstance(k.value, ast.Constant)), None)
                    added[node.args[0].id] = nm
        for fn in [n for n in ast.walk(self.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for dec in fn.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                attr = target.attr if isinstance(target, ast.Attribute) else (
                    target.id if isinstance(target, ast.Name) else None)
                if attr not in ("tool", "call_tool"):
                    continue
                tool_name = fn.name if attr == "tool" else None
                has_ann = False
                if isinstance(dec, ast.Call):
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        tool_name = dec.args[0].value
                    for kw in dec.keywords:
                        if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                            tool_name = kw.value.value
                        if kw.arg and (kw.arg == "annotations" or kw.arg.lower().endswith("hint")):
                            has_ann = True
                found[id(fn)] = Tool(fn, tool_name, self._tool_params(fn), dec, has_ann)
                break
            if id(fn) not in found and fn.name in added:
                found[id(fn)] = Tool(fn, added[fn.name] or fn.name, self._tool_params(fn), None, False)
        return list(found.values())

    @staticmethod
    def _tool_params(fn) -> list[str]:
        out = []
        a = fn.args
        for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs] + ([a.vararg] if a.vararg else []) + (
                [a.kwarg] if a.kwarg else []):
            if arg.arg in ("self", "cls", "ctx", "context"):
                continue
            ann = ast.unparse(arg.annotation) if arg.annotation is not None else ""
            if any(c in ann for c in CTX_ANNOTATIONS):
                continue
            out.append(arg.arg)
        return out

    # ---------------------------------------------------------- reporting
    def add(self, rule: str, sev: str, msg: str, node: ast.AST, **extra) -> None:
        line = getattr(node, "lineno", 0)
        key = (rule, line)
        if key in self._seen:
            return
        raw = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        if "mcp-audit: ignore" in raw:
            return
        self._seen.add(key)
        self.findings.append(Finding(rule, sev, msg, self.rel, line, redact_line(raw),
                                     extra={"lang": "py", **{k: v for k, v in extra.items() if v is not None}}))

    # ---------------------------------------------------------- env secrets
    def secret_env_name(self, e: ast.AST) -> str | None:
        """os.environ['X'] / os.environ.get('X') / os.getenv('X') with a secret-looking X."""
        key = None
        if isinstance(e, ast.Subscript) and self.dotted(e.value) == "os.environ":
            key = e.slice
        elif isinstance(e, ast.Call) and self.callname(e) in ("os.environ.get", "os.getenv", "os.environ.__getitem__"):
            key = e.args[0] if e.args else None
        elif isinstance(e, ast.Call) and self.callname(e) in ("str",) and e.args:
            return self.secret_env_name(e.args[0])
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            if SECRET_KEY_RE.search(key.value) and not NOT_SECRET_KEY_RE.search(key.value):
                return key.value
        return None

    def run(self) -> list[Finding]:
        for tool in self.tools():
            self.analyze(tool.func, set(tool.params), _Ctx(tool, [self.src(tool.func)]))
            self.check_annotations(tool)
        self.check_lowlevel_tool_defs()
        return self.findings

    # ---------------------------------------------------------- core analysis
    def analyze(self, fn, params: set[str], ctx: _Ctx) -> None:
        fa = _FuncAnalysis(self, fn, params)
        fa.propagate()
        sources = "\n".join(ctx.sources)
        is_tool = ctx.depth == 0
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
            self._shell(fa, call)
            self._eval(fa, call)
            self._path(fa, call, sources)
            self._sql(fa, call)
            self._ssrf(fa, call, sources)
        if is_tool:
            self._raw_content(fa, ctx.tool)
            self._secret_echo(fa)
        # follow same-file helpers that receive tainted values
        if ctx.depth >= 2:
            return
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
            helper = None
            if isinstance(call.func, ast.Name):
                helper = self.funcs.get(call.func.id)
            elif isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and \
                    call.func.value.id in ("self", "cls"):
                helper = self.funcs.get(call.func.attr)
            if helper is None or helper is fn:
                continue
            hp = [a.arg for a in [*helper.args.posonlyargs, *helper.args.args] if a.arg not in ("self", "cls")]
            tainted_params: set[str] = set()
            for i, arg in enumerate(call.args):
                if i < len(hp) and fa.ref(arg, fa.tainted):
                    tainted_params.add(hp[i])
            for kw in call.keywords:
                if kw.arg and fa.ref(kw.value, fa.tainted):
                    tainted_params.add(kw.arg)
            if tainted_params:
                self.analyze(helper, tainted_params,
                             _Ctx(ctx.tool, ctx.sources + [self.src(helper)], ctx.depth + 1))

    # ---- MCP101
    def _shell(self, fa: "_FuncAnalysis", call: ast.Call) -> None:
        name = self.callname(call)
        cmd = None
        if name in SHELL_ALWAYS:
            cmd = call.args[0] if call.args else None
            how = f"{name}()"
        elif name in SUBPROCESS_FUNCS:
            cmd = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "args"), None)
            if not any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                       for kw in call.keywords):
                self._program_choice(fa, call, name, cmd)
                return
            how = f"{name}(..., shell=True)"
        else:
            return
        if cmd is None:
            return
        p = fa.ref(cmd, fa.tainted_shell)
        if p:
            p = fa.root(p)
            self.add("MCP101", "critical",
                     f"Tool input '{p}' reaches {how}: a prompt injection can run any shell command.", call,
                     param=p)

    def _program_choice(self, fa, call: ast.Call, name: str, cmd: ast.AST | None) -> None:
        """subprocess.run([user_cmd, ...]) / subprocess.run(user_cmd.split()): the model picks the program."""
        prog = None
        if isinstance(cmd, (ast.List, ast.Tuple)) and cmd.elts:
            prog = cmd.elts[0]
        elif isinstance(cmd, ast.Name) and cmd.id in fa.tainted_shell:
            prog = cmd
        elif isinstance(cmd, ast.Call) and (self.callname(cmd) == "shlex.split" or (
                isinstance(cmd.func, ast.Attribute) and cmd.func.attr == "split")):
            prog = cmd
        if prog is None or isinstance(prog, ast.Starred):
            return
        p = fa.ref(prog, fa.tainted_shell)
        if p:
            p = fa.root(p)
            self.add("MCP101", "high",
                     f"Tool input '{p}' chooses the program run by {name}(): the model can run any executable.",
                     call, param=p)

    # ---- MCP108
    def _eval(self, fa, call: ast.Call) -> None:
        name = self.callname(call)
        if name in EVAL_FUNCS and name not in self.aliases and call.args:
            p = fa.ref(call.args[0], fa.tainted)
            if p:
                p = fa.root(p)
                self.add("MCP108", "critical", f"Tool input '{p}' is passed to {name}(): remote code execution.",
                         call, param=p)

    # ---- MCP102
    def _path(self, fa, call: ast.Call, sources: str) -> None:
        name = self.callname(call)
        targets: list[ast.AST] = []
        write = False
        op = name
        if name in PATH_READ_FUNCS or name in PATH_WRITE_FUNCS:
            if name == "open" and "open" in self.aliases:
                return
            targets = list(call.args[:2]) if name in ("os.rename", "os.replace", "shutil.move", "shutil.copy",
                                                       "shutil.copyfile", "shutil.copy2", "shutil.copytree") \
                else call.args[:1]
            targets += [k.value for k in call.keywords if k.arg in ("file", "path", "src", "dst")]
            write = name in PATH_WRITE_FUNCS
            if name in ("open", "io.open", "codecs.open", "aiofiles.open", "anyio.open_file"):
                mode = call.args[1] if len(call.args) > 1 else next(
                    (k.value for k in call.keywords if k.arg == "mode"), None)
                write = isinstance(mode, ast.Constant) and isinstance(mode.value, str) and \
                    any(c in mode.value for c in "wax+")
        elif isinstance(call.func, ast.Attribute) and call.func.attr in PATH_METHODS_READ | PATH_METHODS_WRITE:
            recv = call.func.value
            if not fa.pathlike(recv):
                return
            targets = [recv]
            write = call.func.attr in PATH_METHODS_WRITE
            if call.func.attr == "open" and call.args:
                m = call.args[0]
                write = isinstance(m, ast.Constant) and isinstance(m.value, str) and any(c in m.value for c in "wax+")
            op = f"Path.{call.func.attr}()"
        else:
            return
        for t in targets:
            p = fa.ref(t, fa.tainted_path)
            if not p:
                continue
            if has_containment(sources) or fa.calls_helper(CONTAIN_HELPER_RE, fa.tainted):
                return
            p = fa.root(p)
            op = op if op.endswith(")") else f"{op}()"
            sev = "critical" if write else "high"
            verb = "write/delete" if write else "read"
            self.add("MCP102", sev,
                     f"Tool input '{p}' is used as a path in {op} ({verb}) with no check that it stays inside an "
                     f"allowed directory: path traversal (../../.ssh/id_rsa).", call, param=p)
            return

    # ---- MCP103
    def _sql(self, fa, call: ast.Call) -> None:
        name = self.callname(call)
        is_sink = name in SQL_FUNCS or (isinstance(call.func, ast.Attribute) and call.func.attr in SQL_METHODS)
        if not is_sink:
            return
        q = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg in ("sql", "query",
                                                                                               "statement")), None)
        if q is None:
            return
        res = fa.dynamic_sql(q)
        if res:
            p, lit = res
            p = fa.root(p)
            self.add("MCP103", "high",
                     f"SQL is built from tool input '{p}' with string formatting and run via "
                     f"{name.rsplit('.', 1)[-1] or 'execute'}(): SQL injection.", call, param=p)

    # ---- MCP104
    def _ssrf(self, fa, call: ast.Call, sources: str) -> None:
        name = self.callname(call)
        url = None
        if name in HTTP_FUNCS:
            idx = 1 if name.endswith(".request") and name != "urllib3.request" else 0
            if name in ("aiohttp.request", "urllib3.request"):
                idx = 1
            url = call.args[idx] if len(call.args) > idx else None
        elif isinstance(call.func, ast.Attribute) and call.func.attr in HTTP_METHODS and fa.is_http_client(
                call.func.value):
            idx = 1 if call.func.attr in ("request", "stream") else 0
            url = call.args[idx] if len(call.args) > idx else None
        else:
            return
        if url is None:
            url = next((k.value for k in call.keywords if k.arg == "url"), None)
        if url is None:
            return
        fa.http_calls.append(call)
        p = fa.ref(url, fa.tainted_url)
        if not p or fa.fixed_host(url):
            return
        if has_url_allowlist(sources) or fa.calls_helper(ALLOW_HELPER_RE, fa.tainted):
            return
        p = fa.root(p)
        self.add("MCP104", "high",
                 f"Tool input '{p}' is used as the URL in {name or 'an HTTP call'}() with no host allowlist or "
                 f"private-address check: SSRF (http://169.254.169.254/, localhost).", call, param=p)

    # ---- MCP105
    def _raw_content(self, fa, tool: Tool) -> None:
        if not fa.http_calls:
            return
        for ret in [n for n in ast.walk(tool.func) if isinstance(n, ast.Return) and n.value is not None]:
            if fa.raw_web_text(ret.value):
                self.add("MCP105", "info",
                         f"Tool '{tool.name or tool.func.name}' returns fetched web content to the model as-is: "
                         f"prompt-injection exposure.", ret, tool=tool.name)
                return

    # ---- MCP107
    def _secret_echo(self, fa) -> None:
        for node in ast.walk(fa.fn):
            if isinstance(node, (ast.Return, ast.Yield)) and node.value is not None:
                what = fa.leaks_secret(node.value)
                if what:
                    self.add("MCP107", "high", f"Tool result includes {what}: it ends up in the model context "
                                               f"and transcript.", node,
                             env=what.split("'")[1] if "'" in what else None)

    # ---- MCP106
    def check_annotations(self, tool: Tool) -> None:
        if tool.has_annotations or tool.name is None:
            return
        deletes = any(isinstance(n, ast.Call) and self.callname(n) in PATH_DELETE_FUNCS
                      for n in ast.walk(tool.func))
        if is_destructive_name(tool.name) or deletes:
            self.add("MCP106", "low",
                     f"Tool '{tool.name}' looks destructive but declares no annotations (destructiveHint / "
                     f"readOnlyHint), so clients cannot tell it apart from a read-only tool.",
                     tool.decorator or tool.func, tool=tool.name)

    def check_lowlevel_tool_defs(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and self.callname(node).rsplit(".", 1)[-1] == "Tool":
                kws = {k.arg: k.value for k in node.keywords if k.arg}
                nm = kws.get("name")
                if isinstance(nm, ast.Constant) and isinstance(nm.value, str) and is_destructive_name(nm.value) \
                        and "annotations" not in kws:
                    self.add("MCP106", "low",
                             f"Tool '{nm.value}' looks destructive but declares no annotations (destructiveHint / "
                             f"readOnlyHint), so clients cannot tell it apart from a read-only tool.",
                             node, tool=nm.value)


def has_containment(src: str) -> bool:
    if re.search(r"is_relative_to\(|commonpath\(|\.relative_to\(", src):
        return True
    return bool(re.search(r"startswith\(", src) and re.search(r"resolve\(|realpath\(|abspath\(|normpath\(", src))


def has_url_allowlist(src: str) -> bool:
    parsed = re.search(r"urlparse\(|urlsplit\(|yarl\.URL\(|httpx\.URL\(|URL\(", src)
    checked = re.search(r"\.hostname\b|\.netloc\b|\.host\b|ipaddress\.|is_private|is_loopback|ALLOWED|allowlist",
                        src)
    return bool(parsed and checked)


class _FuncAnalysis:
    def __init__(self, mod: PyModule, fn, params: set[str]):
        self.m, self.fn, self.params = mod, fn, params
        self.tainted: set[str] = set(params)
        self.tainted_shell: set[str] = set(params)
        self.tainted_path: set[str] = set(params)
        self.tainted_url: set[str] = set(params)
        self.sql_vars: dict[str, tuple[str, str]] = {}
        self.pathlike_vars: set[str] = set(mod.module_pathlike)
        self.http_vars: set[str] = set(mod.http_client_vars)
        self.secret_vars: dict[str, str] = dict(mod.module_secret_vars)
        self.raw_vars: set[str] = set()
        self.http_calls: list[ast.Call] = []
        self.origin: dict[str, str] = {}

    def root(self, name: str) -> str:
        """The tool parameter a tainted variable came from."""
        seen = set()
        while name in self.origin and name not in seen:
            seen.add(name)
            name = self.origin[name]
        return name

    # -- expression helpers
    def ref(self, e: ast.AST, tainted: set[str]) -> str | None:
        """Name of a tainted variable referenced by e (ignoring sanitizer calls), else None."""
        if tainted is self.tainted_shell:
            extra = SHELL_SANITIZERS
        elif tainted is self.tainted_path:
            extra = PATH_SANITIZERS
        else:
            extra = set()
        stack = [e]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.Call):
                cn = self.m.callname(n)
                tail = cn.rsplit(".", 1)[-1]
                if cn in GENERIC_SANITIZERS or cn in extra or (
                        extra is PATH_SANITIZERS and (tail in ("basename", "secure_filename")
                                                      or tail in self.m.contain_funcs)):
                    continue
            if isinstance(n, ast.Compare):
                continue
            if isinstance(n, ast.Name) and n.id in tainted:
                return n.id
            if isinstance(n, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            stack.extend(ast.iter_child_nodes(n))
        return None

    def calls_helper(self, pattern: re.Pattern, tainted: set[str]) -> bool:
        for n in ast.walk(self.fn):
            if isinstance(n, ast.Call):
                cn = self.m.callname(n).rsplit(".", 1)[-1]
                if pattern.search(cn) and any(self.ref(a, tainted) for a in [*n.args, *(k.value for k in n.keywords)]):
                    return True
        return False

    def pathlike(self, e: ast.AST) -> bool:
        if isinstance(e, ast.Name):
            return e.id in self.pathlike_vars
        if isinstance(e, ast.Call):
            cn = self.m.callname(e)
            if cn.endswith(PATH_CTORS) or cn.rsplit(".", 1)[-1] in PATH_CTORS:
                return True
            if isinstance(e.func, ast.Attribute) and e.func.attr in ("resolve", "absolute", "expanduser",
                                                                        "joinpath", "with_suffix", "with_name"):
                return self.pathlike(e.func.value)
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Div):
            return self.pathlike(e.left) or self.pathlike(e.right)
        if isinstance(e, ast.Attribute) and e.attr == "parent":
            return self.pathlike(e.value)
        return False

    def is_http_client(self, e: ast.AST) -> bool:
        if isinstance(e, ast.Name):
            if e.id in self.http_vars:
                return True
            return e.id not in self.m.aliases and bool(HTTP_RECEIVER_RE.match(e.id))
        if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name) and e.value.id == "self":
            return bool(HTTP_RECEIVER_RE.match(e.attr))
        if isinstance(e, ast.Call):
            return self.m.callname(e) in HTTP_CLIENT_CTORS
        return False

    def fixed_host(self, e: ast.AST) -> bool:
        fixed_names = self.m.module_fixed_urls
        if isinstance(e, ast.JoinedStr) and e.values:
            first = e.values[0]
            if isinstance(first, ast.Constant):
                return bool(FIXED_HOST_RE.match(str(first.value)))
            return (isinstance(first, ast.FormattedValue) and isinstance(first.value, ast.Name)
                    and first.value.id in fixed_names)
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
            left = e.left
            while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add):
                left = left.left
            if isinstance(left, ast.Name):
                return left.id in fixed_names
            return isinstance(left, ast.Constant) and bool(FIXED_HOST_RE.match(str(left.value)))
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "format" and \
                isinstance(e.func.value, ast.Constant):
            return bool(FIXED_HOST_RE.match(str(e.func.value.value)))
        return False

    def dynamic_sql(self, e: ast.AST) -> tuple[str, str] | None:
        """(tainted param, literal SQL text) if e builds SQL from tainted input by formatting."""
        if isinstance(e, ast.Name):
            return self.sql_vars.get(e.id)
        lit = ""
        dyn: list[ast.AST] = []
        if isinstance(e, ast.JoinedStr):
            for v in e.values:
                if isinstance(v, ast.Constant):
                    lit += str(v.value)
                else:
                    dyn.append(v)
        elif isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Mod)):
            for n in ast.walk(e):
                if isinstance(n, ast.Constant) and isinstance(n.value, str):
                    lit += n.value + " "
            dyn = [e]
            inner = [self.dynamic_sql(x) for x in (e.left, e.right)]
            for r in inner:
                if r:
                    return r[0], r[1] + lit
        elif isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "format" and \
                isinstance(e.func.value, ast.Constant) and isinstance(e.func.value.value, str):
            lit = e.func.value.value
            dyn = [*e.args, *(k.value for k in e.keywords)]
        else:
            return None
        if not SQL_KEYWORDS_RE.search(lit):
            return None
        for d in dyn:
            p = self.ref(d, self.tainted)
            if p:
                return p, lit
        return None

    def raw_web_text(self, e: ast.AST) -> bool:
        for n in ast.walk(e):
            if isinstance(n, ast.Name) and n.id in self.raw_vars:
                return True
            if isinstance(n, ast.Attribute) and n.attr in ("text", "content") and not isinstance(n.ctx, ast.Store):
                return True
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("text", "read") \
                    and not n.args:
                return True
        return False

    def leaks_secret(self, e: ast.AST) -> str | None:
        stack = [e]
        while stack:
            n = stack.pop()
            env = self.m.secret_env_name(n) if isinstance(n, (ast.Subscript, ast.Call)) else None
            if env:
                return f"the secret env var '{env}'"
            if isinstance(n, ast.Name) and n.id in self.secret_vars:
                return f"the secret env var '{self.secret_vars[n.id]}' (via {n.id})"
            if isinstance(n, (ast.Name, ast.Attribute)) and self.m.dotted(n) == "os.environ":
                return "the whole process environment (os.environ)"
            if isinstance(n, ast.Call):
                cn = self.m.callname(n)
                if cn in ("os.environ.items", "os.environ.copy", "os.environ.values"):
                    return "the whole process environment (os.environ)"
                if cn in SAFE_RESULT_CALLS or cn.rsplit(".", 1)[-1] in SAFE_RESULT_CALLS:
                    stack.extend([*n.args, *(k.value for k in n.keywords)])
                    if isinstance(n.func, ast.Attribute):
                        stack.append(n.func.value)
                continue
            if isinstance(n, (ast.Compare, ast.Subscript, ast.Lambda)):
                continue
            stack.extend(ast.iter_child_nodes(n))
        return None

    # -- propagation
    def propagate(self) -> None:
        assigns: list[tuple[list[ast.AST], ast.AST, bool]] = []
        for n in ast.walk(self.fn):
            if isinstance(n, ast.Assign):
                assigns.append((n.targets, n.value, False))
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                assigns.append(([n.target], n.value, False))
            elif isinstance(n, ast.AugAssign):
                assigns.append(([n.target], n.value, True))
            elif isinstance(n, ast.NamedExpr):
                assigns.append(([n.target], n.value, False))
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                assigns.append(([n.target], n.iter, False))
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    if item.optional_vars is not None:
                        assigns.append(([item.optional_vars], item.context_expr, False))
        for _ in range(6):
            changed = False
            for targets, value, aug in assigns:
                names = [x.id for t in targets for x in ast.walk(t) if isinstance(x, ast.Name)]
                for tset in (self.tainted, self.tainted_shell, self.tainted_path, self.tainted_url):
                    src = self.ref(value, tset)
                    if src:
                        if tset is self.tainted_url and self.fixed_host(value):
                            continue
                        for nm in names:
                            if nm not in tset:
                                tset.add(nm)
                                self.origin.setdefault(nm, src) if nm != src else None
                                changed = True
                if self.pathlike(value) or (isinstance(value, ast.Call) and self.m.callname(value) in (
                        "os.path.join", "os.path.abspath", "os.path.realpath", "os.path.expanduser")):
                    for nm in names:
                        if nm not in self.pathlike_vars and self.pathlike(value):
                            self.pathlike_vars.add(nm)
                            changed = True
                if isinstance(value, ast.Call) and self.m.callname(value) in HTTP_CLIENT_CTORS:
                    self.http_vars.update(names)
                env = self.m.secret_env_name(value)
                if env:
                    for nm in names:
                        self.secret_vars[nm] = env
                if self.raw_web_text(value) and any(isinstance(x, (ast.Await, ast.Call, ast.Attribute))
                                                    for x in ast.walk(value)):
                    for nm in names:
                        if nm not in self.raw_vars:
                            self.raw_vars.add(nm)
                            changed = True
                res = self.dynamic_sql(value)
                if res is None and aug and len(names) == 1 and names[0] in self.sql_vars:
                    res = self.sql_vars[names[0]]
                if res is None and aug and len(names) == 1:
                    # q = "SELECT ..."  then  q += f" WHERE x = '{arg}'"
                    p = self.ref(value, self.tainted)
                    if p:
                        res = (p, "where")
                        base = self._literal_assigned(names[0])
                        if not SQL_KEYWORDS_RE.search(base + " " + self._literal_of(value)):
                            res = None
                if res is not None:
                    for nm in names:
                        if nm not in self.sql_vars:
                            self.sql_vars[nm] = res
                            changed = True
            if not changed:
                break

    def _literal_of(self, e: ast.AST) -> str:
        return " ".join(str(n.value) for n in ast.walk(e) if isinstance(n, ast.Constant) and isinstance(n.value, str))

    def _literal_assigned(self, name: str) -> str:
        out = []
        for n in ast.walk(self.fn):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
                out.append(self._literal_of(n.value))
        return " ".join(out)


def scan_python(rel: str, text: str) -> list[Finding]:
    if not is_mcp_python(text):
        return []
    try:
        mod = PyModule(rel, text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    return mod.run()
