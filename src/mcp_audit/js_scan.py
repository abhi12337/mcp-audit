"""Static checks for TypeScript / JavaScript MCP servers (@modelcontextprotocol/sdk, fastmcp).

There is no JS parser in the standard library, so this works on a lexed copy of the
source: comments are removed and string contents are blanked (template-literal `${...}`
expressions are kept), which keeps offsets stable and stops matches inside strings.
Tool handlers are found from `server.tool(...)`, `server.registerTool(...)`,
`server.addTool(...)` and `setRequestHandler(CallToolRequestSchema, ...)`; their
parameters are tainted and followed through declarations and same-file helper calls."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config_scan import NOT_SECRET_KEY_RE, SECRET_KEY_RE
from .findings import Finding, redact_line
from .py_scan import CONTAIN_HELPER_RE, FIXED_HOST_RE, SQL_KEYWORDS_RE, is_destructive_name

MCP_JS_RE = re.compile(r"""@modelcontextprotocol/sdk|from\s+['"]fastmcp['"]|require\(\s*['"]fastmcp['"]\s*\)""")
IDENT = r"[A-Za-z_$][\w$]*"
KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "await", "new", "typeof", "const", "let",
            "var", "async", "true", "false", "null", "undefined", "this", "of", "in", "instanceof", "else", "case",
            "default", "throw", "try", "delete", "void", "yield", "import", "export", "from", "as", "class"}

FS_METHODS_READ = {"readFile", "readFileSync", "readdir", "readdirSync", "createReadStream", "stat", "statSync",
                   "lstat", "open", "openSync", "readJson", "readJSON", "readJsonSync", "opendir", "access"}
FS_METHODS_WRITE = {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "unlink", "unlinkSync", "rm",
                    "rmSync", "rmdir", "rmdirSync", "createWriteStream", "copyFile", "copyFileSync", "rename",
                    "renameSync", "mkdir", "mkdirSync", "truncate", "cp", "cpSync", "remove", "removeSync",
                    "outputFile", "writeJson", "move", "emptyDir", "chmod"}
FS_DELETE = {"unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "remove", "removeSync", "emptyDir"}
FS_MODULES = r"(?:node:)?fs(?:/promises)?|fs-extra|graceful-fs"
SQL_JS_METHODS = r"query|execute|exec|run|all|get|prepare|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe|" \
                 r"queryRaw|executeRaw"
HTTP_DOTTED = r"(?:axios|got|ky|http|https|undici|superagent|needle)\.(?:get|post|put|delete|patch|head|request)"
JS_SANITIZERS_ALL = ("Number", "parseInt", "parseFloat", "Boolean", "encodeURIComponent", "String(Number")
JS_SANITIZERS_SHELL = ("shellEscape", "quote", "escapeShellArg", "shellQuote")
JS_SANITIZERS_PATH = ("path.basename", "basename")
ALLOWLIST_RE = re.compile(r"(?i)allow(ed)?_?(hosts|list|domains|origins)|whitelist|isPrivate|private_?ip|ipaddr|"
                          r"blocked_?hosts|denylist|\.hostname\s*(?:===|!==|==)|hostname\)|\.hostname\s*\)|"
                          r"isAllowedUrl|validateUrl|assertUrl|checkUrl|ssrf")


def is_mcp_js(text: str) -> bool:
    return bool(MCP_JS_RE.search(text))


# ---------------------------------------------------------------- lexing
def lex(text: str) -> tuple[str, str]:
    """-> (clean, code), both the same length as text.
    clean: comments blanked.  code: comments blanked and string/template contents blanked
    (template `${...}` expressions kept)."""
    n = len(text)
    clean = list(text)
    code = list(text)
    i = 0
    tmpl_stack: list[int] = []      # brace depth at which a template ${ } returns to the template
    brace = 0
    prev_sig = ""                   # last significant char, for regex-literal detection

    def blank(lst, a, b):
        for k in range(a, b):
            if lst[k] != "\n":
                lst[k] = " "

    def template_from(start: int) -> int:
        """start points just after a backtick (or a closing } of ${}); returns index after end."""
        nonlocal brace
        j = start
        while j < n:
            c = text[j]
            if c == "\\":
                blank(code, j, min(j + 2, n))
                j += 2
                continue
            if c == "`":
                return j + 1
            if c == "$" and j + 1 < n and text[j + 1] == "{":
                tmpl_stack.append(brace)
                brace += 1
                return -(j + 2)     # negative = continue in code mode at this index
            blank(code, j, j + 1)
            j += 1
        return n

    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(clean, i, j)
            blank(code, i, j)
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(clean, i, j)
            blank(code, i, j)
            i = j
            continue
        if c in "'\"":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            blank(code, i + 1, min(j, n))
            i = j + 1
            prev_sig = c
            continue
        if c == "`":
            r = template_from(i + 1)
            if r < 0:
                i = -r
                prev_sig = "{"
            else:
                i = r
                prev_sig = "`"
            continue
        if c == "/" and (prev_sig == "" or prev_sig in "(,=:[!&|?{};+-*%<>~^" or
                         re.search(r"\b(return|typeof|case|in|of)\s*$", text[max(0, i - 8):i])):
            j = i + 1
            in_class = False
            while j < n and text[j] != "\n":
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                j += 1
            blank(code, i + 1, min(j, n))
            i = j + 1
            prev_sig = "/"
            continue
        if c == "{":
            brace += 1
        elif c == "}":
            brace -= 1
            if tmpl_stack and brace == tmpl_stack[-1]:
                tmpl_stack.pop()
                r = template_from(i + 1)
                if r < 0:
                    i = -r
                    prev_sig = "{"
                else:
                    i = r
                    prev_sig = "`"
                continue
        prev_sig = c
        i += 1
    return "".join(clean), "".join(code)


_OPEN = {"(": ")", "[": "]", "{": "}"}


def match_close(code: str, open_idx: int) -> int:
    """Index of the bracket closing code[open_idx]; len(code) if unbalanced."""
    depth = 0
    for j in range(open_idx, len(code)):
        c = code[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return j
    return len(code)


def split_args(code: str, start: int, end: int) -> list[tuple[int, int]]:
    """Top-level comma-separated spans of code[start:end]."""
    out, depth, a = [], 0, start
    for j in range(start, end):
        c = code[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append((a, j))
            a = j + 1
    if code[a:end].strip():
        out.append((a, end))
    return out


def strip_calls(expr: str, names) -> str:
    """Blank out NAME(...) for sanitizer calls."""
    for nm in names:
        for m in reversed(list(re.finditer(r"(?<![\w$])" + re.escape(nm) + r"\s*\(", expr))):
            o = m.end() - 1
            c = match_close(expr, o)
            expr = expr[: m.start()] + " " * (c + 1 - m.start()) + expr[c + 1:]
    return expr


def idents(expr: str) -> set[str]:
    """Identifiers used as values (not property names, not object keys)."""
    out = set()
    for m in re.finditer(r"(?<![\w$.])(" + IDENT + r")", expr):
        name = m.group(1)
        if name in KEYWORDS:
            continue
        rest = expr[m.end():m.end() + 3]
        if re.match(r"\s*:(?!:)", rest) and not re.search(r"\?\s*$", expr[:m.start()]):
            # object key `{ path: x }` (but keep ternary `a ? b : c`)
            prev = expr[:m.start()].rstrip()
            if prev.endswith(("{", ",")):
                continue
        out.add(name)
    return out


def parse_params(params: str) -> list[str]:
    p = params.strip()
    if not p:
        return []
    if p.startswith("{"):
        inner = p[1:match_close(p, 0)]
        names = []
        for part, _ in [(inner[a:b], 0) for a, b in split_args(inner, 0, len(inner))]:
            part = part.strip().lstrip(".")
            if not part:
                continue
            key, _, alias = part.partition(":")
            target = alias if alias.strip() and not alias.strip()[0].isupper() else key
            target = target.split("=")[0].strip()
            if re.fullmatch(IDENT, target):
                names.append(target)
        return names
    first = p.split(",")[0].split(":")[0].split("=")[0].strip().lstrip(".")
    return [first] if re.fullmatch(IDENT, first) else []


FN_RE = re.compile(
    r"(?:async\s+)?(?:function\s*" + IDENT + r"?\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)|"
    r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*(?::\s*[^=;{]+?)?\s*=>|(" + IDENT + r")\s*=>)"
)


@dataclass
class Span:
    start: int
    end: int
    tainted: set[str]
    kind: str                      # "tool" | "helper"
    tool_name: str | None = None
    reg_start: int = 0
    sources: list[tuple[int, int]] = field(default_factory=list)
    depth: int = 0
    origin: dict[str, str] = field(default_factory=dict)

    def root(self, name: str) -> str:
        seen = set()
        while name in self.origin and name not in seen:
            seen.add(name)
            name = self.origin[name]
        return name


class JsModule:
    def __init__(self, rel: str, text: str):
        self.rel, self.text = rel, text
        self.clean, self.code = lex(text)
        self.lines = text.splitlines()
        self.line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self.findings: list[Finding] = []
        self._cur: Span | None = None
        self._seen: set[tuple[str, int]] = set()
        self._imports()
        self._helpers = self._find_helpers()
        # same-file functions that resolve a path and check it against a root: calls to them sanitise paths
        self.contain_funcs = tuple(n for n, (_, a, b) in self._helpers.items()
                                   if self._contained_strict(self.clean[a:b]))
        self.module_secrets = self._secret_vars(0, len(self.code))

    # ------------------------------------------------------------ setup
    def _imports(self) -> None:
        c = self.clean
        cp = r"""['"](?:node:)?child_process['"]"""
        self.cp_ns = set(re.findall(r"import\s+\*\s+as\s+(" + IDENT + r")\s+from\s+" + cp, c))
        self.cp_ns |= set(re.findall(r"import\s+(" + IDENT + r")\s+from\s+" + cp, c))
        self.cp_ns |= set(re.findall(r"(?:const|let|var)\s+(" + IDENT + r")\s*=\s*require\(\s*" + cp + r"\s*\)", c))
        self.shell_fns: set[str] = set()      # string-command functions (exec, execSync)
        self.spawn_fns: set[str] = set()      # argv functions (spawn, execFile, execa)
        named = re.findall(r"import\s*\{([^}]*)\}\s*from\s*" + cp, c) + \
            re.findall(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*" + cp + r"\s*\)", c)
        for block in named:
            for part in block.split(","):
                orig, _, local = part.replace(" as ", ":").partition(":")
                orig, local = orig.strip(), (local.strip() or orig.strip())
                if orig in ("exec", "execSync"):
                    self.shell_fns.add(local)
                elif orig in ("spawn", "spawnSync", "execFile", "execFileSync", "fork"):
                    self.spawn_fns.add(local)
        for m in re.finditer(r"import\s*\{([^}]*)\}\s*from\s*['\"]execa['\"]", c):
            for part in m.group(1).split(","):
                orig, _, local = part.replace(" as ", ":").partition(":")
                orig, local = orig.strip(), (local.strip() or orig.strip())
                if orig in ("execaCommand", "execaCommandSync"):
                    self.shell_fns.add(local)
                elif orig in ("execa", "execaSync", "execaNode"):
                    self.spawn_fns.add(local)
        for m in re.finditer(r"(" + IDENT + r")\s*=\s*(?:util\.)?promisify\(\s*(?:(" + IDENT + r")\.)?(" + IDENT +
                             r")\s*\)", c):
            local, ns, fn = m.groups()
            if (ns in self.cp_ns and fn in ("exec",)) or fn in self.shell_fns:
                self.shell_fns.add(local)
            elif (ns in self.cp_ns and fn in ("execFile", "spawn")) or fn in self.spawn_fns:
                self.spawn_fns.add(local)
        for ns in self.cp_ns:
            self.shell_fns |= {f"{ns}.exec", f"{ns}.execSync"}
            self.spawn_fns |= {f"{ns}.spawn", f"{ns}.spawnSync", f"{ns}.execFile", f"{ns}.execFileSync"}

        fsm = r"""['"](?:""" + FS_MODULES + r""")['"]"""
        self.fs_ns = set(re.findall(r"import\s+\*\s+as\s+(" + IDENT + r")\s+from\s+" + fsm, c))
        self.fs_ns |= set(re.findall(r"import\s+(" + IDENT + r")\s*(?:,\s*\{[^}]*\})?\s+from\s+" + fsm, c))
        self.fs_ns |= set(re.findall(r"(?:const|let|var)\s+(" + IDENT + r")\s*=\s*require\(\s*" + fsm + r"\s*\)", c))
        self.fs_ns |= {f"{ns}.promises" for ns in list(self.fs_ns)}
        self.fs_named: dict[str, str] = {}
        named = re.findall(r"import\s*(?:" + IDENT + r"\s*,\s*)?\{([^}]*)\}\s*from\s*" + fsm, c) + \
            re.findall(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*" + fsm + r"\s*\)", c)
        for block in named:
            for part in block.split(","):
                orig, _, local = part.replace(" as ", ":").partition(":")
                orig, local = orig.strip(), (local.strip() or orig.strip())
                if orig in FS_METHODS_READ | FS_METHODS_WRITE:
                    self.fs_named[local] = orig
        self.http_fns = {"fetch"}
        for m in re.finditer(r"import\s+(" + IDENT + r")\s+from\s+['\"](axios|got|ky|node-fetch|cross-fetch|"
                             r"undici|superagent)['\"]", c):
            self.http_fns.add(m.group(1))
        for m in re.finditer(r"import\s*\{([^}]*)\}\s*from\s*['\"]undici['\"]", c):
            for part in m.group(1).split(","):
                orig, _, local = part.replace(" as ", ":").partition(":")
                if orig.strip() in ("request", "fetch"):
                    self.http_fns.add((local.strip() or orig.strip()))

    def _find_helpers(self) -> dict[str, tuple[list[str], int, int]]:
        """name -> (params, body_start, body_end) for same-file functions."""
        out: dict[str, tuple[list[str], int, int]] = {}
        code = self.code
        pats = [
            r"(?:export\s+)?(?:async\s+)?function\s*\*?\s*(" + IDENT + r")\s*(?:<[^>]*>)?\s*\(",
            r"(?:const|let|var)\s+(" + IDENT + r")\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\s*)?\(",
            r"^[ \t]*(?:public\s+|private\s+|protected\s+|static\s+)*(?:async\s+)?(" + IDENT +
            r")\s*\((?=[^)]*\)\s*(?::\s*[^{;]+)?\{)",
        ]
        for pat in pats:
            for m in re.finditer(pat, code, re.M):
                name = m.group(1)
                if name in KEYWORDS or name in out:
                    continue
                po = m.end() - 1
                pc = match_close(code, po)
                params = parse_params_list(code[po + 1:pc])
                k = pc + 1
                rest = code[k:k + 200]
                arrow = re.match(r"\s*(?::\s*[^={]+?)?\s*(=>)?\s*\{", rest)
                if not arrow:
                    continue
                bo = k + arrow.end() - 1
                out[name] = (params, bo, match_close(code, bo))
        return out

    def line_of(self, off: int) -> int:
        lo, hi = 0, len(self.line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.line_starts[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def add(self, rule: str, sev: str, msg: str, off: int, **extra) -> None:
        line = self.line_of(off)
        if (rule, line) in self._seen:
            return
        raw = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        if "mcp-audit: ignore" in raw:
            return
        self._seen.add((rule, line))
        p = extra.get("param")
        if p and self._cur is not None:
            root = self._cur.root(p)
            msg, extra["param"] = msg.replace(f"'{p}'", f"'{root}'"), root
        self.findings.append(Finding(rule, sev, msg, self.rel, line, redact_line(raw),
                                     extra={"lang": "js", **{k: v for k, v in extra.items() if v is not None}}))

    # ------------------------------------------------------------ tool regions
    def tool_spans(self) -> list[Span]:
        spans = []
        code, clean = self.code, self.clean
        for m in re.finditer(r"\.\s*(tool|registerTool|addTool|setRequestHandler)\s*\(", code):
            kind = m.group(1)
            o = m.end() - 1
            c = match_close(code, o)
            args = split_args(code, o + 1, c)
            if not args:
                continue
            first_clean = clean[args[0][0]:args[0][1]]
            if kind == "setRequestHandler" and "CallToolRequestSchema" not in first_clean:
                continue
            name = None
            if kind in ("tool", "registerTool"):
                sm = re.match(r"""\s*['"`]([^'"`]+)['"`]""", first_clean)
                if not sm:
                    continue          # not an MCP tool registration
                name = sm.group(1)
            elif kind == "addTool":
                sm = re.search(r"""\bname\s*:\s*['"`]([^'"`]+)['"`]""", first_clean)
                name = sm.group(1) if sm else None
            # handler: last argument (or execute: in addTool's object)
            ha, hb = args[-1]
            if kind == "addTool":
                em = re.search(r"\bexecute\s*(?::\s*(?:async\s+)?(?:function\s*)?)?", code[ha:hb])
                if em:
                    ha = ha + em.end()
            fm = FN_RE.search(code, ha, hb)
            if not fm:
                continue
            raw_params = fm.group(1) if fm.group(1) is not None else (
                fm.group(2) if fm.group(2) is not None else fm.group(3))
            tainted = set(parse_params(raw_params or ""))
            spans.append(Span(ha, hb, tainted, "tool", name, m.start(), [(m.start(), c)]))
        return spans

    # ------------------------------------------------------------ taint propagation
    def propagate(self, sp: Span) -> dict[str, set[str] | dict]:
        code, clean = self.code, self.clean
        sets = {"all": set(sp.tainted), "shell": set(sp.tainted), "path": set(sp.tainted), "url": set(sp.tainted)}
        sql_vars: dict[str, str] = {}
        decl = re.compile(r"(?:\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|" + IDENT + r")\s*(?::[^=;]+?)?\s*"
                          r"|(?<![\w$.\])])(" + IDENT + r")\s*)(\+?=)(?![=>])")
        stmts = []
        for m in decl.finditer(code, sp.start, sp.end):
            target = m.group(1) or m.group(2)
            if target in KEYWORDS:
                continue
            a = m.end()
            b = _expr_end(code, a, sp.end)
            names = parse_params(target) if target.startswith(("{", "[")) else [target]
            if target.startswith("["):
                names = [x.strip() for x in target[1:-1].split(",") if re.fullmatch(IDENT, x.strip())]
            stmts.append((names, a, b, m.group(3) == "+="))
        for _ in range(6):
            changed = False
            for names, a, b, aug in stmts:
                expr = code[a:b]
                for key, sset in sets.items():
                    src = self.tainted_in(expr, sset, key)
                    if src:
                        if key == "url" and self.fixed_host(clean[a:b]):
                            continue
                        for nm in names:
                            if nm not in sset:
                                sset.add(nm)
                                if nm != src:
                                    sp.origin.setdefault(nm, src)
                                changed = True
                dyn = self.dynamic_sql(clean[a:b], code[a:b], sets["all"], sql_vars)
                if dyn is None and aug and names and names[0] in sql_vars and self.tainted_in(expr, sets["all"]):
                    dyn = sql_vars[names[0]]
                if dyn is not None:
                    for nm in names:
                        if nm not in sql_vars:
                            sql_vars[nm] = dyn
                            changed = True
            if not changed:
                break
        return {**sets, "sql": sql_vars}

    def tainted_in(self, expr: str, tainted: set[str], kind: str = "all") -> str | None:
        e = strip_calls(expr, JS_SANITIZERS_ALL)
        if kind == "shell":
            e = strip_calls(e, JS_SANITIZERS_SHELL)
        elif kind == "path":
            e = strip_calls(e, JS_SANITIZERS_PATH + self.contain_funcs)
        hit = idents(e) & tainted
        return sorted(hit)[0] if hit else None

    @staticmethod
    def fixed_host(expr_clean: str) -> bool:
        s = expr_clean.strip()
        if s[:1] in "'\"`":
            return bool(FIXED_HOST_RE.match(s[1:]))
        return False

    def dynamic_sql(self, expr_clean: str, expr_code: str, tainted: set[str], sql_vars: dict) -> str | None:
        s = expr_clean.strip()
        if re.fullmatch(IDENT, s):
            return sql_vars.get(s)
        literal = re.sub(r"\$\{[^}]*\}", " ", "".join(re.findall(r"`[^`]*`|'[^']*'|\"[^\"]*\"", s)))
        if not SQL_KEYWORDS_RE.search(literal):
            return None
        is_dyn = ("`" in s and "${" in s) or "+" in expr_code or ".concat(" in expr_code
        if not is_dyn:
            return None
        return self.tainted_in(expr_code, tainted)

    def _secret_vars(self, a: int, b: int) -> dict[str, str]:
        out = {}
        for m in re.finditer(r"\b(?:const|let|var)\s+(" + IDENT + r")\s*(?::[^=]+)?=\s*process\.env"
                             r"(?:\.(" + IDENT + r")|\[\s*['\"]([^'\"]+)['\"]\s*\])", self.clean[a:b]):
            env = m.group(2) or m.group(3)
            if SECRET_KEY_RE.search(env) and not NOT_SECRET_KEY_RE.search(env):
                out[m.group(1)] = env
        for m in re.finditer(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*process\.env\b", self.clean[a:b]):
            for nm in parse_params("{" + m.group(1) + "}"):
                if SECRET_KEY_RE.search(nm) and not NOT_SECRET_KEY_RE.search(nm):
                    out[nm] = nm
        return out

    # ------------------------------------------------------------ analysis
    def run(self) -> list[Finding]:
        for sp in self.tool_spans():
            self.analyze(sp)
            self.check_annotations(sp)
        self.check_lowlevel_defs()
        return self.findings

    def analyze(self, sp: Span) -> None:
        env = self.propagate(sp)
        sources = "\n".join(self.clean[a:b] for a, b in sp.sources)
        self._cur = sp
        self._calls(sp, env, sources)
        if sp.kind == "tool":
            self._raw_content(sp)
            self._secret_echo(sp)
        if sp.depth >= 2:
            return
        for name, (params, ba, bb) in self._helpers.items():
            if ba <= sp.start and bb >= sp.end:
                continue      # the enclosing function, not a callee
            for m in re.finditer(r"(?<![\w$.])(?:this\.)?" + re.escape(name) + r"\s*\(", self.code[sp.start:sp.end]):
                o = sp.start + m.end() - 1
                c = match_close(self.code, o)
                hit = set()
                for i, (a, b) in enumerate(split_args(self.code, o + 1, c)):
                    if i < len(params) and self.tainted_in(self.code[a:b], env["all"]):
                        hit |= set(params[i]) if isinstance(params[i], list) else {params[i]}
                if hit:
                    self.analyze(Span(ba, bb, hit, "helper", sp.tool_name, sp.reg_start,
                                      sp.sources + [(ba, bb)], sp.depth + 1))
                    break

    def _first_arg(self, o: int) -> tuple[int, int, int] | None:
        c = match_close(self.code, o)
        args = split_args(self.code, o + 1, c)
        return (args[0][0], args[0][1], c) if args else None

    def _calls(self, sp: Span, env: dict, sources: str) -> None:
        code, clean = self.code, self.clean
        seg = code[sp.start:sp.end]
        for m in re.finditer(r"(?<![\w$])(new\s+)?((?:" + IDENT + r"\.)*" + IDENT + r")\s*\(", seg):
            callee = m.group(2)
            is_new = bool(m.group(1))
            if m.start() > 0 and seg[m.start() - 1] == "." and not is_new:
                continue
            o = sp.start + m.end() - 1
            fa = self._first_arg(o)
            if fa is None:
                continue
            a, b, c = fa
            first_code, first_clean = code[a:b], clean[a:b]
            all_args = code[o + 1:c]
            tail = callee.rsplit(".", 1)[-1]
            off = sp.start + m.start()

            # MCP108 eval
            if (callee == "eval" or (is_new and callee in ("Function", "vm.Script")) or
                    callee in ("vm.runInNewContext", "vm.runInThisContext", "vm.runInContext", "vm.compileFunction")):
                p = self.tainted_in(all_args, env["all"])
                if p:
                    self.add("MCP108", "critical", f"Tool input '{p}' is evaluated as code by {callee}(): remote "
                                                   f"code execution.", off, param=p)
                continue
            # MCP101 shell
            if callee in self.shell_fns:
                p = self.tainted_in(first_code, env["shell"], "shell")
                if p:
                    self.add("MCP101", "critical", f"Tool input '{p}' is interpolated into a shell command run by "
                                                   f"{callee}(): a prompt injection can run any command.", off,
                             param=p)
                continue
            if callee in self.spawn_fns:
                if re.search(r"\bshell\s*:\s*(true|['\"`])", clean[o + 1:c]):
                    p = self.tainted_in(all_args, env["shell"], "shell")
                    if p:
                        self.add("MCP101", "critical", f"Tool input '{p}' reaches {callee}() with shell: true: a "
                                                       f"prompt injection can run any command.", off, param=p)
                else:
                    lead = re.match(r"\s*(" + IDENT + r")", first_code)
                    if lead and lead.group(1) in env["shell"]:
                        self.add("MCP101", "high", f"Tool input '{lead.group(1)}' chooses the program run by "
                                                   f"{callee}(): the model can run any executable.", off,
                                 param=lead.group(1))
                continue
            # MCP102 fs
            fs_op = None
            if "." in callee and callee.rsplit(".", 1)[0] in self.fs_ns and tail in FS_METHODS_READ | FS_METHODS_WRITE:
                fs_op = tail
            elif callee in self.fs_named:
                fs_op = self.fs_named[callee]
            if fs_op:
                check = all_args if fs_op in ("rename", "renameSync", "copyFile", "copyFileSync", "cp", "cpSync",
                                              "move") else first_code
                p = self.tainted_in(check, env["path"], "path")
                if p and not self.contained(sources):
                    write = fs_op in FS_METHODS_WRITE
                    self.add("MCP102", "critical" if write else "high",
                             f"Tool input '{p}' is used as a path in {callee}() "
                             f"({'write/delete' if write else 'read'}) with no check that it stays inside an allowed "
                             f"directory: path traversal (../../.ssh/id_rsa).", off, param=p)
                continue
            # MCP104 SSRF
            if callee in self.http_fns or re.fullmatch(HTTP_DOTTED, callee):
                target = first_code
                inner = re.match(r"\s*new\s+URL\s*\(", target)
                if inner:
                    io = a + inner.end() - 1
                    ia = self._first_arg(io)
                    if ia:
                        target = code[ia[0]:ia[1]]
                        first_clean = clean[ia[0]:ia[1]]
                if self.fixed_host(first_clean):
                    continue
                lead = re.match(r"\s*(?:`\s*\$\{\s*)?(" + IDENT + r")", target)
                if lead and lead.group(1) in env["url"] and not self.allowlisted(sources):
                    self.add("MCP104", "high", f"Tool input '{lead.group(1)}' is used as the URL in {callee}() with "
                                               f"no host allowlist or private-address check: SSRF "
                                               f"(http://169.254.169.254/, localhost).", off, param=lead.group(1))
                continue
            # MCP103 SQL
            if re.fullmatch(r"(?:" + IDENT + r"\.)+(?:" + SQL_JS_METHODS + r")", callee):
                p = self.dynamic_sql(first_clean, first_code, env["all"], env["sql"])
                if p:
                    self.add("MCP103", "high", f"SQL is built from tool input '{p}' with string interpolation and "
                                               f"run via {tail}(): SQL injection.", off, param=p)
                continue

    @staticmethod
    def _contained_strict(src: str) -> bool:
        if re.search(r"path\.relative\s*\(|isPathInside|isSubPath|isSubdir", src):
            return True
        return bool(re.search(r"\.startsWith\s*\(", src) and re.search(
            r"path\.resolve\s*\(|realpath|path\.normalize\s*\(|\bresolve\s*\(", src))

    def contained(self, sources: str) -> bool:
        if self._contained_strict(sources):
            return True
        return any(CONTAIN_HELPER_RE.search(m.group(1)) for m in re.finditer(r"(?<![\w$.])(" + IDENT + r")\s*\(",
                                                                             sources) if m.group(1) != "safeParse")

    @staticmethod
    def allowlisted(sources: str) -> bool:
        return bool(ALLOWLIST_RE.search(sources))

    # ---- MCP105
    def _raw_content(self, sp: Span) -> None:
        seg = self.code[sp.start:sp.end]
        has_http = any(re.search(r"(?<![\w$.])" + re.escape(f) + r"\s*\(", seg) for f in self.http_fns) or \
            re.search(HTTP_DOTTED + r"\s*\(", seg)
        if not has_http:
            return
        m = re.search(r"\.text\s*\(\s*\)", seg)
        if m and re.search(r"\btext\s*:", seg):
            self.add("MCP105", "info", f"Tool '{sp.tool_name or '?'}' returns fetched web content to the model as-is: "
                                       f"prompt-injection exposure.", sp.start + m.start(), tool=sp.tool_name)

    # ---- MCP107
    def _secret_echo(self, sp: Span) -> None:
        secrets = {**self.module_secrets}
        code, clean = self.code, self.clean
        for m in re.finditer(r"\btext\s*:", code[sp.start:sp.end]):
            a = sp.start + m.end()
            b = _expr_end(code, a, sp.end, stop_at_comma=True)
            expr = strip_calls(code[a:b], _non_string_calls(code[a:b]))
            env = None
            em = re.search(r"process\.env(?:\.(" + IDENT + r")|\[\s*['\"]([^'\"]+))?", clean[a:b])
            if em and re.search(r"process\.env", expr):
                key = em.group(1) or em.group(2)
                if key is None:
                    env = "the whole process environment (process.env)"
                elif SECRET_KEY_RE.search(key) and not NOT_SECRET_KEY_RE.search(key):
                    env = f"the secret env var '{key}'"
            if env is None:
                hit = idents(expr) & set(secrets)
                if hit:
                    v = sorted(hit)[0]
                    env = f"the secret env var '{secrets[v]}' (via {v})"
            if env:
                self.add("MCP107", "high", f"Tool result includes {env}: it ends up in the model context and "
                                           f"transcript.", a, env=env.split("'")[1] if "'" in env else None)

    # ---- MCP106
    def check_annotations(self, sp: Span) -> None:
        if sp.tool_name is None or sp.kind != "tool":
            return
        reg = self.clean[sp.reg_start:sp.end]
        if re.search(r"destructiveHint|readOnlyHint|\bannotations\s*:", reg):
            return
        deletes = re.search(r"\.(?:" + "|".join(sorted(FS_DELETE)) + r")\s*\(", self.code[sp.start:sp.end])
        if is_destructive_name(sp.tool_name) or deletes:
            self.add("MCP106", "low", f"Tool '{sp.tool_name}' looks destructive but declares no annotations "
                                      f"(destructiveHint / readOnlyHint), so clients cannot tell it apart from a "
                                      f"read-only tool.", sp.reg_start, tool=sp.tool_name)

    def check_lowlevel_defs(self) -> None:
        if "ListToolsRequestSchema" not in self.clean:
            return
        defs = [m for m in re.finditer(r"""\bname\s*:\s*['"]([\w\-.]+)['"]""", self.clean)
                if "inputSchema" in self.clean[m.end():m.end() + 1500]]
        for i, m in enumerate(defs):
            end = defs[i + 1].start() if i + 1 < len(defs) else len(self.clean)
            obj = self.clean[m.start():end]
            if is_destructive_name(m.group(1)) and not re.search(r"destructiveHint|readOnlyHint|annotations", obj):
                self.add("MCP106", "low", f"Tool '{m.group(1)}' looks destructive but declares no annotations "
                                          f"(destructiveHint / readOnlyHint), so clients cannot tell it apart from "
                                          f"a read-only tool.", m.start(), tool=m.group(1))


def parse_params_list(params: str) -> list:
    """Positional params; a destructured param becomes a list of its names."""
    out: list = []
    for a, b in split_args(params, 0, len(params)):
        part = params[a:b].strip()
        if part.startswith("{"):
            out.append(parse_params(part))
        else:
            nm = part.split(":")[0].split("=")[0].strip().lstrip(".")
            out.append(nm)
    return out


def _non_string_calls(expr: str) -> list[str]:
    keep = {"String", "JSON.stringify", "stringify", "toString", "concat", "join"}
    names = set()
    for m in re.finditer(r"((?:" + IDENT + r"\.)*" + IDENT + r")\s*\(", expr):
        nm = m.group(1)
        if nm not in keep and nm.rsplit(".", 1)[-1] not in keep:
            names.add(nm)
    return sorted(names, key=len, reverse=True)


def _expr_end(code: str, a: int, limit: int, stop_at_comma: bool = False) -> int:
    depth = 0
    j = a
    while j < limit:
        c = code[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return j
            depth -= 1
        elif depth == 0 and (c == ";" or (c == "," and stop_at_comma)):
            return j
        elif depth == 0 and c == "\n":
            nxt = code[j + 1:j + 40].lstrip()
            prev = code[a:j].rstrip()
            if not nxt.startswith(("+", ".", "?", ":", "&&", "||", "`")) and not prev.endswith(
                    ("+", "=", "(", ",", "?", ":", "&&", "||")):
                return j
        j += 1
    return limit


def scan_js(rel: str, text: str) -> list[Finding]:
    if not is_mcp_js(text):
        return []
    try:
        return JsModule(rel, text).run()
    except RecursionError:
        return []
