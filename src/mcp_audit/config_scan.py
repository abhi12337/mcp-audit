"""Static checks for MCP client config files (Claude Desktop, Claude Code, Cursor, VS Code,
Windsurf, Cline, Zed, ...). Files are parsed as JSON / JSONC; nothing is executed."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, urlsplit

from .findings import Finding, find_known_secret, mask_secret, redact_line

# File names that are MCP client configs by convention.
CONFIG_NAMES = {
    "claude_desktop_config.json",
    "mcp.json",              # .cursor/mcp.json, .vscode/mcp.json, .roo/mcp.json
    ".mcp.json",             # Claude Code project scope
    "mcp_config.json",       # Windsurf
    "cline_mcp_settings.json",
    "mcp_settings.json",     # Roo Code
}
SERVER_CONTAINER_KEYS = ("mcpServers", "servers", "context_servers")

SECRET_KEY_RE = re.compile(
    r"(?i)(token|secret|passw(or)?d|passwd|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|"
    r"credential|client[_\-]?secret|auth|bearer|(^|[_\-])pat$|session[_\-]?key|signing[_\-]?key)"
)
# Names that contain a secret-ish word but hold non-secret values.
NOT_SECRET_KEY_RE = re.compile(
    r"(?i)(_url|_uri|_endpoint|_host|_file|_path|_dir|_type|_mode|_method|_header|_name|_id$|"
    r"_enabled|_expir|_ttl|_timeout|^auth_provider|_issuer|_audience|_scope|_region)"
)
ENV_REF_RE = re.compile(r"\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|\{env:[^}]+\}")
PLACEHOLDER_RE = re.compile(
    r"(?i)(your|<[^>]*>|xxx|changeme|change_me|placeholder|example|replace|todo|insert|dummy|"
    r"redacted|\*\*\*|\.\.\.|^test$|^none$|^null$|^true$|^false$)"
)
SECRET_FLAG_RE = re.compile(
    r"(?i)^--?(?:[a-z\-]*(?:token|secret|password|api-?key|apikey|access-key|auth))(?:=(.*))?$"
)

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal", "[::1]"}
MOVING_TAGS = {"latest", "next", "canary", "beta", "alpha", "edge", "nightly", "main", "master", "dev"}

NPX_VALUE_FLAGS = {"--registry", "--cache", "--userconfig", "--prefix", "-w", "--workspace", "--loglevel"}
UVX_VALUE_FLAGS = {"--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--with-requirements",
                   "--with-editable", "--env-file", "--constraints", "-c", "--overrides", "--directory",
                   "--project", "--cache-dir", "--config-file", "--python-preference"}
DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "--mount", "--name", "-p", "--publish", "--network", "--net",
                      "-w", "--workdir", "-u", "--user", "--entrypoint", "--env-file", "--cap-add", "--cap-drop",
                      "--pid", "--ipc", "--platform", "-l", "--label", "-m", "--memory", "--cpus", "--add-host",
                      "--device", "--security-opt", "--tmpfs", "-h", "--hostname", "--restart", "--runtime",
                      "--gpus", "--ulimit", "--userns", "--uts", "--log-driver", "--log-opt", "--pull", "--shm-size",
                      "--stop-signal", "--cgroupns", "--dns", "--label-file", "--group-add"}


@dataclass
class ConfigResult:
    findings: list[Finding] = field(default_factory=list)
    servers: int = 0
    parsed: bool = False


# ---------------------------------------------------------------- JSONC
def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, keeping line structure."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
        else:
            out.append(ch)
            i += 1
    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r" \1", cleaned)


def looks_like_mcp_config(name: str, text: str) -> bool:
    if name in CONFIG_NAMES:
        return True
    if name.endswith(".json") and '"mcpServers"' in text:
        return True
    if name == "settings.json" and '"mcp"' in text:      # VS Code user/workspace settings
        return True
    return False


def extract_servers(data) -> dict[str, dict]:
    if not isinstance(data, dict):
        return {}
    servers: dict[str, dict] = {}
    containers = [data]
    if isinstance(data.get("mcp"), dict):
        containers.append(data["mcp"])
    # Claude Code ~/.claude.json keeps per-project servers under projects.<path>.mcpServers
    if isinstance(data.get("projects"), dict):
        containers += [p for p in data["projects"].values() if isinstance(p, dict)]
    for c in containers:
        for key in SERVER_CONTAINER_KEYS:
            block = c.get(key)
            if isinstance(block, dict):
                for name, spec in block.items():
                    if isinstance(spec, dict):
                        servers.setdefault(name, spec)
    return servers


# ---------------------------------------------------------------- locating lines
class _Locator:
    def __init__(self, text: str):
        self.text = text
        self.line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self.secrets: list[str] = []      # every secret found in this file, masked in all evidence

    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self.line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def server_offset(self, name: str) -> int:
        m = re.search(re.escape(json.dumps(name)) + r"\s*:\s*\{", self.text)
        return m.start() if m else 0

    def find(self, value: str, start: int) -> int:
        for needle in (json.dumps(value), value):
            pos = self.text.find(needle, start)
            if pos != -1:
                return pos
        return start

    def line_text(self, line: int) -> str:
        lines = self.text.splitlines()
        return lines[line - 1] if 0 < line <= len(lines) else ""


# ---------------------------------------------------------------- helpers
def _base_cmd(cmd: str) -> str:
    base = re.split(r"[\\/]", cmd.strip())[-1].lower()
    for ext in (".cmd", ".exe", ".bat", ".ps1"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base


def unwrap_command(command: str, args: list[str]) -> tuple[str, list[str]]:
    """`cmd /c npx -y pkg` and `bash -c "npx pkg"`-style wrappers -> (npx, [-y, pkg])."""
    base = _base_cmd(command)
    if base == "cmd" and args and args[0].lower() in ("/c", "/k", "/s"):
        rest = [a for a in args[1:] if a.lower() not in ("/c", "/k", "/s")]
        if rest:
            return _base_cmd(rest[0]), rest[1:]
    if base in ("sh", "bash", "zsh") and len(args) >= 2 and args[0] in ("-c", "-lc"):
        parts = args[1].split()
        if parts:
            return _base_cmd(parts[0]), parts[1:]
    if base in ("pnpm", "yarn") and args and args[0] == "dlx":
        return "npx", args[1:]
    if base == "npm" and args and args[0] == "exec":
        return "npx", args[1:]
    if base == "bun" and args and args[0] == "x":
        return "npx", args[1:]
    if base in ("bunx", "pnpx"):
        return "npx", args
    if base == "uv" and len(args) >= 2 and args[0] == "tool" and args[1] == "run":
        return "uvx", args[2:]
    if base == "pipx" and args and args[0] == "run":
        return "pipx-run", args[1:]
    return base, list(args)


def _is_local_spec(spec: str) -> bool:
    return bool(re.match(r"^(\.{1,2}[\\/]|/|~|[A-Za-z]:[\\/]|file:|git\+|git:|https?:|github:)", spec)) \
        or spec.endswith((".tgz", ".tar.gz", ".whl", ".py", ".js"))


def parse_npm_spec(spec: str) -> tuple[str, str | None]:
    if spec.startswith("@"):
        name, sep, ver = spec[1:].partition("@")
        return "@" + name, (ver if sep else None)
    name, sep, ver = spec.partition("@")
    return name, (ver if sep else None)


def parse_py_spec(spec: str) -> tuple[str, str | None, bool]:
    """-> (name, version, exact). `pkg==1.2`, `pkg@1.2`, `pkg[extra]>=1`."""
    m = re.match(r"^([A-Za-z0-9_.\-]+(?:\[[^\]]*\])?)\s*(==|===|@|>=|<=|~=|>|<|!=)?\s*(.*)$", spec)
    if not m:
        return spec, None, False
    name, op, ver = m.group(1), m.group(2), m.group(3) or None
    if not op:
        return name, None, False
    return name, ver, op in ("==", "===", "@")


def _version_kind(ver: str | None) -> str:
    """'none' | 'moving' | 'range' | 'exact'"""
    if not ver:
        return "none"
    v = ver.strip().lower()
    if v in MOVING_TAGS:
        return "moving"
    if v in ("*", "x") or v[0] in "^~><" or re.search(r"(^|\.)(x|\*)($|\.)", v) or " " in v:
        return "range"
    if not re.match(r"^v?\d", v):
        return "moving"    # any other dist-tag
    return "exact"


def _is_env_ref(value: str) -> bool:
    return bool(ENV_REF_RE.search(value)) and len(ENV_REF_RE.sub("", value).strip()) < 4


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    return (not v or len(v) < 8 or bool(PLACEHOLDER_RE.search(v)) or len(set(v)) <= 2
            or v.isdigit() or bool(re.match(r"^(https?|wss?)://", v)) or bool(re.match(r"^[~./\\]|^[A-Za-z]:\\", v)))


def _broad_root(arg: str) -> str | None:
    a = arg.strip().strip('"')
    if not a:
        return None
    norm = a.replace("\\", "/")
    trimmed = norm.rstrip("/") if len(norm) > 1 else norm
    if trimmed in ("/", "") and norm.startswith("/"):
        return "/ (the whole filesystem)"
    if re.fullmatch(r"[A-Za-z]:/?", norm):
        return f"{a} (a whole drive)"
    if trimmed in ("~", "$HOME", "${HOME}", "%USERPROFILE%", "%HOMEPATH%", "${env:HOME}", "${env:USERPROFILE}",
                   "${userHome}", "/Users", "/home", "/root"):
        return f"{a} (your home directory)"
    if re.fullmatch(r"/(Users|home)/[^/]+", trimmed) or re.fullmatch(r"[A-Za-z]:/Users(/[^/]+)?", trimmed, re.I):
        return f"{a} (your home directory)"
    return None


def _host_of_mount(spec: str) -> str:
    """docker -v host:container[:opts] -> host part (handles C:\\ drive letters)."""
    m = re.match(r"^([A-Za-z]:[\\/][^:]*|[^:]*)", spec)
    return m.group(1) if m else spec


def _is_local_url(url: str) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host in LOCAL_HOSTS or host.startswith("127.") or host.endswith(".localhost") or host.endswith(".local")


# ---------------------------------------------------------------- per server checks
class _ServerCheck:
    def __init__(self, rel: str, name: str, spec: dict, loc: _Locator):
        self.rel, self.name, self.spec, self.loc = rel, name, spec, loc
        self.base_off = loc.server_offset(name)
        self.findings: list[Finding] = []

    def at(self, value: str | None) -> int:
        off = self.loc.find(value, self.base_off) if value else self.base_off
        return self.loc.line_of(off)

    def add(self, rule: str, sev: str, msg: str, value: str | None, *, secrets: list[str] | None = None,
            evidence: str | None = None, **extra) -> None:
        line = self.at(value)
        raw_line = self.loc.line_text(line)
        if "mcp-audit: ignore" in raw_line:
            return
        ev = evidence if evidence is not None else redact_line(raw_line, secrets)
        self.findings.append(Finding(rule, sev, msg, self.rel, line, ev, extra={"server": self.name, **extra}))

    # ---- MCP001
    def secrets(self) -> None:
        env = self.spec.get("env") if isinstance(self.spec.get("env"), dict) else {}
        headers = self.spec.get("headers") if isinstance(self.spec.get("headers"), dict) else {}
        for kind, block in (("env", env), ("headers", headers)):
            for key, value in block.items():
                if not isinstance(value, str):
                    continue
                self._check_value(key, value, f"{kind}.{key}")
        args = [a for a in self.spec.get("args", []) if isinstance(a, str)] if isinstance(self.spec.get("args"), list) else []
        for i, a in enumerate(args):
            known = find_known_secret(a)
            if known and not _is_env_ref(a):
                self._report_secret(known[1], f"args[{i}]", label=known[0], key=None, critical=True)
                continue
            m = SECRET_FLAG_RE.match(a)
            if m:
                val = m.group(1) if m.group(1) is not None else (args[i + 1] if i + 1 < len(args) else "")
                if val and not _is_env_ref(val) and not _is_placeholder(val):
                    flag = a.split("=")[0].lstrip("-")
                    self._report_secret(val, f"args ({a.split('=')[0]})", label=None,
                                        key=flag.upper().replace("-", "_"), critical=False)
            for hk, hv in _header_arg(args, i):
                self._check_value(hk, hv, f"args header {hk}")
            if "://" in a:            # postgresql://user:password@host/db, https://x?api_key=...
                self._check_url_secret(a, where=f"args[{i}]")
        url = self._url()
        if url:
            self._check_url_secret(url)

    def _check_value(self, key: str, value: str, where: str) -> None:
        if _is_env_ref(value):
            return
        known = find_known_secret(value)
        if known:
            self._report_secret(known[1], where, label=known[0], key=key, critical=True)
            return
        if key.lower() == "authorization":
            token = re.sub(r"(?i)^(bearer|basic|token)\s+", "", value.strip())
            if not _is_env_ref(token) and not _is_placeholder(token):
                self._report_secret(token, where, label=None, key="AUTH_TOKEN", critical=False)
            return
        if SECRET_KEY_RE.search(key) and not NOT_SECRET_KEY_RE.search(key) and not _is_placeholder(value):
            self._report_secret(value, where, label=None, key=key, critical=False)

    def _check_url_secret(self, url: str, where: str = "url") -> None:
        try:
            parts = urlsplit(url.strip())
            password = parts.password
        except ValueError:
            return
        if password and not _is_env_ref(password) and not _is_placeholder(password):
            self._report_secret(password, f"{where} (password in user:password@)", label=None,
                                key="DATABASE_URL" if "sql" in parts.scheme or "mongo" in parts.scheme else
                                "URL_PASSWORD", critical=False, value_for_line=url)
        for k, v in parse_qsl(parts.query):
            if SECRET_KEY_RE.search(k) or k.lower() in ("key", "apikey", "code"):
                if not _is_env_ref(v) and not _is_placeholder(v):
                    self._report_secret(v, f"{where} (query ?{k}=)", label=None, key=k.upper(), critical=False,
                                        value_for_line=url)

    def _report_secret(self, secret: str, where: str, *, label: str | None, key: str | None, critical: bool,
                       value_for_line: str | None = None) -> None:
        self.loc.secrets.append(secret)
        what = label or "Secret-looking value"
        sev = "critical" if critical else "high"
        self.add("MCP001", sev,
                 f"{what} hard-coded in {where} of server '{self.name}'. Anyone with this file has it.",
                 value_for_line or secret, secrets=[secret],
                 evidence=f"{where} = {mask_secret(secret)}", key=key or _guess_env_name(label))

    # ---- MCP002/003/004/005
    def launch(self) -> None:
        command = self.spec.get("command")
        if not isinstance(command, str) or not command.strip():
            return
        raw_args = self.spec.get("args") if isinstance(self.spec.get("args"), list) else []
        args = [a for a in raw_args if isinstance(a, str)]
        parts = command.split()
        if len(parts) > 1 and not re.match(r"^[A-Za-z]:\\", command):   # "npx -y pkg" written as one string
            command, args = parts[0], parts[1:] + args
        base, rest = unwrap_command(command, args)
        if base == "npx":
            self._npx(rest)
        elif base in ("uvx", "pipx-run"):
            self._uvx(rest, base)
        elif base in ("docker", "podman"):
            self._docker(rest)
        if base not in ("docker", "podman"):
            self._roots(rest)

    def _npx(self, args: list[str]) -> None:
        specs: list[str] = []
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-p", "--package"):
                if i + 1 < len(args):
                    specs.append(args[i + 1])
                i += 2
                continue
            if a.startswith("--package="):
                specs.append(a.split("=", 1)[1])
            elif a in ("-c", "--call"):
                return
            elif a in NPX_VALUE_FLAGS:
                i += 2
                continue
            elif a == "--":
                pass
            elif not a.startswith("-"):
                if not specs:
                    specs.append(a)
                break
            i += 1
        for spec in specs:
            if _is_local_spec(spec):
                continue
            name, ver = parse_npm_spec(spec)
            self._version_finding(spec, name, ver, f"npx -y {name}@<version>", "npm")

    def _uvx(self, args: list[str], base: str) -> None:
        spec = None
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("--from", "--spec"):
                spec = args[i + 1] if i + 1 < len(args) else None
                break
            if a.startswith(("--from=", "--spec=")):
                spec = a.split("=", 1)[1]
                break
            if a in UVX_VALUE_FLAGS:
                i += 2
                continue
            if not a.startswith("-"):
                spec = a
                break
            i += 1
        if not spec or _is_local_spec(spec):
            return
        name, ver, exact = parse_py_spec(spec)
        tool = "uvx" if base == "uvx" else "pipx run"
        if ver and not exact:
            kind = "range"
        else:
            kind = _version_kind(ver)
        self._report_version(spec, name, kind, f"{tool} {name}==<version>", ver)

    def _version_finding(self, spec: str, name: str, ver: str | None, pinned: str, eco: str) -> None:
        self._report_version(spec, name, _version_kind(ver), pinned, ver)

    def _report_version(self, spec: str, name: str, kind: str, pinned: str, ver: str | None) -> None:
        if kind == "exact":
            return
        if kind == "moving":
            self.add("MCP003", "medium",
                     f"Server '{self.name}' runs {name} at the moving tag '{ver}': every client start can pull "
                     f"new, unreviewed code.", spec, pinned=pinned, package=name)
        elif kind == "range":
            self.add("MCP002", "medium",
                     f"Server '{self.name}' runs {name} with the version range '{ver}': new releases are "
                     f"installed automatically.", spec, pinned=pinned, package=name)
        else:
            self.add("MCP002", "medium",
                     f"Server '{self.name}' runs {name} with no version: whatever the registry serves at "
                     f"launch time is executed.", spec, pinned=pinned, package=name)

    def _docker(self, args: list[str]) -> None:
        if not args or args[0] not in ("run", "container"):
            return
        args = args[1:] if args[0] == "run" else args[2:]
        image = None
        i = 0
        while i < len(args):
            a = args[i]
            flag, eq, val = a.partition("=")
            takes_value = flag in DOCKER_VALUE_FLAGS and not eq
            value = args[i + 1] if takes_value and i + 1 < len(args) else (val if eq else None)
            if a == "--privileged" or (flag == "--privileged" and val.lower() != "false"):
                self.add("MCP005", "critical",
                         f"Server '{self.name}' runs a --privileged container: it has full access to the host "
                         f"devices and kernel.", a, flag="--privileged")
            elif flag in ("-v", "--volume") and value:
                self._mount(_host_of_mount(value), value, flag)
            elif flag == "--mount" and value:
                m = re.search(r"(?:^|,)(?:source|src)=([^,]+)", value)
                if m and "type=bind" in value:
                    self._mount(m.group(1), value, flag)
            elif flag in ("--network", "--net", "--pid", "--ipc", "--uts") and value == "host":
                self.add("MCP005", "medium",
                         f"Server '{self.name}' uses {flag} host: the container shares the host's "
                         f"{flag.lstrip('-')} namespace (for --network host it can reach every local service).",
                         a, flag=f"{flag} host")
            elif flag == "--cap-add" and value and value.upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN",
                                                                       "DAC_READ_SEARCH", "SYS_MODULE"):
                self.add("MCP005", "high", f"Server '{self.name}' adds the {value} capability to its container.",
                         value, flag=f"--cap-add {value}")
            elif flag == "--security-opt" and value and ("unconfined" in value or "disable" in value):
                self.add("MCP005", "high", f"Server '{self.name}' disables container security ({value}).",
                         value, flag=f"--security-opt {value}")
            if takes_value:
                i += 2
                continue
            if not a.startswith("-"):
                image = a
                break
            i += 1
        if image and not _is_env_ref(image):
            if "@sha256:" in image:
                return
            last = image.rsplit("/", 1)[-1]
            name, sep, tag = last.partition(":")
            repo = image[: len(image) - len(last)] + name
            pinned = f'"{repo}:<version>"  or  "{repo}@sha256:<digest>"'
            if not sep:
                self.add("MCP002", "medium",
                         f"Server '{self.name}' runs docker image {image} with no tag (= :latest): it can change "
                         f"on every pull.", image, pinned=pinned, package=repo)
            elif tag.lower() in MOVING_TAGS:
                self.add("MCP003", "medium",
                         f"Server '{self.name}' runs docker image {image}: ':{tag}' moves with every release.",
                         image, pinned=pinned, package=repo)

    def _mount(self, host: str, raw: str, flag: str) -> None:
        h = host.replace("\\", "/")
        if h.rstrip("/") in ("/var/run/docker.sock", "/run/docker.sock", "//./pipe/docker_engine") or \
                h.endswith("docker.sock"):
            self.add("MCP005", "critical",
                     f"Server '{self.name}' mounts the docker socket: the container can start privileged "
                     f"containers and take over the host.", raw, flag=f"{flag} {raw}")
            return
        broad = _broad_root(host)
        if broad:
            sev = "critical" if "whole" in broad else "high"
            self.add("MCP005", sev, f"Server '{self.name}' mounts {broad} into its container.", raw,
                     flag=f"{flag} {raw}")
        elif h.rstrip("/") in ("/etc", "/root", "/var", "/proc", "/sys", "/boot", "/dev") or \
                re.search(r"/\.(ssh|aws|kube|gnupg|docker|config/gcloud)(/|$)", h):
            self.add("MCP005", "high", f"Server '{self.name}' mounts the sensitive host path {host}.", raw,
                     flag=f"{flag} {raw}")

    def _roots(self, args: list[str]) -> None:
        for i, a in enumerate(args):
            val = a
            m = re.match(r"^--?[A-Za-z\-]*(?:root|dir|directory|directories|path|allow[A-Za-z\-]*)=(.+)$", a)
            if m:
                val = m.group(1)
            elif a.startswith("-"):
                continue
            for part in val.split(",") if m else [val]:
                broad = _broad_root(part)
                if broad:
                    self.add("MCP004", "high",
                             f"Server '{self.name}' is given {broad} as an accessible root: the model can read "
                             f"(and possibly write) everything under it.", a, path=part)

    # ---- MCP006
    def _url(self) -> str | None:
        for k in ("url", "serverUrl", "httpUrl", "uri"):
            v = self.spec.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None

    def transport(self) -> None:
        urls: list[str] = []
        u = self._url()
        if u:
            urls.append(u)
        if isinstance(self.spec.get("args"), list) and isinstance(self.spec.get("command"), str):
            urls += [a for a in self.spec["args"] if isinstance(a, str) and a.lower().startswith("http://")]
        for url in urls:
            if url.lower().startswith("http://") and not _is_local_url(url):
                self.add("MCP006", "high",
                         f"Server '{self.name}' connects to {_safe_url(url)} over plain http: tool calls, results "
                         f"and tokens travel unencrypted.", url, evidence=_safe_url(url),
                         https_url="https://" + _safe_url(url)[len("http://"):])


def _header_arg(args: list[str], i: int) -> list[tuple[str, str]]:
    """mcp-remote style: --header "Authorization: Bearer xyz"."""
    if args[i] in ("--header", "-H") and i + 1 < len(args) and ":" in args[i + 1]:
        k, _, v = args[i + 1].partition(":")
        return [(k.strip(), v.strip())]
    return []


def _safe_url(url: str) -> str:
    try:
        p = urlsplit(url)
        netloc = p.hostname or ""
        if p.port:
            netloc += f":{p.port}"
        return f"{p.scheme}://{netloc}{p.path}"
    except ValueError:
        return "http://..."


def _guess_env_name(label: str | None) -> str:
    if not label:
        return "API_TOKEN"
    return re.sub(r"[^A-Z0-9]+", "_", label.upper()).strip("_")


def scan_config_text(rel: str, text: str) -> ConfigResult:
    res = ConfigResult()
    try:
        data = json.loads(strip_jsonc(text))
    except (json.JSONDecodeError, ValueError):
        return res
    res.parsed = True
    servers = extract_servers(data)
    res.servers = len(servers)
    loc = _Locator(text)
    for name, spec in servers.items():
        chk = _ServerCheck(rel, name, spec, loc)
        chk.secrets()                       # a disabled server's token is still in the file
        if spec.get("disabled") is not True:
            chk.launch()
            chk.transport()
        res.findings += chk.findings
    for f in res.findings:
        if f.evidence:
            f.evidence = redact_line(f.evidence, sorted(set(loc.secrets), key=len, reverse=True))
    return res


def is_config_path(rel: str) -> bool:
    return PurePosixPath(rel).name in CONFIG_NAMES
