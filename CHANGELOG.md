# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-11-12

### Fixed

- A Python MCP server file with a syntax error was skipped silently, so a scan of broken code
  could report nothing. It is now reported: a `warning: <path>: syntax error line N; file not
  scanned` line on stderr, a count in the text header and a
  `"skipped": [{"path": ..., "reason": ...}]` list in the JSON report. Exit codes are unchanged.

## [0.1.0] - 2026-11-11

First release.

### Added

- `mcp-audit scan [PATH ...]`: static scan of folders or single files. Never starts, imports
  or connects to an MCP server; no network access.
- `mcp-audit scan --user-configs`: scan the default per-user config locations of Claude
  Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline, Roo Code, Gemini CLI and Zed.
- `mcp-audit rules`: every rule with why it matters and how to fix it.
- Client config rules (JSON and JSONC, `mcpServers` / `servers` / `context_servers`, Claude
  Code per-project servers):
  - MCP001 hard-coded secrets in `env`, `headers`, `args` and URLs (masked to at most 4 characters)
  - MCP002 servers launched via `npx` / `uvx` / `pipx run` / docker without a pinned version
  - MCP003 moving tags (`@latest`, `:latest`, ...)
  - MCP004 filesystem servers given `/`, a whole drive or a home directory
  - MCP005 docker servers with `--privileged`, the docker socket, host-root/home/sensitive
    mounts, extra capabilities or host namespaces
  - MCP006 remote servers over plain http
- Server source rules for Python (`mcp`, FastMCP; `ast`-based) and TypeScript/JavaScript
  (`@modelcontextprotocol/sdk`, `fastmcp`; lexer-based), following tool arguments through
  assignments and up to two levels of same-file helpers:
  - MCP101 shell command injection / model-chosen program
  - MCP102 file access without path containment (path traversal)
  - MCP103 SQL built from tool input
  - MCP104 SSRF: tool input used as a request URL without an allowlist
  - MCP105 raw fetched web content returned to the model (info)
  - MCP106 destructive tools without `destructiveHint` / `readOnlyHint` annotations
  - MCP107 secrets from the environment returned in tool results
  - MCP108 `eval` / `exec` / `new Function` / `vm` on tool input
- Text and JSON reports, a language-specific fix for every finding, `--fail-on`,
  `--min-severity`, `--disable`, `--exclude`, `--include-tests`, `mcp-audit: ignore` comments,
  exit codes `0` / `1` / `2`.
- Demo project generator (`examples/make_demo.py`) and a GitHub Actions example.
