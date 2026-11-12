"""Generate a deliberately insecure demo project to try mcp-audit on.

    python examples/make_demo.py demo-mcp
    mcp-audit scan demo-mcp

The demo contains a Cursor MCP config with common mistakes plus two vulnerable MCP
servers (copied from tests/fixtures). The fake token is assembled at runtime so this
repository never contains a secret-shaped string. Nothing in it works anywhere.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"

FAKE_GITHUB_TOKEN = "ghp" + "_" + "DEMOdemoDEMOdemo0123456789notArealTOKEN"[:36]

CONFIG = {
    "mcpServers": {
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE_GITHUB_TOKEN},
        },
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@latest", "/Users/alice"],
        },
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
        "time": {"command": "uvx", "args": ["mcp-server-time==0.6.2"]},
        "browser": {
            "command": "docker",
            "args": ["run", "-i", "--rm", "--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                     "mcp/browser:latest"],
        },
        "team-wiki": {"type": "sse", "url": "http://wiki.internal.example.com:8080/sse"},
        "notes": {"command": "python", "args": ["server-python/server.py"]},
    }
}


def main(dest: str) -> None:
    root = Path(dest)
    (root / ".cursor").mkdir(parents=True, exist_ok=True)
    (root / ".cursor" / "mcp.json").write_text(json.dumps(CONFIG, indent=2) + "\n", encoding="utf-8")
    (root / "server-python").mkdir(exist_ok=True)
    shutil.copy(FIXTURES / "py_vulnerable" / "server.py", root / "server-python" / "server.py")
    (root / "server-ts" / "src").mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "ts_vulnerable" / "src" / "index.ts", root / "server-ts" / "src" / "index.ts")
    print(f"Demo project written to {root}. Now run:  mcp-audit scan {root}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo-mcp")
