"""The same notes server written safely. mcp-audit must report nothing here."""

import ipaddress
import os
import shlex
import socket
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
DB = sqlite3.connect("notes.db")
NOTES_DIR = Path(os.environ.get("NOTES_DIR", "/srv/notes")).resolve()
OPENAI_KEY = os.environ["OPENAI_API_KEY"]
ALLOWED_HOSTS = {"docs.python.org", "developer.mozilla.org"}


def _safe_path(name: str) -> Path:
    target = (NOTES_DIR / name).resolve()
    if not target.is_relative_to(NOTES_DIR):
        raise ValueError("path outside notes directory")
    return target


@mcp.tool()
def git_log(branch: str) -> str:
    """Show the git log for a branch (no shell, argument list)."""
    out = subprocess.run(["git", "log", "--oneline", "--", branch], capture_output=True, text=True, timeout=30)
    return out.stdout


@mcp.tool()
def disk_usage(folder: str) -> str:
    """Disk usage of a folder (quoted)."""
    return subprocess.run(f"du -sh {shlex.quote(folder)}", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def uptime() -> str:
    """Fixed command, no input."""
    return os.popen("uptime").read()


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note."""
    return _safe_path(name).read_text()


@mcp.tool()
def read_note_inline(name: str) -> str:
    """Read a note, containment check inline."""
    path = os.path.realpath(os.path.join(NOTES_DIR, name))
    if not path.startswith(str(NOTES_DIR) + os.sep):
        raise ValueError("denied")
    with open(path) as f:
        return f.read()


@mcp.tool()
def read_by_basename(name: str) -> str:
    """Only the file name is used."""
    with open(os.path.join(NOTES_DIR, os.path.basename(name))) as f:
        return f.read()


@mcp.tool(annotations={"destructiveHint": True, "readOnlyHint": False})
def delete_note(name: str) -> str:
    """Delete a note."""
    os.remove(_safe_path(name))
    return "deleted"


@mcp.tool()
def search_notes(term: str, limit: int = 10) -> list:
    """Search notes by title (bound parameters)."""
    cur = DB.cursor()
    cur.execute("SELECT id, title FROM notes WHERE title LIKE ? LIMIT ?", (f"%{term}%", int(limit)))
    return cur.fetchall()


@mcp.tool()
def recent_notes(limit: int = 10) -> list:
    """f-string with a sanitised int only."""
    return DB.execute(f"SELECT id, title FROM notes ORDER BY id DESC LIMIT {int(limit)}").fetchall()


@mcp.tool()
async def fetch_doc(url: str) -> dict:
    """Fetch an allowlisted documentation page."""
    host = urlparse(url).hostname
    if url.startswith("http://") or host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    for info in socket.getaddrinfo(host, 443):
        if ipaddress.ip_address(info[4][0]).is_private:
            raise ValueError("private address")
    async with httpx.AsyncClient(follow_redirects=False) as client:
        resp = await client.get(url)
        return resp.json()


@mcp.tool()
async def weather(city: str) -> dict:
    """Fixed host, user input only in the path."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://api.weather.example.com/v1/{city}",
                                headers={"Authorization": f"Bearer {OPENAI_KEY}"})
        return resp.json()


@mcp.tool()
def config_status() -> dict:
    """Report whether keys are configured, without revealing them."""
    return {"notes_dir": str(NOTES_DIR), "openai_key_configured": bool(OPENAI_KEY),
            "home": os.environ.get("HOME")}


def not_a_tool(command: str) -> None:
    """Not registered as a tool, so not model-reachable."""
    os.system(command)


if __name__ == "__main__":
    mcp.run()
