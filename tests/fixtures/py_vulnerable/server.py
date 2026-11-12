"""A deliberately insecure FastMCP server. Every tool here has a known bug. Do not run it."""

import os
import sqlite3
import subprocess
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
DB = sqlite3.connect("notes.db")
NOTES_DIR = "/srv/notes"
OPENAI_KEY = os.environ["OPENAI_API_KEY"]


@mcp.tool()
def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    out = subprocess.run(command, shell=True, capture_output=True, text=True)
    return out.stdout


@mcp.tool()
def git_log(branch: str) -> str:
    """Show the git log for a branch."""
    return os.popen(f"git log --oneline {branch}").read()


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note."""
    path = os.path.join(NOTES_DIR, name)
    with open(path) as f:
        return f.read()


@mcp.tool()
def save_note(name: str, body: str) -> str:
    """Save a note."""
    Path(NOTES_DIR, name).write_text(body)
    return "saved"


@mcp.tool()
def delete_note(name: str) -> str:
    """Delete a note."""
    _remove(name)
    return "deleted"


def _remove(name: str) -> None:
    os.remove(os.path.join(NOTES_DIR, name))


@mcp.tool()
def search_notes(term: str) -> list:
    """Search notes by title."""
    cur = DB.cursor()
    cur.execute(f"SELECT id, title FROM notes WHERE title LIKE '%{term}%'")
    return cur.fetchall()


@mcp.tool()
def notes_by_tag(tag: str, limit: int = 10) -> list:
    """Notes with a tag."""
    sql = "SELECT id, title FROM notes WHERE tag = '" + tag + "'"
    return DB.execute(sql).fetchall()


@mcp.tool()
async def fetch_page(url: str) -> str:
    """Fetch a web page."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        return resp.text


@mcp.tool()
def calculate(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))


@mcp.tool()
def debug_config() -> dict:
    """Show the server configuration."""
    return {"notes_dir": NOTES_DIR, "openai_key": OPENAI_KEY}


if __name__ == "__main__":
    mcp.run()
