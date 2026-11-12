// The same server written safely. mcp-audit must report nothing here.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import pg from "pg";

const execFileAsync = promisify(execFile);
const db = new pg.Pool();
const WORKSPACE = path.resolve(process.env.WORKSPACE ?? "/workspace");
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const ALLOWED_HOSTS = new Set(["api.github.com", "registry.npmjs.org"]);

function resolveInWorkspace(file: string): string {
  const target = path.resolve(WORKSPACE, file);
  if (target !== WORKSPACE && !target.startsWith(WORKSPACE + path.sep)) {
    throw new Error("path outside workspace");
  }
  return target;
}

const server = new McpServer({ name: "devtools", version: "1.0.0" });

server.tool("run_tests", "Run the test suite for a package", { pkg: z.string() }, async ({ pkg }) => {
  // regex literal with quotes and slashes must not confuse the scanner: /["'`]/
  if (!/^[a-z0-9@/._-]+$/.test(pkg)) throw new Error("bad package name");
  const { stdout } = await execFileAsync("npm", ["test", "--workspace", pkg]);
  return { content: [{ type: "text", text: stdout }] };
});

server.tool("read_file", "Read a file from the workspace", { file: z.string() }, async ({ file }) => {
  const text = await fs.readFile(resolveInWorkspace(file), "utf8");
  return { content: [{ type: "text", text }] };
});

server.registerTool(
  "delete_file",
  {
    description: "Delete a file",
    inputSchema: { file: z.string() },
    annotations: { destructiveHint: true, readOnlyHint: false },
  },
  async ({ file }) => {
    await fs.rm(resolveInWorkspace(file), { force: true });
    return { content: [{ type: "text", text: "deleted" }] };
  },
);

server.tool("find_user", "Look up a user by email", { email: z.string() }, async ({ email }) => {
  const result = await db.query("SELECT id, name FROM users WHERE email = $1", [email]);
  const label = `Found ${result.rowCount} user(s) for ${email}`;
  return { content: [{ type: "text", text: label }] };
});

server.tool("repo_info", "GitHub repo metadata", { repo: z.string() }, async ({ repo }) => {
  const res = await fetch(`https://api.github.com/repos/${encodeURIComponent(repo)}`, {
    headers: { Authorization: `Bearer ${GITHUB_TOKEN}` },
  });
  return { content: [{ type: "text", text: JSON.stringify(await res.json()) }] };
});

server.tool("fetch_allowed", "Fetch an allowlisted URL", { url: z.string() }, async ({ url }) => {
  const u = new URL(url);
  if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname)) throw new Error("host not allowed");
  const res = await fetch(u);
  return { content: [{ type: "text", text: JSON.stringify(await res.json()) }] };
});

server.tool("whoami", "Is a GitHub token configured?", {}, async () => {
  return { content: [{ type: "text", text: `token configured: ${Boolean(GITHUB_TOKEN)}` }] };
});

// Not a tool: a fixed maintenance command.
export async function rotateLogs(): Promise<void> {
  await execFileAsync("logrotate", ["/etc/logrotate.conf"]);
}

await server.connect(new StdioServerTransport());
