// A deliberately insecure MCP server (TypeScript SDK). Every tool here has a known bug.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec, spawn } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import pg from "pg";

const execAsync = promisify(exec);
const db = new pg.Pool();
const WORKSPACE = process.env.WORKSPACE ?? "/workspace";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

const server = new McpServer({ name: "devtools", version: "1.0.0" });

server.tool("run_tests", "Run the test suite for a package", { pkg: z.string() }, async ({ pkg }) => {
  const { stdout } = await execAsync(`npm test --workspace ${pkg}`);
  return { content: [{ type: "text", text: stdout }] };
});

server.registerTool(
  "run_program",
  { description: "Run a program", inputSchema: { program: z.string(), args: z.array(z.string()) } },
  async ({ program, args }) => {
    const child = spawn(program, args);
    return { content: [{ type: "text", text: `started ${child.pid}` }] };
  },
);

server.tool("read_file", "Read a file from the workspace", { file: z.string() }, async ({ file }) => {
  const full = path.join(WORKSPACE, file);
  const text = await fs.readFile(full, "utf8");
  return { content: [{ type: "text", text }] };
});

server.tool("delete_file", "Delete a file", { file: z.string() }, async ({ file }) => {
  await fs.rm(path.join(WORKSPACE, file), { force: true });
  return { content: [{ type: "text", text: "deleted" }] };
});

server.tool("find_user", "Look up a user by email", { email: z.string() }, async ({ email }) => {
  const result = await db.query(`SELECT id, name FROM users WHERE email = '${email}'`);
  return { content: [{ type: "text", text: JSON.stringify(result.rows) }] };
});

server.tool("fetch_url", "Fetch a URL and return the page", { url: z.string() }, async ({ url }) => {
  const res = await fetch(url);
  const body = await res.text();
  return { content: [{ type: "text", text: body }] };
});

server.tool("whoami", "Show which GitHub token is configured", {}, async () => {
  return { content: [{ type: "text", text: `token: ${GITHUB_TOKEN}` }] };
});

await server.connect(new StdioServerTransport());
