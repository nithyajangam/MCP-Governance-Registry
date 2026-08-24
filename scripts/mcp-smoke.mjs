/**
 * Minimal endpoint conformance scaffold. It validates capability metadata,
 * tools/list and a scoped tools/call request against the reference server.
 */
const baseUrl = (process.env.MCP_BASE_URL || "http://localhost:3000").replace(/\/$/, "");
const token = process.env.MCP_BEARER_TOKEN || "demo|northstar|demo:alice|project:read,metrics:read,incident:read";
const protocolVersion = "2026-07-28";

async function request(path, init = {}) {
  const response = await fetch(`${baseUrl}${path}`, init);
  const body = await response.json();
  if (!response.ok) throw new Error(`${init.method || "GET"} ${path} returned ${response.status}: ${JSON.stringify(body)}`);
  return body;
}

const manifest = await request("/.well-known/mcp-capabilities");
if (manifest.server?.transport !== "streamable-http") throw new Error("Capability manifest does not declare streamable-http transport");
if (!Array.isArray(manifest.tools) || !manifest.tools.length) throw new Error("Capability manifest does not list reference tools");

const headers = {
  "content-type": "application/json",
  "authorization": `Bearer ${token}`,
  "mcp-protocol-version": protocolVersion,
};
const metadata = { "io.modelcontextprotocol/protocolVersion": protocolVersion };

const list = await request("/mcp/read", {
  method: "POST",
  headers: { ...headers, "mcp-method": "tools/list" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: metadata } }),
});
if (!Array.isArray(list.result?.tools) || !list.result.tools.some(tool => tool.name === "project.search")) throw new Error("tools/list did not return project.search");

const call = await request("/mcp/read", {
  method: "POST",
  headers: { ...headers, "mcp-method": "tools/call", "mcp-name": "project.search" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "project.search", arguments: { query: "telemetry" }, _meta: metadata } }),
});
if (call.result?.isError || !call.result?.structuredContent?.results) throw new Error("Scoped project.search call did not return a structured result");

console.log(JSON.stringify({ status: "passed", transport: manifest.server.transport, tools: list.result.tools.length, result: call.result.structuredContent }, null, 2));
