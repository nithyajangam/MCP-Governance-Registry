# Aegis MCP Governance Registry

**Aegis** is a production-oriented reference implementation for governing tenant-aware MCP tools. It combines two deliberately bounded Streamable HTTP reference endpoints with a secure registry dashboard, policy outcomes, a short-lived human-approval flow, and a tamper-evident audit ledger. It does not connect to or operate customer systems.

## What You Can Demonstrate

| Capability | Implementation in this repository |
| --- | --- |
| Reference MCP endpoints | `POST /mcp/read` hosts safe deterministic tools and `POST /mcp/write` hosts a simulated destructive tool. Both expect modern MCP request metadata headers. |
| Capability discovery | Each endpoint has internal capability metadata at `/.well-known/mcp-capabilities?server=read` or `?server=write`. |
| Tenant and scope enforcement | A bearer token adapter resolves a tenant, principal, and scopes before every MCP tool call. |
| Policy gate | The local policy evaluator enforces scope and payload caps. Setting `OPA_URL` enables an OPA-compatible decision request while retaining a safe local fallback. |
| Human approval | `change.create` generates a queue item, expires after fifteen minutes, and consumes an approved elevation once. |
| Auditability | Policy, approval, and execution activities are redacted, append-only through the application surface, tenant-isolated, and hash-chained. |
| Operator console | Authenticated users can inspect registry services, tenants, policies, approvals, and the audit ledger. Administrators may validate and enable/disable reference services and make approval decisions. |

The implementation aligns its transport and resource discovery shape with the MCP Streamable HTTP and authorization specifications.[1] [2] Its private registry metadata is an internal extension; it is not presented as the public MCP Registry `server.json` format.[3]

## Local Development

You need Node.js 22+ and a MySQL-compatible database. Copy the environment values required by your host, install dependencies, and launch the app.

```bash
pnpm install
pnpm drizzle-kit generate
pnpm db:push
pnpm dev
```

When the service starts, visit the dashboard URL and sign in. Seed records are created lazily the first time a governance endpoint or dashboard query accesses the registry. The reference interface uses only deterministic seed data, not real customer systems.

## MCP Quick Start

During local development, demo tokens take the exact form below. They are a development adapter, not an OAuth substitute.

```text
demo|northstar|demo:alice|project:read,incident:read,metrics:read,change:write
```

To confirm the endpoint contract, run the included smoke test after the service starts.

```bash
pnpm exec node scripts/mcp-smoke.mjs
```

To issue a direct JSON-RPC tool call:

```bash
curl -sS -X POST http://localhost:3000/mcp/read \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer demo|northstar|demo:alice|project:read' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: project.search' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"project.search","arguments":{"query":"telemetry"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}'
```

The write endpoint follows the same contract at `/mcp/write`, but `change.create` will first create an approval record. Approve it from the Aegis console, then submit the **identical** call again before the elevation expires.

## Antigravity Deployment Steps

The project is an ordinary Node/TypeScript application and intentionally has no custom Dockerfile, worker, or OS-level dependency. Give Antigravity the repository and configure its standard Node deployment as follows.

| Antigravity setting | Value |
| --- | --- |
| Install command | `pnpm install --frozen-lockfile` |
| Build command | `pnpm build` |
| Run command | `pnpm start` |
| Node version | 22 or newer |
| Database | Managed MySQL or TiDB-compatible connection via `DATABASE_URL` |
| Public routes | `/`, `/api/trpc/*`, `/mcp/read`, `/mcp/write`, `/.well-known/*` |

Configure the following environment values in the deployment settings. Never commit them to source control.

| Variable | Purpose | Production requirement |
| --- | --- | --- |
| `DATABASE_URL` | MySQL/TiDB database connection. | Required. |
| `JWT_SECRET` | Session signing secret. | Required. Use a high-entropy secret. |
| `MCP_ALLOWED_ORIGINS` | Comma-delimited origins accepted by MCP HTTP routes. | Required for browser-originated MCP requests. |
| `MCP_AUTHORIZATION_SERVER` | Authorization server issuer published in protected-resource metadata. | Required when using real OAuth 2.1. |
| `OPA_URL` | Optional OPA policy decision endpoint. | Recommended for a production policy bundle. |
| `ALLOW_DEMO_MCP_TOKENS` | Enables the local `demo|...` bearer adapter. | Keep unset or `false` in production. |
| OAuth application variables | Your host's session/login configuration. | Required for the operator dashboard. |

After deployment, set `MCP_BASE_URL=https://your-domain.example` and rerun the smoke test. Configure the platform's HTTPS TLS termination, route all `/.well-known/*` and `/mcp/*` paths without body rewriting, and allow `text/event-stream` at the proxy if you later introduce per-request streaming responses.

## Verification and Load Scaffold

Run the application tests before every release.

```bash
pnpm check
pnpm test
pnpm exec node scripts/mcp-smoke.mjs
```

The load scaffold sends independent JSON-RPC requests, which is appropriate for validating a stateless Streamable HTTP deployment behind a load balancer. Begin with 100 requests and 20 concurrent clients, then repeat after scaling the deployment to a second replica and compare p50/p95 latency and error rate.

```bash
CONCURRENCY=20 REQUESTS=100 pnpm exec node scripts/load-test.mjs
```

For an official protocol conformance run, install and execute the current official MCP conformance suite separately against both `/mcp/read` and `/mcp/write`. Retain its versioned output as release evidence; this repository's smoke script is intentionally narrow and does not claim to replace that suite.

## Extending the Platform

Add a new safe reference tool by inserting its registry record and schema into `defaultToolRows` in `server/governance.ts`, extending `simulatedToolOutput`, then adding a test and rerunning the smoke script. A real integration should live behind a least-privilege service identity and return redacted results only.

Replace the demo bearer adapter in `server/mcp.ts` with JWT validation against your configured issuer or perform validation at an API gateway. The MCP authorization specification expects HTTP-based implementations that support authorization to act as OAuth resource servers and publish protected-resource metadata.[2] For production audit retention, export the hash-chained events to immutable object storage or a SIEM and restrict database credentials so the service principal has no update/delete permission on `auditEvents`.

## References

[1] [Model Context Protocol — Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)

[2] [Model Context Protocol — Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

[3] [Model Context Protocol — Registry overview](https://modelcontextprotocol.io/registry/about)
