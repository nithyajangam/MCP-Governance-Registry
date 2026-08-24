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

## Beginner Deployment: TiDB Cloud + Render

This is the recommended low-cost deployment path for a learning or portfolio environment. TiDB Cloud Starter is MySQL compatible and requires TLS for public connections, while Render can host this Node application as a Web Service.[4] [5] Free Render services can sleep when idle, so expect the first visit after inactivity to take longer.[6]

### A. Create and connect TiDB Cloud

Create a **Starter** instance with its spending limit set to `0`. On the instance page, click **Connect** in the upper-right corner, keep `Public` selected, choose `General`, and generate a password. Keep the password private.

### B. Create the Render Web Service

After pushing this repository to GitHub, open the Render dashboard. Click **+ New** in the upper-right corner, select **Web Service**, click **Connect** beside this repository, and use these exact values.

| Render form field | Value |
| --- | --- |
| Name | `mcp-governance-registry` |
| Branch | `main` |
| Language | `Node` |
| Build Command | `corepack enable && pnpm install --frozen-lockfile && pnpm db:render-migrate && pnpm build` |
| Start Command | `pnpm start` |
| Instance Type | `Free` |
| Root Directory | Leave empty |

### C. Add Render environment variables

In the same Render form, open **Advanced**. Under **Environment Variables**, add each row below. Do not put any secret value in GitHub or in a screenshot.

| Key | Value |
| --- | --- |
| `DATABASE_URL` | The TiDB URL in this shape: `mysql://USERNAME:PASSWORD@HOST:4000/test`. URL-encode special characters in the username or password. |
| `TIDB_ENABLE_SSL` | `true` |
| `NODE_VERSION` | `22` |
| `VITE_PORTABLE_AUTH` | `true` |
| `JWT_SECRET` | A newly generated long random secret. |
| `DASHBOARD_ACCESS_KEY` | A separate long password that you will type into the dashboard after deployment. |
| `ALLOW_DEMO_MCP_TOKENS` | `false` |

The database URL is private. TiDB Cloud Starter requires TLS for a public connection, and the app’s `TIDB_ENABLE_SSL=true` configuration enables it.[5]

Click **Create Web Service** at the bottom of the form. Render opens the service’s **Events** page. Wait until the status is **Live**, then click the displayed `onrender.com` link. On the first visit, enter the value you set for `DASHBOARD_ACCESS_KEY` and click **Open dashboard**.

### D. Verify

After the dashboard opens, visit **Registry**, **Approvals**, and **Audit ledger**. Use the smoke test with your Render URL only after you deliberately configure a real OAuth access-token validator for MCP clients; demo tokens are disabled by default.

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

[4] [TiDB Cloud — Select Your Plan](https://docs.pingcap.com/tidbcloud/select-cluster-tier/)

[5] [TiDB Cloud — Connect to TiDB with node-mysql2](https://docs.pingcap.com/developer/dev-guide-sample-application-nodejs-mysql2/)

[6] [Render — Deploy for Free](https://render.com/docs/free)
