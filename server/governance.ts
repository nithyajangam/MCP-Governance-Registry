import { and, asc, desc, eq } from "drizzle-orm";
import { createHash } from "node:crypto";
import { nanoid } from "nanoid";
import {
  approvalRequests,
  auditEvents,
  mcpServers,
  mcpTools,
  policyDecisions,
  tenants,
  type ApprovalRequest,
  type McpServer,
  type McpTool,
  type Tenant,
} from "../drizzle/schema";
import { getDb } from "./db";

export const MCP_PROTOCOL_VERSION = "2026-07-28";
export const READ_SERVER_ID = "srv_reference_read";
export const WRITE_SERVER_ID = "srv_reference_write";

export type RiskLevel = "read_only" | "sensitive" | "destructive";

export type PolicyInput = {
  tenantId: string;
  principal: string;
  tool: Pick<McpTool, "id" | "name" | "riskLevel" | "requiredScope" | "maxPayloadBytes">;
  grantedScopes: string[];
  arguments: Record<string, unknown>;
};

export type PolicyResult = {
  allow: boolean;
  reason: string;
  requireHumanApproval: boolean;
  redactions: string[];
  maxPayloadBytes: number;
  source: "local" | "opa";
};

const defaultTenantRows = [
  {
    id: "ten_northstar",
    slug: "northstar",
    name: "Northstar Systems",
    region: "us-east-1",
    status: "active" as const,
  },
  {
    id: "ten_harbor",
    slug: "harbor",
    name: "Harbor Operations",
    region: "eu-west-1",
    status: "active" as const,
  },
];

const defaultServerRows = [
  {
    id: READ_SERVER_ID,
    tenantId: "ten_northstar",
    name: "Reference Intelligence",
    namespace: "com.northstar/reference-intelligence",
    description: "Demonstrative read-only MCP tools with deterministic, non-customer output.",
    endpointUrl: "/mcp/read",
    capabilityUrl: "/.well-known/mcp-capabilities?server=read",
    transport: "streamable-http",
    ownerTeam: "Platform Reliability",
    slo: "99.95% monthly availability",
    status: "active" as const,
    validationStatus: "valid" as const,
  },
  {
    id: WRITE_SERVER_ID,
    tenantId: "ten_northstar",
    name: "Reference Change Control",
    namespace: "com.northstar/reference-change-control",
    description: "Simulated write requests gated by policy and time-limited human approval.",
    endpointUrl: "/mcp/write",
    capabilityUrl: "/.well-known/mcp-capabilities?server=write",
    transport: "streamable-http",
    ownerTeam: "Security Engineering",
    slo: "99.90% monthly availability",
    status: "active" as const,
    validationStatus: "valid" as const,
  },
];

const defaultToolRows = [
  {
    id: "tool_project_search",
    serverId: READ_SERVER_ID,
    tenantId: "ten_northstar",
    name: "project.search",
    description: "Searches a safe reference project catalog.",
    riskLevel: "read_only" as const,
    requiredScope: "project:read",
    maxPayloadBytes: 4096,
    inputSchema: JSON.stringify({
      type: "object",
      properties: { query: { type: "string", minLength: 1, maxLength: 120 } },
      required: ["query"],
    }),
  },
  {
    id: "tool_incident_lookup",
    serverId: READ_SERVER_ID,
    tenantId: "ten_northstar",
    name: "incident.lookup",
    description: "Looks up an incident in a deterministic reference feed.",
    riskLevel: "sensitive" as const,
    requiredScope: "incident:read",
    maxPayloadBytes: 2048,
    inputSchema: JSON.stringify({
      type: "object",
      properties: { incidentId: { type: "string", pattern: "^INC-[0-9]{3,5}$" } },
      required: ["incidentId"],
    }),
  },
  {
    id: "tool_metrics_read",
    serverId: READ_SERVER_ID,
    tenantId: "ten_northstar",
    name: "metrics.read",
    description: "Returns synthetic service-health metrics for a bounded time window.",
    riskLevel: "read_only" as const,
    requiredScope: "metrics:read",
    maxPayloadBytes: 4096,
    inputSchema: JSON.stringify({
      type: "object",
      properties: {
        service: { type: "string", maxLength: 60 },
        windowMinutes: { type: "integer", minimum: 5, maximum: 1440 },
      },
      required: ["service"],
    }),
  },
  {
    id: "tool_change_create",
    serverId: WRITE_SERVER_ID,
    tenantId: "ten_northstar",
    name: "change.create",
    description: "Creates a simulated change request after a human approval elevation.",
    riskLevel: "destructive" as const,
    requiredScope: "change:write",
    maxPayloadBytes: 2048,
    inputSchema: JSON.stringify({
      type: "object",
      properties: {
        summary: { type: "string", minLength: 5, maxLength: 140 },
        changeWindow: { type: "string", format: "date-time" },
      },
      required: ["summary", "changeWindow"],
    }),
  },
];

function serialize(value: unknown) {
  return JSON.stringify(value ?? {});
}

export function parseJson<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export function redact(value: unknown): unknown {
  const sensitiveNames = /email|phone|ssn|token|secret|authorization|password/i;
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, sensitiveNames.test(key) ? "[REDACTED]" : redact(item)])
    );
  }
  if (typeof value === "string" && value.length > 500) return `${value.slice(0, 500)}…[TRUNCATED]`;
  return value;
}

export function requestFingerprint(input: {
  tenantId: string;
  principal: string;
  toolName: string;
  arguments: Record<string, unknown>;
}) {
  return createHash("sha256")
    .update(JSON.stringify({ ...input, arguments: redact(input.arguments) }))
    .digest("hex");
}

export function computeAuditHash(input: {
  previousHash: string;
  tenantId: string;
  eventType: string;
  actor: string;
  resource: string;
  outcome: string;
  correlationId: string;
  details: string;
  createdAt: Date;
}) {
  return createHash("sha256")
    .update(`${input.previousHash}|${input.tenantId}|${input.eventType}|${input.actor}|${input.resource}|${input.outcome}|${input.correlationId}|${input.details}|${input.createdAt.toISOString()}`)
    .digest("hex");
}

export function evaluateLocalPolicy(input: PolicyInput): PolicyResult {
  const payloadSize = Buffer.byteLength(JSON.stringify(input.arguments));
  const hasScope = input.grantedScopes.includes(input.tool.requiredScope);
  if (!hasScope) {
    return {
      allow: false,
      reason: `Missing required scope: ${input.tool.requiredScope}`,
      requireHumanApproval: false,
      redactions: ["email", "phone", "ssn", "token", "secret"],
      maxPayloadBytes: input.tool.maxPayloadBytes,
      source: "local",
    };
  }
  if (payloadSize > input.tool.maxPayloadBytes) {
    return {
      allow: false,
      reason: `Payload exceeds the ${input.tool.maxPayloadBytes}-byte policy cap`,
      requireHumanApproval: false,
      redactions: ["email", "phone", "ssn", "token", "secret"],
      maxPayloadBytes: input.tool.maxPayloadBytes,
      source: "local",
    };
  }
  return {
    allow: true,
    reason: input.tool.riskLevel === "destructive" ? "Scope verified; a current human approval is required." : "Scope and payload policy verified.",
    requireHumanApproval: input.tool.riskLevel === "destructive",
    redactions: ["email", "phone", "ssn", "token", "secret"],
    maxPayloadBytes: input.tool.maxPayloadBytes,
    source: "local",
  };
}

export async function evaluatePolicy(input: PolicyInput): Promise<PolicyResult> {
  const fallback = evaluateLocalPolicy(input);
  if (!process.env.OPA_URL) return fallback;
  try {
    const response = await fetch(process.env.OPA_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: serialize({ input: { ...input, arguments: redact(input.arguments) } }),
      signal: AbortSignal.timeout(2500),
    });
    if (!response.ok) return { ...fallback, reason: `${fallback.reason} OPA was unavailable; the local fail-closed policy applied.` };
    const body = (await response.json()) as { result?: Partial<PolicyResult> };
    const result = body.result;
    if (typeof result?.allow !== "boolean") return fallback;
    return {
      allow: result.allow,
      reason: result.reason ?? "OPA policy decision",
      requireHumanApproval: result.requireHumanApproval ?? fallback.requireHumanApproval,
      redactions: result.redactions ?? fallback.redactions,
      maxPayloadBytes: result.maxPayloadBytes ?? fallback.maxPayloadBytes,
      source: "opa",
    };
  } catch {
    return { ...fallback, reason: `${fallback.reason} OPA was unavailable; the local fail-closed policy applied.` };
  }
}

export async function ensureSeedData() {
  const db = await getDb();
  if (!db) return;
  const existing = await db.select({ id: tenants.id }).from(tenants).limit(1);
  if (existing.length) return;

  await db.insert(tenants).values(defaultTenantRows);
  await db.insert(mcpServers).values(
    defaultServerRows.map(server => ({ ...server, lastValidatedAt: new Date() }))
  );
  await db.insert(mcpTools).values(defaultToolRows);

  const expiresAt = new Date(Date.now() + 12 * 60 * 1000);
  await db.insert(approvalRequests).values({
    id: "apr_demo_pending",
    tenantId: "ten_northstar",
    serverId: WRITE_SERVER_ID,
    toolId: "tool_change_create",
    requestHash: requestFingerprint({
      tenantId: "ten_northstar",
      principal: "demo:alex",
      toolName: "change.create",
      arguments: { summary: "Rotate the reference service certificate", changeWindow: "2026-08-25T01:00:00Z" },
    }),
    requestedBy: "demo:alex",
    argumentsRedacted: serialize({ summary: "Rotate the reference service certificate", changeWindow: "2026-08-25T01:00:00Z" }),
    status: "pending",
    expiresAt,
  });
  await appendAudit({
    tenantId: "ten_northstar",
    eventType: "approval.requested",
    actor: "demo:alex",
    resource: "change.create",
    outcome: "pending",
    correlationId: "seed-approval",
    details: { source: "seed", approvalId: "apr_demo_pending" },
  });
}

export async function appendAudit(input: {
  tenantId: string;
  eventType: string;
  actor: string;
  resource: string;
  outcome: string;
  correlationId: string;
  details: unknown;
}) {
  const db = await getDb();
  if (!db) return;
  const previous = await db
    .select({ eventHash: auditEvents.eventHash })
    .from(auditEvents)
    .where(eq(auditEvents.tenantId, input.tenantId))
    .orderBy(desc(auditEvents.createdAt))
    .limit(1);
  const previousHash = previous[0]?.eventHash ?? "GENESIS";
  const createdAt = new Date();
  const details = redact(input.details);
  const serializedDetails = serialize(details);
  const eventHash = computeAuditHash({
    previousHash,
    tenantId: input.tenantId,
    eventType: input.eventType,
    actor: input.actor,
    resource: input.resource,
    outcome: input.outcome,
    correlationId: input.correlationId,
    details: serializedDetails,
    createdAt,
  });
  await db.insert(auditEvents).values({
    id: `aud_${nanoid(14)}`,
    tenantId: input.tenantId,
    eventType: input.eventType,
    actor: input.actor,
    resource: input.resource,
    outcome: input.outcome,
    correlationId: input.correlationId,
    details: serializedDetails,
    previousHash,
    eventHash,
    createdAt,
  });
}

export async function logPolicyDecision(input: {
  tenantId: string;
  requestHash: string;
  principal: string;
  toolName: string;
  requiredScope: string;
  grantedScopes: string[];
  result: PolicyResult;
  correlationId: string;
}) {
  const db = await getDb();
  if (!db) return;
  await db.insert(policyDecisions).values({
    id: `pol_${nanoid(14)}`,
    tenantId: input.tenantId,
    requestHash: input.requestHash,
    principal: input.principal,
    toolName: input.toolName,
    requiredScope: input.requiredScope,
    grantedScopes: serialize(input.grantedScopes),
    decision: input.result.allow ? "allow" : "deny",
    reason: input.result.reason,
    source: input.result.source,
    requireHumanApproval: input.result.requireHumanApproval,
    redactions: serialize(input.result.redactions),
    correlationId: input.correlationId,
  });
  await appendAudit({
    tenantId: input.tenantId,
    eventType: "policy.evaluated",
    actor: input.principal,
    resource: input.toolName,
    outcome: input.result.allow ? "allow" : "deny",
    correlationId: input.correlationId,
    details: { requiredScope: input.requiredScope, grantedScopes: input.grantedScopes, reason: input.result.reason, source: input.result.source },
  });
}

export async function getTenantBySlug(slug: string): Promise<Tenant | undefined> {
  await ensureSeedData();
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(tenants).where(eq(tenants.slug, slug)).limit(1);
  return result[0];
}

export async function getServer(serverId: string): Promise<McpServer | undefined> {
  await ensureSeedData();
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(mcpServers).where(eq(mcpServers.id, serverId)).limit(1);
  return result[0];
}

export async function getTool(serverId: string, name: string): Promise<McpTool | undefined> {
  await ensureSeedData();
  const db = await getDb();
  if (!db) return undefined;
  const result = await db
    .select()
    .from(mcpTools)
    .where(and(eq(mcpTools.serverId, serverId), eq(mcpTools.name, name), eq(mcpTools.isEnabled, true)))
    .limit(1);
  return result[0];
}

export async function listServerTools(serverId: string) {
  await ensureSeedData();
  const db = await getDb();
  if (!db) return [];
  return db.select().from(mcpTools).where(and(eq(mcpTools.serverId, serverId), eq(mcpTools.isEnabled, true)));
}

export async function createApproval(input: {
  tenantId: string;
  serverId: string;
  toolId: string;
  requestHash: string;
  requestedBy: string;
  arguments: Record<string, unknown>;
  correlationId: string;
}) {
  const db = await getDb();
  if (!db) throw new Error("Database is not available");
  const duplicate = await db
    .select()
    .from(approvalRequests)
    .where(and(eq(approvalRequests.tenantId, input.tenantId), eq(approvalRequests.requestHash, input.requestHash), eq(approvalRequests.status, "pending")))
    .limit(1);
  if (duplicate[0]) return duplicate[0];
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  const approval = {
    id: `apr_${nanoid(14)}`,
    tenantId: input.tenantId,
    serverId: input.serverId,
    toolId: input.toolId,
    requestHash: input.requestHash,
    requestedBy: input.requestedBy,
    argumentsRedacted: serialize(redact(input.arguments)),
    status: "pending" as const,
    expiresAt,
  };
  await db.insert(approvalRequests).values(approval);
  await appendAudit({
    tenantId: input.tenantId,
    eventType: "approval.requested",
    actor: input.requestedBy,
    resource: input.toolId,
    outcome: "pending",
    correlationId: input.correlationId,
    details: { approvalId: approval.id, expiresAt, arguments: input.arguments },
  });
  return approval;
}

export async function findActiveApproval(tenantId: string, requestHash: string) {
  const db = await getDb();
  if (!db) return undefined;
  const records = await db
    .select()
    .from(approvalRequests)
    .where(and(eq(approvalRequests.tenantId, tenantId), eq(approvalRequests.requestHash, requestHash), eq(approvalRequests.status, "approved")))
    .orderBy(desc(approvalRequests.decidedAt))
    .limit(1);
  const record = records[0];
  if (!record || record.expiresAt.getTime() < Date.now() || record.consumedAt) return undefined;
  return record;
}

export async function consumeApproval(id: string, correlationId: string) {
  const db = await getDb();
  if (!db) return;
  const current = await db.select().from(approvalRequests).where(eq(approvalRequests.id, id)).limit(1);
  const approval = current[0];
  if (!approval || approval.consumedAt || approval.expiresAt.getTime() < Date.now()) return;
  await db.update(approvalRequests).set({ consumedAt: new Date(), updatedAt: new Date() }).where(eq(approvalRequests.id, id));
  await appendAudit({
    tenantId: approval.tenantId,
    eventType: "approval.consumed",
    actor: approval.requestedBy,
    resource: approval.toolId,
    outcome: "elevated",
    correlationId,
    details: { approvalId: approval.id },
  });
}

export async function decideApproval(input: { id: string; reviewer: string; decision: "approved" | "rejected"; note?: string }) {
  const db = await getDb();
  if (!db) throw new Error("Database is not available");
  const rows = await db.select().from(approvalRequests).where(eq(approvalRequests.id, input.id)).limit(1);
  const approval = rows[0];
  if (!approval) throw new Error("Approval request not found");
  if (approval.status !== "pending") throw new Error("Only pending requests can be decided");
  if (approval.expiresAt.getTime() < Date.now()) {
    await db.update(approvalRequests).set({ status: "expired", updatedAt: new Date() }).where(eq(approvalRequests.id, input.id));
    throw new Error("This approval request has expired");
  }
  const now = new Date();
  await db
    .update(approvalRequests)
    .set({ status: input.decision, reviewer: input.reviewer, decisionNote: input.note ?? null, decidedAt: now, updatedAt: now })
    .where(eq(approvalRequests.id, input.id));
  await appendAudit({
    tenantId: approval.tenantId,
    eventType: `approval.${input.decision}`,
    actor: input.reviewer,
    resource: approval.toolId,
    outcome: input.decision,
    correlationId: `approval-${approval.id}`,
    details: { approvalId: approval.id, note: input.note },
  });
  return { ...approval, status: input.decision, reviewer: input.reviewer, decisionNote: input.note ?? null, decidedAt: now };
}

export async function expireApprovals() {
  const db = await getDb();
  if (!db) return 0;
  const pending = await db.select().from(approvalRequests).where(eq(approvalRequests.status, "pending"));
  const stale = pending.filter(item => item.expiresAt.getTime() < Date.now());
  for (const item of stale) {
    await db.update(approvalRequests).set({ status: "expired", updatedAt: new Date() }).where(eq(approvalRequests.id, item.id));
    await appendAudit({
      tenantId: item.tenantId,
      eventType: "approval.expired",
      actor: "system:expiry",
      resource: item.toolId,
      outcome: "expired",
      correlationId: `approval-${item.id}`,
      details: { approvalId: item.id },
    });
  }
  return stale.length;
}

export async function governanceSnapshot(input?: { tenantId?: string; search?: string }) {
  await ensureSeedData();
  await expireApprovals();
  const db = await getDb();
  if (!db) return { tenants: [], servers: [], tools: [], approvals: [], events: [], decisions: [] };
  const tenantRows = input?.tenantId ? await db.select().from(tenants).where(eq(tenants.id, input.tenantId)) : await db.select().from(tenants);
  const tenantIds = new Set(tenantRows.map(item => item.id));
  const [servers, tools, approvals, events, decisions] = await Promise.all([
    db.select().from(mcpServers),
    db.select().from(mcpTools),
    db.select().from(approvalRequests).orderBy(desc(approvalRequests.createdAt)),
    db.select().from(auditEvents).orderBy(desc(auditEvents.createdAt)),
    db.select().from(policyDecisions).orderBy(desc(policyDecisions.createdAt)),
  ]);
  const search = input?.search?.toLowerCase().trim();
  const matches = (value: string) => !search || value.toLowerCase().includes(search);
  return {
    tenants: tenantRows,
    servers: servers.filter(item => tenantIds.has(item.tenantId) && matches(`${item.name} ${item.namespace} ${item.ownerTeam}`)),
    tools: tools.filter(item => tenantIds.has(item.tenantId) && matches(`${item.name} ${item.description}`)),
    approvals: approvals.filter(item => tenantIds.has(item.tenantId) && matches(`${item.requestedBy} ${item.status} ${item.toolId}`)),
    events: events.filter(item => tenantIds.has(item.tenantId) && matches(`${item.eventType} ${item.actor} ${item.resource} ${item.outcome}`)).slice(0, 100),
    decisions: decisions.filter(item => tenantIds.has(item.tenantId) && matches(`${item.toolName} ${item.principal} ${item.decision}`)).slice(0, 100),
  };
}

export async function verifyAuditIntegrity(tenantId?: string) {
  const db = await getDb();
  if (!db) return { valid: false, checked: 0, issues: ["Database is not available"] };
  const rows = await db.select().from(auditEvents).orderBy(asc(auditEvents.createdAt));
  const previousByTenant = new Map<string, string>();
  const issues: string[] = [];
  const filteredRows = rows.filter(item => !tenantId || item.tenantId === tenantId);
  for (const event of filteredRows) {
    const expectedPrevious = previousByTenant.get(event.tenantId) ?? "GENESIS";
    if (event.previousHash !== expectedPrevious) {
      issues.push(`Audit chain discontinuity at ${event.id}`);
      previousByTenant.set(event.tenantId, event.eventHash);
      continue;
    }
    const expectedHash = computeAuditHash({
      previousHash: event.previousHash,
      tenantId: event.tenantId,
      eventType: event.eventType,
      actor: event.actor,
      resource: event.resource,
      outcome: event.outcome,
      correlationId: event.correlationId,
      details: event.details,
      createdAt: event.createdAt,
    });
    if (event.eventHash !== expectedHash) issues.push(`Audit hash mismatch at ${event.id}`);
    previousByTenant.set(event.tenantId, event.eventHash);
  }
  return { valid: issues.length === 0, checked: filteredRows.length, issues };
}

export function buildCapabilityManifest(server: McpServer, tools: McpTool[], baseUrl: string) {
  return {
    version: "1.0",
    generatedAt: new Date().toISOString(),
    server: {
      id: server.id,
      name: server.name,
      namespace: server.namespace,
      description: server.description,
      transport: "streamable-http",
      endpoint: `${baseUrl}${server.endpointUrl}`,
      owner: server.ownerTeam,
      slo: server.slo,
    },
    authorization: {
      protectedResourceMetadata: `${baseUrl}/.well-known/oauth-protected-resource`,
      scopes: Array.from(new Set(tools.map(tool => tool.requiredScope))),
      humanApproval: tools.some(tool => tool.riskLevel === "destructive"),
    },
    tools: tools.map(tool => ({
      name: tool.name,
      description: tool.description,
      inputSchema: parseJson(tool.inputSchema, {}),
      risk: tool.riskLevel,
      requiredScope: tool.requiredScope,
      maxPayloadBytes: tool.maxPayloadBytes,
    })),
  };
}

export function simulatedToolOutput(name: string, args: Record<string, unknown>) {
  switch (name) {
    case "project.search":
      return { query: String(args.query ?? ""), results: [{ id: "REF-102", name: "Telemetry reliability program", status: "active" }], source: "reference-fixture" };
    case "incident.lookup":
      return { incidentId: String(args.incidentId ?? ""), severity: "SEV-3", status: "resolved", summary: "Reference incident with synthetic metadata only." };
    case "metrics.read":
      return { service: String(args.service ?? "reference-service"), windowMinutes: Number(args.windowMinutes ?? 60), availability: 99.98, p95LatencyMs: 132, source: "synthetic" };
    case "change.create":
      return { changeId: `REFCHG-${nanoid(7).toUpperCase()}`, state: "simulated", message: "The reference service recorded a simulated change; no external system was changed." };
    default:
      return { message: "Reference tool completed." };
  }
}
