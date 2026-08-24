import { boolean, index, int, mysqlEnum, mysqlTable, text, timestamp, uniqueIndex, varchar } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 * Extend this file with additional tables as your product grows.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = mysqlTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: int("id").autoincrement().primaryKey(),
  /** Manus OAuth identifier (openId) returned from the OAuth callback. Unique per user. */
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

export const tenants = mysqlTable("tenants", {
  id: varchar("id", { length: 64 }).primaryKey(),
  slug: varchar("slug", { length: 64 }).notNull().unique(),
  name: varchar("name", { length: 160 }).notNull(),
  region: varchar("region", { length: 64 }).notNull(),
  status: mysqlEnum("status", ["active", "suspended"]).notNull().default("active"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export const mcpServers = mysqlTable("mcpServers", {
  id: varchar("id", { length: 64 }).primaryKey(),
  tenantId: varchar("tenantId", { length: 64 }).notNull(),
  name: varchar("name", { length: 160 }).notNull(),
  namespace: varchar("namespace", { length: 220 }).notNull(),
  description: text("description").notNull(),
  endpointUrl: varchar("endpointUrl", { length: 512 }).notNull(),
  capabilityUrl: varchar("capabilityUrl", { length: 512 }).notNull(),
  transport: varchar("transport", { length: 64 }).notNull().default("streamable-http"),
  ownerTeam: varchar("ownerTeam", { length: 120 }).notNull(),
  slo: varchar("slo", { length: 120 }).notNull(),
  status: mysqlEnum("status", ["active", "disabled", "needs_review"]).notNull().default("active"),
  validationStatus: mysqlEnum("validationStatus", ["valid", "warning", "invalid"]).notNull().default("valid"),
  lastValidatedAt: timestamp("lastValidatedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => [index("mcpServers_tenant_idx").on(table.tenantId), uniqueIndex("mcpServers_namespace_idx").on(table.namespace)]);

export const mcpTools = mysqlTable("mcpTools", {
  id: varchar("id", { length: 64 }).primaryKey(),
  serverId: varchar("serverId", { length: 64 }).notNull(),
  tenantId: varchar("tenantId", { length: 64 }).notNull(),
  name: varchar("name", { length: 160 }).notNull(),
  description: text("description").notNull(),
  riskLevel: mysqlEnum("riskLevel", ["read_only", "sensitive", "destructive"]).notNull(),
  requiredScope: varchar("requiredScope", { length: 160 }).notNull(),
  maxPayloadBytes: int("maxPayloadBytes").notNull().default(4096),
  inputSchema: text("inputSchema").notNull(),
  isEnabled: boolean("isEnabled").notNull().default(true),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => [index("mcpTools_server_idx").on(table.serverId), index("mcpTools_tenant_idx").on(table.tenantId), uniqueIndex("mcpTools_server_name_idx").on(table.serverId, table.name)]);

export const approvalRequests = mysqlTable("approvalRequests", {
  id: varchar("id", { length: 64 }).primaryKey(),
  tenantId: varchar("tenantId", { length: 64 }).notNull(),
  serverId: varchar("serverId", { length: 64 }).notNull(),
  toolId: varchar("toolId", { length: 64 }).notNull(),
  requestHash: varchar("requestHash", { length: 64 }).notNull(),
  requestedBy: varchar("requestedBy", { length: 160 }).notNull(),
  argumentsRedacted: text("argumentsRedacted").notNull(),
  status: mysqlEnum("status", ["pending", "approved", "rejected", "expired"]).notNull().default("pending"),
  reviewer: varchar("reviewer", { length: 160 }),
  decisionNote: text("decisionNote"),
  expiresAt: timestamp("expiresAt").notNull(),
  decidedAt: timestamp("decidedAt"),
  consumedAt: timestamp("consumedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => [index("approvalRequests_tenant_idx").on(table.tenantId), index("approvalRequests_status_idx").on(table.status), index("approvalRequests_hash_idx").on(table.requestHash)]);

export const policyDecisions = mysqlTable("policyDecisions", {
  id: varchar("id", { length: 64 }).primaryKey(),
  tenantId: varchar("tenantId", { length: 64 }).notNull(),
  requestHash: varchar("requestHash", { length: 64 }).notNull(),
  principal: varchar("principal", { length: 160 }).notNull(),
  toolName: varchar("toolName", { length: 160 }).notNull(),
  requiredScope: varchar("requiredScope", { length: 160 }).notNull(),
  grantedScopes: text("grantedScopes").notNull(),
  decision: mysqlEnum("decision", ["allow", "deny"]).notNull(),
  reason: text("reason").notNull(),
  source: mysqlEnum("source", ["local", "opa"]).notNull().default("local"),
  requireHumanApproval: boolean("requireHumanApproval").notNull().default(false),
  redactions: text("redactions").notNull(),
  correlationId: varchar("correlationId", { length: 96 }).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => [index("policyDecisions_tenant_idx").on(table.tenantId), index("policyDecisions_correlation_idx").on(table.correlationId)]);

export const auditEvents = mysqlTable("auditEvents", {
  id: varchar("id", { length: 64 }).primaryKey(),
  tenantId: varchar("tenantId", { length: 64 }).notNull(),
  eventType: varchar("eventType", { length: 120 }).notNull(),
  actor: varchar("actor", { length: 160 }).notNull(),
  resource: varchar("resource", { length: 160 }).notNull(),
  outcome: varchar("outcome", { length: 64 }).notNull(),
  correlationId: varchar("correlationId", { length: 96 }).notNull(),
  details: text("details").notNull(),
  previousHash: varchar("previousHash", { length: 64 }).notNull(),
  eventHash: varchar("eventHash", { length: 64 }).notNull(),
  createdAt: timestamp("createdAt").notNull(),
}, table => [index("auditEvents_tenant_created_idx").on(table.tenantId, table.createdAt), uniqueIndex("auditEvents_hash_idx").on(table.eventHash)]);

export type Tenant = typeof tenants.$inferSelect;
export type McpServer = typeof mcpServers.$inferSelect;
export type McpTool = typeof mcpTools.$inferSelect;
export type ApprovalRequest = typeof approvalRequests.$inferSelect;
export type AuditEvent = typeof auditEvents.$inferSelect;
