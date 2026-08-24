import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { adminProcedure, protectedProcedure, router } from "./_core/trpc";
import { eq } from "drizzle-orm";
import { mcpServers, tenants } from "../drizzle/schema";
import { getDb } from "./db";
import { appendAudit, decideApproval, ensureSeedData, governanceSnapshot, verifyAuditIntegrity } from "./governance";

export const governanceRouter = router({
  snapshot: protectedProcedure
    .input(z.object({ tenantId: z.string().max(64).optional(), search: z.string().max(120).optional() }).optional())
    .query(async ({ input }) => governanceSnapshot(input)),

  bootstrapDemo: adminProcedure.mutation(async () => {
    await ensureSeedData();
    return { success: true } as const;
  }),

  setTenantStatus: adminProcedure
    .input(z.object({ id: z.string().min(1).max(64), status: z.enum(["active", "suspended"]) }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database is not available" });
      const records = await db.select().from(tenants).where(eq(tenants.id, input.id)).limit(1);
      const tenant = records[0];
      if (!tenant) throw new TRPCError({ code: "NOT_FOUND", message: "Tenant was not found" });
      await db.update(tenants).set({ status: input.status, updatedAt: new Date() }).where(eq(tenants.id, input.id));
      await appendAudit({ tenantId: tenant.id, eventType: "tenant.status_changed", actor: ctx.user.email ?? ctx.user.name ?? `user:${ctx.user.id}`, resource: tenant.slug, outcome: input.status, correlationId: `tenant-${tenant.id}`, details: { from: tenant.status, to: input.status } });
      return { ...tenant, status: input.status };
    }),

  setServerStatus: adminProcedure
    .input(z.object({ id: z.string().min(1).max(64), status: z.enum(["active", "disabled", "needs_review"]) }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database is not available" });
      const records = await db.select().from(mcpServers).where(eq(mcpServers.id, input.id)).limit(1);
      const server = records[0];
      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "Registry server was not found" });
      await db.update(mcpServers).set({ status: input.status, updatedAt: new Date() }).where(eq(mcpServers.id, input.id));
      await appendAudit({ tenantId: server.tenantId, eventType: "registry.status_changed", actor: ctx.user.email ?? ctx.user.name ?? `user:${ctx.user.id}`, resource: server.namespace, outcome: input.status, correlationId: `registry-${server.id}`, details: { from: server.status, to: input.status } });
      return { ...server, status: input.status };
    }),

  validateServer: adminProcedure
    .input(z.object({ id: z.string().min(1).max(64) }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database is not available" });
      const records = await db.select().from(mcpServers).where(eq(mcpServers.id, input.id)).limit(1);
      const server = records[0];
      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "Registry server was not found" });
      const valid = server.transport === "streamable-http" && Boolean(server.endpointUrl) && Boolean(server.capabilityUrl) && Boolean(server.ownerTeam);
      const validationStatus = valid ? "valid" : "warning";
      const now = new Date();
      await db.update(mcpServers).set({ validationStatus, lastValidatedAt: now, updatedAt: now }).where(eq(mcpServers.id, input.id));
      await appendAudit({ tenantId: server.tenantId, eventType: "registry.validated", actor: ctx.user.email ?? ctx.user.name ?? `user:${ctx.user.id}`, resource: server.namespace, outcome: validationStatus, correlationId: `registry-${server.id}`, details: { transport: server.transport, endpointUrl: server.endpointUrl, capabilityUrl: server.capabilityUrl } });
      return { ...server, validationStatus, lastValidatedAt: now };
    }),

  verifyAuditIntegrity: protectedProcedure
    .input(z.object({ tenantId: z.string().max(64).optional() }).optional())
    .query(({ input }) => verifyAuditIntegrity(input?.tenantId)),

  decideApproval: adminProcedure
    .input(
      z.object({
        id: z.string().min(1).max(64),
        decision: z.enum(["approved", "rejected"]),
        note: z.string().max(500).optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      try {
        return await decideApproval({
          id: input.id,
          reviewer: ctx.user.email ?? ctx.user.name ?? `user:${ctx.user.id}`,
          decision: input.decision,
          note: input.note,
        });
      } catch (error) {
        throw new TRPCError({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "Approval decision failed" });
      }
    }),
});
