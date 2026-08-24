// server/_core/index.ts
import "dotenv/config";
import express2 from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";

// shared/const.ts
var COOKIE_NAME = "app_session_id";
var ONE_YEAR_MS = 1e3 * 60 * 60 * 24 * 365;
var AXIOS_TIMEOUT_MS = 3e4;
var UNAUTHED_ERR_MSG = "Please login (10001)";
var NOT_ADMIN_ERR_MSG = "You do not have required permission (10002)";
var OAUTH_STATE_COOKIE = "__Host-oauth_state";
var decodeOAuthState = (state) => {
  let decoded;
  try {
    decoded = atob(state);
  } catch {
    return { redirectUri: "" };
  }
  try {
    const parsed = JSON.parse(decoded);
    if (parsed && typeof parsed.redirectUri === "string") return parsed;
  } catch {
  }
  return { redirectUri: decoded };
};

// server/_core/oauth.ts
import { parse as parseCookieHeader2 } from "cookie";

// server/db.ts
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";

// drizzle/schema.ts
import { boolean, index, int, mysqlEnum, mysqlTable, text, timestamp, uniqueIndex, varchar } from "drizzle-orm/mysql-core";
var users = mysqlTable("users", {
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
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull()
});
var tenants = mysqlTable("tenants", {
  id: varchar("id", { length: 64 }).primaryKey(),
  slug: varchar("slug", { length: 64 }).notNull().unique(),
  name: varchar("name", { length: 160 }).notNull(),
  region: varchar("region", { length: 64 }).notNull(),
  status: mysqlEnum("status", ["active", "suspended"]).notNull().default("active"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull()
});
var mcpServers = mysqlTable("mcpServers", {
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
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull()
}, (table) => [index("mcpServers_tenant_idx").on(table.tenantId), uniqueIndex("mcpServers_namespace_idx").on(table.namespace)]);
var mcpTools = mysqlTable("mcpTools", {
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
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull()
}, (table) => [index("mcpTools_server_idx").on(table.serverId), index("mcpTools_tenant_idx").on(table.tenantId), uniqueIndex("mcpTools_server_name_idx").on(table.serverId, table.name)]);
var approvalRequests = mysqlTable("approvalRequests", {
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
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull()
}, (table) => [index("approvalRequests_tenant_idx").on(table.tenantId), index("approvalRequests_status_idx").on(table.status), index("approvalRequests_hash_idx").on(table.requestHash)]);
var policyDecisions = mysqlTable("policyDecisions", {
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
  createdAt: timestamp("createdAt").defaultNow().notNull()
}, (table) => [index("policyDecisions_tenant_idx").on(table.tenantId), index("policyDecisions_correlation_idx").on(table.correlationId)]);
var auditEvents = mysqlTable("auditEvents", {
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
  createdAt: timestamp("createdAt").notNull()
}, (table) => [index("auditEvents_tenant_created_idx").on(table.tenantId, table.createdAt), uniqueIndex("auditEvents_hash_idx").on(table.eventHash)]);

// server/_core/env.ts
var ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? ""
};

// server/db.ts
var _db = null;
function getDatabaseConnectionConfig() {
  const url = process.env.DATABASE_URL;
  if (!url) return null;
  if (process.env.TIDB_ENABLE_SSL !== "true") return url;
  const parsed = new URL(url);
  return {
    host: parsed.hostname,
    port: Number(parsed.port || 4e3),
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
    database: decodeURIComponent(parsed.pathname.replace(/^\//, "") || "test"),
    ssl: { minVersion: "TLSv1.2" },
    enableKeepAlive: true
  };
}
async function getDb() {
  if (!_db) {
    try {
      const config = getDatabaseConnectionConfig();
      if (!config) return null;
      _db = typeof config === "string" ? drizzle(config) : drizzle({ connection: config });
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}
async function upsertUser(user) {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }
  try {
    const values = {
      openId: user.openId
    };
    const updateSet = {};
    const textFields = ["name", "email", "loginMethod"];
    const assignNullable = (field) => {
      const value = user[field];
      if (value === void 0) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };
    textFields.forEach(assignNullable);
    if (user.lastSignedIn !== void 0) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== void 0) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = "admin";
      updateSet.role = "admin";
    }
    if (!values.lastSignedIn) {
      values.lastSignedIn = /* @__PURE__ */ new Date();
    }
    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = /* @__PURE__ */ new Date();
    }
    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}
async function getUserByOpenId(openId) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return void 0;
  }
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}

// server/_core/cookies.ts
function isSecureRequest(req) {
  if (req.protocol === "https") return true;
  const forwardedProto = req.headers["x-forwarded-proto"];
  if (!forwardedProto) return false;
  const protoList = Array.isArray(forwardedProto) ? forwardedProto : forwardedProto.split(",");
  return protoList.some((proto) => proto.trim().toLowerCase() === "https");
}
function getSessionCookieOptions(req) {
  return {
    httpOnly: true,
    path: "/",
    sameSite: "none",
    secure: isSecureRequest(req)
  };
}

// shared/_core/errors.ts
var HttpError = class extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = "HttpError";
  }
};
var ForbiddenError = (msg) => new HttpError(403, msg);

// server/_core/sdk.ts
import axios from "axios";
import { parse as parseCookieHeader } from "cookie";
import { SignJWT, jwtVerify } from "jose";
var isNonEmptyString = (value) => typeof value === "string" && value.length > 0;
var EXCHANGE_TOKEN_PATH = `/webdev.v1.WebDevAuthPublicService/ExchangeToken`;
var GET_USER_INFO_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfo`;
var GET_USER_INFO_WITH_JWT_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfoWithJwt`;
var OAuthService = class {
  constructor(client) {
    this.client = client;
    console.log("[OAuth] Initialized with baseURL:", ENV.oAuthServerUrl);
    if (!ENV.oAuthServerUrl) {
      console.error(
        "[OAuth] ERROR: OAUTH_SERVER_URL is not configured! Set OAUTH_SERVER_URL environment variable."
      );
    }
  }
  decodeState(state) {
    return decodeOAuthState(state).redirectUri;
  }
  async getTokenByCode(code, state) {
    const payload = {
      clientId: ENV.appId,
      grantType: "authorization_code",
      code,
      redirectUri: this.decodeState(state)
    };
    const { data } = await this.client.post(
      EXCHANGE_TOKEN_PATH,
      payload
    );
    return data;
  }
  async getUserInfoByToken(token) {
    const { data } = await this.client.post(
      GET_USER_INFO_PATH,
      {
        accessToken: token.accessToken
      }
    );
    return data;
  }
};
var createOAuthHttpClient = () => axios.create({
  baseURL: ENV.oAuthServerUrl,
  timeout: AXIOS_TIMEOUT_MS
});
var SDKServer = class {
  client;
  oauthService;
  constructor(client = createOAuthHttpClient()) {
    this.client = client;
    this.oauthService = new OAuthService(this.client);
  }
  deriveLoginMethod(platforms, fallback) {
    if (fallback && fallback.length > 0) return fallback;
    if (!Array.isArray(platforms) || platforms.length === 0) return null;
    const set = new Set(
      platforms.filter((p) => typeof p === "string")
    );
    if (set.has("REGISTERED_PLATFORM_EMAIL")) return "email";
    if (set.has("REGISTERED_PLATFORM_GOOGLE")) return "google";
    if (set.has("REGISTERED_PLATFORM_APPLE")) return "apple";
    if (set.has("REGISTERED_PLATFORM_MICROSOFT") || set.has("REGISTERED_PLATFORM_AZURE"))
      return "microsoft";
    if (set.has("REGISTERED_PLATFORM_GITHUB")) return "github";
    const first = Array.from(set)[0];
    return first ? first.toLowerCase() : null;
  }
  /**
   * Exchange OAuth authorization code for access token
   * @example
   * const tokenResponse = await sdk.exchangeCodeForToken(code, state);
   */
  async exchangeCodeForToken(code, state) {
    return this.oauthService.getTokenByCode(code, state);
  }
  /**
   * Get user information using access token
   * @example
   * const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
   */
  async getUserInfo(accessToken) {
    const data = await this.oauthService.getUserInfoByToken({
      accessToken
    });
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  parseCookies(cookieHeader) {
    if (!cookieHeader) {
      return /* @__PURE__ */ new Map();
    }
    const parsed = parseCookieHeader(cookieHeader);
    return new Map(Object.entries(parsed));
  }
  getSessionSecret() {
    const secret = ENV.cookieSecret;
    return new TextEncoder().encode(secret);
  }
  /**
   * Create a session token for a Manus user openId
   * @example
   * const sessionToken = await sdk.createSessionToken(userInfo.openId);
   */
  async createSessionToken(openId, options = {}) {
    return this.signSession(
      {
        openId,
        appId: ENV.appId,
        name: options.name || ""
      },
      options
    );
  }
  async signSession(payload, options = {}) {
    const issuedAt = Date.now();
    const expiresInMs = options.expiresInMs ?? ONE_YEAR_MS;
    const expirationSeconds = Math.floor((issuedAt + expiresInMs) / 1e3);
    const secretKey = this.getSessionSecret();
    return new SignJWT({
      openId: payload.openId,
      appId: payload.appId,
      name: payload.name
    }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setExpirationTime(expirationSeconds).sign(secretKey);
  }
  async verifySession(cookieValue) {
    if (!cookieValue) {
      console.warn("[Auth] Missing session cookie");
      return null;
    }
    try {
      const secretKey = this.getSessionSecret();
      const { payload } = await jwtVerify(cookieValue, secretKey, {
        algorithms: ["HS256"]
      });
      const { openId, appId, name } = payload;
      if (!isNonEmptyString(openId) || !isNonEmptyString(appId) || !isNonEmptyString(name)) {
        console.warn("[Auth] Session payload missing required fields");
        return null;
      }
      return {
        openId,
        appId,
        name
      };
    } catch (error) {
      console.warn("[Auth] Session verification failed", String(error));
      return null;
    }
  }
  async getUserInfoWithJwt(jwtToken) {
    const payload = {
      jwtToken,
      projectId: ENV.appId
    };
    const { data } = await this.client.post(
      GET_USER_INFO_WITH_JWT_PATH,
      payload
    );
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  async authenticateRequest(req) {
    const cookies = this.parseCookies(req.headers.cookie);
    let sessionToken = cookies.get(COOKIE_NAME);
    if (!sessionToken) {
      const authHeader = req.headers.authorization;
      if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
        sessionToken = authHeader.slice(7);
      }
    }
    const session = await this.verifySession(sessionToken);
    if (!session) {
      throw ForbiddenError("Invalid session cookie");
    }
    if (session.openId.startsWith(CRON_OPEN_ID_PREFIX)) {
      const userInfo = await this.getUserInfoWithJwt(sessionToken ?? "");
      const taskUid = userInfo.taskUid ?? null;
      if (!taskUid) {
        throw ForbiddenError("Cron session missing task_uid");
      }
      return buildCronUser(userInfo);
    }
    const sessionUserId = session.openId;
    const signedInAt = /* @__PURE__ */ new Date();
    let user = await getUserByOpenId(sessionUserId);
    if (!user) {
      try {
        const userInfo = await this.getUserInfoWithJwt(sessionToken ?? "");
        await upsertUser({
          openId: userInfo.openId,
          name: userInfo.name || null,
          email: userInfo.email ?? null,
          loginMethod: userInfo.loginMethod ?? userInfo.platform ?? null,
          lastSignedIn: signedInAt
        });
        user = await getUserByOpenId(userInfo.openId);
      } catch (error) {
        console.error("[Auth] Failed to sync user from OAuth:", error);
        throw ForbiddenError("Failed to sync user info");
      }
    }
    if (!user) {
      throw ForbiddenError("User not found");
    }
    await upsertUser({
      openId: user.openId,
      lastSignedIn: signedInAt
    });
    return user;
  }
};
var CRON_OPEN_ID_PREFIX = "cron_";
function buildCronUser(userInfo) {
  const now = /* @__PURE__ */ new Date();
  return {
    id: -1,
    openId: userInfo.openId,
    name: userInfo.name || "Manus Scheduled Task",
    email: null,
    loginMethod: null,
    role: "user",
    createdAt: now,
    updatedAt: now,
    lastSignedIn: now,
    taskUid: userInfo.taskUid ?? void 0,
    isCron: true
  };
}
var sdk = new SDKServer();

// server/_core/oauth.ts
function getQueryParam(req, key) {
  const value = req.query[key];
  return typeof value === "string" ? value : void 0;
}
function registerOAuthRoutes(app) {
  app.get("/api/oauth/callback", async (req, res) => {
    const code = getQueryParam(req, "code");
    const state = getQueryParam(req, "state");
    if (!code || !state) {
      res.status(400).json({ error: "code and state are required" });
      return;
    }
    const { nonce } = decodeOAuthState(state);
    const expectedNonce = parseCookieHeader2(req.headers.cookie ?? "")[OAUTH_STATE_COOKIE];
    if (!nonce || nonce !== expectedNonce) {
      res.status(403).json({ error: "invalid oauth state" });
      return;
    }
    res.clearCookie(OAUTH_STATE_COOKIE, { path: "/", secure: true, sameSite: "none" });
    try {
      const tokenResponse = await sdk.exchangeCodeForToken(code, state);
      const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
      if (!userInfo.openId) {
        res.status(400).json({ error: "openId missing from user info" });
        return;
      }
      await upsertUser({
        openId: userInfo.openId,
        name: userInfo.name || null,
        email: userInfo.email ?? null,
        loginMethod: userInfo.loginMethod ?? userInfo.platform ?? null,
        lastSignedIn: /* @__PURE__ */ new Date()
      });
      const sessionToken = await sdk.createSessionToken(userInfo.openId, {
        name: userInfo.name || "",
        expiresInMs: ONE_YEAR_MS
      });
      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      res.redirect(302, "/");
    } catch (error) {
      console.error("[OAuth] Callback failed", error);
      res.status(500).json({ error: "OAuth callback failed" });
    }
  });
}

// server/_core/storageProxy.ts
function registerStorageProxy(app) {
  app.get("/manus-storage/*", async (req, res) => {
    const key = req.params[0];
    if (!key) {
      res.status(400).send("Missing storage key");
      return;
    }
    if (!ENV.forgeApiUrl || !ENV.forgeApiKey) {
      res.status(500).send("Storage proxy not configured");
      return;
    }
    try {
      const forgeUrl = new URL(
        "v1/storage/presign/get",
        ENV.forgeApiUrl.replace(/\/+$/, "") + "/"
      );
      forgeUrl.searchParams.set("path", key);
      const forgeResp = await fetch(forgeUrl, {
        headers: { Authorization: `Bearer ${ENV.forgeApiKey}` }
      });
      if (!forgeResp.ok) {
        const body = await forgeResp.text().catch(() => "");
        console.error(`[StorageProxy] forge error: ${forgeResp.status} ${body}`);
        res.status(502).send("Storage backend error");
        return;
      }
      const { url } = await forgeResp.json();
      if (!url) {
        res.status(502).send("Empty signed URL from backend");
        return;
      }
      res.set("Cache-Control", "no-store");
      res.redirect(307, url);
    } catch (err) {
      console.error("[StorageProxy] failed:", err);
      res.status(502).send("Storage proxy error");
    }
  });
}

// server/_core/systemRouter.ts
import { z } from "zod";

// server/_core/notification.ts
import { TRPCError } from "@trpc/server";
var TITLE_MAX_LENGTH = 1200;
var CONTENT_MAX_LENGTH = 2e4;
var trimValue = (value) => value.trim();
var isNonEmptyString2 = (value) => typeof value === "string" && value.trim().length > 0;
var buildEndpointUrl = (baseUrl) => {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  return new URL(
    "webdevtoken.v1.WebDevService/SendNotification",
    normalizedBase
  ).toString();
};
var validatePayload = (input) => {
  if (!isNonEmptyString2(input.title)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification title is required."
    });
  }
  if (!isNonEmptyString2(input.content)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification content is required."
    });
  }
  const title = trimValue(input.title);
  const content = trimValue(input.content);
  if (title.length > TITLE_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification title must be at most ${TITLE_MAX_LENGTH} characters.`
    });
  }
  if (content.length > CONTENT_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification content must be at most ${CONTENT_MAX_LENGTH} characters.`
    });
  }
  return { title, content };
};
async function notifyOwner(payload) {
  const { title, content } = validatePayload(payload);
  if (!ENV.forgeApiUrl) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service URL is not configured."
    });
  }
  if (!ENV.forgeApiKey) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service API key is not configured."
    });
  }
  const endpoint = buildEndpointUrl(ENV.forgeApiUrl);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${ENV.forgeApiKey}`,
        "content-type": "application/json",
        "connect-protocol-version": "1"
      },
      body: JSON.stringify({ title, content })
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      console.warn(
        `[Notification] Failed to notify owner (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`
      );
      return false;
    }
    return true;
  } catch (error) {
    console.warn("[Notification] Error calling notification service:", error);
    return false;
  }
}

// server/_core/trpc.ts
import { initTRPC, TRPCError as TRPCError2 } from "@trpc/server";
import superjson from "superjson";
var t = initTRPC.context().create({
  transformer: superjson
});
var router = t.router;
var publicProcedure = t.procedure;
var requireUser = t.middleware(async (opts) => {
  const { ctx, next } = opts;
  if (!ctx.user) {
    throw new TRPCError2({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }
  return next({
    ctx: {
      ...ctx,
      user: ctx.user
    }
  });
});
var protectedProcedure = t.procedure.use(requireUser);
var adminProcedure = t.procedure.use(
  t.middleware(async (opts) => {
    const { ctx, next } = opts;
    if (!ctx.user || ctx.user.role !== "admin") {
      throw new TRPCError2({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }
    return next({
      ctx: {
        ...ctx,
        user: ctx.user
      }
    });
  })
);

// server/_core/systemRouter.ts
var systemRouter = router({
  health: publicProcedure.input(
    z.object({
      timestamp: z.number().min(0, "timestamp cannot be negative")
    })
  ).query(() => ({
    ok: true
  })),
  notifyOwner: adminProcedure.input(
    z.object({
      title: z.string().min(1, "title is required"),
      content: z.string().min(1, "content is required")
    })
  ).mutation(async ({ input }) => {
    const delivered = await notifyOwner(input);
    return {
      success: delivered
    };
  })
});

// server/portableAuth.ts
import { timingSafeEqual } from "crypto";
import { SignJWT as SignJWT2, jwtVerify as jwtVerify2 } from "jose";
import { parse as parseCookie } from "cookie";
var PORTABLE_AUTH_COOKIE = "aegis_render_session";
var SESSION_LIFETIME = "8h";
function getSecret() {
  const value = process.env.JWT_SECRET;
  return value ? new TextEncoder().encode(value) : null;
}
function isPortableAuthConfigured() {
  return Boolean(process.env.DASHBOARD_ACCESS_KEY && getSecret());
}
function configuredAccessKeyMatches(candidate) {
  const configured = process.env.DASHBOARD_ACCESS_KEY;
  if (!configured) return false;
  const expected = Buffer.from(configured);
  const supplied = Buffer.from(candidate);
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}
async function createPortableSession(accessKey) {
  const secret = getSecret();
  if (!secret || !configuredAccessKeyMatches(accessKey)) return null;
  return new SignJWT2({ mode: "portable-dashboard", role: "admin" }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime(SESSION_LIFETIME).sign(secret);
}
async function getPortableUser(req) {
  const secret = getSecret();
  if (!secret || !isPortableAuthConfigured()) return null;
  const token = parseCookie(req.headers.cookie ?? "")[PORTABLE_AUTH_COOKIE];
  if (!token) return null;
  try {
    const { payload } = await jwtVerify2(token, secret);
    if (payload.mode !== "portable-dashboard" || payload.role !== "admin") return null;
    const now = /* @__PURE__ */ new Date();
    return {
      id: 0,
      openId: "render-dashboard-operator",
      name: "Dashboard operator",
      email: null,
      loginMethod: "access-key",
      role: "admin",
      createdAt: now,
      updatedAt: now,
      lastSignedIn: now
    };
  } catch {
    return null;
  }
}

// server/routers.ts
import { z as z3 } from "zod";

// server/governanceRouter.ts
import { TRPCError as TRPCError3 } from "@trpc/server";
import { z as z2 } from "zod";
import { eq as eq3 } from "drizzle-orm";

// server/governance.ts
import { and, asc, desc, eq as eq2 } from "drizzle-orm";
import { createHash } from "node:crypto";
import { nanoid } from "nanoid";
var MCP_PROTOCOL_VERSION = "2026-07-28";
var READ_SERVER_ID = "srv_reference_read";
var WRITE_SERVER_ID = "srv_reference_write";
var defaultTenantRows = [
  {
    id: "ten_northstar",
    slug: "northstar",
    name: "Northstar Systems",
    region: "us-east-1",
    status: "active"
  },
  {
    id: "ten_harbor",
    slug: "harbor",
    name: "Harbor Operations",
    region: "eu-west-1",
    status: "active"
  }
];
var defaultServerRows = [
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
    status: "active",
    validationStatus: "valid"
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
    status: "active",
    validationStatus: "valid"
  }
];
var defaultToolRows = [
  {
    id: "tool_project_search",
    serverId: READ_SERVER_ID,
    tenantId: "ten_northstar",
    name: "project.search",
    description: "Searches a safe reference project catalog.",
    riskLevel: "read_only",
    requiredScope: "project:read",
    maxPayloadBytes: 4096,
    inputSchema: JSON.stringify({
      type: "object",
      properties: { query: { type: "string", minLength: 1, maxLength: 120 } },
      required: ["query"]
    })
  },
  {
    id: "tool_incident_lookup",
    serverId: READ_SERVER_ID,
    tenantId: "ten_northstar",
    name: "incident.lookup",
    description: "Looks up an incident in a deterministic reference feed.",
    riskLevel: "sensitive",
    requiredScope: "incident:read",
    maxPayloadBytes: 2048,
    inputSchema: JSON.stringify({
      type: "object",
      properties: { incidentId: { type: "string", pattern: "^INC-[0-9]{3,5}$" } },
      required: ["incidentId"]
    })
  },
  {
    id: "tool_metrics_read",
    serverId: READ_SERVER_ID,
    tenantId: "ten_northstar",
    name: "metrics.read",
    description: "Returns synthetic service-health metrics for a bounded time window.",
    riskLevel: "read_only",
    requiredScope: "metrics:read",
    maxPayloadBytes: 4096,
    inputSchema: JSON.stringify({
      type: "object",
      properties: {
        service: { type: "string", maxLength: 60 },
        windowMinutes: { type: "integer", minimum: 5, maximum: 1440 }
      },
      required: ["service"]
    })
  },
  {
    id: "tool_change_create",
    serverId: WRITE_SERVER_ID,
    tenantId: "ten_northstar",
    name: "change.create",
    description: "Creates a simulated change request after a human approval elevation.",
    riskLevel: "destructive",
    requiredScope: "change:write",
    maxPayloadBytes: 2048,
    inputSchema: JSON.stringify({
      type: "object",
      properties: {
        summary: { type: "string", minLength: 5, maxLength: 140 },
        changeWindow: { type: "string", format: "date-time" }
      },
      required: ["summary", "changeWindow"]
    })
  }
];
function serialize(value) {
  return JSON.stringify(value ?? {});
}
function parseJson(value, fallback) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
function redact(value) {
  const sensitiveNames = /email|phone|ssn|token|secret|authorization|password/i;
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, sensitiveNames.test(key) ? "[REDACTED]" : redact(item)])
    );
  }
  if (typeof value === "string" && value.length > 500) return `${value.slice(0, 500)}\u2026[TRUNCATED]`;
  return value;
}
function requestFingerprint(input) {
  return createHash("sha256").update(JSON.stringify({ ...input, arguments: redact(input.arguments) })).digest("hex");
}
function computeAuditHash(input) {
  return createHash("sha256").update(`${input.previousHash}|${input.tenantId}|${input.eventType}|${input.actor}|${input.resource}|${input.outcome}|${input.correlationId}|${input.details}|${input.createdAt.toISOString()}`).digest("hex");
}
function evaluateLocalPolicy(input) {
  const payloadSize = Buffer.byteLength(JSON.stringify(input.arguments));
  const hasScope = input.grantedScopes.includes(input.tool.requiredScope);
  if (!hasScope) {
    return {
      allow: false,
      reason: `Missing required scope: ${input.tool.requiredScope}`,
      requireHumanApproval: false,
      redactions: ["email", "phone", "ssn", "token", "secret"],
      maxPayloadBytes: input.tool.maxPayloadBytes,
      source: "local"
    };
  }
  if (payloadSize > input.tool.maxPayloadBytes) {
    return {
      allow: false,
      reason: `Payload exceeds the ${input.tool.maxPayloadBytes}-byte policy cap`,
      requireHumanApproval: false,
      redactions: ["email", "phone", "ssn", "token", "secret"],
      maxPayloadBytes: input.tool.maxPayloadBytes,
      source: "local"
    };
  }
  return {
    allow: true,
    reason: input.tool.riskLevel === "destructive" ? "Scope verified; a current human approval is required." : "Scope and payload policy verified.",
    requireHumanApproval: input.tool.riskLevel === "destructive",
    redactions: ["email", "phone", "ssn", "token", "secret"],
    maxPayloadBytes: input.tool.maxPayloadBytes,
    source: "local"
  };
}
async function evaluatePolicy(input) {
  const fallback = evaluateLocalPolicy(input);
  if (!process.env.OPA_URL) return fallback;
  try {
    const response = await fetch(process.env.OPA_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: serialize({ input: { ...input, arguments: redact(input.arguments) } }),
      signal: AbortSignal.timeout(2500)
    });
    if (!response.ok) return { ...fallback, reason: `${fallback.reason} OPA was unavailable; the local fail-closed policy applied.` };
    const body = await response.json();
    const result = body.result;
    if (typeof result?.allow !== "boolean") return fallback;
    return {
      allow: result.allow,
      reason: result.reason ?? "OPA policy decision",
      requireHumanApproval: result.requireHumanApproval ?? fallback.requireHumanApproval,
      redactions: result.redactions ?? fallback.redactions,
      maxPayloadBytes: result.maxPayloadBytes ?? fallback.maxPayloadBytes,
      source: "opa"
    };
  } catch {
    return { ...fallback, reason: `${fallback.reason} OPA was unavailable; the local fail-closed policy applied.` };
  }
}
async function ensureSeedData() {
  const db = await getDb();
  if (!db) return;
  const existing = await db.select({ id: tenants.id }).from(tenants).limit(1);
  if (existing.length) return;
  await db.insert(tenants).values(defaultTenantRows);
  await db.insert(mcpServers).values(
    defaultServerRows.map((server) => ({ ...server, lastValidatedAt: /* @__PURE__ */ new Date() }))
  );
  await db.insert(mcpTools).values(defaultToolRows);
  const expiresAt = new Date(Date.now() + 12 * 60 * 1e3);
  await db.insert(approvalRequests).values({
    id: "apr_demo_pending",
    tenantId: "ten_northstar",
    serverId: WRITE_SERVER_ID,
    toolId: "tool_change_create",
    requestHash: requestFingerprint({
      tenantId: "ten_northstar",
      principal: "demo:alex",
      toolName: "change.create",
      arguments: { summary: "Rotate the reference service certificate", changeWindow: "2026-08-25T01:00:00Z" }
    }),
    requestedBy: "demo:alex",
    argumentsRedacted: serialize({ summary: "Rotate the reference service certificate", changeWindow: "2026-08-25T01:00:00Z" }),
    status: "pending",
    expiresAt
  });
  await appendAudit({
    tenantId: "ten_northstar",
    eventType: "approval.requested",
    actor: "demo:alex",
    resource: "change.create",
    outcome: "pending",
    correlationId: "seed-approval",
    details: { source: "seed", approvalId: "apr_demo_pending" }
  });
}
async function appendAudit(input) {
  const db = await getDb();
  if (!db) return;
  const previous = await db.select({ eventHash: auditEvents.eventHash }).from(auditEvents).where(eq2(auditEvents.tenantId, input.tenantId)).orderBy(desc(auditEvents.createdAt)).limit(1);
  const previousHash = previous[0]?.eventHash ?? "GENESIS";
  const createdAt = /* @__PURE__ */ new Date();
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
    createdAt
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
    createdAt
  });
}
async function logPolicyDecision(input) {
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
    correlationId: input.correlationId
  });
  await appendAudit({
    tenantId: input.tenantId,
    eventType: "policy.evaluated",
    actor: input.principal,
    resource: input.toolName,
    outcome: input.result.allow ? "allow" : "deny",
    correlationId: input.correlationId,
    details: { requiredScope: input.requiredScope, grantedScopes: input.grantedScopes, reason: input.result.reason, source: input.result.source }
  });
}
async function getTenantBySlug(slug) {
  await ensureSeedData();
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(tenants).where(eq2(tenants.slug, slug)).limit(1);
  return result[0];
}
async function getServer(serverId) {
  await ensureSeedData();
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(mcpServers).where(eq2(mcpServers.id, serverId)).limit(1);
  return result[0];
}
async function getTool(serverId, name) {
  await ensureSeedData();
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(mcpTools).where(and(eq2(mcpTools.serverId, serverId), eq2(mcpTools.name, name), eq2(mcpTools.isEnabled, true))).limit(1);
  return result[0];
}
async function listServerTools(serverId) {
  await ensureSeedData();
  const db = await getDb();
  if (!db) return [];
  return db.select().from(mcpTools).where(and(eq2(mcpTools.serverId, serverId), eq2(mcpTools.isEnabled, true)));
}
async function createApproval(input) {
  const db = await getDb();
  if (!db) throw new Error("Database is not available");
  const duplicate = await db.select().from(approvalRequests).where(and(eq2(approvalRequests.tenantId, input.tenantId), eq2(approvalRequests.requestHash, input.requestHash), eq2(approvalRequests.status, "pending"))).limit(1);
  if (duplicate[0]) return duplicate[0];
  const expiresAt = new Date(Date.now() + 15 * 60 * 1e3);
  const approval = {
    id: `apr_${nanoid(14)}`,
    tenantId: input.tenantId,
    serverId: input.serverId,
    toolId: input.toolId,
    requestHash: input.requestHash,
    requestedBy: input.requestedBy,
    argumentsRedacted: serialize(redact(input.arguments)),
    status: "pending",
    expiresAt
  };
  await db.insert(approvalRequests).values(approval);
  await appendAudit({
    tenantId: input.tenantId,
    eventType: "approval.requested",
    actor: input.requestedBy,
    resource: input.toolId,
    outcome: "pending",
    correlationId: input.correlationId,
    details: { approvalId: approval.id, expiresAt, arguments: input.arguments }
  });
  return approval;
}
async function findActiveApproval(tenantId, requestHash) {
  const db = await getDb();
  if (!db) return void 0;
  const records = await db.select().from(approvalRequests).where(and(eq2(approvalRequests.tenantId, tenantId), eq2(approvalRequests.requestHash, requestHash), eq2(approvalRequests.status, "approved"))).orderBy(desc(approvalRequests.decidedAt)).limit(1);
  const record = records[0];
  if (!record || record.expiresAt.getTime() < Date.now() || record.consumedAt) return void 0;
  return record;
}
async function consumeApproval(id, correlationId) {
  const db = await getDb();
  if (!db) return;
  const current = await db.select().from(approvalRequests).where(eq2(approvalRequests.id, id)).limit(1);
  const approval = current[0];
  if (!approval || approval.consumedAt || approval.expiresAt.getTime() < Date.now()) return;
  await db.update(approvalRequests).set({ consumedAt: /* @__PURE__ */ new Date(), updatedAt: /* @__PURE__ */ new Date() }).where(eq2(approvalRequests.id, id));
  await appendAudit({
    tenantId: approval.tenantId,
    eventType: "approval.consumed",
    actor: approval.requestedBy,
    resource: approval.toolId,
    outcome: "elevated",
    correlationId,
    details: { approvalId: approval.id }
  });
}
async function decideApproval(input) {
  const db = await getDb();
  if (!db) throw new Error("Database is not available");
  const rows = await db.select().from(approvalRequests).where(eq2(approvalRequests.id, input.id)).limit(1);
  const approval = rows[0];
  if (!approval) throw new Error("Approval request not found");
  if (approval.status !== "pending") throw new Error("Only pending requests can be decided");
  if (approval.expiresAt.getTime() < Date.now()) {
    await db.update(approvalRequests).set({ status: "expired", updatedAt: /* @__PURE__ */ new Date() }).where(eq2(approvalRequests.id, input.id));
    throw new Error("This approval request has expired");
  }
  const now = /* @__PURE__ */ new Date();
  await db.update(approvalRequests).set({ status: input.decision, reviewer: input.reviewer, decisionNote: input.note ?? null, decidedAt: now, updatedAt: now }).where(eq2(approvalRequests.id, input.id));
  await appendAudit({
    tenantId: approval.tenantId,
    eventType: `approval.${input.decision}`,
    actor: input.reviewer,
    resource: approval.toolId,
    outcome: input.decision,
    correlationId: `approval-${approval.id}`,
    details: { approvalId: approval.id, note: input.note }
  });
  return { ...approval, status: input.decision, reviewer: input.reviewer, decisionNote: input.note ?? null, decidedAt: now };
}
async function expireApprovals() {
  const db = await getDb();
  if (!db) return 0;
  const pending = await db.select().from(approvalRequests).where(eq2(approvalRequests.status, "pending"));
  const stale = pending.filter((item) => item.expiresAt.getTime() < Date.now());
  for (const item of stale) {
    await db.update(approvalRequests).set({ status: "expired", updatedAt: /* @__PURE__ */ new Date() }).where(eq2(approvalRequests.id, item.id));
    await appendAudit({
      tenantId: item.tenantId,
      eventType: "approval.expired",
      actor: "system:expiry",
      resource: item.toolId,
      outcome: "expired",
      correlationId: `approval-${item.id}`,
      details: { approvalId: item.id }
    });
  }
  return stale.length;
}
async function governanceSnapshot(input) {
  await ensureSeedData();
  await expireApprovals();
  const db = await getDb();
  if (!db) return { tenants: [], servers: [], tools: [], approvals: [], events: [], decisions: [] };
  const tenantRows = input?.tenantId ? await db.select().from(tenants).where(eq2(tenants.id, input.tenantId)) : await db.select().from(tenants);
  const tenantIds = new Set(tenantRows.map((item) => item.id));
  const [servers, tools, approvals, events, decisions] = await Promise.all([
    db.select().from(mcpServers),
    db.select().from(mcpTools),
    db.select().from(approvalRequests).orderBy(desc(approvalRequests.createdAt)),
    db.select().from(auditEvents).orderBy(desc(auditEvents.createdAt)),
    db.select().from(policyDecisions).orderBy(desc(policyDecisions.createdAt))
  ]);
  const search = input?.search?.toLowerCase().trim();
  const matches = (value) => !search || value.toLowerCase().includes(search);
  return {
    tenants: tenantRows,
    servers: servers.filter((item) => tenantIds.has(item.tenantId) && matches(`${item.name} ${item.namespace} ${item.ownerTeam}`)),
    tools: tools.filter((item) => tenantIds.has(item.tenantId) && matches(`${item.name} ${item.description}`)),
    approvals: approvals.filter((item) => tenantIds.has(item.tenantId) && matches(`${item.requestedBy} ${item.status} ${item.toolId}`)),
    events: events.filter((item) => tenantIds.has(item.tenantId) && matches(`${item.eventType} ${item.actor} ${item.resource} ${item.outcome}`)).slice(0, 100),
    decisions: decisions.filter((item) => tenantIds.has(item.tenantId) && matches(`${item.toolName} ${item.principal} ${item.decision}`)).slice(0, 100)
  };
}
async function verifyAuditIntegrity(tenantId) {
  const db = await getDb();
  if (!db) return { valid: false, checked: 0, issues: ["Database is not available"] };
  const rows = await db.select().from(auditEvents).orderBy(asc(auditEvents.createdAt));
  const previousByTenant = /* @__PURE__ */ new Map();
  const issues = [];
  const filteredRows = rows.filter((item) => !tenantId || item.tenantId === tenantId);
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
      createdAt: event.createdAt
    });
    if (event.eventHash !== expectedHash) issues.push(`Audit hash mismatch at ${event.id}`);
    previousByTenant.set(event.tenantId, event.eventHash);
  }
  return { valid: issues.length === 0, checked: filteredRows.length, issues };
}
function buildCapabilityManifest(server, tools, baseUrl) {
  return {
    version: "1.0",
    generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
    server: {
      id: server.id,
      name: server.name,
      namespace: server.namespace,
      description: server.description,
      transport: "streamable-http",
      endpoint: `${baseUrl}${server.endpointUrl}`,
      owner: server.ownerTeam,
      slo: server.slo
    },
    authorization: {
      protectedResourceMetadata: `${baseUrl}/.well-known/oauth-protected-resource`,
      scopes: Array.from(new Set(tools.map((tool) => tool.requiredScope))),
      humanApproval: tools.some((tool) => tool.riskLevel === "destructive")
    },
    tools: tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: parseJson(tool.inputSchema, {}),
      risk: tool.riskLevel,
      requiredScope: tool.requiredScope,
      maxPayloadBytes: tool.maxPayloadBytes
    }))
  };
}
function simulatedToolOutput(name, args) {
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

// server/governanceRouter.ts
var governanceRouter = router({
  snapshot: protectedProcedure.input(z2.object({ tenantId: z2.string().max(64).optional(), search: z2.string().max(120).optional() }).optional()).query(async ({ input }) => governanceSnapshot(input)),
  bootstrapDemo: adminProcedure.mutation(async () => {
    await ensureSeedData();
    return { success: true };
  }),
  setTenantStatus: adminProcedure.input(z2.object({ id: z2.string().min(1).max(64), status: z2.enum(["active", "suspended"]) })).mutation(async ({ ctx, input }) => {
    const db = await getDb();
    if (!db) throw new TRPCError3({ code: "INTERNAL_SERVER_ERROR", message: "Database is not available" });
    const records = await db.select().from(tenants).where(eq3(tenants.id, input.id)).limit(1);
    const tenant = records[0];
    if (!tenant) throw new TRPCError3({ code: "NOT_FOUND", message: "Tenant was not found" });
    await db.update(tenants).set({ status: input.status, updatedAt: /* @__PURE__ */ new Date() }).where(eq3(tenants.id, input.id));
    await appendAudit({ tenantId: tenant.id, eventType: "tenant.status_changed", actor: ctx.user.email ?? ctx.user.name ?? `user:${ctx.user.id}`, resource: tenant.slug, outcome: input.status, correlationId: `tenant-${tenant.id}`, details: { from: tenant.status, to: input.status } });
    return { ...tenant, status: input.status };
  }),
  setServerStatus: adminProcedure.input(z2.object({ id: z2.string().min(1).max(64), status: z2.enum(["active", "disabled", "needs_review"]) })).mutation(async ({ ctx, input }) => {
    const db = await getDb();
    if (!db) throw new TRPCError3({ code: "INTERNAL_SERVER_ERROR", message: "Database is not available" });
    const records = await db.select().from(mcpServers).where(eq3(mcpServers.id, input.id)).limit(1);
    const server = records[0];
    if (!server) throw new TRPCError3({ code: "NOT_FOUND", message: "Registry server was not found" });
    await db.update(mcpServers).set({ status: input.status, updatedAt: /* @__PURE__ */ new Date() }).where(eq3(mcpServers.id, input.id));
    await appendAudit({ tenantId: server.tenantId, eventType: "registry.status_changed", actor: ctx.user.email ?? ctx.user.name ?? `user:${ctx.user.id}`, resource: server.namespace, outcome: input.status, correlationId: `registry-${server.id}`, details: { from: server.status, to: input.status } });
    return { ...server, status: input.status };
  }),
  validateServer: adminProcedure.input(z2.object({ id: z2.string().min(1).max(64) })).mutation(async ({ ctx, input }) => {
    const db = await getDb();
    if (!db) throw new TRPCError3({ code: "INTERNAL_SERVER_ERROR", message: "Database is not available" });
    const records = await db.select().from(mcpServers).where(eq3(mcpServers.id, input.id)).limit(1);
    const server = records[0];
    if (!server) throw new TRPCError3({ code: "NOT_FOUND", message: "Registry server was not found" });
    const valid = server.transport === "streamable-http" && Boolean(server.endpointUrl) && Boolean(server.capabilityUrl) && Boolean(server.ownerTeam);
    const validationStatus = valid ? "valid" : "warning";
    const now = /* @__PURE__ */ new Date();
    await db.update(mcpServers).set({ validationStatus, lastValidatedAt: now, updatedAt: now }).where(eq3(mcpServers.id, input.id));
    await appendAudit({ tenantId: server.tenantId, eventType: "registry.validated", actor: ctx.user.email ?? ctx.user.name ?? `user:${ctx.user.id}`, resource: server.namespace, outcome: validationStatus, correlationId: `registry-${server.id}`, details: { transport: server.transport, endpointUrl: server.endpointUrl, capabilityUrl: server.capabilityUrl } });
    return { ...server, validationStatus, lastValidatedAt: now };
  }),
  verifyAuditIntegrity: protectedProcedure.input(z2.object({ tenantId: z2.string().max(64).optional() }).optional()).query(({ input }) => verifyAuditIntegrity(input?.tenantId)),
  decideApproval: adminProcedure.input(
    z2.object({
      id: z2.string().min(1).max(64),
      decision: z2.enum(["approved", "rejected"]),
      note: z2.string().max(500).optional()
    })
  ).mutation(async ({ ctx, input }) => {
    try {
      return await decideApproval({
        id: input.id,
        reviewer: ctx.user.email ?? ctx.user.name ?? `user:${ctx.user.id}`,
        decision: input.decision,
        note: input.note
      });
    } catch (error) {
      throw new TRPCError3({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "Approval decision failed" });
    }
  })
});

// server/routers.ts
var appRouter = router({
  // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    portableAccess: publicProcedure.input(z3.object({ accessKey: z3.string().min(1).max(512) })).mutation(async ({ ctx, input }) => {
      if (!isPortableAuthConfigured()) {
        return { success: false, message: "Portable dashboard access is not configured on this server." };
      }
      const session = await createPortableSession(input.accessKey);
      if (!session) return { success: false, message: "That access key is not correct." };
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.cookie(PORTABLE_AUTH_COOKIE, session, { ...cookieOptions, sameSite: "lax", maxAge: 8 * 60 * 60 * 1e3 });
      return { success: true };
    }),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      ctx.res.clearCookie(PORTABLE_AUTH_COOKIE, { ...cookieOptions, sameSite: "lax", maxAge: -1 });
      return {
        success: true
      };
    })
  }),
  governance: governanceRouter
});

// server/_core/context.ts
async function createContext(opts) {
  let user = null;
  try {
    user = await sdk.authenticateRequest(opts.req);
  } catch (error) {
    user = null;
  }
  if (!user) {
    user = await getPortableUser(opts.req);
  }
  return {
    req: opts.req,
    res: opts.res,
    user
  };
}

// server/mcp.ts
import { nanoid as nanoid2 } from "nanoid";
function responseBase(req) {
  const protocol = req.header("x-forwarded-proto")?.split(",")[0]?.trim() || req.protocol;
  return `${protocol}://${req.get("host")}`;
}
function rpc(res, id, result, status = 200) {
  res.status(status).type("application/json").json({ jsonrpc: "2.0", id: id ?? null, result });
}
function rpcError(res, id, code, message, status = 400, data) {
  res.status(status).type("application/json").json({ jsonrpc: "2.0", id: id ?? null, error: { code, message, ...data ? { data } : {} } });
}
function parseDemoBearer(req) {
  const value = req.header("authorization")?.replace(/^Bearer\s+/i, "").trim();
  if (!value?.startsWith("demo|")) return void 0;
  if (process.env.NODE_ENV === "production" && process.env.ALLOW_DEMO_MCP_TOKENS !== "true") return void 0;
  const [, tenantSlug, principal, scopes] = value.split("|");
  if (!tenantSlug || !principal) return void 0;
  return { tenantSlug, principal, scopes: (scopes ?? "").split(",").map((scope) => scope.trim()).filter(Boolean) };
}
function originAllowed(req) {
  const origin = req.header("origin");
  if (!origin) return true;
  const allowed = new Set(
    (process.env.MCP_ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean)
  );
  allowed.add(responseBase(req));
  return allowed.has(origin);
}
function validateRequestHeaders(req, body) {
  const protocolHeader = req.header("mcp-protocol-version");
  const bodyProtocol = body.params?._meta?.["io.modelcontextprotocol/protocolVersion"];
  if (protocolHeader !== MCP_PROTOCOL_VERSION || bodyProtocol !== MCP_PROTOCOL_VERSION || protocolHeader !== bodyProtocol) {
    return { code: -32020, message: `HeaderMismatch: MCP-Protocol-Version and _meta protocol version must both be ${MCP_PROTOCOL_VERSION}` };
  }
  if (req.header("mcp-method") !== body.method) {
    return { code: -32020, message: "HeaderMismatch: Mcp-Method must match the JSON-RPC method" };
  }
  if (body.method === "tools/call" && req.header("mcp-name") !== body.params?.name) {
    return { code: -32020, message: "HeaderMismatch: Mcp-Name must match params.name" };
  }
  return void 0;
}
function mcpToolDefinition(tool) {
  return {
    name: tool.name,
    description: tool.description,
    inputSchema: parseJson(tool.inputSchema, { type: "object", properties: {} }),
    annotations: { readOnlyHint: tool.riskLevel !== "destructive", destructiveHint: tool.riskLevel === "destructive" }
  };
}
async function handleMcp(serverId, req, res) {
  if (!originAllowed(req)) {
    rpcError(res, null, -32001, "Forbidden origin", 403);
    return;
  }
  const body = req.body;
  if (!body || body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    rpcError(res, body?.id, -32600, "Invalid JSON-RPC request", 400);
    return;
  }
  const headerError = validateRequestHeaders(req, body);
  if (headerError) {
    rpcError(res, body.id, headerError.code, headerError.message, 400);
    return;
  }
  const server = await getServer(serverId);
  if (!server || server.status !== "active") {
    rpcError(res, body.id, -32004, "Reference server unavailable", 503);
    return;
  }
  if (body.method === "initialize") {
    rpc(res, body.id, {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: { name: server.namespace, version: "0.1.0-reference" },
      instructions: "Reference-only MCP service. Tool calls are tenant scoped, policy evaluated, and audit logged."
    });
    return;
  }
  const principal = parseDemoBearer(req);
  if (!principal) {
    const tools = await listServerTools(serverId);
    const scope = body.method === "tools/call" ? tools.find((tool2) => tool2.name === body.params?.name)?.requiredScope ?? "registry:read" : "registry:read";
    res.setHeader("WWW-Authenticate", `Bearer resource_metadata="${responseBase(req)}/.well-known/oauth-protected-resource", scope="${scope}"`);
    rpcError(res, body.id, -32e3, "Unauthorized: supply a valid OAuth access token", 401);
    return;
  }
  const tenant = await getTenantBySlug(principal.tenantSlug);
  if (!tenant || tenant.status !== "active") {
    rpcError(res, body.id, -32003, "Tenant is not active", 403);
    return;
  }
  if (body.method === "tools/list") {
    const tools = (await listServerTools(serverId)).filter((tool2) => tool2.tenantId === tenant.id);
    await appendAudit({ tenantId: tenant.id, eventType: "mcp.tools.list", actor: principal.principal, resource: server.namespace, outcome: "ok", correlationId: `mcp-${nanoid2(12)}`, details: { serverId, count: tools.length } });
    rpc(res, body.id, { tools: tools.map(mcpToolDefinition) });
    return;
  }
  if (body.method !== "tools/call" || !body.params?.name) {
    rpcError(res, body.id, -32601, "Method not found", 404);
    return;
  }
  const tool = await getTool(serverId, body.params.name);
  if (!tool || tool.tenantId !== tenant.id) {
    rpcError(res, body.id, -32602, "Unknown or disabled tool for this tenant", 404);
    return;
  }
  const argumentsValue = body.params.arguments ?? {};
  const correlationId = `mcp-${nanoid2(14)}`;
  const requestHash = requestFingerprint({ tenantId: tenant.id, principal: principal.principal, toolName: tool.name, arguments: argumentsValue });
  const policy = await evaluatePolicy({ tenantId: tenant.id, principal: principal.principal, tool, grantedScopes: principal.scopes, arguments: argumentsValue });
  await logPolicyDecision({ tenantId: tenant.id, requestHash, principal: principal.principal, toolName: tool.name, requiredScope: tool.requiredScope, grantedScopes: principal.scopes, result: policy, correlationId });
  if (!policy.allow) {
    rpc(res, body.id, { content: [{ type: "text", text: `Denied by policy: ${policy.reason}` }], isError: true, _meta: { correlationId } });
    return;
  }
  if (policy.requireHumanApproval) {
    const approval = await findActiveApproval(tenant.id, requestHash);
    if (!approval) {
      const pending = await createApproval({ tenantId: tenant.id, serverId, toolId: tool.id, requestHash, requestedBy: principal.principal, arguments: argumentsValue, correlationId });
      rpc(res, body.id, { content: [{ type: "text", text: `Human approval is required before ${tool.name} can run.` }], isError: true, _meta: { correlationId, approvalId: pending.id, expiresAt: pending.expiresAt.toISOString() } });
      return;
    }
    await consumeApproval(approval.id, correlationId);
  }
  const output = simulatedToolOutput(tool.name, argumentsValue);
  await appendAudit({ tenantId: tenant.id, eventType: "mcp.tool.executed", actor: principal.principal, resource: tool.name, outcome: "ok", correlationId, details: { arguments: argumentsValue, response: output, risk: tool.riskLevel } });
  rpc(res, body.id, { content: [{ type: "text", text: JSON.stringify(output) }], structuredContent: output, _meta: { correlationId, policySource: policy.source } });
}
function registerMcpRoutes(app) {
  app.get("/.well-known/oauth-protected-resource", (req, res) => {
    const baseUrl = responseBase(req);
    res.type("application/json").json({
      resource: `${baseUrl}/mcp/read`,
      authorization_servers: [process.env.MCP_AUTHORIZATION_SERVER ?? `${baseUrl}/oauth`],
      scopes_supported: ["project:read", "incident:read", "metrics:read", "change:write"],
      bearer_methods_supported: ["header"]
    });
  });
  app.get("/.well-known/mcp-capabilities", async (req, res, next) => {
    try {
      const serverId = req.query.server === "write" ? WRITE_SERVER_ID : READ_SERVER_ID;
      const server = await getServer(serverId);
      if (!server) return res.status(404).json({ error: "Reference server not found" });
      const tools = await listServerTools(serverId);
      return res.type("application/json").json(buildCapabilityManifest(server, tools, responseBase(req)));
    } catch (error) {
      return next(error);
    }
  });
  app.post("/mcp/read", (req, res, next) => handleMcp(READ_SERVER_ID, req, res).catch(next));
  app.post("/mcp/write", (req, res, next) => handleMcp(WRITE_SERVER_ID, req, res).catch(next));
}

// server/_core/vite.ts
import express from "express";
import fs2 from "fs";
import { nanoid as nanoid3 } from "nanoid";
import path2 from "path";
import { createServer as createViteServer } from "vite";

// vite.config.ts
import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "node:path";
import { defineConfig } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";
var PROJECT_ROOT = import.meta.dirname;
var LOG_DIR = path.join(PROJECT_ROOT, ".manus-logs");
var MAX_LOG_SIZE_BYTES = 1 * 1024 * 1024;
var TRIM_TARGET_BYTES = Math.floor(MAX_LOG_SIZE_BYTES * 0.6);
function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}
function trimLogFile(logPath, maxSize) {
  try {
    if (!fs.existsSync(logPath) || fs.statSync(logPath).size <= maxSize) {
      return;
    }
    const lines = fs.readFileSync(logPath, "utf-8").split("\n");
    const keptLines = [];
    let keptBytes = 0;
    const targetSize = TRIM_TARGET_BYTES;
    for (let i = lines.length - 1; i >= 0; i--) {
      const lineBytes = Buffer.byteLength(`${lines[i]}
`, "utf-8");
      if (keptBytes + lineBytes > targetSize) break;
      keptLines.unshift(lines[i]);
      keptBytes += lineBytes;
    }
    fs.writeFileSync(logPath, keptLines.join("\n"), "utf-8");
  } catch {
  }
}
function writeToLogFile(source, entries) {
  if (entries.length === 0) return;
  ensureLogDir();
  const logPath = path.join(LOG_DIR, `${source}.log`);
  const lines = entries.map((entry) => {
    const ts = (/* @__PURE__ */ new Date()).toISOString();
    return `[${ts}] ${JSON.stringify(entry)}`;
  });
  fs.appendFileSync(logPath, `${lines.join("\n")}
`, "utf-8");
  trimLogFile(logPath, MAX_LOG_SIZE_BYTES);
}
function vitePluginManusDebugCollector() {
  return {
    name: "manus-debug-collector",
    transformIndexHtml(html) {
      if (process.env.NODE_ENV === "production") {
        return html;
      }
      return {
        html,
        tags: [
          {
            tag: "script",
            attrs: {
              src: "/__manus__/debug-collector.js",
              defer: true
            },
            injectTo: "head"
          }
        ]
      };
    },
    configureServer(server) {
      server.middlewares.use("/__manus__/logs", (req, res, next) => {
        if (req.method !== "POST") {
          return next();
        }
        const handlePayload = (payload) => {
          if (payload.consoleLogs?.length > 0) {
            writeToLogFile("browserConsole", payload.consoleLogs);
          }
          if (payload.networkRequests?.length > 0) {
            writeToLogFile("networkRequests", payload.networkRequests);
          }
          if (payload.sessionEvents?.length > 0) {
            writeToLogFile("sessionReplay", payload.sessionEvents);
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true }));
        };
        const reqBody = req.body;
        if (reqBody && typeof reqBody === "object") {
          try {
            handlePayload(reqBody);
          } catch (e) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, error: String(e) }));
          }
          return;
        }
        let body = "";
        req.on("data", (chunk) => {
          body += chunk.toString();
        });
        req.on("end", () => {
          try {
            const payload = JSON.parse(body);
            handlePayload(payload);
          } catch (e) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, error: String(e) }));
          }
        });
      });
    }
  };
}
var plugins = [react(), tailwindcss(), jsxLocPlugin(), vitePluginManusRuntime(), vitePluginManusDebugCollector()];
var vite_config_default = defineConfig({
  plugins,
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  envDir: path.resolve(import.meta.dirname),
  root: path.resolve(import.meta.dirname, "client"),
  publicDir: path.resolve(import.meta.dirname, "client", "public"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    host: true,
    allowedHosts: [
      ".manuspre.computer",
      ".manus.computer",
      ".manus-asia.computer",
      ".manuscomputer.ai",
      ".manusvm.computer",
      "localhost",
      "127.0.0.1"
    ],
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/_core/vite.ts
async function setupVite(app, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    server: serverOptions,
    appType: "custom"
  });
  app.use(vite.middlewares);
  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "../..",
        "client",
        "index.html"
      );
      let template = await fs2.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid3()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app) {
  const distPath = process.env.NODE_ENV === "development" ? path2.resolve(import.meta.dirname, "../..", "dist", "public") : path2.resolve(import.meta.dirname, "public");
  if (!fs2.existsSync(distPath)) {
    console.error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app.use(express.static(distPath));
  app.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/runtimeConfig.ts
var REQUIRED_RENDER_VARIABLES = ["DATABASE_URL", "JWT_SECRET", "DASHBOARD_ACCESS_KEY"];
function validateRuntimeEnvironment(environment = process.env) {
  if (environment.VITE_PORTABLE_AUTH !== "true") return { portable: false, missing: [] };
  const missing = REQUIRED_RENDER_VARIABLES.filter((key) => !environment[key]?.trim());
  if (environment.TIDB_ENABLE_SSL !== "true") missing.push("TIDB_ENABLE_SSL=true");
  return { portable: true, missing };
}
function assertRuntimeEnvironment() {
  const result = validateRuntimeEnvironment();
  if (result.missing.length) {
    throw new Error(`Render deployment is missing required environment variables: ${result.missing.join(", ")}`);
  }
}

// server/_core/index.ts
function isPortAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}
async function findAvailablePort(startPort = 3e3) {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}
async function startServer() {
  assertRuntimeEnvironment();
  const app = express2();
  const server = createServer(app);
  app.use(express2.json({ limit: "50mb" }));
  app.use(express2.urlencoded({ limit: "50mb", extended: true }));
  registerStorageProxy(app);
  registerOAuthRoutes(app);
  registerMcpRoutes(app);
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext
    })
  );
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);
  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }
  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });
}
startServer().catch(console.error);
