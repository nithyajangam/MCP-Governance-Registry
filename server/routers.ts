import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";
import { createPortableSession, isPortableAuthConfigured, PORTABLE_AUTH_COOKIE } from "./portableAuth";
import { z } from "zod";
import { governanceRouter } from "./governanceRouter";

export const appRouter = router({
    // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    portableAccess: publicProcedure
      .input(z.object({ accessKey: z.string().min(1).max(512) }))
      .mutation(async ({ ctx, input }) => {
        if (!isPortableAuthConfigured()) {
          return { success: false, message: "Portable dashboard access is not configured on this server." } as const;
        }
        const session = await createPortableSession(input.accessKey);
        if (!session) return { success: false, message: "That access key is not correct." } as const;
        const cookieOptions = getSessionCookieOptions(ctx.req);
        ctx.res.cookie(PORTABLE_AUTH_COOKIE, session, { ...cookieOptions, sameSite: "lax", maxAge: 8 * 60 * 60 * 1000 });
        return { success: true } as const;
      }),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      ctx.res.clearCookie(PORTABLE_AUTH_COOKIE, { ...cookieOptions, sameSite: "lax", maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),
  governance: governanceRouter,
});

export type AppRouter = typeof appRouter;
