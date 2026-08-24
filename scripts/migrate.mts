import { migrate } from "drizzle-orm/mysql2/migrator";
import { drizzle } from "drizzle-orm/mysql2";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL is required to run migrations.");
}

if (process.env.TIDB_ENABLE_SSL === "true") {
  const parsed = new URL(databaseUrl);
  const db = drizzle({
    connection: {
      host: parsed.hostname,
      port: Number(parsed.port || 4000),
      user: decodeURIComponent(parsed.username),
      password: decodeURIComponent(parsed.password),
      database: decodeURIComponent(parsed.pathname.slice(1) || "test"),

      ssl: { minVersion: "TLSv1.2" },
      enableKeepAlive: true,
    },
  });
  await migrate(db, { migrationsFolder: "drizzle" });
} else {
  await migrate(drizzle(databaseUrl), { migrationsFolder: "drizzle" });
}

console.log("Database migrations completed.");
