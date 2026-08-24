import { migrate } from "drizzle-orm/mysql2/migrator";
import { getDb } from "../server/db.js";

const db = await getDb();
if (!db) {
  throw new Error("DATABASE_URL is required to run migrations.");
}

await migrate(db, { migrationsFolder: "drizzle" });
console.log("Database migrations completed.");
