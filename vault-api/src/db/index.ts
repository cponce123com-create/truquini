import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import Database from "better-sqlite3";
import { drizzle as drizzleSqlite } from "drizzle-orm/better-sqlite3";
import * as sqliteSchema from "./schema.js";
import * as pgSchema from "./schema-pg.js";

const DB_TYPE = process.env.DB_TYPE || "neon";

let db: any;

if (DB_TYPE === "sqlite") {
  const sqlite = new Database("vault.db");
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  db = drizzleSqlite(sqlite, { schema: sqliteSchema });
} else {
  const DATABASE_URL = process.env.DATABASE_URL;
  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL environment variable is required for Neon mode");
  }
  const sql = neon(DATABASE_URL);
  db = drizzle(sql, { schema: pgSchema });
}

const schema = DB_TYPE === "sqlite" ? sqliteSchema : pgSchema;
export const users = schema.users;
export const vaultBlobs = schema.vaultBlobs;

export { db };
