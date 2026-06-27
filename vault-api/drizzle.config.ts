import { defineConfig } from "drizzle-kit";

const DB_TYPE = process.env.DB_TYPE || "neon";

export default DB_TYPE === "sqlite"
  ? defineConfig({
      schema: "./src/db/schema.ts",
      out: "./drizzle",
      dialect: "sqlite",
      dbCredentials: {
        url: "./vault.db",
      },
    })
  : defineConfig({
      schema: "./src/db/schema-pg.ts",
      out: "./drizzle",
      dialect: "postgresql",
      dbCredentials: {
        url: process.env.DATABASE_URL!,
      },
    });
