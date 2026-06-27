import { execSync } from "node:child_process";
import { rmSync, existsSync } from "node:fs";
import { resolve } from "node:path";

// Set test environment before anything else
process.env.DB_TYPE = "sqlite";
process.env.JWT_SECRET = "test-jwt-secret-for-testing-only";
process.env.FRONTEND_ORIGIN = "http://localhost:8080";
process.env.ALLOW_REGISTRATION = "true";
process.env.PORT = "0"; // random port, supertest handles it

// Clean DB and push schema
const dbPath = resolve(process.cwd(), "vault.db");
if (existsSync(dbPath)) {
  rmSync(dbPath);
}
if (existsSync(`${dbPath}-shm`)) {
  rmSync(`${dbPath}-shm`);
}
if (existsSync(`${dbPath}-wal`)) {
  rmSync(`${dbPath}-wal`);
}

execSync("npx drizzle-kit push --config=drizzle.config.ts", {
  stdio: "pipe",
  env: { ...process.env, DB_TYPE: "sqlite" },
});
