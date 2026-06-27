import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.js";
import vaultRoutes from "./routes/vault.js";

// Validate required environment variables early
const DB_TYPE = process.env.DB_TYPE || "neon";
const requiredEnvVars: string[] = ["JWT_SECRET", "FRONTEND_ORIGIN", "PORT"];

// DATABASE_URL is only required for Neon mode
if (DB_TYPE !== "sqlite") {
  requiredEnvVars.push("DATABASE_URL");
}

for (const varName of requiredEnvVars) {
  if (!process.env[varName]) {
    console.error(`FATAL: La variable de entorno ${varName} es requerida`);
    process.exit(1);
  }
}

const app = express();

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
      },
    },
  })
);

// CORS — only allow the configured frontend origin with credentials
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN,
    credentials: true,
  })
);

// Parse cookies (for JWT)
app.use(cookieParser());

// Parse JSON bodies — NEVER log vault request bodies
app.use(express.json({ limit: "6mb" }));

// Serve static frontend (single index.html at /)
app.use(express.static("public"));

// Mount API routes
app.use("/api/auth", authRoutes);
app.use("/api/vault", vaultRoutes);

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Start server only if not in test or serverless environment
if (!process.env.VITEST) {
  const PORT = parseInt(process.env.PORT!, 10);
  app.listen(PORT, () => {
    console.log(`vault-api corriendo en puerto ${PORT}`);
    console.log(`  DB_TYPE: ${DB_TYPE}`);
  });
}

export default app;
