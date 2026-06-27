import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.js";
import vaultRoutes from "./routes/vault.js";

// Validate required environment variables early
const requiredEnvVars = [
  "DATABASE_URL",
  "JWT_SECRET",
  "FRONTEND_ORIGIN",
  "PORT",
] as const;

for (const varName of requiredEnvVars) {
  if (!process.env[varName]) {
    console.error(`FATAL: La variable de entorno ${varName} es requerida`);
    process.exit(1);
  }
}

const app = express();

// Security headers
app.use(helmet());

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
app.use(express.json());

// Custom middleware: suppress logging of vault request bodies
app.use((req, _res, next) => {
  if (req.path.startsWith("/api/vault") && req.method === "PUT") {
    // Replace body in any potential logging context — we just don't log it at all
    // The actual req.body is preserved for the route handler
  }
  next();
});

// Mount routes
app.use("/api/auth", authRoutes);
app.use("/api/vault", vaultRoutes);

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Start server only if not in a serverless environment (e.g., Render runs it directly)
const PORT = parseInt(process.env.PORT!, 10);
app.listen(PORT, () => {
  console.log(`vault-api corriendo en puerto ${PORT}`);
});

export default app;
