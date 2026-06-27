import { Router, type Request, type Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { eq } from "drizzle-orm";
import { db } from "../db/index.js";
import { users } from "../db/schema.js";
import { loginRateLimiter } from "../middleware/rateLimit.js";
import { authMiddleware, type AuthPayload } from "../middleware/auth.js";

const router = Router();

const JWT_SECRET = process.env.JWT_SECRET!;
const BCRYPT_ROUNDS = 12;
const JWT_EXPIRY = "30d";

// POST /api/auth/register
router.post(
  "/register",
  async (req: Request, res: Response): Promise<void> => {
    try {
      // Check if registration is allowed
      if (process.env.ALLOW_REGISTRATION !== "true") {
        res.status(403).json({ error: "El registro está deshabilitado" });
        return;
      }

      const { username, password } = req.body;

      // Validate input
      if (
        !username ||
        !password ||
        typeof username !== "string" ||
        typeof password !== "string"
      ) {
        res.status(400).json({ error: "Username y password son requeridos" });
        return;
      }

      if (username.trim().length < 1 || password.length < 1) {
        res.status(400).json({ error: "Username y password no pueden estar vacíos" });
        return;
      }

      // Check if username already exists
      const existing = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.username, username.trim()))
        .limit(1);

      if (existing.length > 0) {
        res.status(409).json({ error: "El usuario ya existe" });
        return;
      }

      // Hash password and create user
      const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

      await db.insert(users).values({
        username: username.trim(),
        passwordHash,
      });

      res.status(201).json({ message: "Usuario creado exitosamente" });
    } catch (err) {
      console.error("Register error:", err instanceof Error ? err.message : err);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  }
);

// POST /api/auth/login
router.post(
  "/login",
  loginRateLimiter,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { username, password } = req.body;

      if (
        !username ||
        !password ||
        typeof username !== "string" ||
        typeof password !== "string"
      ) {
        res.status(400).json({ error: "Usuario o contraseña incorrectos" });
        return;
      }

      // Find user
      const result = await db
        .select()
        .from(users)
        .where(eq(users.username, username.trim()))
        .limit(1);

      const user = result[0];

      if (!user) {
        res.status(401).json({ error: "Usuario o contraseña incorrectos" });
        return;
      }

      // Compare password
      const valid = await bcrypt.compare(password, user.passwordHash);
      if (!valid) {
        res.status(401).json({ error: "Usuario o contraseña incorrectos" });
        return;
      }

      // Generate JWT
      const payload: AuthPayload = {
        userId: user.id,
        username: user.username,
      };

      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });

      // Set cookie
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days in ms
        path: "/",
      });

      res.json({ username: user.username });
    } catch (err) {
      console.error("Login error:", err instanceof Error ? err.message : err);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  }
);

// POST /api/auth/logout
router.post("/logout", (_req: Request, res: Response): void => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  });
  res.json({ message: "Sesión cerrada" });
});

// GET /api/auth/me
router.get(
  "/me",
  authMiddleware,
  (req: Request, res: Response): void => {
    res.json({ username: req.user!.username });
  }
);

export default router;
