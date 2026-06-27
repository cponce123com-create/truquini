import { Router, type Request, type Response } from "express";
import { eq } from "drizzle-orm";
import { db, vaultBlobs } from "../db/index.js";
import { authMiddleware } from "../middleware/auth.js";

const router = Router();

// All vault routes require authentication
router.use(authMiddleware);

// GET /api/vault — retrieve the encrypted blob for the authenticated user
router.get("/", async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user!.userId;

    const result = await db
      .select({
        salt: vaultBlobs.salt,
        iv: vaultBlobs.iv,
        data: vaultBlobs.data,
        version: vaultBlobs.version,
        updatedAt: vaultBlobs.updatedAt,
      })
      .from(vaultBlobs)
      .where(eq(vaultBlobs.userId, userId))
      .limit(1);

    const blob = result[0];

    if (!blob) {
      res.status(404).json({ error: "No hay bóveda guardada aún" });
      return;
    }

    res.json(blob);
  } catch (err) {
    console.error("Vault GET error:", err instanceof Error ? err.message : err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// PUT /api/vault — create or update the encrypted blob
router.put("/", async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user!.userId;
    const { salt, iv, data } = req.body;

    // Validate that fields are non-empty strings — treat content as opaque
    if (
      !salt ||
      !iv ||
      !data ||
      typeof salt !== "string" ||
      typeof iv !== "string" ||
      typeof data !== "string"
    ) {
      res.status(400).json({ error: "salt, iv y data son requeridos y deben ser strings" });
      return;
    }

    if (salt.trim().length === 0 || iv.trim().length === 0 || data.trim().length === 0) {
      res.status(400).json({ error: "salt, iv y data no pueden estar vacíos" });
      return;
    }

    // Max lengths to prevent DB abuse
    if (salt.length > 256) {
      res.status(400).json({ error: "salt excede el tamaño máximo (256 caracteres)" });
      return;
    }
    if (iv.length > 256) {
      res.status(400).json({ error: "iv excede el tamaño máximo (256 caracteres)" });
      return;
    }
    if (data.length > 5 * 1024 * 1024) {
      res.status(400).json({ error: "data excede el tamaño máximo (5MB)" });
      return;
    }

    // Upsert: check if a blob already exists for this user
    const existing = await db
      .select({ id: vaultBlobs.id, version: vaultBlobs.version })
      .from(vaultBlobs)
      .where(eq(vaultBlobs.userId, userId))
      .limit(1);

    const now = new Date().toISOString();

    if (existing.length > 0) {
      // Update existing
      await db
        .update(vaultBlobs)
        .set({
          salt,
          iv,
          data,
          version: existing[0].version + 1,
          updatedAt: now,
        })
        .where(eq(vaultBlobs.userId, userId));
    } else {
      // Insert new
      await db.insert(vaultBlobs).values({
        userId,
        salt,
        iv,
        data,
        version: 1,
        updatedAt: now,
      });
    }

    res.json({ updatedAt: now });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("Vault PUT error:", msg);
    if (err instanceof Error && err.stack) {
      console.error("Vault PUT stack:", err.stack);
    }
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

export default router;
