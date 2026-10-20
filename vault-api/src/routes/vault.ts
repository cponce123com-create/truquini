import { Router, type Request, type Response } from "express";
import { eq, sql } from "drizzle-orm";
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
        kdf: vaultBlobs.kdf,
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
    const { salt, iv, data, kdf, baseVersion } = req.body;

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

    // baseVersion es obligatorio: sin él, un cliente viejo podría pisar
    // silenciosamente los cambios de otra pestaña/dispositivo.
    if (!Number.isInteger(baseVersion) || baseVersion < 0) {
      res.status(400).json({
        error: "baseVersion es requerido y debe ser un entero mayor o igual a 0",
      });
      return;
    }

    // El KDF es metadata pública (algoritmo, hash e iteraciones), nunca la
    // contraseña ni la clave. Se guarda como texto JSON opaco para el servidor.
    if (
      kdf !== undefined &&
      kdf !== null &&
      (typeof kdf !== "string" || kdf.trim().length === 0 || kdf.length > 512)
    ) {
      res.status(400).json({
        error: "kdf debe ser un string JSON no vacío de hasta 512 caracteres",
      });
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

    // Upsert atómico con control optimista de concurrencia. El WHERE de
    // DO UPDATE hace que la escritura solo ocurra si la versión que vio el
    // cliente sigue siendo la actual; si no, no se modifica nada y se
    // responde 409 con la versión vigente.
    const now = process.env.DB_TYPE === "sqlite"
      ? new Date().toISOString()
      : new Date();

    const [saved] = await db
      .insert(vaultBlobs)
      .values({
        userId,
        salt,
        iv,
        data,
        kdf: typeof kdf === "string" ? kdf : null,
        version: 1,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: vaultBlobs.userId,
        set: {
          salt,
          iv,
          data,
          kdf: typeof kdf === "string" ? kdf : null,
          version: sql`${vaultBlobs.version} + 1`,
          updatedAt: now,
        },
        where: sql`${vaultBlobs.version} = ${baseVersion}`,
      })
      .returning({
        version: vaultBlobs.version,
        updatedAt: vaultBlobs.updatedAt,
      });

    if (!saved) {
      // El upsert condicional no devolvió fila: hay otra versión en el
      // servidor (o una carrera la cambió justo antes). Consultamos la
      // versión actual solo para informar al cliente; no escribimos nada.
      const [current] = await db
        .select({
          version: vaultBlobs.version,
          updatedAt: vaultBlobs.updatedAt,
        })
        .from(vaultBlobs)
        .where(eq(vaultBlobs.userId, userId))
        .limit(1);

      res.status(409).json({
        error:
          "La bóveda fue modificada en otra pestaña o dispositivo. Recarga antes de guardar.",
        version: current?.version ?? 0,
        updatedAt: current?.updatedAt ?? null,
      });
      return;
    }

    res.json(saved);
  } catch {
    // No registrar el error completo: puede incluir parámetros de la consulta
    // con el blob cifrado. El README promete no loguear datos de la bóveda.
    console.error("Vault PUT error");
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

export default router;
