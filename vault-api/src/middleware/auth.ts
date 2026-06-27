import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET environment variable is required");
}

export interface AuthPayload {
  userId: string;
  username: string;
}

// Extend Express Request to carry the authenticated user payload
declare global {
  namespace Express {
    interface Request {
      user?: AuthPayload;
    }
  }
}

/**
 * Middleware that verifies the JWT from the "token" cookie.
 * If valid, sets req.user and calls next(). Otherwise returns 401.
 */
export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const token = req.cookies?.token;

  if (!token) {
    res.status(401).json({ error: "No autorizado — token ausente" });
    return;
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET!) as AuthPayload;
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: "No autorizado — token inválido o expirado" });
  }
}
