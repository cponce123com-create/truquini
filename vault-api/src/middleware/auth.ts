import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET environment variable is required");
}

export interface AuthPayload {
  userId: string;
  username: string;
  tokenIssuedAt?: number;
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
 * If the token has less than 50% of its lifetime remaining, a new
 * token is issued (silent rotation).
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
    const payload = jwt.verify(token, JWT_SECRET!) as AuthPayload & {
      iat?: number;
      exp?: number;
    };

    // Silent token rotation: if less than 50% of lifetime remains, issue a new token
    if (payload.iat && payload.exp) {
      const now = Math.floor(Date.now() / 1000);
      const remaining = (payload.exp - now) / (payload.exp - payload.iat);
      if (remaining < 0.5) {
        const newToken = jwt.sign(
          { userId: payload.userId, username: payload.username, tokenIssuedAt: Date.now() },
          JWT_SECRET!,
          { expiresIn: "30d" }
        );
        res.cookie("token", newToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV !== "development",
          sameSite: "strict",
          maxAge: 30 * 24 * 60 * 60 * 1000,
          path: "/",
        });
      }
    }

    req.user = { userId: payload.userId, username: payload.username };
    next();
  } catch {
    res.status(401).json({ error: "No autorizado — token inválido o expirado" });
  }
}
