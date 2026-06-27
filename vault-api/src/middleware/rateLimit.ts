import rateLimit from "express-rate-limit";

/**
 * Rate limiter for login endpoint: max 10 attempts per 15 minutes per IP.
 */
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Demasiados intentos de inicio de sesión. Intenta de nuevo en 15 minutos.",
  },
});

/**
 * Rate limiter for registration: max 3 attempts per 15 minutes per IP.
 * More restrictive than login to prevent mass account creation.
 */
export const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Demasiados intentos de registro. Intenta de nuevo en 15 minutos.",
  },
});
