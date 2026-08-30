import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AppConfig } from "./config.js";

export const DEFAULT_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

export function registerSecurityHeaders(app: FastifyInstance, config?: AppConfig): void {
  app.addHook("onSend", async (_request: FastifyRequest, reply: FastifyReply) => {
    // 1. Content Security Policy (Prevents XSS, untrusted script execution, clickjacking framing)
    reply.header("Content-Security-Policy", DEFAULT_CSP);

    // 2. Anti-Clickjacking
    reply.header("X-Frame-Options", "DENY");

    // 3. MIME-Type Sniffing Protection
    reply.header("X-Content-Type-Options", "nosniff");

    // 4. Referrer Policy (Prevents leaking URL paths / query params to external origins)
    reply.header("Referrer-Policy", "strict-origin-when-cross-origin");

    // 5. Disable Unused Dangerous Browser Features
    reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

    // 6. Cross-Origin Context Isolation
    reply.header("Cross-Origin-Opener-Policy", "same-origin");
    reply.header("Cross-Origin-Resource-Policy", "same-origin");

    // 7. Strict-Transport-Security (HSTS in production or non-loopback)
    if (config?.nodeEnv === "production") {
      reply.header(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
      );
    }
  });
}

