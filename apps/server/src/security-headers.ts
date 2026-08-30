import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AppConfig } from "./config.js";

export function buildCsp(isDev = false): string {
  if (isDev) {
    return [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline' https: http:",
      "style-src-elem 'self' 'unsafe-inline' https: http:",
      "style-src-attr 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https: http:",
      "connect-src 'self' ws: wss: http://localhost:5173 http://127.0.0.1:5173",
      "font-src 'self' data: https: http:",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join("; ");
  }

  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https:",
    "style-src-elem 'self' 'unsafe-inline' https:",
    "style-src-attr 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "connect-src 'self'",
    "font-src 'self' data: https:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

export function registerSecurityHeaders(app: FastifyInstance, config?: AppConfig): void {
  const isDev = config?.nodeEnv === "development";
  const cspHeader = buildCsp(isDev);

  app.addHook("onSend", async (_request: FastifyRequest, reply: FastifyReply) => {
    // 1. Content Security Policy (Prevents XSS, untrusted script execution, clickjacking framing)
    reply.header("Content-Security-Policy", cspHeader);

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

