import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AppConfig } from "./config.js";

const MUTATING_METHODS = new Set(["POST", "PATCH", "DELETE", "PUT"]);

export class CsrfGuard {
  /**
   * Evaluates whether an incoming HTTP request complies with CSRF and Origin policy.
   */
  static validateRequest(
    request: FastifyRequest,
    config?: AppConfig,
  ): { allowed: boolean; reason?: string } {
    // Non-mutating methods (GET, HEAD, OPTIONS) do not alter server state
    if (!MUTATING_METHODS.has(request.method)) {
      return { allowed: true };
    }

    // 1. Sec-Fetch-Site validation (Modern Browser Metadata)
    const secFetchSite = request.headers["sec-fetch-site"];
    if (typeof secFetchSite === "string") {
      const site = secFetchSite.toLowerCase().trim();
      if (site === "cross-site") {
        // In development mode, allow cross-site only from localhost vite dev server (5173)
        if (config?.nodeEnv === "development") {
          const origin = request.headers.origin;
          if (
            origin === "http://localhost:5173" ||
            origin === "http://127.0.0.1:5173"
          ) {
            return { allowed: true };
          }
        }
        return {
          allowed: false,
          reason: "Cross-site request blocked by CSRF protection (Sec-Fetch-Site: cross-site)",
        };
      }
    }

    // 2. Origin & Referer Header Validation (if present)
    const origin = request.headers.origin;
    if (origin && typeof origin === "string") {
      const host = request.headers.host;
      if (host) {
        const originUrl = new URL(origin);
        const hostWithoutPort = host.split(":")[0];
        const isSameHost =
          originUrl.hostname === hostWithoutPort ||
          originUrl.host === host ||
          (config?.nodeEnv === "development" &&
            (originUrl.hostname === "localhost" || originUrl.hostname === "127.0.0.1"));

        if (!isSameHost) {
          return {
            allowed: false,
            reason: `Untrusted Origin header (${origin}) does not match server host (${host})`,
          };
        }
      }
    }

    return { allowed: true };
  }
}

export function registerCsrfGuard(app: FastifyInstance, config?: AppConfig): void {
  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    // Only guard API routes
    if (!request.url.startsWith("/api/")) {
      return;
    }

    const decision = CsrfGuard.validateRequest(request, config);
    if (!decision.allowed) {
      return reply.code(403).send({
        error: decision.reason ?? "Forbidden: CSRF validation failed",
      });
    }
  });
}

