import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

export interface RateLimitOptions {
  windowMs?: number;
  maxRequests?: number;
  authMaxRequests?: number;
}

interface ClientRecord {
  count: number;
  authCount: number;
  resetTime: number;
}

export class InMemoryRateLimiter {
  private readonly clients = new Map<string, ClientRecord>();
  private readonly windowMs: number;
  private readonly maxRequests: number;
  private readonly authMaxRequests: number;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(options?: RateLimitOptions) {
    this.windowMs = options?.windowMs ?? 60_000; // 1 minute
    this.maxRequests = options?.maxRequests ?? 300; // 300 req / min general
    this.authMaxRequests = options?.authMaxRequests ?? 30; // 30 req / min auth attempts
  }

  startCleanup(): void {
    if (!this.cleanupInterval) {
      this.cleanupInterval = setInterval(() => this.cleanup(), this.windowMs);
      this.cleanupInterval.unref();
    }
  }

  stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  reset(): void {
    this.clients.clear();
  }

  checkLimit(
    ip: string,
    isAuthEndpoint = false,
  ): { allowed: boolean; remaining: number; resetTime: number; limit: number } {
    const now = Date.now();
    let record = this.clients.get(ip);

    if (!record || now >= record.resetTime) {
      record = {
        count: 0,
        authCount: 0,
        resetTime: now + this.windowMs,
      };
      this.clients.set(ip, record);
    }

    record.count++;
    if (isAuthEndpoint) {
      record.authCount++;
    }

    const limit = isAuthEndpoint ? this.authMaxRequests : this.maxRequests;
    const currentCount = isAuthEndpoint ? record.authCount : record.count;
    const remaining = Math.max(0, limit - currentCount);
    const allowed = currentCount <= limit;

    return {
      allowed,
      remaining,
      resetTime: record.resetTime,
      limit,
    };
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [ip, record] of this.clients.entries()) {
      if (now >= record.resetTime) {
        this.clients.delete(ip);
      }
    }
  }
}

export function registerRateLimiter(
  app: FastifyInstance,
  options?: RateLimitOptions,
): InMemoryRateLimiter {
  const limiter = new InMemoryRateLimiter(options);
  limiter.startCleanup();

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    // Skip static assets and favicon
    if (
      !request.url.startsWith("/api/") &&
      request.url !== "/" &&
      !request.url.startsWith("/index.html")
    ) {
      return;
    }

    const ip = request.ip || request.socket.remoteAddress || "127.0.0.1";
    const isAuthEndpoint = request.url === "/api/auth" || request.headers.authorization !== undefined;
    const result = limiter.checkLimit(ip, isAuthEndpoint);

    const retryAfterSecs = Math.max(1, Math.ceil((result.resetTime - Date.now()) / 1000));
    reply.header("RateLimit-Limit", result.limit);
    reply.header("RateLimit-Remaining", result.remaining);
    reply.header("RateLimit-Reset", Math.ceil(result.resetTime / 1000));

    if (!result.allowed) {
      reply.header("Retry-After", retryAfterSecs);
      return reply.code(429).send({
        error: "Too many requests. Please try again later.",
        retryAfter: retryAfterSecs,
      });
    }
  });

  return limiter;
}

