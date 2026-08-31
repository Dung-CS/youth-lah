import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { InMemoryRateLimiter } from "./rate-limiter.js";
import type { AgentService } from "./agent-service.js";

describe("Layer 1: In-Memory Rate Limiter", () => {
  it("allows requests under the limit and provides rate limit headers", () => {
    const limiter = new InMemoryRateLimiter({
      windowMs: 10_000,
      maxRequests: 5,
      authMaxRequests: 2,
    });

    const check1 = limiter.checkLimit("192.168.1.10", false);
    expect(check1.allowed).toBe(true);
    expect(check1.remaining).toBe(4);
    expect(check1.limit).toBe(5);

    const check2 = limiter.checkLimit("192.168.1.10", false);
    expect(check2.allowed).toBe(true);
    expect(check2.remaining).toBe(3);
  });

  it("enforces stricter limits on auth endpoints", () => {
    const limiter = new InMemoryRateLimiter({
      windowMs: 10_000,
      maxRequests: 10,
      authMaxRequests: 2,
    });

    expect(limiter.checkLimit("192.168.1.20", true).allowed).toBe(true);
    expect(limiter.checkLimit("192.168.1.20", true).allowed).toBe(true);
    // 3rd attempt should be blocked
    const blocked = limiter.checkLimit("192.168.1.20", true);
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
  });

  it("resets limits after reset()", () => {
    const limiter = new InMemoryRateLimiter({
      windowMs: 10_000,
      maxRequests: 2,
    });

    limiter.checkLimit("10.0.0.1");
    limiter.checkLimit("10.0.0.1");
    expect(limiter.checkLimit("10.0.0.1").allowed).toBe(false);

    limiter.reset();
    expect(limiter.checkLimit("10.0.0.1").allowed).toBe(true);
  });
});

