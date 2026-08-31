import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";

const mockService = {
  systemInfo: async () => ({ ok: true }),
  listAgents: () => [],
} as unknown as AgentService;

describe("Layer 1: HTTP Security Headers", () => {
  it("attaches standard security headers to API responses", async () => {
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      APP_DATA_DIR: ".data-test",
    });
    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "GET",
      url: "/api/health",
    });

    expect(res.statusCode).toBe(200);

    // 1. Content Security Policy
    expect(res.headers["content-security-policy"]).toContain("default-src 'self'");
    expect(res.headers["content-security-policy"]).toContain("frame-ancestors 'none'");

    // 2. Anti-Clickjacking
    expect(res.headers["x-frame-options"]).toBe("DENY");

    // 3. MIME sniffing prevention
    expect(res.headers["x-content-type-options"]).toBe("nosniff");

    // 4. Referrer Policy
    expect(res.headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");

    // 5. Context Isolation
    expect(res.headers["cross-origin-opener-policy"]).toBe("same-origin");
    expect(res.headers["cross-origin-resource-policy"]).toBe("same-origin");
    expect(res.headers["permissions-policy"]).toContain("camera=()");
  });

  it("attaches Strict-Transport-Security in production mode", async () => {
    const config = loadConfig({
      NODE_ENV: "production",
      HOST: "127.0.0.1",
      APP_DATA_DIR: ".data-test",
    });
    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "GET",
      url: "/api/health",
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers["strict-transport-security"]).toContain("max-age=31536000");
  });
});

