import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";

const mockService = {
  createAgent: async () => ({ id: "11111111-1111-4111-8111-111111111111", name: "Test" }),
  systemInfo: async () => ({ ok: true }),
  listAgents: () => [],
} as unknown as AgentService;

describe("Layer 1: CSRF & Origin Guard", () => {
  it("allows same-origin mutating requests", async () => {
    const config = loadConfig({
      NODE_ENV: "production",
      HOST: "127.0.0.1",
      APP_DATA_DIR: ".data-test",
    });
    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: {
        "sec-fetch-site": "same-origin",
        "content-type": "application/json",
      },
      payload: { name: "Agent 1" },
    });

    expect(res.statusCode).toBe(201);
  });

  it("blocks cross-site mutating requests with 403 Forbidden", async () => {
    const config = loadConfig({
      NODE_ENV: "production",
      HOST: "127.0.0.1",
      APP_DATA_DIR: ".data-test",
    });
    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: {
        "sec-fetch-site": "cross-site",
        "content-type": "application/json",
      },
      payload: { name: "Attacker Agent" },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.error).toContain("CSRF protection");
  });

  it("blocks untrusted origin headers", async () => {
    const config = loadConfig({
      NODE_ENV: "production",
      HOST: "127.0.0.1",
      APP_DATA_DIR: ".data-test",
    });
    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: {
        origin: "https://evil-hacker.com",
        host: "launchpad.internal",
        "content-type": "application/json",
      },
      payload: { name: "Attacker Agent" },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.error).toContain("Untrusted Origin");
  });
});

