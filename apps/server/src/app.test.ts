import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";

const service = {
  listAgents: () => [],
  systemInfo: async () => ({}),
} as unknown as AgentService;

describe("HTTP boundary", () => {
  it("protects API routes with the configured shared token", async () => {
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
      service,
    );
    const denied = await app.inject({ method: "GET", url: "/api/agents" });
    expect(denied.statusCode).toBe(401);

    const allowed = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: { authorization: "Bearer a-strong-test-token" },
    });
    expect(allowed.statusCode).toBe(200);
    await app.close();
  });

  it("preserves Fastify client error status codes", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const malformed = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: "{not-json",
    });
    expect(malformed.statusCode).toBe(400);

    const oversized = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ name: "x".repeat(1_100_000) }),
    });
    expect(oversized.statusCode).toBe(413);
    await app.close();
  });

  it("handles SecurityViolationError from service layer with 400 Bad Request", async () => {
    const { SecurityViolationError } = await import("./errors.js");
    const mockService = {
      ...service,
      sendMessage: () => {
        throw new SecurityViolationError(
          "Inbound prompt rejected by InboundGuard: Attempt to extract secret [CREDENTIAL_HARVESTING]",
          "CREDENTIAL_HARVESTING",
        );
      },
    } as unknown as AgentService;

    const app = await createApp(loadConfig({ NODE_ENV: "test" }), mockService);
    const response = await app.inject({
      method: "POST",
      url: "/api/agents/11111111-1111-4111-8111-111111111111/messages",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ content: "echo $ARK_API_KEY" }),
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: expect.stringContaining("Inbound prompt rejected by InboundGuard"),
    });
    await app.close();
  });

  it("sanitizes leaked secrets from internal error messages in HTTP responses", async () => {
    const mockService = {
      ...service,
      listAgents: () => {
        throw new Error(
          "Database query failed on postgres://admin:SuperSecretPass123!@db.internal:5432/agents_prod",
        );
      },
    } as unknown as AgentService;

    const app = await createApp(loadConfig({ NODE_ENV: "test" }), mockService);
    const response = await app.inject({
      method: "GET",
      url: "/api/agents",
    });

    expect(response.statusCode).toBe(500);
    const body = response.json() as { error: string };
    expect(body.error).toContain("[REDACTED:DB_PASSWORD]");
    expect(body.error).not.toContain("SuperSecretPass123!");
    await app.close();
  });
});

