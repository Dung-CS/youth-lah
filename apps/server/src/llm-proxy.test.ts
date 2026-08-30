import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { SecretBroker } from "./secret-broker.js";
import type { AgentService } from "./agent-service.js";

const mockService = {
  systemInfo: async () => ({ ok: true }),
  listAgents: () => [],
} as unknown as AgentService;

describe("Layer 2: Host-Side LLM Secret Broker & Reverse Proxy", () => {
  const agentId = "11111111-1111-4111-8111-111111111111";

  beforeEach(() => {
    SecretBroker.resetSessions();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    SecretBroker.resetSessions();
    vi.restoreAllMocks();
  });

  it("rejects proxy requests without a session token (401)", async () => {
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
    });
    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "POST",
      url: `/api/internal/llm-proxy/${agentId}/chat/completions`,
      payload: { model: "ep-test-model", messages: [] },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toContain("session authentication required");
  });

  it("rejects proxy requests with an invalid or forged session token (403)", async () => {
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
    });
    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "POST",
      url: `/api/internal/llm-proxy/${agentId}/chat/completions`,
      headers: {
        authorization: "Bearer ast_forged_invalid_token_12345",
      },
      payload: { model: "ep-test-model", messages: [] },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error).toContain("Invalid, expired, or revoked");
  });

  it("rejects proxy requests for endpoints not in the allowlist (403)", async () => {
    const sessionToken = SecretBroker.issueAgentSession(agentId);
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
    });
    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "POST",
      url: `/api/internal/llm-proxy/${agentId}/admin/billing/invoices`,
      headers: {
        authorization: `Bearer ${sessionToken}`,
      },
      payload: {},
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error).toContain("not permitted by LLM proxy security policy");
  });

  it("rejects proxy requests after session is revoked (403)", async () => {
    const sessionToken = SecretBroker.issueAgentSession(agentId);
    SecretBroker.revokeAgentSession(agentId);

    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
    });
    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "POST",
      url: `/api/internal/llm-proxy/${agentId}/chat/completions`,
      headers: {
        authorization: `Bearer ${sessionToken}`,
      },
      payload: { model: "ep-test-model", messages: [] },
    });

    expect(res.statusCode).toBe(403);
  });

  it("successfully proxies authorized LLM request and attaches real host ARK_API_KEY", async () => {
    const sessionToken = SecretBroker.issueAgentSession(agentId);
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
      ARK_BASE_URL: "https://ark.cn-beijing.volces.com/api/v3",
    });

    let interceptedAuthHeader = "";
    let interceptedTargetUrl = "";

    // Mock global fetch to verify outbound request headers
    const fetchMock = vi.fn().mockImplementation((url: string, init: RequestInit) => {
      interceptedTargetUrl = url;
      interceptedAuthHeader = (init.headers as Record<string, string>)?.Authorization ?? "";
      return Promise.resolve(
        new Response(JSON.stringify({ id: "chat-123", choices: [{ message: { content: "Hello!" } }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "POST",
      url: `/api/internal/llm-proxy/${agentId}/chat/completions`,
      headers: {
        authorization: `Bearer ${sessionToken}`,
        "content-type": "application/json",
      },
      payload: { model: "ep-test-model", messages: [{ role: "user", content: "Hi" }] },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.id).toBe("chat-123");

    // Verify upstream forwarding
    expect(interceptedTargetUrl).toBe("https://ark.cn-beijing.volces.com/api/v3/chat/completions");
    // Verify host master key was injected
    expect(interceptedAuthHeader).toBe("Bearer ark-real-secret-key-12345");
  });
});

