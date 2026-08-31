import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { SecretBroker } from "./secret-broker.js";
import { resolveUpstreamUrl } from "./llm-proxy.js";
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

  it("strips unsupported fields like external_web_access from request body before forwarding to Ark", async () => {
    const sessionToken = SecretBroker.issueAgentSession(agentId);
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
      ARK_BASE_URL: "https://ark.cn-beijing.volces.com/api/v3",
    });

    let interceptedBody = "";

    const fetchMock = vi.fn().mockImplementation((_url: string, init: RequestInit) => {
      interceptedBody = (init.body as string) ?? "";
      return Promise.resolve(
        new Response(JSON.stringify({ id: "chat-456", choices: [{ message: { content: "OK" } }] }), {
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
      payload: {
        model: "ep-test-model",
        messages: [{ role: "user", content: "Write a hello world script" }],
        tools: [
          {
            type: "function",
            function: { name: "bash", description: "Execute bash" },
            external_web_access: false,
          },
        ],
      },
    });

    expect(res.statusCode).toBe(200);
    expect(interceptedBody).not.toContain("external_web_access");
    const parsedBody = JSON.parse(interceptedBody);
    expect(parsedBody.tools[0].type).toBe("function");
    expect(parsedBody.tools[0].function.name).toBe("bash");
    expect(parsedBody.tools[0].external_web_access).toBeUndefined();
  });

  it("successfully proxies OpenAI Responses API payload with input intact and strips external_web_access", async () => {
    const sessionToken = SecretBroker.issueAgentSession(agentId);
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
      ARK_BASE_URL: "https://ark.ap-southeast.bytepluses.com/api/v3",
    });

    let interceptedTargetUrl = "";
    let interceptedBody = "";

    const fetchMock = vi.fn().mockImplementation((url: string, init: RequestInit) => {
      interceptedTargetUrl = url;
      interceptedBody = (init.body as string) ?? "";
      return Promise.resolve(
        new Response(
          JSON.stringify({
            id: "resp-789",
            output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "Hello" }] }],
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const app = await createApp(config, mockService);

    const res = await app.inject({
      method: "POST",
      url: `/api/internal/llm-proxy/${agentId}/responses`,
      headers: {
        authorization: `Bearer ${sessionToken}`,
        "content-type": "application/json",
      },
      payload: {
        model: "ep-test-model",
        input: [
          {
            type: "message",
            role: "user",
            content: [{ type: "input_text", text: "Say hello in one word" }],
          },
        ],
        tools: [
          {
            type: "function",
            name: "bash",
            description: "Run command",
            parameters: { type: "object", properties: {} },
            external_web_access: false,
          },
        ],
      },
    });

    expect(res.statusCode).toBe(200);
    expect(interceptedTargetUrl).toBe("https://ark.ap-southeast.bytepluses.com/api/v3/responses");
    const parsedBody = JSON.parse(interceptedBody);
    expect(parsedBody.input).toBeDefined();
    expect(Array.isArray(parsedBody.input)).toBe(true);
    expect(parsedBody.tools[0].external_web_access).toBeUndefined();
    expect(res.json().id).toBe("resp-789");
  });

  it("never forwards upstream when the request path escapes the proxy prefix", async () => {
    const sessionToken = SecretBroker.issueAgentSession(agentId);
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
      ARK_BASE_URL: "https://ark.cn-beijing.volces.com/api/v3",
    });

    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const app = await createApp(config, mockService);

    // Satisfies the endpoint allowlist prefix check, then normalises upward.
    // Fastify's router normalises the path before matching, so this never
    // reaches the handler at all; resolveUpstreamUrl is the second line of
    // defence, covered by the unit tests below.
    const res = await app.inject({
      method: "POST",
      url: `/api/internal/llm-proxy/${agentId}/chat/completions/%2e%2e/%2e%2e/%2e%2e/admin`,
      headers: {
        authorization: `Bearer ${sessionToken}`,
        "content-type": "application/json",
      },
      payload: {},
    });

    expect(res.statusCode).toBe(404);
    // Whatever the routing outcome, nothing may reach the upstream provider.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  describe("resolveUpstreamUrl", () => {
    const base = "https://ark.cn-beijing.volces.com/api/v3";

    it("resolves an allowed path under the configured base", () => {
      expect(resolveUpstreamUrl(base, "chat/completions", "")?.toString()).toBe(
        "https://ark.cn-beijing.volces.com/api/v3/chat/completions",
      );
    });

    it("preserves the query string", () => {
      expect(resolveUpstreamUrl(base, "models", "?limit=10")?.toString()).toBe(
        "https://ark.cn-beijing.volces.com/api/v3/models?limit=10",
      );
    });

    it("rejects traversal that climbs out of the base path", () => {
      expect(resolveUpstreamUrl(base, "../../../etc/passwd", "")).toBeNull();
      expect(
        resolveUpstreamUrl(base, "chat/completions/../../../../admin", ""),
      ).toBeNull();
    });

    it("keeps shallow traversal inside the configured base path", () => {
      // Two segments up from chat/completions lands back on the base itself,
      // so this stays in bounds; the endpoint allowlist is what restricts it.
      expect(
        resolveUpstreamUrl(base, "chat/completions/../../admin", "")?.pathname,
      ).toBe("/api/v3/admin");
    });

    it("cannot be redirected to another origin by an absolute-looking path", () => {
      const resolved = resolveUpstreamUrl(base, "https://attacker.example.com/steal", "");
      expect(resolved?.origin).toBe("https://ark.cn-beijing.volces.com");
    });
  });

  it("accepts request bodies larger than the 1 MiB application limit", async () => {
    const sessionToken = SecretBroker.issueAgentSession(agentId);
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
      ARK_BASE_URL: "https://ark.cn-beijing.volces.com/api/v3",
    });

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "chat-large" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const app = await createApp(config, mockService);

    // A long conversation: comfortably past the 1 MiB global bodyLimit.
    const payload = {
      model: "ep-test-model",
      messages: [{ role: "user", content: "x".repeat(2 * 1024 * 1024) }],
    };
    expect(JSON.stringify(payload).length).toBeGreaterThan(1_048_576);

    const res = await app.inject({
      method: "POST",
      url: `/api/internal/llm-proxy/${agentId}/chat/completions`,
      headers: {
        authorization: `Bearer ${sessionToken}`,
        "content-type": "application/json",
      },
      payload,
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().id).toBe("chat-large");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("bounds the upstream request with an abort signal", async () => {
    const sessionToken = SecretBroker.issueAgentSession(agentId);
    const config = loadConfig({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      ARK_API_KEY: "ark-real-secret-key-12345",
      ARK_MODEL: "ep-test-model",
      ARK_BASE_URL: "https://ark.cn-beijing.volces.com/api/v3",
    });

    let interceptedSignal: unknown = undefined;
    const fetchMock = vi.fn().mockImplementation((_url: string, init: RequestInit) => {
      interceptedSignal = init.signal;
      return Promise.resolve(
        new Response(JSON.stringify({ id: "chat-signal" }), {
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
    expect(interceptedSignal).toBeInstanceOf(AbortSignal);
  });
});



