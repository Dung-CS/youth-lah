import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import {
  ARK_PROXY_PREFIX,
  containerProxyBaseUrl,
  HOST_GATEWAY_ALIAS,
  resolveUpstreamUrl,
  RunTokenRegistry,
} from "./credential-proxy.js";
import type { AgentService } from "./agent-service.js";

const ARK_KEY = "live-ark-key-that-must-never-leave-the-backend";

const service = {
  listAgents: () => [],
  systemInfo: async () => ({}),
} as unknown as AgentService;

function proxyConfig() {
  return loadConfig({
    NODE_ENV: "test",
    PORT: "3000",
    ARK_API_KEY: ARK_KEY,
    ARK_MODEL: "ep-test",
    ARK_BASE_URL: "https://ark.cn-beijing.volces.com/api/v3",
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("RunTokenRegistry", () => {
  it("issues unpredictable tokens and resolves them to their agent", () => {
    const registry = new RunTokenRegistry();
    const first = registry.issue("agent-a", 60_000);
    const second = registry.issue("agent-b", 60_000);

    expect(first).not.toBe(second);
    expect(first.length).toBeGreaterThanOrEqual(40);
    expect(registry.verify(first)?.agentId).toBe("agent-a");
    expect(registry.verify(second)?.agentId).toBe("agent-b");
  });

  it("rejects unknown tokens", () => {
    const registry = new RunTokenRegistry();
    registry.issue("agent-a", 60_000);

    expect(registry.verify("not-a-real-token")).toBeNull();
    expect(registry.verify("")).toBeNull();
  });

  it("rejects a token once its run is revoked", () => {
    const registry = new RunTokenRegistry();
    const token = registry.issue("agent-a", 60_000);
    expect(registry.verify(token)).not.toBeNull();

    registry.revoke(token);
    expect(registry.verify(token)).toBeNull();
    expect(registry.activeCount()).toBe(0);
  });

  it("expires tokens after the run window closes", () => {
    vi.useFakeTimers();
    const registry = new RunTokenRegistry();
    const token = registry.issue("agent-a", 60_000);

    vi.advanceTimersByTime(60_000);
    expect(registry.verify(token)).not.toBeNull();

    // 60s TTL plus the 30s grace period.
    vi.advanceTimersByTime(31_000);
    expect(registry.verify(token)).toBeNull();
    expect(registry.activeCount()).toBe(0);
  });
});

describe("resolveUpstreamUrl", () => {
  const base = "https://ark.cn-beijing.volces.com/api/v3";

  it("maps a proxied path onto the configured Ark base URL", () => {
    const url = resolveUpstreamUrl(base, "responses", "");
    expect(url?.toString()).toBe(
      "https://ark.cn-beijing.volces.com/api/v3/responses",
    );
  });

  it("preserves the query string", () => {
    const url = resolveUpstreamUrl(base, "responses", "?stream=true");
    expect(url?.search).toBe("?stream=true");
  });

  it("refuses to escape the Ark base path via traversal", () => {
    expect(resolveUpstreamUrl(base, "../../evil", "")).toBeNull();
    expect(resolveUpstreamUrl(base, "responses/../../../v1/keys", "")).toBeNull();
  });
});

describe("containerProxyBaseUrl", () => {
  it("points the container at the host gateway, not at Ark", () => {
    const url = containerProxyBaseUrl(proxyConfig());
    expect(url).toBe("http://" + HOST_GATEWAY_ALIAS + ":3000" + ARK_PROXY_PREFIX);
    expect(url).not.toContain("volces.com");
  });
});

describe("Ark credential proxy route", () => {
  it("rejects requests with a missing or invalid run token", async () => {
    const registry = new RunTokenRegistry();
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const app = await createApp(proxyConfig(), service, registry);

    const anonymous = await app.inject({
      method: "POST",
      url: ARK_PROXY_PREFIX + "/responses",
      headers: { "content-type": "application/json" },
      payload: { input: "hello" },
    });
    expect(anonymous.statusCode).toBe(401);

    const forged = await app.inject({
      method: "POST",
      url: ARK_PROXY_PREFIX + "/responses",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer forged-token",
      },
      payload: { input: "hello" },
    });
    expect(forged.statusCode).toBe(401);

    // No upstream call may be attempted for an unauthenticated request.
    expect(fetchSpy).not.toHaveBeenCalled();
    await app.close();
  });

  it("swaps a valid run token for the Ark key and streams the response back", async () => {
    const registry = new RunTokenRegistry();
    const config = proxyConfig();
    const token = registry.issue("agent-a", config.codexTimeoutMs);

    const fetchSpy = vi.fn(
      async () =>
        new Response("data: {\"type\":\"response.completed\"}\n\n", {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        }),
    );
    vi.stubGlobal("fetch", fetchSpy);

    const app = await createApp(config, service, registry);
    const response = await app.inject({
      method: "POST",
      url: ARK_PROXY_PREFIX + "/responses?stream=true",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + token,
      },
      payload: { input: "hello" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toBe("text/event-stream");
    expect(response.body).toContain("response.completed");

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [upstreamUrl, init] = fetchSpy.mock.calls[0] as unknown as [
      URL,
      RequestInit,
    ];
    expect(upstreamUrl.toString()).toBe(
      "https://ark.cn-beijing.volces.com/api/v3/responses?stream=true",
    );

    // The run token is replaced by the real key on the way out, and only here.
    const headers = init.headers as Headers;
    expect(headers.get("authorization")).toBe("Bearer " + ARK_KEY);
    expect(headers.get("authorization")).not.toContain(token);

    await app.close();
  });

  it("reports a fixed error when Ark is unreachable", async () => {
    const registry = new RunTokenRegistry();
    const config = proxyConfig();
    const token = registry.issue("agent-a", config.codexTimeoutMs);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("connect ECONNREFUSED " + ARK_KEY);
      }),
    );

    const app = await createApp(config, service, registry);
    const response = await app.inject({
      method: "POST",
      url: ARK_PROXY_PREFIX + "/responses",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + token,
      },
      payload: { input: "hello" },
    });

    expect(response.statusCode).toBe(502);
    expect(response.body).not.toContain(ARK_KEY);
    await app.close();
  });

  it("stays unmounted when no registry is supplied", async () => {
    const app = await createApp(proxyConfig(), service);
    const response = await app.inject({
      method: "POST",
      url: ARK_PROXY_PREFIX + "/responses",
      headers: { "content-type": "application/json" },
      payload: { input: "hello" },
    });
    expect(response.statusCode).toBe(404);
    await app.close();
  });
});
