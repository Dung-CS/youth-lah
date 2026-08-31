import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AppConfig } from "./config.js";
import { SecretBroker } from "./secret-broker.js";

// Allowlist of permitted upstream model provider endpoint prefixes
export const ALLOWED_LLM_ENDPOINTS = [
  "chat/completions",
  "responses",
  "models",
  "embeddings",
] as const;

// Route prefix of the in-process LLM proxy.
export const LLM_PROXY_PREFIX = "/api/internal/llm-proxy";

// Model requests carry the whole conversation, so they routinely exceed the
// 1 MiB application body limit. Scoped to the proxy route only.
export const LLM_PROXY_BODY_LIMIT = 33_554_432;

/**
 * Resolves the upstream Ark URL for a proxied request path, rejecting anything
 * that would escape the configured Ark base URL.
 *
 * The endpoint allowlist alone does not close this: a path such as
 * "chat/completions/../../admin" satisfies the allowlist prefix check and then
 * normalises upward at fetch time.
 */
export function resolveUpstreamUrl(
  arkBaseUrl: string,
  requestPath: string,
  search: string,
): URL | null {
  let base: URL;
  try {
    base = new URL(arkBaseUrl);
  } catch {
    return null;
  }
  const basePath = base.pathname.replace(/\/+$/, "");
  const suffix = requestPath.replace(/^\/+/, "");
  let target: URL;
  try {
    // URL normalises "." and ".." segments, so a traversal attempt lands
    // outside the base pathname and is rejected below.
    target = new URL(basePath + "/" + suffix + search, base);
  } catch {
    return null;
  }
  if (target.origin !== base.origin) return null;
  if (!target.pathname.startsWith(basePath + "/")) return null;
  return target;
}

/**
 * Recursively removes unsupported/incompatible fields from LLM request payloads
 * (such as Codex-specific `external_web_access` inside tools or messages)
 * before sending to Volcengine Ark API.
 */
export function sanitizeArkPayload(data: unknown): unknown {
  if (data === null || data === undefined) return data;
  if (typeof data !== "object") return data;

  if (Array.isArray(data)) {
    return data.map((item) => sanitizeArkPayload(item));
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    // Strip external_web_access which is rejected by Volcengine Ark schema validator
    if (key === "external_web_access") {
      continue;
    }

    if (key === "tools" && Array.isArray(value)) {
      result[key] = value.map((tool) => {
        if (!tool || typeof tool !== "object") return tool;
        const cleanedTool: Record<string, unknown> = {};
        for (const [tKey, tVal] of Object.entries(tool as Record<string, unknown>)) {
          if (tKey === "external_web_access") continue;
          cleanedTool[tKey] = sanitizeArkPayload(tVal);
        }
        return cleanedTool;
      });
      continue;
    }

    if (key === "input" && Array.isArray(value)) {
      result[key] = value.map((item) => {
        if (!item || typeof item !== "object") return item;
        const cleanedItem = sanitizeArkPayload(item) as Record<string, unknown>;
        if (typeof cleanedItem === "object" && cleanedItem !== null && !cleanedItem.status) {
          cleanedItem.status = "completed";
        }
        return cleanedItem;
      });
      continue;
    }

    if (key === "instructions" && typeof value === "string") {
      result[key] =
        value +
        "\nAlways respond in English when the user writes in English. Never acknowledge or echo system date/time metadata.";
      continue;
    }

    result[key] = sanitizeArkPayload(value);
  }

  if (result.input && !result.instructions) {
    result.instructions =
      "You are a coding assistant. Always respond in English when prompted in English. Directly complete the user's coding and workspace requests. Never acknowledge, echo, or discuss system time or date metadata.";
  }

  return result;
}

export class LlmProxyHandler {
  /**
   * Checks if an incoming sub-path is permitted under proxy endpoint policy.
   */
  static isAllowedEndpoint(path: string): boolean {
    if (!path) return false;
    const cleanPath = path
      .replace(/^\/+/, "")
      .replace(/^api\/v3\//i, "")
      .replace(/^v1\//i, "")
      .toLowerCase();
    return ALLOWED_LLM_ENDPOINTS.some(
      (allowed) => cleanPath === allowed || cleanPath.startsWith(allowed + "/"),
    );
  }

  /**
   * Proxies an authenticated LLM request from a sandboxed container to the upstream model provider.
   */
  static async handleProxyRequest(
    request: FastifyRequest,
    reply: FastifyReply,
    config: AppConfig,
  ): Promise<unknown> {
    const params = request.params as { agentId?: string; "*"?: string };
    const agentId = params.agentId || "";
    const wildcardPath = (params["*"] || "").replace(/^\/+/, "");

    // 1. Authenticate Container Session Token
    const authHeader = request.headers.authorization || "";
    const sessionToken = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : authHeader.trim();

    if (!sessionToken) {
      return reply.code(401).send({ error: "Agent session authentication required" });
    }

    const isValidSession = SecretBroker.verifyAgentSession(agentId, sessionToken);
    if (!isValidSession) {
      return reply.code(403).send({ error: "Invalid, expired, or revoked agent session token" });
    }

    // 2. Enforce Endpoint Whitelist (Prevent administrative / billing abuse)
    if (!this.isAllowedEndpoint(wildcardPath)) {
      return reply.code(403).send({
        error: `Endpoint '${wildcardPath}' is not permitted by LLM proxy security policy`,
      });
    }

    // 3. Verify Upstream Host Configuration
    if (!config.arkApiKey || config.arkApiKey.startsWith("replace-")) {
      return reply.code(503).send({
        error: "Upstream Ark API key is not configured on the host server",
      });
    }

    // 4. Construct and validate the upstream target URL
    const baseUrl = config.arkBaseUrl.replace(/\/+$/, "");
    let targetPath = wildcardPath.replace(/^\/+/, "");
    if (baseUrl.endsWith("/api/v3") && targetPath.startsWith("api/v3/")) {
      targetPath = targetPath.slice("api/v3/".length);
    }
    if (targetPath.startsWith("v1/")) {
      targetPath = targetPath.slice("v1/".length);
    }

    // Preserve query parameters if present
    const rawUrl = request.raw.url || "";
    const queryIndex = rawUrl.indexOf("?");
    const search = queryIndex === -1 ? "" : rawUrl.slice(queryIndex);

    const upstream = resolveUpstreamUrl(baseUrl, targetPath, search);
    if (!upstream) {
      return reply.code(400).send({ error: "Invalid upstream path" });
    }
    const targetUrl = upstream.toString();

    // 5. Build Upstream Headers (Injecting Host Master Key)
    const outgoingHeaders: Record<string, string> = {
      Authorization: `Bearer ${config.arkApiKey}`,
      Accept: (request.headers.accept as string) || "*/*",
    };

    if (request.headers["content-type"]) {
      outgoingHeaders["Content-Type"] = request.headers["content-type"] as string;
    }

    const isBodyMethod = ["POST", "PUT", "PATCH"].includes(request.method.toUpperCase());
    let bodyPayload: string | Buffer | undefined = undefined;

    if (isBodyMethod && request.body !== undefined) {
      if (typeof request.body === "string") {
        try {
          const parsed = JSON.parse(request.body);
          const sanitized = sanitizeArkPayload(parsed);
          bodyPayload = JSON.stringify(sanitized);
          outgoingHeaders["Content-Type"] = "application/json";
        } catch {
          bodyPayload = request.body;
        }
      } else if (Buffer.isBuffer(request.body)) {
        try {
          const text = request.body.toString("utf8");
          const parsed = JSON.parse(text);
          const sanitized = sanitizeArkPayload(parsed);
          bodyPayload = JSON.stringify(sanitized);
          outgoingHeaders["Content-Type"] = "application/json";
        } catch {
          bodyPayload = request.body;
        }
      } else if (typeof request.body === "object" && request.body !== null) {
        const sanitized = sanitizeArkPayload(request.body);
        bodyPayload = JSON.stringify(sanitized);
        outgoingHeaders["Content-Type"] = "application/json";
      }
    }

    try {
      // 6. Forward Request to Upstream LLM Provider
      const fetchOptions: RequestInit = {
        method: request.method,
        headers: outgoingHeaders,
        // Bound the upstream call: without a signal a hung provider holds the
        // request open indefinitely.
        signal: AbortSignal.timeout(config.codexTimeoutMs),
      };
      if (bodyPayload !== undefined) {
        fetchOptions.body = bodyPayload;
      }

      // Never log bodyPayload itself: it carries the entire conversation, and
      // the logger's redact list only covers headers. Size is enough to debug
      // forwarding without writing user prompts to disk.
      request.log.info(
        {
          targetUrl,
          bodyBytes: bodyPayload === undefined ? 0 : Buffer.byteLength(bodyPayload),
        },
        "LLM proxy forwarding request",
      );
      const upstreamResponse = await fetch(targetUrl, fetchOptions);

      reply.code(upstreamResponse.status);

      // Forward relevant response headers
      const contentType = upstreamResponse.headers.get("content-type");
      if (contentType) {
        reply.header("Content-Type", contentType);
      }
      const cacheControl = upstreamResponse.headers.get("cache-control");
      if (cacheControl) {
        reply.header("Cache-Control", cacheControl);
      }

      // Stream response body directly back to container (supports SSE / JSON)
      if (upstreamResponse.body) {
        return reply.send(upstreamResponse.body);
      }

      return reply.send();
    } catch (error) {
      request.log.error(error, "Upstream LLM proxy forwarding failed");
      return reply.code(502).send({
        error: "Failed to connect to upstream model provider from host proxy",
      });
    }
  }
}

export async function registerLlmProxy(
  app: FastifyInstance,
  config: AppConfig,
): Promise<void> {
  await app.register(
    async (scope) => {
      // Forward request bodies verbatim: the proxy must not reinterpret the
      // payload, and the application-wide JSON limit is far too small here.
      scope.removeAllContentTypeParsers();
      scope.addContentTypeParser(
        "*",
        { parseAs: "buffer", bodyLimit: LLM_PROXY_BODY_LIMIT },
        (
          _request: FastifyRequest,
          body: Buffer,
          done: (err: Error | null, result?: unknown) => void,
        ) => {
          done(null, body);
        },
      );

      scope.all(
        "/:agentId/*",
        { bodyLimit: LLM_PROXY_BODY_LIMIT },
        async (request: FastifyRequest, reply: FastifyReply) => {
          return LlmProxyHandler.handleProxyRequest(request, reply, config);
        },
      );
    },
    { prefix: LLM_PROXY_PREFIX },
  );
}
