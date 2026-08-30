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

export class LlmProxyHandler {
  /**
   * Checks if an incoming sub-path is permitted under proxy endpoint policy.
   */
  static isAllowedEndpoint(path: string): boolean {
    if (!path) return false;
    const cleanPath = path.replace(/^\/+/, "").toLowerCase();
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

    // 4. Construct Upstream Target URL
    const baseUrl = config.arkBaseUrl.replace(/\/+$/, "");
    let targetUrl = `${baseUrl}/${wildcardPath}`;

    // Preserve query parameters if present
    const rawUrl = request.raw.url || "";
    const queryIndex = rawUrl.indexOf("?");
    if (queryIndex !== -1) {
      targetUrl += rawUrl.slice(queryIndex);
    }

    // 5. Build Upstream Headers (Injecting Host Master Key)
    const outgoingHeaders: Record<string, string> = {
      Authorization: `Bearer ${config.arkApiKey}`,
      Accept: (request.headers.accept as string) || "*/*",
    };

    if (request.headers["content-type"]) {
      outgoingHeaders["Content-Type"] = request.headers["content-type"] as string;
    }

    const isBodyMethod = ["POST", "PUT", "PATCH"].includes(request.method.toUpperCase());
    const bodyPayload = isBodyMethod
      ? typeof request.body === "string" || Buffer.isBuffer(request.body)
        ? request.body
        : JSON.stringify(request.body)
      : undefined;

    try {
      // 6. Forward Request to Upstream LLM Provider
      const fetchOptions: RequestInit = {
        method: request.method,
        headers: outgoingHeaders,
      };
      if (bodyPayload !== undefined) {
        fetchOptions.body = bodyPayload;
      }

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

export function registerLlmProxy(app: FastifyInstance, config: AppConfig): void {
  app.all("/api/internal/llm-proxy/:agentId/*", async (request, reply) => {
    return LlmProxyHandler.handleProxyRequest(request, reply, config);
  });
}
