import { randomBytes, timingSafeEqual } from "node:crypto";
import { Readable } from "node:stream";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AppConfig } from "./config.js";

// Environment variable Codex reads for its bearer credential inside the Runtime
// container. Deliberately NOT named ARK_API_KEY: the container never receives
// the real Ark key, only a short-lived token scoped to a single run.
export const RUN_TOKEN_ENV_KEY = "LAUNCHPAD_RUN_TOKEN";

// Route prefix of the in-process credential proxy.
export const ARK_PROXY_PREFIX = "/ark-proxy";

// Hostname alias the Runtime container uses to reach the backend process.
export const HOST_GATEWAY_ALIAS = "host.docker.internal";

// Model requests carry the whole conversation, so they routinely exceed the
// 1 MiB application body limit. Scoped to the proxy route only.
export const ARK_PROXY_BODY_LIMIT = 33_554_432;

// Grace period so a token stays valid slightly beyond the Codex timeout.
const RUN_TOKEN_GRACE_MS = 30_000;

const HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
] as const;

// Dropped on the way to Ark: the container's bearer is a run token, never a
// credential Ark would accept, and it must not be forwarded.
const STRIPPED_REQUEST_HEADERS = new Set<string>([
  ...HOP_BY_HOP_HEADERS,
  "authorization",
  "cookie",
  "accept-encoding",
]);

// Dropped on the way back: undici has already decoded the body, so a stale
// content-encoding would make the container fail to parse the stream.
const STRIPPED_RESPONSE_HEADERS = new Set<string>([
  ...HOP_BY_HOP_HEADERS,
  "content-encoding",
  "set-cookie",
]);

export interface RunTokenLease {
  agentId: string;
  expiresAt: number;
}

/**
 * Issues and validates single-run bearer tokens for the credential proxy.
 *
 * A token is the only credential that ever enters a Runtime container. It is
 * meaningless outside this process: the proxy exchanges it for the real Ark key
 * and discards it when the run ends.
 */
export class RunTokenRegistry {
  private readonly leases = new Map<string, RunTokenLease>();

  /**
   * Mints a token for one agent run. TTL defaults to the Codex timeout plus a
   * grace period so an in-flight request cannot be rejected mid-stream.
   */
  issue(agentId: string, ttlMs: number): string {
    const token = randomBytes(32).toString("base64url");
    this.leases.set(token, {
      agentId,
      expiresAt: Date.now() + Math.max(ttlMs, 0) + RUN_TOKEN_GRACE_MS,
    });
    return token;
  }

  /**
   * Invalidates a token. Called when a run settles, cancels, or times out.
   */
  revoke(token: string): void {
    this.leases.delete(token);
  }

  /**
   * Resolves a candidate token to its lease, or null when unknown or expired.
   * Compares in constant time and never short-circuits on a match.
   */
  verify(candidate: string): RunTokenLease | null {
    if (!candidate) return null;
    const now = Date.now();
    const candidateBuffer = Buffer.from(candidate);
    let matched: RunTokenLease | null = null;

    for (const [token, lease] of this.leases) {
      if (lease.expiresAt <= now) {
        this.leases.delete(token);
        continue;
      }
      const tokenBuffer = Buffer.from(token);
      if (
        tokenBuffer.length === candidateBuffer.length &&
        timingSafeEqual(tokenBuffer, candidateBuffer)
      ) {
        matched = lease;
      }
    }

    return matched;
  }

  /**
   * Number of currently issued tokens, after pruning expired leases.
   */
  activeCount(): number {
    const now = Date.now();
    for (const [token, lease] of this.leases) {
      if (lease.expiresAt <= now) this.leases.delete(token);
    }
    return this.leases.size;
  }
}

/**
 * Base URL a Runtime container should use as its Codex `model_provider`
 * endpoint, pointing back at this process rather than directly at Ark.
 */
export function containerProxyBaseUrl(config: AppConfig): string {
  return "http://" + HOST_GATEWAY_ALIAS + ":" + config.port + ARK_PROXY_PREFIX;
}

/**
 * Resolves the upstream Ark URL for a proxied request path, rejecting anything
 * that would escape the configured Ark base URL.
 */
export function resolveUpstreamUrl(
  arkBaseUrl: string,
  requestPath: string,
  search: string,
): URL | null {
  const base = new URL(arkBaseUrl);
  const suffix = requestPath.replace(/^\/+/, "");
  let target: URL;
  try {
    // URL normalises "." and ".." segments, so a traversal attempt lands
    // outside the base pathname and is rejected below.
    target = new URL(base.pathname.replace(/\/+$/, "") + "/" + suffix + search, base);
  } catch {
    return null;
  }
  if (target.origin !== base.origin) return null;
  if (!target.pathname.startsWith(base.pathname.replace(/\/+$/, "") + "/")) return null;
  return target;
}

function buildUpstreamHeaders(
  request: FastifyRequest,
  arkApiKey: string,
): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (value === undefined) continue;
    if (STRIPPED_REQUEST_HEADERS.has(name.toLowerCase())) continue;
    for (const entry of Array.isArray(value) ? value : [value]) {
      headers.append(name, entry);
    }
  }
  headers.set("authorization", "Bearer " + arkApiKey);
  return headers;
}

function bearerToken(request: FastifyRequest): string {
  const header = request.headers.authorization ?? "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

/**
 * Mounts the credential proxy. The Runtime container authenticates with a run
 * token; this handler swaps it for the real Ark key and streams the upstream
 * response back untouched, so the key never leaves the backend process.
 */
export async function registerArkProxy(
  app: FastifyInstance,
  config: AppConfig,
  runTokens: RunTokenRegistry,
): Promise<void> {
  await app.register(
    async (scope) => {
      // Forward request bodies verbatim: the proxy must not reinterpret the
      // payload, and the application-wide JSON limit is far too small here.
      scope.removeAllContentTypeParsers();
      scope.addContentTypeParser(
        "*",
        { parseAs: "buffer", bodyLimit: ARK_PROXY_BODY_LIMIT },
        (_request: FastifyRequest, body: Buffer, done: (err: Error | null, result?: unknown) => void) => {
          done(null, body);
        },
      );

      scope.all(
        "/*",
        { bodyLimit: ARK_PROXY_BODY_LIMIT },
        async (request: FastifyRequest, reply: FastifyReply) => {
          const lease = runTokens.verify(bearerToken(request));
          if (!lease) {
            return reply.code(401).send({ error: "Invalid or expired run token" });
          }
          if (!config.arkApiKey) {
            return reply.code(503).send({ error: "Ark is not configured" });
          }

          const wildcard = (request.params as Record<string, string | undefined>)["*"] ?? "";
          const queryIndex = request.url.indexOf("?");
          const search = queryIndex === -1 ? "" : request.url.slice(queryIndex);
          const upstream = resolveUpstreamUrl(config.arkBaseUrl, wildcard, search);
          if (!upstream) {
            return reply.code(400).send({ error: "Invalid upstream path" });
          }

          const body = request.body;
          let response: Response;
          try {
            response = await fetch(upstream, {
              method: request.method,
              headers: buildUpstreamHeaders(request, config.arkApiKey),
              signal: AbortSignal.timeout(config.codexTimeoutMs),
              ...(Buffer.isBuffer(body) && body.length > 0 ? { body } : {}),
            });
          } catch {
            // The upstream failure message can carry request detail; report a
            // fixed string rather than risk echoing it to the container.
            return reply.code(502).send({ error: "Ark upstream request failed" });
          }

          for (const [name, value] of response.headers) {
            if (STRIPPED_RESPONSE_HEADERS.has(name.toLowerCase())) continue;
            reply.header(name, value);
          }
          reply.code(response.status);

          if (!response.body) {
            return reply.send(Buffer.from(await response.arrayBuffer()));
          }
          // Stream rather than buffer: wire_api = "responses" is SSE, and the
          // container must see tokens as they arrive.
          return reply.send(
            Readable.fromWeb(response.body as unknown as Parameters<typeof Readable.fromWeb>[0]),
          );
        },
      );
    },
    { prefix: ARK_PROXY_PREFIX },
  );
}
