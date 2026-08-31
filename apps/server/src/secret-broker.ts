import { randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import type { AppConfig } from "./config.js";

// Standard allowlist of safe system environment variables that child processes may inherit
export const SAFE_SYSTEM_ENV_ALLOWLIST = [
  "PATH",
  "HOME",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "TERM",
  "NO_COLOR",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "XDG_RUNTIME_DIR",
] as const;

// Pattern matching sensitive environment variable keys that should be stripped
const SENSITIVE_ENV_PATTERN =
  /(?:KEY|TOKEN|SECRET|PASS|AUTH|CREDENTIAL|PRIVATE|ARK_|VOLC_|AWS_|OPENAI_|GITHUB_|GH_|COOKIE)/i;

export interface AgentSession {
  token: string;
  runId?: string | undefined;
  createdAt: number;
  expiresAt: number;
}

export class SecretBroker {
  private static readonly activeSessions = new Map<string, AgentSession>();

  /**
   * Generates a cryptographically random, short-lived session token for an active agent run.
   */
  static issueAgentSession(
    agentId: string,
    runId?: string,
    ttlMs = 600_000, // 10 minutes default
  ): string {
    const safeAgentId = agentId.replace(/[^a-zA-Z0-9_-]/g, "");
    if (!safeAgentId) {
      throw new Error("Invalid agentId for session token issuance");
    }

    const token = `ast_${randomBytes(24).toString("hex")}`;
    const now = Date.now();
    const session: AgentSession = {
      token,
      createdAt: now,
      expiresAt: now + ttlMs,
    };
    if (runId !== undefined) {
      session.runId = runId;
    }
    this.activeSessions.set(safeAgentId, session);

    return token;
  }

  /**
   * Constant-time verification of an agent session token.
   */
  static verifyAgentSession(agentId: string, token: string): boolean {
    if (!agentId || !token) return false;
    const safeAgentId = agentId.replace(/[^a-zA-Z0-9_-]/g, "");
    const session = this.activeSessions.get(safeAgentId);
    if (!session) return false;

    if (Date.now() > session.expiresAt) {
      this.activeSessions.delete(safeAgentId);
      return false;
    }

    const expectedBuffer = Buffer.from(session.token);
    const candidateBuffer = Buffer.from(token);
    if (expectedBuffer.length !== candidateBuffer.length) {
      return false;
    }

    return timingSafeEqual(candidateBuffer, expectedBuffer);
  }

  /**
   * Revokes and cleans up an agent's active session token immediately upon run completion.
   */
  static revokeAgentSession(agentId: string): void {
    const safeAgentId = agentId.replace(/[^a-zA-Z0-9_-]/g, "");
    if (safeAgentId) {
      this.activeSessions.delete(safeAgentId);
    }
  }

  /**
   * Clears all active agent sessions (primarily used for test isolation).
   */
  static resetSessions(): void {
    this.activeSessions.clear();
  }

  /**
   * Returns the internal LLM reverse proxy base URL for an agent.
   */
  static getAgentProxyUrl(
    agentId: string,
    config: AppConfig,
    host = "host.docker.internal",
  ): string {
    const safeAgentId = agentId.replace(/[^a-zA-Z0-9_-]/g, "");
    return `http://${host}:${config.port}/api/internal/llm-proxy/${safeAgentId}`;
  }

  /**
   * Checks if an environment variable key name indicates sensitive credential data.
   */
  static isSensitiveEnvKey(key: string): boolean {
    if (!key) return false;
    return SENSITIVE_ENV_PATTERN.test(key);
  }

  /**
   * Strips all sensitive credentials from the source environment, preserving only
   * safe allowlisted system variables and applying explicit, necessary overrides.
   */
  static sanitizeEnvironment(
    baseEnv: NodeJS.ProcessEnv = process.env,
    options?: {
      allowList?: readonly string[];
      overrides?: NodeJS.ProcessEnv;
    },
  ): NodeJS.ProcessEnv {
    const allowList = options?.allowList ?? SAFE_SYSTEM_ENV_ALLOWLIST;
    const sanitized: NodeJS.ProcessEnv = {};

    for (const name of allowList) {
      // Do not inherit if the variable in baseEnv matches sensitive patterns
      if (baseEnv[name] !== undefined && !this.isSensitiveEnvKey(name)) {
        sanitized[name] = baseEnv[name];
      }
    }

    // Apply explicit runtime overrides (e.g. per-agent CODEX_HOME, session token for Codex)
    if (options?.overrides) {
      for (const [key, value] of Object.entries(options.overrides)) {
        if (value !== undefined) {
          sanitized[key] = value;
        }
      }
    }

    return sanitized;
  }

  /**
   * Computes the isolated per-agent CODEX_HOME directory.
   */
  static getAgentCodexHome(agentId: string, baseCodexHome: string): string {
    const safeAgentId = agentId.replace(/[^a-zA-Z0-9_-]/g, "");
    if (!safeAgentId) {
      throw new Error("Invalid agentId for CODEX_HOME isolation");
    }
    return path.join(path.resolve(baseCodexHome), "agents", safeAgentId);
  }

  /**
   * Ensures an isolated CODEX_HOME directory exists for an agent and writes
   * its private configuration pointing to the host LLM reverse proxy.
   */
  static async ensureAgentCodexHome(
    agentId: string,
    config: AppConfig,
    options?: { proxyHost?: string },
  ): Promise<string> {
    const agentHome = this.getAgentCodexHome(agentId, config.codexHome);
    await mkdir(agentHome, { recursive: true, mode: 0o700 });

    const proxyUrl = this.getAgentProxyUrl(
      agentId,
      config,
      options?.proxyHost ?? (config.runtimeProvider === "container" ? "host.docker.internal" : "127.0.0.1"),
    );

    const toml = [
      "# Isolated Codex configuration for agent " + agentId,
      "model = " + JSON.stringify(config.arkModel || "ep-not-configured"),
      'model_provider = "volcengine_ark"',
      'web_search = "disabled"',
      "",
      "[model_providers.volcengine_ark]",
      'name = "Volcengine Ark"',
      "base_url = " + JSON.stringify(proxyUrl),
      'env_key = "AGENT_SESSION_TOKEN"',
      'wire_api = "responses"',
      "requires_openai_auth = false",
      "",
    ].join("\n");

    await writeFile(path.join(agentHome, "config.toml"), toml, {
      encoding: "utf8",
      mode: 0o600,
    });

    return agentHome;
  }

  /**
   * Cleans up the isolated CODEX_HOME directory when an agent is deleted.
   */
  static async cleanupAgentCodexHome(
    agentId: string,
    baseCodexHome: string,
  ): Promise<void> {
    try {
      const agentHome = this.getAgentCodexHome(agentId, baseCodexHome);
      await rm(agentHome, { recursive: true, force: true });
    } catch {
      // Ignore if directory does not exist
    }
  }
}
