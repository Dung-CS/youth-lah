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

export class SecretBroker {
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

    // Apply explicit runtime overrides (e.g. per-agent CODEX_HOME, model API key for Codex)
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
   * its private configuration with restricted permissions (0o600).
   *
   * Containerised runs pass overrides so Codex authenticates against the
   * in-process credential proxy with a run token instead of holding the Ark
   * key. Local process runs omit them and keep the direct Ark endpoint.
   */
  static async ensureAgentCodexHome(
    agentId: string,
    config: AppConfig,
    overrides?: {
      baseUrl?: string | undefined;
      envKey?: string | undefined;
    },
  ): Promise<string> {
    const agentHome = this.getAgentCodexHome(agentId, config.codexHome);
    await mkdir(agentHome, { recursive: true, mode: 0o700 });

    const baseUrl = overrides?.baseUrl || config.arkBaseUrl;
    const envKey = overrides?.envKey || "ARK_API_KEY";

    const toml = [
      "# Isolated Codex configuration for agent " + agentId,
      "model = " + JSON.stringify(config.arkModel || "ep-not-configured"),
      'model_provider = "volcengine_ark"',
      "",
      "[model_providers.volcengine_ark]",
      'name = "Volcengine Ark"',
      "base_url = " + JSON.stringify(baseUrl),
      "env_key = " + JSON.stringify(envKey),
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

