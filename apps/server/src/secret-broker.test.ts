import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { SecretBroker } from "./secret-broker.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("SecretBroker", () => {
  describe("isSensitiveEnvKey", () => {
    it("identifies sensitive credential environment variable names", () => {
      const sensitiveKeys = [
        "ARK_API_KEY",
        "APP_AUTH_TOKEN",
        "VOLCENGINE_ACCESS_KEY",
        "VOLCENGINE_SECRET_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "DB_PASSWORD",
        "MY_SECRET_KEY",
        "USER_AUTH_HEADER",
        "PRIVATE_KEY_PEM",
        "SESSION_COOKIE",
      ];

      for (const key of sensitiveKeys) {
        expect(SecretBroker.isSensitiveEnvKey(key)).toBe(true);
      }
    });

    it("identifies safe, non-credential system variables", () => {
      const safeKeys = [
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "TERM",
        "NO_COLOR",
        "NODE_ENV",
        "PORT",
        "HOST",
      ];

      for (const key of safeKeys) {
        expect(SecretBroker.isSensitiveEnvKey(key)).toBe(false);
      }
    });
  });

  describe("sanitizeEnvironment (Environment Stripping)", () => {
    it("strips all host credentials while preserving safe system variables", () => {
      const dirtyHostEnv: NodeJS.ProcessEnv = {
        PATH: "/usr/local/bin:/usr/bin:/bin",
        HOME: "/home/runner",
        LANG: "en_US.UTF-8",
        TERM: "xterm-256color",
        APP_AUTH_TOKEN: "super-secret-demo-token-12345678",
        VOLCENGINE_ACCESS_KEY: "AKLT_" + "sample_volc_access_key",
        VOLCENGINE_SECRET_KEY: "secret_" + "sample_volc_secret_key",
        AWS_SECRET_ACCESS_KEY: "wJalrXUtn" + "FEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        GITHUB_TOKEN: "ghp_" + "xxxxxxxxxxxxxxxxxxxx",
        CUSTOM_DB_PASS: "P@ssw0rd123!",
        RANDOM_SECRET: "arbitrary-secret-value",
      };

      const sanitized = SecretBroker.sanitizeEnvironment(dirtyHostEnv);

      // Safe variables must be preserved
      expect(sanitized.PATH).toBe("/usr/local/bin:/usr/bin:/bin");
      expect(sanitized.HOME).toBe("/home/runner");
      expect(sanitized.LANG).toBe("en_US.UTF-8");
      expect(sanitized.TERM).toBe("xterm-256color");

      // All sensitive variables MUST be stripped
      expect(sanitized.APP_AUTH_TOKEN).toBeUndefined();
      expect(sanitized.VOLCENGINE_ACCESS_KEY).toBeUndefined();
      expect(sanitized.VOLCENGINE_SECRET_KEY).toBeUndefined();
      expect(sanitized.AWS_SECRET_ACCESS_KEY).toBeUndefined();
      expect(sanitized.GITHUB_TOKEN).toBeUndefined();
      expect(sanitized.CUSTOM_DB_PASS).toBeUndefined();
      expect(sanitized.RANDOM_SECRET).toBeUndefined();
    });

    it("applies runtime overrides explicitly needed for runner execution", () => {
      const baseEnv: NodeJS.ProcessEnv = {
        PATH: "/bin",
        APP_AUTH_TOKEN: "leak-me-not",
      };

      const sanitized = SecretBroker.sanitizeEnvironment(baseEnv, {
        overrides: {
          CODEX_HOME: "/app/codex-home/agents/agent-123",
          ARK_API_KEY: "brokered-ark-key",
          NO_COLOR: "1",
        },
      });

      expect(sanitized.APP_AUTH_TOKEN).toBeUndefined();
      expect(sanitized.CODEX_HOME).toBe("/app/codex-home/agents/agent-123");
      expect(sanitized.ARK_API_KEY).toBe("brokered-ark-key");
      expect(sanitized.NO_COLOR).toBe("1");
    });
  });

  describe("Per-Agent CODEX_HOME Isolation", () => {
    it("computes isolated per-agent directory paths safely", () => {
      const baseCodexHome = "/app/codex-home";
      const agentId = "11111111-2222-3333-4444-555555555555";
      const agentHome = SecretBroker.getAgentCodexHome(agentId, baseCodexHome);

      expect(agentHome).toBe(
        path.join(path.resolve(baseCodexHome), "agents", agentId),
      );
    });

    it("prevents directory traversal in agentId", () => {
      const baseCodexHome = "/app/codex-home";
      const traversalId = "../../../etc/passwd";
      const safeHome = SecretBroker.getAgentCodexHome(traversalId, baseCodexHome);

      // Traversal characters like '/' and '.' are stripped
      expect(safeHome).not.toContain("..");
      expect(safeHome).toBe(
        path.join(path.resolve(baseCodexHome), "agents", "etcpasswd"),
      );
    });

    it("creates isolated config.toml and cleans up on agent deletion", async () => {
      const root = await mkdtemp(path.join(tmpdir(), "launchpad-secret-test-"));
      temporaryDirectories.push(root);

      const codexHome = path.join(root, "codex-home");
      const config = loadConfig({
        NODE_ENV: "test",
        CODEX_HOME: codexHome,
        ARK_API_KEY: "test-ark-key",
        ARK_MODEL: "ep-test-model",
      });

      const agentId = "agent-alpha-1";
      const agentHome = await SecretBroker.ensureAgentCodexHome(agentId, config);

      expect(agentHome).toBe(path.join(codexHome, "agents", agentId));

      const configFile = path.join(agentHome, "config.toml");
      const content = await readFile(configFile, "utf8");
      expect(content).toContain('model = "ep-test-model"');
      expect(content).toContain('name = "Volcengine Ark"');

      // Check file permissions (owner readable/writable)
      const fileStat = await stat(configFile);
      expect(fileStat.mode & 0o777).toBe(0o600);

      // Test cleanup
      await SecretBroker.cleanupAgentCodexHome(agentId, codexHome);
      const { access } = await import("node:fs/promises");
      await expect(access(agentHome)).rejects.toThrow();
    });

    it("guarantees isolation between multiple agents", async () => {
      const root = await mkdtemp(path.join(tmpdir(), "launchpad-multi-test-"));
      temporaryDirectories.push(root);

      const codexHome = path.join(root, "codex-home");
      const config = loadConfig({
        NODE_ENV: "test",
        CODEX_HOME: codexHome,
        ARK_API_KEY: "test-key",
        ARK_MODEL: "ep-model-1",
      });

      const agentA = "agent-aaa";
      const agentB = "agent-bbb";

      const homeA = await SecretBroker.ensureAgentCodexHome(agentA, config);
      const homeB = await SecretBroker.ensureAgentCodexHome(agentB, config);

      expect(homeA).not.toBe(homeB);
      expect(path.dirname(homeA)).toBe(path.dirname(homeB));
      expect(path.basename(homeA)).toBe("agent-aaa");
      expect(path.basename(homeB)).toBe("agent-bbb");
    });
  });
});

