import { describe, expect, it } from "vitest";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { HttpError, SecurityViolationError } from "./errors.js";
import { ErrorSanitizer } from "./error-sanitizer.js";

describe("ErrorSanitizer & PathMasker", () => {
  const testConfig = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: "/var/data/launchpad-app",
    AGENT_WORKSPACE_ROOT: "/opt/launchpad/workspaces",
    CODEX_HOME: "/etc/codex-home",
  });

  const prodConfig = loadConfig({
    NODE_ENV: "production",
    HOST: "127.0.0.1",
    APP_AUTH_TOKEN: "a-secure-production-auth-token-12345678",
    APP_DATA_DIR: "/var/data/launchpad-app",
    AGENT_WORKSPACE_ROOT: "/opt/launchpad/workspaces",
    CODEX_HOME: "/etc/codex-home",
  });

  describe("maskPaths", () => {
    it("masks explicitly configured workspace, data, and codex directories", () => {
      const sample =
        "Failed to read file from /opt/launchpad/workspaces/agent-123/src/index.ts. Store located at /var/data/launchpad-app/db.json and config at /etc/codex-home/config.toml";
      const masked = ErrorSanitizer.maskPaths(sample, testConfig);

      expect(masked).toBe(
        "Failed to read file from [WORKSPACE_ROOT]/agent-123/src/index.ts. Store located at [DATA_DIR]/db.json and config at [CODEX_HOME]/config.toml",
      );
    });

    it("masks Linux user home, macOS user home, and root directories", () => {
      const samples = [
        "Error at /home/developer/workspace/app.js:24",
        "Stack: /Users/sarah/Projects/launchpad/index.ts:10",
        "Permission denied for /root/.ssh/id_rsa",
      ];

      expect(ErrorSanitizer.maskPaths(samples[0])).toBe(
        "Error at ~[USER_HOME]/workspace/app.js:24",
      );
      expect(ErrorSanitizer.maskPaths(samples[1])).toBe(
        "Stack: ~[USER_HOME]/Projects/launchpad/index.ts:10",
      );
      expect(ErrorSanitizer.maskPaths(samples[2])).toBe(
        "Permission denied for ~[USER_HOME]/.ssh/id_rsa",
      );
    });

    it("masks temporary directories and container storage paths", () => {
      const tempPath = "Wrote scratch file to /tmp/launchpad-test-84920/temp.json";
      const dockerPath =
        "Failed to extract layer at /var/lib/docker/overlay2/9834279abcdef/merged/root";

      expect(ErrorSanitizer.maskPaths(tempPath)).toBe(
        "Wrote scratch file to [TEMP_DIR]/temp.json",
      );
      expect(ErrorSanitizer.maskPaths(dockerPath)).toBe(
        "Failed to extract layer at [CONTAINER_STORAGE]",
      );
    });

    it("masks Windows filesystem paths", () => {
      const winPath =
        "Failed to load C:\\Users\\Administrator\\AppData\\Local\\config.json";
      expect(ErrorSanitizer.maskPaths(winPath)).toBe(
        "Failed to load ~[USER_HOME]\\AppData\\Local\\config.json",
      );
    });
  });

  describe("sanitizeError", () => {
    it("redacts secrets and masks paths in development/test error payloads", () => {
      const err = new Error(
        "Database query failed at /opt/launchpad/workspaces/db.ts:25 for postgres://admin:SuperSecretPass123!@db.internal:5432/app",
      );
      const payload = ErrorSanitizer.sanitizeError(err, testConfig);

      expect(payload.statusCode).toBe(500);
      expect(payload.code).toBe("INTERNAL_SERVER_ERROR");
      expect(payload.error).toBe(
        "Database query failed at [WORKSPACE_ROOT]/db.ts:25 for postgres://admin:[REDACTED:DB_PASSWORD]@db.internal:5432/app",
      );
      expect(payload.error).not.toContain("SuperSecretPass123!");
      expect(payload.error).not.toContain("/opt/launchpad/workspaces");
    });

    it("preserves HttpError and SecurityViolationError client codes and messages", () => {
      const httpErr = new HttpError(404, "Agent not found");
      const secErr = new SecurityViolationError(
        "Prompt injection detected at /opt/launchpad/workspaces",
        "CREDENTIAL_HARVESTING",
      );

      const httpPayload = ErrorSanitizer.sanitizeError(httpErr, testConfig);
      expect(httpPayload.statusCode).toBe(404);
      expect(httpPayload.code).toBe("HttpError");
      expect(httpPayload.error).toBe("Agent not found");

      const secPayload = ErrorSanitizer.sanitizeError(secErr, testConfig);
      expect(secPayload.statusCode).toBe(400);
      expect(secPayload.code).toBe("SecurityViolationError");
      expect(secPayload.error).toBe("Prompt injection detected at [WORKSPACE_ROOT]");
    });

    it("handles Zod validation errors with status 400 and validation issues", () => {
      const schema = z.object({ name: z.string().min(3) });
      const parseResult = schema.safeParse({ name: "a" });
      if (parseResult.success) throw new Error("Expected validation failure");

      const payload = ErrorSanitizer.sanitizeError(parseResult.error, testConfig);
      expect(payload.statusCode).toBe(400);
      expect(payload.code).toBe("VALIDATION_ERROR");
      expect(payload.details).toBeDefined();
    });

    it("conceals 500 internal errors in production with a correlated reference ID", () => {
      const internalErr = new Error(
        "Fatal socket exception at /var/lib/docker/overlay2/deadbeef/layer.sock",
      );
      const payload = ErrorSanitizer.sanitizeError(internalErr, prodConfig);

      expect(payload.statusCode).toBe(500);
      expect(payload.error).toBe("An unexpected internal server error occurred");
      expect(payload.code).toBe("INTERNAL_SERVER_ERROR");
      expect(payload.ref).toMatch(/^err_[a-f0-9]{8}$/);
      expect(payload.error).not.toContain("/var/lib/docker");
    });
  });
});
