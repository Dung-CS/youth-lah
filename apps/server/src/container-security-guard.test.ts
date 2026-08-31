import { describe, expect, it } from "vitest";
import { ContainerSecurityGuard } from "./container-security-guard.js";
import { buildContainerRunArgs } from "./container-codex-runner.js";
import { loadConfig } from "./config.js";

describe("Layer 3: Container Security Guard", () => {
  const baseConfig = loadConfig({
    NODE_ENV: "test",
    CODEX_HOME: "/tmp/codex-home",
    RUNTIME_PROVIDER: "container",
    CONTAINER_ENGINE: "docker",
    CONTAINER_RUNTIME_IMAGE: "runtime:test",
    CONTAINER_USER: "1000:1000",
    CONTAINER_CPU_LIMIT: 2,
    CONTAINER_MEMORY_LIMIT: "2g",
    CONTAINER_PIDS_LIMIT: 256,
  });

  it("approves fully compliant, hardened container arguments", () => {
    const args = buildContainerRunArgs(
      {
        agentId: "agent-123",
        workspacePath: "/tmp/workspace",
        prompt: "test",
        threadId: null,
      },
      baseConfig,
      "/tmp/codex-home/agents/agent-123",
      "ast_test_session_token_12345",
    );

    const decision = ContainerSecurityGuard.validateContainerRunArgs(args);
    expect(decision.safe).toBe(true);
    expect(decision.violations).toHaveLength(0);

    expect(() => ContainerSecurityGuard.validateOrThrow(args)).not.toThrow();
  });

  it("detects and rejects prohibited credentials in container --env", () => {
    const dangerousArgs = [
      "run",
      "--rm",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--memory",
      "2g",
      "--pids-limit",
      "256",
      "--cpus",
      "2",
      "--user",
      "1000:1000",
      "--env",
      "ARK_API_KEY=ark-leaked-key",
      "--mount",
      "type=bind,src=/tmp/home,dst=/codex-home,readonly",
    ];

    const decision = ContainerSecurityGuard.validateContainerRunArgs(dangerousArgs);
    expect(decision.safe).toBe(false);
    expect(decision.violations.some((v) => v.includes("ARK_API_KEY"))).toBe(true);
    expect(() => ContainerSecurityGuard.validateOrThrow(dangerousArgs)).toThrowError(
      /Prohibited sensitive environment variable/,
    );
  });

  it("detects and rejects missing capability drops (--cap-drop ALL)", () => {
    const dangerousArgs = [
      "run",
      "--rm",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--memory",
      "2g",
      "--pids-limit",
      "256",
      "--cpus",
      "2",
      "--user",
      "1000:1000",
      "--mount",
      "type=bind,src=/tmp/home,dst=/codex-home,readonly",
    ];

    const decision = ContainerSecurityGuard.validateContainerRunArgs(dangerousArgs);
    expect(decision.safe).toBe(false);
    expect(decision.violations.some((v) => v.includes("--cap-drop ALL"))).toBe(true);
  });

  it("detects and rejects missing read-only root filesystem (--read-only)", () => {
    const dangerousArgs = [
      "run",
      "--rm",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--memory",
      "2g",
      "--pids-limit",
      "256",
      "--cpus",
      "2",
      "--user",
      "1000:1000",
      "--mount",
      "type=bind,src=/tmp/home,dst=/codex-home,readonly",
    ];

    const decision = ContainerSecurityGuard.validateContainerRunArgs(dangerousArgs);
    expect(decision.safe).toBe(false);
    expect(decision.violations.some((v) => v.includes("--read-only"))).toBe(true);
  });

  it("detects and rejects codex-home mounted without a read-only config.toml", () => {
    const dangerousArgs = [
      "run",
      "--rm",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--memory",
      "2g",
      "--pids-limit",
      "256",
      "--cpus",
      "2",
      "--user",
      "1000:1000",
      "--mount",
      "type=bind,src=/tmp/home,dst=/codex-home", // no readonly config.toml overlay!
    ];

    const decision = ContainerSecurityGuard.validateContainerRunArgs(dangerousArgs);
    expect(decision.safe).toBe(false);
    expect(decision.violations.some((v) => v.includes("codex-home"))).toBe(true);

    const safeArgs = [
      ...dangerousArgs,
      "--mount",
      "type=bind,src=/tmp/home/config.toml,dst=/codex-home/config.toml,readonly",
    ];
    expect(
      ContainerSecurityGuard.validateContainerRunArgs(safeArgs).violations.some((v) =>
        v.includes("codex-home"),
      ),
    ).toBe(false);
  });

  it("detects and rejects root user execution", () => {
    const dangerousArgs = [
      "run",
      "--rm",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--memory",
      "2g",
      "--pids-limit",
      "256",
      "--cpus",
      "2",
      "--user",
      "0", // root user!
      "--mount",
      "type=bind,src=/tmp/home,dst=/codex-home,readonly",
    ];

    const decision = ContainerSecurityGuard.validateContainerRunArgs(dangerousArgs);
    expect(decision.safe).toBe(false);
    expect(decision.violations.some((v) => v.includes("non-root user"))).toBe(true);
  });
});

