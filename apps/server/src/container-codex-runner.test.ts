import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import {
  buildContainerRunArgs,
  containerName,
} from "./container-codex-runner.js";

describe("Container Codex runner", () => {
  it("builds an isolated Docker/Podman-compatible invocation", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "secret-that-must-not-appear-in-argv",
      ARK_MODEL: "ep-test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
      CONTAINER_ENGINE: "podman",
      CONTAINER_RUNTIME_IMAGE: "runtime:test",
      CONTAINER_USER: "501:20",
      RUNTIME_INSTANCE_ID: "test-instance",
    });
    const args = buildContainerRunArgs(
      {
        agentId: "agent/unsafe",
        workspacePath: "/tmp/agent-workspace",
        prompt: "write a small program",
        threadId: null,
      },
      config,
    );

    expect(containerName("agent/unsafe", "test-instance")).toBe(
      "launchpad-test-instance-agent-unsafe",
    );
    expect(args).toContain("runtime:test");
    expect(args).toContain("type=bind,src=/tmp/agent-workspace,dst=/workspace");
    expect(args).toContain("type=bind,src=/tmp/codex-home,dst=/codex-home,readonly");
    expect(args).toContain("501:20");
    expect(args).toContain("workspace-write");
    expect(args).toContain("/workspace");
    expect(args).toContain("io.codejam.instance-id=test-instance");
    expect(args).toContain("keep-id");
    expect(args).toContain("--add-host");
    expect(args).toContain("host.docker.internal:host-gateway");
    expect(args).toContain("--read-only");
    expect(args).toContain("--tmpfs");
    expect(args).toContain("/tmp:rw,nosuid,size=128m");
    expect(args).toContain("AGENT_SESSION_TOKEN=");
    expect(args).not.toContain("ARK_API_KEY");
    expect(args).not.toContain("secret-that-must-not-appear-in-argv");
  });

  it("resumes a thread inside the mounted Runtime workspace", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
    });
    const args = buildContainerRunArgs(
      {
        agentId: "agent",
        workspacePath: "/tmp/workspace",
        prompt: "continue",
        threadId: "thread-123",
      },
      config,
    );
    expect(args.slice(-3)).toEqual(["resume", "thread-123", "continue"]);
    expect(args).not.toContain("keep-id");
  });

  it("mounts isolated per-agent codex-home when provided", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
    });
    const isolatedHome = "/tmp/codex-home/agents/agent-123";
    const args = buildContainerRunArgs(
      {
        agentId: "agent-123",
        workspacePath: "/tmp/workspace",
        prompt: "test",
        threadId: null,
      },
      config,
      isolatedHome,
    );
    expect(args).toContain(
      "type=bind,src=/tmp/codex-home/agents/agent-123,dst=/codex-home,readonly",
    );
  });

  it("applies air-gapped --network none when EGRESS_NETWORK_MODE is 'none'", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
      EGRESS_NETWORK_MODE: "none",
    });
    const args = buildContainerRunArgs(
      {
        agentId: "agent-123",
        workspacePath: "/tmp/workspace",
        prompt: "offline work",
        threadId: null,
      },
      config,
    );
    expect(args).toContain("--network");
    expect(args).toContain("none");
    expect(args).not.toContain("bridge");
  });
});
