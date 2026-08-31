import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig, writeCodexConfig } from "./config.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("Codex configuration", () => {
  it("disables native web search for Ark models", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-config-test-"));
    temporaryDirectories.push(root);

    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: path.join(root, "codex-home"),
      ARK_MODEL: "ep-test-model",
    });

    await writeCodexConfig(config);

    const content = await readFile(
      path.join(config.codexHome, "config.toml"),
      "utf8",
    );
    expect(content).toContain('web_search = "disabled"');
  });
});
