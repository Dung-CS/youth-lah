import { SecurityViolationError } from "./errors.js";

// Pattern matching sensitive environment variable keys that should never enter a container
const PROHIBITED_CONTAINER_ENV_PATTERN =
  /(?:ARK_API_KEY|APP_AUTH_TOKEN|VOLCENGINE_|AWS_|OPENAI_|GITHUB_|GH_|PRIVATE_KEY|DB_PASS|DATABASE_URL|MASTER_KEY)/i;

export interface ContainerSecurityDecision {
  safe: boolean;
  violations: string[];
}

export class ContainerSecurityGuard {
  /**
   * Performs pre-flight security inspection of container execution arguments
   * to guarantee that container runtime hardening policies are strictly enforced.
   */
  static validateContainerRunArgs(args: string[]): ContainerSecurityDecision {
    const violations: string[] = [];

    // 1. Verify No High-Privilege Secrets in Environment Variables
    for (let i = 0; i < args.length; i++) {
      if (args[i] === "--env" || args[i] === "-e") {
        const envVal = args[i + 1] || "";
        const envKey = envVal.split("=")[0] || "";
        if (PROHIBITED_CONTAINER_ENV_PATTERN.test(envKey)) {
          violations.push(
            `Prohibited sensitive environment variable key '${envKey}' detected in container arguments`,
          );
        }
      }
    }

    // 2. Verify Dropped Capabilities (--cap-drop ALL)
    const capDropIndex = args.indexOf("--cap-drop");
    if (capDropIndex === -1 || args[capDropIndex + 1]?.toUpperCase() !== "ALL") {
      violations.push("Container missing mandatory '--cap-drop ALL' capability restriction");
    }

    // 3. Verify No New Privileges Flag
    const hasNoNewPrivileges = args.some(
      (arg, idx) =>
        (arg === "--security-opt" && args[idx + 1] === "no-new-privileges") ||
        arg === "--security-opt=no-new-privileges",
    );
    if (!hasNoNewPrivileges) {
      violations.push("Container missing mandatory '--security-opt no-new-privileges' escalation guard");
    }

    // 4. Verify Read-Only Root Filesystem
    if (!args.includes("--read-only")) {
      violations.push("Container missing mandatory '--read-only' root filesystem flag");
    }

    // 5. Verify Read-Only Configuration Mount for codex-home
    const codexHomeMount = args.find(
      (arg) => arg.includes("dst=/codex-home") || arg.includes("destination=/codex-home"),
    );
    if (codexHomeMount && !codexHomeMount.includes("readonly") && !codexHomeMount.includes("ro")) {
      violations.push("Container configuration mount for '/codex-home' must be read-only (readonly)");
    }

    // 6. Verify Resource Bounds (CPU, Memory, and PIDs limits)
    if (!args.includes("--memory") && !args.some((a) => a.startsWith("--memory="))) {
      violations.push("Container missing memory limit bound (--memory)");
    }
    if (!args.includes("--pids-limit") && !args.some((a) => a.startsWith("--pids-limit="))) {
      violations.push("Container missing PIDs limit bound (--pids-limit)");
    }
    if (!args.includes("--cpus") && !args.some((a) => a.startsWith("--cpus="))) {
      violations.push("Container missing CPU limit bound (--cpus)");
    }

    // 7. Verify Non-Root User Execution
    const userIndex = args.indexOf("--user");
    const userVal = userIndex !== -1 ? args[userIndex + 1] : "";
    if (!userVal || userVal === "0" || userVal === "root" || userVal === "0:0") {
      violations.push("Container must execute under an unprivileged non-root user account");
    }

    return {
      safe: violations.length === 0,
      violations,
    };
  }

  /**
   * Validates container arguments and throws a SecurityViolationError if any policy violation is detected.
   */
  static validateOrThrow(args: string[]): void {
    const decision = this.validateContainerRunArgs(args);
    if (!decision.safe) {
      const summary = decision.violations.join("; ");
      throw new SecurityViolationError(
        `Container pre-flight security validation failed: ${summary}`,
        "CONTAINER_SANDBOX_POLICY_VIOLATION",
        summary,
      );
    }
  }
}

