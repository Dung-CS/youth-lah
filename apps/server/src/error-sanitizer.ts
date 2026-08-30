import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import { HttpError } from "./errors.js";
import { OutboundDlpRedactor } from "./outbound-dlp.js";

export interface SanitizedErrorPayload {
  statusCode: number;
  error: string;
  code?: string;
  ref?: string;
  details?: unknown;
}

export class ErrorSanitizer {
  /**
   * Masks absolute host filesystem paths with normalized relative aliases.
   */
  static maskPaths(text: string, config?: AppConfig): string {
    if (!text) return "";
    let processed = text;

    // 1. Explicitly configured server paths
    if (config) {
      if (config.workspaceRoot) {
        processed = processed.replaceAll(config.workspaceRoot, "[WORKSPACE_ROOT]");
      }
      if (config.dataDirectory) {
        processed = processed.replaceAll(config.dataDirectory, "[DATA_DIR]");
      }
      if (config.codexHome) {
        processed = processed.replaceAll(config.codexHome, "[CODEX_HOME]");
      }
    }

    // 2. Container & Docker overlay/runtime mounts (/var/lib/docker/overlay2/...)
    processed = processed.replace(
      /\/var\/lib\/(?:docker|containerd)\/[a-zA-Z0-9_\/.-]+/g,
      "[CONTAINER_STORAGE]",
    );
    processed = processed.replace(
      /\/run\/(?:docker|containerd)\/[a-zA-Z0-9_\/.-]+/g,
      "[CONTAINER_RUNTIME]",
    );

    // 3. Cloud workspace paths (e.g. /workspaces/youth-lah)
    processed = processed.replace(/\/workspaces\/[a-zA-Z0-9_-]+/g, "[WORKSPACE_ROOT]");

    // 4. User home directories (/home/<user> or /Users/<user> or /root)
    processed = processed.replace(/\/(?:home|Users)\/[a-zA-Z0-9_-]+/g, "~[USER_HOME]");
    processed = processed.replace(/(?<=^|[\s"'=:(])\/root(?=[\/\s"':)]|$)/g, "~[USER_HOME]");

    // 5. Temporary directories (/tmp/launchpad-test-xxx or /tmp/...)
    processed = processed.replace(
      /\/tmp\/(?:launchpad-[a-zA-Z0-9_-]+|[a-zA-Z0-9_-]+)/g,
      "[TEMP_DIR]",
    );
    processed = processed.replace(/(?<=^|[\s"'=:(])\/tmp(?=[\/\s"':)]|$)/g, "[TEMP_DIR]");

    // 6. Windows file paths (C:\Users\<user>\... or D:\...)
    processed = processed.replace(
      /[a-zA-Z]:\\(?:Users|Documents and Settings)\\[a-zA-Z0-9_-]+/gi,
      "~[USER_HOME]",
    );
    processed = processed.replace(/[a-zA-Z]:\\[a-zA-Z0-9_.\-\\]+/g, "[WINDOWS_PATH]");

    return processed;
  }

  /**
   * Sanitizes an error payload for client presentation:
   * 1. Redacts sensitive credentials, passwords, and tokens.
   * 2. Masks internal filesystem paths.
   * 3. Conceals internal stack traces and exceptions in production with correlated reference IDs.
   */
  static sanitizeError(error: unknown, config?: AppConfig): SanitizedErrorPayload {
    const isProd = config?.nodeEnv === "production";
    const appError = error instanceof Error ? error : new Error(String(error));
    const validationError = error instanceof z.ZodError;

    const frameworkStatus =
      typeof (error as { statusCode?: unknown })?.statusCode === "number"
        ? (error as { statusCode: number }).statusCode
        : null;

    const statusCode =
      error instanceof HttpError
        ? error.statusCode
        : validationError
          ? 400
          : frameworkStatus && frameworkStatus >= 400 && frameworkStatus <= 599
            ? frameworkStatus
            : 500;

    // 1. Scrub credentials via Outbound DLP
    const rawMessage = appError.message || "An error occurred";
    let message = OutboundDlpRedactor.redact(rawMessage, { config }).redactedText;

    // 2. Mask filesystem paths
    message = this.maskPaths(message, config);

    // 3. Conceal internal server error details in production
    if (statusCode >= 500 && isProd) {
      const ref = `err_${randomUUID().slice(0, 8)}`;
      return {
        statusCode,
        error: "An unexpected internal server error occurred",
        code: "INTERNAL_SERVER_ERROR",
        ref,
      };
    }

    const payload: SanitizedErrorPayload = {
      statusCode,
      error: message,
    };

    if (error instanceof HttpError) {
      payload.code = error.name;
    } else if (validationError) {
      payload.code = "VALIDATION_ERROR";
      payload.details = error.issues;
    } else if (statusCode >= 500) {
      payload.code = "INTERNAL_SERVER_ERROR";
    }

    return payload;
  }
}
