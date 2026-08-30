import type { AppConfig } from "./config.js";

export type DlpCategory =
  | "API_KEY"
  | "PRIVATE_KEY"
  | "DB_CREDENTIALS"
  | "JWT_TOKEN"
  | "PII_EMAIL"
  | "PII_PHONE"
  | "PII_CREDIT_CARD"
  | "RUNTIME_SECRET"
  | "GENERIC_SECRET";

export interface RedactionFinding {
  category: DlpCategory;
  description: string;
  matchedLength: number;
}

export interface RedactionResult {
  redactedText: string;
  redactorsTriggered: RedactionFinding[];
  hadViolations: boolean;
}

export interface DlpOptions {
  config?: AppConfig;
  redactPii?: boolean;
  customSecrets?: string[];
}

interface StaticDlpRule {
  category: DlpCategory;
  description: string;
  pattern: RegExp;
  replacement: string | ((substring: string, ...args: any[]) => string);
  isPii?: boolean;
}

const STATIC_DLP_RULES: StaticDlpRule[] = [
  // 1. Cryptographic Private Keys
  {
    category: "PRIVATE_KEY",
    description: "Cryptographic Private Key block",
    pattern:
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    replacement: "[REDACTED:PRIVATE_KEY]",
  },

  // 2. OpenAI API Keys
  {
    category: "API_KEY",
    description: "OpenAI Secret Key",
    pattern: /\b(?:sk-[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b/g,
    replacement: "[REDACTED:OPENAI_API_KEY]",
  },

  // 3. Volcengine Access Keys
  {
    category: "API_KEY",
    description: "Volcengine Access Key",
    pattern: /\bAKLT[a-zA-Z0-9]{20,}\b/g,
    replacement: "[REDACTED:VOLCENGINE_KEY]",
  },

  // 4. AWS Access Keys
  {
    category: "API_KEY",
    description: "AWS Access Key ID",
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    replacement: "[REDACTED:AWS_ACCESS_KEY]",
  },

  // 5. GitHub Personal Access & OAuth Tokens
  {
    category: "API_KEY",
    description: "GitHub Token",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b|\bgithub_pat_[a-zA-Z0-9_]{22,}\b/g,
    replacement: "[REDACTED:GITHUB_TOKEN]",
  },

  // 6. Google Cloud API Keys
  {
    category: "API_KEY",
    description: "Google Cloud API Key",
    pattern: /\bAIza[0-9A-Za-z-_]{35}\b/g,
    replacement: "[REDACTED:GOOGLE_API_KEY]",
  },

  // 7. JWT and Bearer Tokens
  {
    category: "JWT_TOKEN",
    description: "Bearer JWT Authentication Token",
    pattern: /\bBearer\s+eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g,
    replacement: "Bearer [REDACTED:JWT_TOKEN]",
  },
  {
    category: "JWT_TOKEN",
    description: "JSON Web Token (JWT)",
    pattern: /\beyJ[a-zA-Z0-9_-]{15,}\.eyJ[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}\b/g,
    replacement: "[REDACTED:JWT_TOKEN]",
  },

  // 8. Database Connection URIs with Embedded Passwords
  {
    category: "DB_CREDENTIALS",
    description: "Database Connection String Credentials",
    pattern:
      /\b((?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/[^:\s"'@]+):(?!\s*\[REDACTED:)([^\s"']+)@([a-zA-Z0-9_.-]+(?::\d+)?(?:\/[^\s"']*)?)/gi,
    replacement: (_match, prefix, _pass, host) => `${prefix}:[REDACTED:DB_PASSWORD]@${host}`,
  },

  // 9. Generic Key-Value Secret Assignments in JSON or config code
  {
    category: "GENERIC_SECRET",
    description: "Assigned Secret / Password Property",
    pattern:
      /\b((?:api_key|apikey|secret_key|secret|password|access_token|auth_token|client_secret)\s*[:=]\s*["'])(?!\s*\[REDACTED:)([^"'\s]{8,})(["'])/gi,
    replacement: (_match, prefix, _val, suffix) => `${prefix}[REDACTED:SECRET]${suffix}`,
  },

  // 10. PII - Email Addresses
  {
    category: "PII_EMAIL",
    description: "Email Address (PII)",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    replacement: "[REDACTED:EMAIL]",
    isPii: true,
  },

  // 11. PII - Phone Numbers
  {
    category: "PII_PHONE",
    description: "Phone Number (PII)",
    pattern: /(?:\+\d{1,3}[-.\s]?)?\(?\b\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    replacement: "[REDACTED:PHONE]",
    isPii: true,
  },

  // 12. PII - Credit Card Numbers (Formatted with spaces/dashes or continuous digits)
  {
    category: "PII_CREDIT_CARD",
    description: "Credit Card Number (PII)",
    pattern:
      /\b(?:4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|5[1-5][0-9]{2}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}|6(?:011|5[0-9]{2})[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    replacement: "[REDACTED:CREDIT_CARD]",
    isPii: true,
  },
];

export class OutboundDlpRedactor {
  /**
   * Scans and redacts sensitive credentials, API keys, private keys, and PII from a text string.
   */
  static redact(text: string, options?: DlpOptions): RedactionResult {
    if (!text) {
      return { redactedText: "", redactorsTriggered: [], hadViolations: false };
    }

    let processed = text;
    const findings: RedactionFinding[] = [];
    const redactPii = options?.redactPii ?? true;

    // 1. Dynamic Runtime Keys (e.g. active ARK_API_KEY, APP_AUTH_TOKEN)
    if (options?.config) {
      const { arkApiKey, authToken } = options.config;

      if (arkApiKey && arkApiKey.length >= 8 && !arkApiKey.startsWith("replace-")) {
        if (processed.includes(arkApiKey)) {
          findings.push({
            category: "RUNTIME_SECRET",
            description: "Active Ark Model Provider API Key",
            matchedLength: arkApiKey.length,
          });
          processed = processed.replaceAll(arkApiKey, "[REDACTED:ARK_API_KEY]");
        }
      }

      if (authToken && authToken.length >= 8 && !authToken.startsWith("replace-")) {
        if (processed.includes(authToken)) {
          findings.push({
            category: "RUNTIME_SECRET",
            description: "Active Master Platform Auth Token",
            matchedLength: authToken.length,
          });
          processed = processed.replaceAll(authToken, "[REDACTED:APP_AUTH_TOKEN]");
        }
      }
    }

    // 2. Custom operator secret strings
    if (Array.isArray(options?.customSecrets)) {
      for (const secret of options.customSecrets) {
        if (secret && secret.length >= 4 && processed.includes(secret)) {
          findings.push({
            category: "GENERIC_SECRET",
            description: "Custom Operator Secret",
            matchedLength: secret.length,
          });
          processed = processed.replaceAll(secret, "[REDACTED:SECRET]");
        }
      }
    }

    // 3. Static Pattern Rules
    for (const rule of STATIC_DLP_RULES) {
      if (rule.isPii && !redactPii) continue;

      // Reset regex state
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(processed)) {
        findings.push({
          category: rule.category,
          description: rule.description,
          matchedLength: 0,
        });
        rule.pattern.lastIndex = 0;
        processed = processed.replace(rule.pattern, rule.replacement as any);
      }
    }

    return {
      redactedText: processed,
      redactorsTriggered: findings,
      hadViolations: findings.length > 0,
    };
  }

  /**
   * Recursively redacts sensitive strings within nested JSON objects, arrays, and primitives.
   */
  static redactObject<T>(target: T, options?: DlpOptions): T {
    if (target === null || target === undefined) return target;

    if (typeof target === "string") {
      return this.redact(target, options).redactedText as unknown as T;
    }

    if (Array.isArray(target)) {
      return target.map((item) => this.redactObject(item, options)) as unknown as T;
    }

    if (typeof target === "object" && !(target instanceof Date) && !(target instanceof RegExp)) {
      const copy: Record<string, any> = {};
      for (const [key, value] of Object.entries(target)) {
        copy[key] = this.redactObject(value, options);
      }
      return copy as T;
    }

    return target;
  }

  /**
   * Fast check returning true if text contains any sensitive credentials or secrets.
   */
  static containsSecrets(text: string, options?: DlpOptions): boolean {
    return this.redact(text, options).hadViolations;
  }
}

