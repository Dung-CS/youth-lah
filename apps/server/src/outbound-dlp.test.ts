import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { OutboundDlpRedactor } from "./outbound-dlp.js";

describe("OutboundDlpRedactor", () => {
  const testConfig = loadConfig({
    NODE_ENV: "test",
    ARK_API_KEY: "ark-runtime-test-secret-key-12345",
    APP_AUTH_TOKEN: "app-master-auth-token-secret-67890",
  });

  describe("Dynamic Runtime Secret Redaction", () => {
    it("redacts active ARK_API_KEY from agent output", () => {
      const output =
        "The model request failed with key ark-runtime-test-secret-key-12345 unauthorized.";
      const result = OutboundDlpRedactor.redact(output, { config: testConfig });

      expect(result.redactedText).toBe(
        "The model request failed with key [REDACTED:ARK_API_KEY] unauthorized.",
      );
      expect(result.hadViolations).toBe(true);
      expect(
        result.redactorsTriggered.some((f) => f.category === "RUNTIME_SECRET"),
      ).toBe(true);
    });

    it("redacts active APP_AUTH_TOKEN from agent output or error traces", () => {
      const output =
        "Authorization header was set to Bearer app-master-auth-token-secret-67890.";
      const result = OutboundDlpRedactor.redact(output, { config: testConfig });

      expect(result.redactedText).toContain("[REDACTED:APP_AUTH_TOKEN]");
      expect(result.redactedText).not.toContain("app-master-auth-token-secret-67890");
    });
  });

  describe("Cloud & Platform API Key Redaction", () => {
    it("redacts OpenAI secret keys", () => {
      const fakeKey = "sk-proj-" + "1234567890abcdefghijklmnopqrstuv";
      const sample = `const client = new OpenAI({ apiKey: '${fakeKey}' });`;
      const result = OutboundDlpRedactor.redact(sample);

      expect(result.redactedText).toBe(
        "const client = new OpenAI({ apiKey: '[REDACTED:OPENAI_API_KEY]' });",
      );
      expect(result.hadViolations).toBe(true);
    });

    it("redacts Volcengine access keys", () => {
      const fakeKey = "AKLT" + "abcdefghijklmnopqrstuvwxyz12345";
      const sample = `export VOLC_AK=${fakeKey}`;
      const result = OutboundDlpRedactor.redact(sample);

      expect(result.redactedText).toBe("export VOLC_AK=[REDACTED:VOLCENGINE_KEY]");
      expect(result.hadViolations).toBe(true);
    });

    it("redacts AWS Access Key IDs", () => {
      const fakeKey = "AKIA" + "IOSFODNN7EXAMPLE";
      const sample = `AWS_ACCESS_KEY_ID=${fakeKey}`;
      const result = OutboundDlpRedactor.redact(sample);

      expect(result.redactedText).toBe("AWS_ACCESS_KEY_ID=[REDACTED:AWS_ACCESS_KEY]");
      expect(result.hadViolations).toBe(true);
    });

    it("redacts GitHub tokens", () => {
      const fakeKey = "ghp_" + "123456789012345678901234567890123456";
      const sample = `GITHUB_TOKEN=${fakeKey} git push`;
      const result = OutboundDlpRedactor.redact(sample);

      expect(result.redactedText).toBe("GITHUB_TOKEN=[REDACTED:GITHUB_TOKEN] git push");
      expect(result.hadViolations).toBe(true);
    });

    it("redacts Google Cloud API keys", () => {
      const fakeKey = "AIza" + "SyD-1234567890abcdef1234567890abcde";
      const sample = `https://maps.googleapis.com/maps/api/js?key=${fakeKey}`;
      const result = OutboundDlpRedactor.redact(sample);

      expect(result.redactedText).toBe(
        "https://maps.googleapis.com/maps/api/js?key=[REDACTED:GOOGLE_API_KEY]",
      );
      expect(result.hadViolations).toBe(true);
    });
  });

  describe("Cryptographic Private Key Redaction", () => {
    it("redacts RSA and OpenSSH private key blocks", () => {
      const rsaKey = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA0Y3w1J4...",
        "qX8zX4kL9yZ2...",
        "-----END RSA PRIVATE KEY-----",
      ].join("\n");

      const result = OutboundDlpRedactor.redact(
        `Here is the private key:\n${rsaKey}\nDo not share.`,
      );

      expect(result.redactedText).toBe(
        "Here is the private key:\n[REDACTED:PRIVATE_KEY]\nDo not share.",
      );
      expect(result.hadViolations).toBe(true);
    });
  });

  describe("Database Connection URI Credential Redaction", () => {
    it("redacts passwords from PostgreSQL, MySQL, and MongoDB connection strings", () => {
      const postgres =
        "postgres://admin:SuperSecretPass123!@db.example.com:5432/production";
      const mysql =
        "mysql://app_user:MySqlP@ssw0rd@localhost:3306/analytics";
      const mongo =
        "mongodb://root:SecretMongoPass@cluster0.mongodb.net/app_db";

      expect(OutboundDlpRedactor.redact(postgres).redactedText).toBe(
        "postgres://admin:[REDACTED:DB_PASSWORD]@db.example.com:5432/production",
      );
      expect(OutboundDlpRedactor.redact(mysql).redactedText).toBe(
        "mysql://app_user:[REDACTED:DB_PASSWORD]@localhost:3306/analytics",
      );
      expect(OutboundDlpRedactor.redact(mongo).redactedText).toBe(
        "mongodb://root:[REDACTED:DB_PASSWORD]@cluster0.mongodb.net/app_db",
      );
    });
  });

  describe("JWT and Bearer Token Redaction", () => {
    it("redacts Bearer JWT tokens", () => {
      const sample =
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature123";
      const result = OutboundDlpRedactor.redact(sample);

      expect(result.redactedText).toBe(
        "Authorization: Bearer [REDACTED:JWT_TOKEN]",
      );
      expect(result.hadViolations).toBe(true);
    });
  });

  describe("PII Redaction", () => {
    it("redacts email addresses, phone numbers, and credit cards", () => {
      const sample =
        "Contact alice.smith@example.org or call +1-555-867-5309. Card: 4111111111111111";
      const result = OutboundDlpRedactor.redact(sample);

      expect(result.redactedText).toBe(
        "Contact [REDACTED:EMAIL] or call [REDACTED:PHONE]. Card: [REDACTED:CREDIT_CARD]",
      );
      expect(result.hadViolations).toBe(true);
    });

    it("preserves PII when redactPii option is false", () => {
      const sample = "Send receipt to user@example.com";
      const result = OutboundDlpRedactor.redact(sample, { redactPii: false });

      expect(result.redactedText).toBe("Send receipt to user@example.com");
      expect(result.hadViolations).toBe(false);
    });
  });

  describe("Recursive Object Redaction (redactObject)", () => {
    it("recursively sanitizes deeply nested JSON objects and arrays", () => {
      const nestedData = {
        agentId: "agent-123",
        metadata: {
          apiKey: "sk-proj-" + "12345678901234567890abcdef",
          dbUrl: "postgres://user:secret@localhost:5432/db",
          contact: {
            email: "support@company.com",
          },
        },
        logs: [
          "Operation completed for support@company.com",
          "Generated key " + "AKIA" + "IOSFODNN7EXAMPLE",
        ],
      };

      const sanitized = OutboundDlpRedactor.redactObject(nestedData);

      expect(sanitized.metadata.apiKey).toBe("[REDACTED:OPENAI_API_KEY]");
      expect(sanitized.metadata.dbUrl).toBe(
        "postgres://user:[REDACTED:DB_PASSWORD]@localhost:5432/db",
      );
      expect(sanitized.metadata.contact.email).toBe("[REDACTED:EMAIL]");
      expect(sanitized.logs[0]).toBe("Operation completed for [REDACTED:EMAIL]");
      expect(sanitized.logs[1]).toBe("Generated key [REDACTED:AWS_ACCESS_KEY]");
    });
  });

  describe("Benign Developer Code Preservation", () => {
    it("preserves standard programming statements without false redaction", () => {
      const benignSamples = [
        "const apiKey = getApiKey();",
        "SELECT * FROM users WHERE id = 1;",
        "import { useState } from 'react';",
        "console.log('Server running on port 3000');",
      ];

      for (const sample of benignSamples) {
        const result = OutboundDlpRedactor.redact(sample);
        expect(result.redactedText).toBe(sample);
        expect(result.hadViolations).toBe(false);
      }
    });
  });
});

