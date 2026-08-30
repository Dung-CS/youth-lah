# Walkthrough: Complete Multi-Stage Defense Pipeline for Information Disclosure

We have successfully designed, built, and verified all **5 Stages** of the threat defense interception pipeline targeting STRIDE **Information Disclosure**:

```
[Inbound Request]
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Inbound Guard & Prompt Sanitizer                   │
│ (Homoglyphs, Base64, Delimiters, Probes, Jailbreaks)        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: Secret Broker & Environment Stripping              │
│ (Host Env Sanitization, Per-Agent CODEX_HOME Isolation)     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 3: Egress Network Filter & Sandbox Firewall           │
│ (32-bit Canonical IP, Cloud IMDS, CGNAT, Allowlist)         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 4: Outbound DLP & Secret Redactor                     │
│ (Ark, OpenAI, AWS, GitHub, Tokens, DB URIs, PII)            │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 5: Error Sanitizer & Path Masker                      │
│ (Host Path Masking, Stack Trace Concealment, Ref Codes)     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
[Safe Response to Client / Persistence to Storage]
```

---

## Summary of All 5 Defense Stages

### 1. Stage 1: Inbound Guard & Prompt Sanitizer ([`inbound-guard.ts`](file:///workspaces/youth-lah/apps/server/src/inbound-guard.ts))
- **Deobfuscation**: Strips zero-width/control characters, Cyrillic lookalike homoglyph mapping, Base64 payload decoding, URL percent-decoding.
- **Threat Categories**: System prompt extraction, credential harvesting (`ARK_API_KEY`, `.env`, `printenv`, `/proc/self/environ`, IMDS `169.254.169.254`), path traversal (`/etc/passwd`, `~/.ssh`), exfiltration commands (`curl -d @.env ...`), delimiter injection (`<|im_start|>`), known jailbreaks.
- **Zero False Positives**: Preserves legitimate developer expressions like `process.env.PORT` and `.env.example`.

### 2. Stage 2: Secret Broker & Environment Stripping ([`secret-broker.ts`](file:///workspaces/youth-lah/apps/server/src/secret-broker.ts))
- **Environment Stripping**: Strips host credentials (`APP_AUTH_TOKEN`, `VOLCENGINE_*`, `AWS_*`, `GITHUB_*`, passwords, tokens) before passing execution contexts to processes.
- **Per-Agent `CODEX_HOME` Isolation**: Provisions isolated directories (`codex-home/agents/<agent-id>`) with `0o700` directory and `0o600` `config.toml` permissions, eliminating cross-agent token/session leaks.
- **Lifecycle Cleanup**: Automatically cleans up private `CODEX_HOME` when an agent is deleted.

### 3. Stage 3: Egress Network Filter & Sandbox Firewall ([`egress-network-filter.ts`](file:///workspaces/youth-lah/apps/server/src/egress-network-filter.ts))
- **Canonical 32-bit IP Normalization**: Defeats decimal integer (`2852039166`), hex (`0xa9fea9fe`), octal (`0251.0376.0251.0376`), and IPv4-mapped IPv6 obfuscations.
- **Multi-Cloud IMDS & Subnet Protection**: Blocks AWS, GCP, Azure, Volcengine (`100.96.0.96`), Alibaba Cloud (`100.100.100.200`), CGNAT `100.64.0.0/10`, and RFC 1918 subnets.
- **Policy Modes**: `restricted` (allowlist), `none` (air-gapped), `bridge`.
- **Command Inspection**: Inspects shell commands (`curl`, `wget`, `git`, `pip`, `npm`, `python`, `node`, sockets).

### 4. Stage 4: Outbound DLP & Secret Redactor ([`outbound-dlp.ts`](file:///workspaces/youth-lah/apps/server/src/outbound-dlp.ts))
- **Runtime Keys**: Dynamically redacts active `ARK_API_KEY` and `APP_AUTH_TOKEN`.
- **Cloud & AI Provider Keys**: OpenAI (`sk-...`), Anthropic (`sk-ant-...`), Volcengine (`AKLT...`), AWS (`AKIA...`), GitHub (`ghp_...`), Google Cloud (`AIza...`), Slack (`xoxb-...`), Stripe (`sk_live_...`), GitLab (`glpat-...`), HuggingFace (`hf_...`), NPM (`npm_...`), PyPI (`pypi-...`).
- **Cryptographic Keys & Database Passwords**: Strips RSA/OpenSSH/EC private key blocks and database URI credentials (`postgres://...`, `mongodb://...`, `mysql://...`, `redis://...`).
- **PII**: Redacts emails, international/domestic phone numbers, and credit cards.

### 5. Stage 5: Error Sanitizer & Path Masker ([`error-sanitizer.ts`](file:///workspaces/youth-lah/apps/server/src/error-sanitizer.ts))
- **Host Path Masking**: Replaces server workspace roots, data directories, codex home paths, user homes (`/home/<user>`, `/root`), temp dirs, Docker overlay mounts (`/var/lib/docker/overlay2/...`), and Windows paths with normalized aliases (`[WORKSPACE_ROOT]`, `[DATA_DIR]`, `~[USER_HOME]`, `[CONTAINER_STORAGE]`, `[TEMP_DIR]`).
- **Production Error Concealment**: In production mode (`NODE_ENV === "production"`), 500 errors conceal raw stack traces and internal exceptions, generating correlated tracking codes (`ref: "err_xxxx"`).
- **Application-Wide Integration**: Integrated into Fastify's `setErrorHandler` in [`app.ts`](file:///workspaces/youth-lah/apps/server/src/app.ts) and run execution in [`agent-service.ts`](file:///workspaces/youth-lah/apps/server/src/agent-service.ts).

---

## Verification Results: 10/10 Test Suites Passing (128 Tests)

```
Test Files  10 passed (10)
     Tests  128 passed (128)
```
- `src/inbound-guard.test.ts` (29 passed)
- `src/secret-broker.test.ts` (9 passed)
- `src/egress-network-filter.test.ts` (48 passed)
- `src/outbound-dlp.test.ts` (17 passed)
- `src/error-sanitizer.test.ts` (8 passed)
- `src/agent-service.test.ts` (7 passed)
- `src/app.test.ts` (4 passed)
- `src/container-codex-runner.test.ts` (3 passed)
- `src/codex-runner.test.ts` (3 passed)
