# Volc Agent Launchpad

A secure, middleware-hardened AI Coding Agent platform featuring an interactive React Playground, Fastify control plane, persistent workspaces, disposable container sandboxing, and Codex CLI integration backed by the Volcengine Ark Responses API.

---

## 🎯 The Middleware Problem & Rationale

Autonomous AI coding agents possess shell execution and file modification capabilities. While powerful, giving an LLM terminal and filesystem access creates critical security vulnerabilities:

1. **System Prompt & Instruction Extraction**: Adversaries craft prompts to override system instructions and dump proprietary platform directives or internal rules.
2. **Credential & Secret Harvesting**: Malicious or injected prompts probe for environment variables (`ARK_API_KEY`, `APP_AUTH_TOKEN`, `AWS_*`, `VOLCENGINE_*`), dump `/proc/self/environ`, inspect `.env` files, or query Cloud Instance Metadata Services (IMDS at `169.254.169.254` or `100.96.0.96`) for cloud IAM credentials.
3. **Cross-Agent Session Leaks**: In multi-agent environments, unisolated session directories allow agents to read peer conversation histories and cached configurations.
4. **Data Exfiltration via Egress**: Prompt injection can trigger outbound `curl`/`wget` exfiltration or reverse shells sending local workspace files to external servers.
5. **Evasion Obfuscation**: Attackers easily bypass naive keyword filters using Cyrillic lookalike homoglyphs (`а` vs `a`), Base64/URL encoding, or indirect coding requests (*"write a script that reads process.env"*).

### Why Defense-in-Depth?
A single barrier or client-side prompt check is insufficient. If a prompt bypasses the input filter via indirect phrasing, downstream security layers must guarantee that **secrets** are **absent from the runtime environment**, **network egress** is **restricted**, and any **leaked tokens** in tool outputs are **redacted** before reaching the client.

---

## ️ Design Summary: 5-Stage Defense Pipeline

The platform implements a **5-Stage Security Pipeline** targeting STRIDE **Information Disclosure** and **Tampering**:

```
[Inbound User Request]
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Inbound Guard & Prompt Sanitizer                   │
│ (Homoglyphs, Base64 decoding, Probes, Jailbreaks -> 400 Bad)│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Secret Broker & Environment Isolation              │
│ (process.env stripping, per-agent CODEX_HOME 0o700 boundary)│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Host LLM Reverse Proxy & Egress Network Firewall   │
│ (Ephemeral session tokens, Cloud IMDS & private IP blocking)│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Outbound DLP & Secret Redactor                     │
│ (Real-time regex masking of API keys, tokens, and PII)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 5: Error Sanitizer & Path Masker                      │
│ (Host path pseudonymization, stack trace concealment)       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
[Safe Response to Client / Storage Persistence]
```

### Defense Layers Overview

* **Layer 1: Inbound Guard & Prompt Sanitizer** ([`inbound-guard.ts`](file:///workspaces/youth-lah/apps/server/src/inbound-guard.ts))
  * De-obfuscates Cyrillic homoglyphs, strips zero-width/control characters, decodes Base64/URL payloads.
  * Rejects extraction attacks, credential probes, and path traversal attempts with HTTP `400 Bad Request`.
* **Layer 2: Secret Broker & Environment Stripping** ([`secret-broker.ts`](file:///workspaces/youth-lah/apps/server/src/secret-broker.ts))
  * Strips all host credentials (`ARK_API_KEY`, `APP_AUTH_TOKEN`, `VOLCENGINE_*`, `AWS_*`, tokens, database URLs) from child process and container environments.
  * Provisions private per-agent `CODEX_HOME` directories with POSIX `0o700` (`drwx------`) directory and `0o600` file permissions.
* **Layer 3: Host LLM Reverse Proxy & Egress Firewall** ([`llm-proxy.ts`](file:///workspaces/youth-lah/apps/server/src/llm-proxy.ts) & [`egress-network-filter.ts`](file:///workspaces/youth-lah/apps/server/src/egress-network-filter.ts))
  * Agents receive only a short-lived, ephemeral `AGENT_SESSION_TOKEN`. The real `ARK_API_KEY` stays on the host server.
  * 32-bit canonical IP normalization blocks access to cloud IMDS endpoints (AWS, GCP, Azure, Volcengine `100.96.0.96`, Alibaba Cloud `100.100.100.200`), CGNAT, and RFC 1918 private subnets.
* **Layer 4: Outbound DLP & Secret Redactor** ([`outbound-dlp.ts`](file:///workspaces/youth-lah/apps/server/src/outbound-dlp.ts))
  * Scans agent output and tool logs in real time, redacting API keys (Ark, OpenAI, Anthropic, AWS, GitHub), database connection URIs, private keys, and PII.
* **Layer 5: Error Sanitizer & Path Masker** ([`error-sanitizer.ts`](file:///workspaces/youth-lah/apps/server/src/error-sanitizer.ts))
  * Normalizes absolute host paths, Docker overlay mounts, and user directories to pseudonymized placeholders (`[WORKSPACE_ROOT]`, `[CODEX_HOME]`, `~[USER_HOME]`).
  * Conceals internal 500 error stack traces in production with correlated tracking references (`ref: "err_xxxx"`).
* **Container Sandbox & Process Hardening** ([`container-codex-runner.ts`](file:///workspaces/youth-lah/apps/server/src/container-codex-runner.ts), [`container-security-guard.ts`](file:///workspaces/youth-lah/apps/server/src/container-security-guard.ts))
  * Enforces `--read-only` root filesystem, `--cap-drop ALL`, `--security-opt no-new-privileges`, non-root user execution, memory bounds (`--memory`), CPU limits (`--cpus`), and process quotas (`--pids-limit`).

---

## ⚡ Quickstart

### Prerequisites
* **Node.js**: `22+`
* **npm**: `10+`
* **Container Engine**: Docker, Colima, or rootless Podman (one is required)
* **Volcengine Ark Endpoint**: An Ark API key and endpoint ID supporting the Responses API

---

### Step 1: Configure Environment Variables
Copy the example environment file:
```bash
cp .env.example .env
```

Open `.env` and fill in your Ark API credentials:
```dotenv
ARK_API_KEY=your-ark-api-key
ARK_MODEL=ep-your-endpoint-id
```

---

### Step 2: Start the Application

#### Option A: Local POC (Recommended — Disposable Container Sandbox)
```bash
npm run poc
```
* The script automatically loads `.env`, detects your container engine (Docker, Colima, or Podman), builds the runtime image on the first run, and launches the control plane on `http://localhost:3000`.
* Each turn executes inside an isolated, disposable container with strict resource limits.

#### Option B: Docker Compose (All-in-One Containerized Profile)
```bash
docker compose up --build
```
* Runs both the Fastify control plane and runtime in a single container. Stop with `docker compose down`.

#### Option C: Pure Local Development (Live Reload)
```bash
npm install
npm run dev
```
* Starts the React frontend on `http://localhost:5173` (Vite) and the Fastify backend on `http://localhost:3000` with hot-reloading. Requires `@openai/codex` installed locally.

---

### Step 3: Open the Web UI

Visit **<http://localhost:3000>** (or `http://localhost:5173` in local dev).

1. **Unlock Screen**: If `APP_AUTH_TOKEN` is set in your `.env`, enter the token in the prompt to unlock the dashboard.
2. **Create Agent**: Click **＋ Create Agent**, enter a name (e.g. `Builder`), description, and custom instructions.
3. **Run Tasks**: Select the agent and send a coding task in the Playground:
   ```text
   Create a TypeScript CLI tool that parses JSON from a file, add a unit test, and run it.
   ```
4. **Lifecycle & Session Continuity**: The agent creates files, runs commands inside the workspace, and resumes the stored session thread across subsequent messages.

---

## 🧪 Automated Testing & Verification

The repository includes comprehensive automated unit and integration tests across all defense stages.

### Run All Tests
```bash
# Run all vitest suites
npm test

# Run full quality check (typecheck, tests, and build)
npm run check
```

### Test Specific Defense Layers
```bash
# Layer 1: Inbound prompt injection, extraction, homoglyphs, and jailbreaks
npm test -w @launchpad/server -- inbound-guard.test.ts

# Layer 2: Secret broker, environment stripping, and POSIX 0o700 session isolation
npm test -w @launchpad/server -- secret-broker.test.ts

# Layer 3: Egress network filter, 32-bit IP canonicalization, and IMDS protection
npm test -w @launchpad/server -- egress-network-filter.test.ts

# Layer 3: Host LLM reverse proxy and session authentication
npm test -w @launchpad/server -- llm-proxy.test.ts

# Layer 4: Outbound DLP secret redaction (keys, tokens, PII)
npm test -w @launchpad/server -- outbound-dlp.test.ts

# Layer 5: Error sanitizer and host path pseudonymization
npm test -w @launchpad/server -- error-sanitizer.test.ts

# Container security pre-flight validator
npm test -w @launchpad/server -- container-security-guard.test.ts
```

### 🔬 Manual Verification Prompts
See **[`middleware_verification_prompts.md`](file:///workspaces/youth-lah/middleware_verification_prompts.md)** for ready-to-run prompts to manually test and demonstrate each defense layer in the UI.

---

## ⚙️ Configuration Reference

All settings can be configured via `.env` or system environment variables:

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `ARK_API_KEY` | *Required* | Volcengine Ark model API key. |
| `ARK_MODEL` | *Required* | Responses-capable endpoint or model ID (`ep-xxxxxxxx`). |
| `ARK_BASE_URL` | Beijing v3 endpoint | Volcengine Ark OpenAI-compatible API base URL. |
| `APP_AUTH_TOKEN` | Empty on loopback | Shared access token; 24+ random characters required for remote deployments. |
| `RUNTIME_PROVIDER` | `local-process` | `container` for disposable local containers; `local-process` for direct process execution. |
| `CONTAINER_ENGINE` | `docker` | Container engine binary (`docker` or `podman`). |
| `CODEX_SANDBOX_MODE`| `workspace-write` | Codex inner sandbox mode (`workspace-write`, `read-only`, `danger-full-access`). |
| `CODEX_TIMEOUT_MS` | `600000` (10m) | Maximum turn execution duration before automatic timeout cancellation. |
| `CODEX_MAX_OUTPUT_BYTES` | `2097152` (2MB) | Maximum stream output size to prevent buffer overflow attacks. |
| `EGRESS_NETWORK_MODE`| `restricted` | Egress network policy: `restricted` (allowlist), `none` (air-gapped), or `bridge`. |
| `EGRESS_ALLOWLIST` | Standard package mirrors | Comma-separated list of allowed egress domains (e.g. `registry.npmjs.org,pypi.org`). |
| `LOCAL_POC_DATA_ROOT`| Platform default | Root directory for persistent data, workspaces, and sessions. |

See [`.env.example`](file:///workspaces/youth-lah/.env.example) for additional resource-limit and container-mirror variables.

---

## ⚠️ Known Limitations

1. **Single-Node Control Plane**: Designed as a single-node, single-user demo with a shared access token (`APP_AUTH_TOKEN`); it does not include multi-tenant user accounts or role-based access control (RBAC).
2. **Container Boundary vs Hypervisor Virtualization**: Disposable Docker/Podman containers provide process, filesystem, and resource isolation, but do not provide full hardware-virtualized multi-tenant isolation.
3. **Master Key in Host Memory**: The upstream Ark model API key is held in server host memory for reverse proxy authentication brokering.

---

## 📁 Repository Structure

```text
├── apps/
│   ├── server/               # Fastify backend & defense middleware pipeline
│   │   └── src/
│   │       ├── inbound-guard.ts          # Stage 1: Inbound prompt sanitizer & threat detector
│   │       ├── secret-broker.ts          # Stage 2: Environment stripping & session isolation
│   │       ├── llm-proxy.ts              # Stage 3: Host LLM reverse proxy
│   │       ├── egress-network-filter.ts  # Stage 3: Egress firewall & IMDS protection
│   │       ├── outbound-dlp.ts           # Stage 4: Outbound secret & PII redactor
│   │       ├── error-sanitizer.ts        # Stage 5: Error concealment & path masker
│   │       ├── container-codex-runner.ts # Disposable container execution manager
│   │       └── container-security-guard.ts # Container pre-flight hardening validator
│   └── web/                  # React + TypeScript Web Playground UI
├── scripts/                  # Startup and deployment automation scripts
│   ├── start-local-poc.sh    # Local POC launcher with auto-engine detection
│   ├── bootstrap-local.sh    # Initial workspace directory & .env setup
│   └── deploy-existing-ecs.sh# Volcengine ECS deployment script
├── docs/                     # Technical architecture and extension guides
├── middleware_verification_prompts.md # Verification test prompts guide
├── SECURITY.md               # Security policy and mitigation overview
└── Dockerfile.runtime        # Hardened Agent runtime container definition
```

---

## 📚 Documentation Links

* [Architecture Guide](docs/ARCHITECTURE.md)
* [Local POC Setup & Troubleshooting](docs/LOCAL_POC.md)
* [Deployment on Volcengine ECS & Terraform](docs/DEPLOYMENT.md)
* [Hackathon Extension Guide](docs/HACKATHON_EXTENSION_GUIDE.md)
* [Security Policy](SECURITY.md)
* [Verification Prompts Guide](middleware_verification_prompts.md)

---

## 📄 License

[MIT](LICENSE)

