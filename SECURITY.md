# Security policy

Volc Agent Launchpad is a hackathon proof of concept. Only the latest revision
on the default branch is supported.

## Report a vulnerability

Send the repository owner or event organizer the affected revision,
reproduction steps, impact, and suggested mitigation. Do not publish
credentials, personal data, or exploit details in an issue.

## Defensive Architecture & Mitigations

This implementation features a comprehensive **5-Stage Defense Pipeline** targeting STRIDE **Information Disclosure** and **Tampering**:

1. **HTTP Security & CSRF Guard**: Enforces strict origin matching (`Sec-Fetch-Site`, `Origin`, `Referer`), custom header verification (`X-Launchpad-Client`), and security headers (`CSP`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).
2. **Inbound Guard & Prompt Sanitizer**: Pre-execution rejection of system prompt extraction, credential harvesting probes, path traversal probing, homoglyph lookalikes, and known jailbreak framing with HTTP `400 Bad Request`.
3. **Secret Broker & Environment Isolation**: All host secrets (`ARK_API_KEY`, `APP_AUTH_TOKEN`, cloud tokens, database URLs) are stripped from agent processes/containers. Per-agent session configurations are locked to POSIX `0o700` directories and `0o600` files.
4. **Host LLM Reverse Proxy & Egress Network Filter**: Ephemeral tokens (`AGENT_SESSION_TOKEN`) route requests through a host-side proxy. The master `ARK_API_KEY` is never exposed to the agent or container. Cloud IMDS metadata (`169.254.169.254`, `100.96.0.96`), CGNAT, and private subnets are blocked.
5. **Outbound DLP & Error/Path Sanitization**: Real-time redaction of API keys, private keys, database connection strings, and PII. Host paths and Docker overlay paths are normalized into pseudonymized aliases (`[WORKSPACE_ROOT]`, `[CODEX_HOME]`, `~[USER_HOME]`).

## Known Limitations

- Designed as a single-node control plane with shared demo authentication (`APP_AUTH_TOKEN`); no per-user RBAC.
- Local containers provide process, filesystem, and resource isolation, but are not virtualization-level multi-tenant sandboxes.
- Model key is stored in memory on the host server running the control plane.

## Safe Use

- Use a dedicated development machine or disposable ECS instance.
- Use a scoped, revocable Ark key and set `APP_AUTH_TOKEN` (24+ characters) for remote or public deployments.
- Keep local usage on loopback (`127.0.0.1`) and restrict firewall/security group ingress for remote instances.
- Never mount host root directories or provide cloud root account credentials to agents.
- See [middleware_verification_prompts.md](middleware_verification_prompts.md) for test prompts to verify all defense layers.
