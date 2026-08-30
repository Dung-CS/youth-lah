import { SecurityViolationError } from "./errors.js";

export type ThreatCategory =
  | "SYSTEM_PROMPT_EXTRACTION"
  | "CREDENTIAL_HARVESTING"
  | "PATH_TRAVERSAL_PROBING"
  | "EXFILTRATION_COMMANDS"
  | "DELIMITER_INJECTION"
  | "KNOWN_JAILBREAK_PATTERNS";

export interface ThreatFinding {
  category: ThreatCategory;
  severity: "high" | "critical";
  pattern: string;
  reason: string;
  sourceText?: string;
}

export interface InspectionResult {
  allowed: boolean;
  sanitizedPrompt: string;
  threats: ThreatFinding[];
  riskScore: number;
}

interface ThreatRule {
  category: ThreatCategory;
  severity: "high" | "critical";
  regex: RegExp;
  reason: string;
}

// Cyrillic homoglyphs mapping to lookalike Latin letters to prevent unicode bypass
const HOMOGLYPH_MAP: Record<string, string> = {
  "\u0430": "a", // Cyrillic small a
  "\u0410": "A", // Cyrillic capital A
  "\u0435": "e", // Cyrillic small e
  "\u0415": "E", // Cyrillic capital E
  "\u043E": "o", // Cyrillic small o
  "\u041E": "O", // Cyrillic capital O
  "\u0440": "p", // Cyrillic small p
  "\u0420": "P", // Cyrillic capital P
  "\u0441": "c", // Cyrillic small c
  "\u0421": "C", // Cyrillic capital C
  "\u0445": "x", // Cyrillic small x
  "\u0425": "X", // Cyrillic capital X
  "\u0443": "y", // Cyrillic small y
  "\u0423": "Y", // Cyrillic capital Y
  "\u0456": "i", // Cyrillic small i
  "\u0406": "I", // Cyrillic capital I
  "\u0458": "j", // Cyrillic small j
  "\u0408": "J", // Cyrillic capital J
  "\u0412": "B", // Cyrillic capital B
  "\u041A": "K", // Cyrillic capital K
  "\u041C": "M", // Cyrillic capital M
  "\u041D": "H", // Cyrillic capital H
  "\u0422": "T", // Cyrillic capital T
};

const HOMOGLYPH_REGEX = new RegExp("[" + Object.keys(HOMOGLYPH_MAP).join("") + "]", "g");

// Invisible control characters, zero-width characters, and directional marks used for filter evasion
const INVISIBLE_AND_CONTROL_CHARACTERS =
  /[\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFE00-\uFE0F\uFEFF\u00AD\u0000-\u0008\u000B\u000C\u000E-\u001F]/g;

// Regex for extracting Base64 chunks (min 16 chars)
const BASE64_CANDIDATE_REGEX = /\b[A-Za-z0-9+/]{16,}={0,2}\b/g;

const THREAT_RULES: ThreatRule[] = [
  // 1. System Prompt Extraction Attempts (STRIDE Information Disclosure)
  {
    category: "SYSTEM_PROMPT_EXTRACTION",
    severity: "critical",
    regex: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules|directives)/i,
    reason: "Attempt to override or disregard prior system instructions",
  },
  {
    category: "SYSTEM_PROMPT_EXTRACTION",
    severity: "critical",
    regex: /(?:repeat|print|dump|show|reveal|display|output|echo|tell\s+me)\s+(?:all\s+)?(?:your\s+)?(?:system\s+prompt|initial\s+instructions|system\s+instructions|system\s+context|instructions\s+verbatim|original\s+prompt|hidden\s+rules)/i,
    reason: "Direct request to reveal or dump system prompt/instructions",
  },
  {
    category: "SYSTEM_PROMPT_EXTRACTION",
    severity: "high",
    regex: /(?:output|dump|print|cat|read|display)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:AGENTS\.md|platform-managed\s+instructions)/i,
    reason: "Attempt to extract internal platform-managed instruction files (AGENTS.md)",
  },
  {
    category: "SYSTEM_PROMPT_EXTRACTION",
    severity: "high",
    regex: /(?:what\s+are\s+your\s+(?:exact\s+)?(?:system\s+instructions|core\s+directives|initial\s+prompts|system\s+rules))/i,
    reason: "Probing for internal system directives or system instructions",
  },
  {
    category: "SYSTEM_PROMPT_EXTRACTION",
    severity: "critical",
    regex: /(?:忽略|无视|覆盖|绕过)(?:所有|之前的)?(?:系统)?(?:提示词|指令|规则)|(?:输出|打印|显示|获取|查看)(?:你的)?(?:系统提示词|初始指令|系统指令|AGENTS\.md|隐藏规则)/i,
    reason: "Multi-language system prompt extraction attempt",
  },

  // 2. Credential & Environment Variable Harvesting (STRIDE Information Disclosure)
  {
    category: "CREDENTIAL_HARVESTING",
    severity: "critical",
    regex: /\b(?:ARK_API_KEY|APP_AUTH_TOKEN|VOLCENGINE_ACCESS_KEY|VOLCENGINE_SECRET_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|VAULT_TOKEN)\b/i,
    reason: "Direct probe for high-privilege platform API keys or tokens",
  },
  {
    category: "CREDENTIAL_HARVESTING",
    severity: "critical",
    regex: /(?:echo|print|export|env|dump)\s+\$(?:[A-Z0-9_]*KEY|[A-Z0-9_]*TOKEN|[A-Z0-9_]*SECRET|[A-Z0-9_]*PASS)/i,
    reason: "Shell command targeting secret environment variable expansion",
  },
  {
    category: "CREDENTIAL_HARVESTING",
    severity: "critical",
    regex: /(?:\bprintenv\b|\benv\s*\|\s*grep|\/proc\/(?:self|\d+)\/(?:environ|cmdline))/i,
    reason: "Attempt to dump process environment variables or /proc environ",
  },
  {
    category: "CREDENTIAL_HARVESTING",
    severity: "critical",
    regex: /(?:console\.log|JSON\.stringify|Object\.keys|Object\.entries|Object\.values)\s*\(\s*process\.env\s*\)|(?:dump|print|reveal|output|display|show|leak)\s+(?:all\s+)?process\.env\b/i,
    reason: "Targeted script attempt to dump the full process.env object",
  },
  {
    category: "CREDENTIAL_HARVESTING",
    severity: "high",
    regex: /(?:cat|read|dump|extract|print|grep|head|tail|base64|source)\s+[^\n;]*?(?:(?<![a-zA-Z0-9_.])\.env(?:\.local|\.production|\.development)?|launchpad\.json|codex-home\/config\.toml)\b(?!\.example|\.sample|\.template)/i,
    reason: "Attempt to inspect or extract sensitive .env files or internal platform store/config",
  },
  {
    category: "CREDENTIAL_HARVESTING",
    severity: "critical",
    regex: /(?:169\.254\.169\.254|100\.96\.0\.96|metadata\.google\.internal|fd00:ec2::254)/i,
    reason: "Probing cloud instance metadata services (IMDS) for cloud credentials or IAM tokens",
  },

  // 3. Path Traversal & Sensitive Host File Probing (STRIDE Information Disclosure)
  {
    category: "PATH_TRAVERSAL_PROBING",
    severity: "critical",
    regex: /(?:\/etc\/(?:passwd|shadow|sudoers|master\.passwd|environment|profile)|\/var\/run\/docker\.sock|\/root\/\.ssh)/i,
    reason: "Accessing sensitive host OS configuration or authentication files",
  },
  {
    category: "PATH_TRAVERSAL_PROBING",
    severity: "critical",
    regex: /(?:id_rsa|id_ed25519|id_ecdsa|\.ssh\/authorized_keys|\.aws\/(?:credentials|config)|\.config\/gcloud|\.docker\/config\.json|\.npmrc|\.git-credentials|\.netrc|KUBECONFIG)/i,
    reason: "Attempt to harvest private SSH keys, cloud credentials, or package manager tokens",
  },
  {
    category: "PATH_TRAVERSAL_PROBING",
    severity: "high",
    regex: /(?:\.\.\/){3,}|(?:\.\.\\){3,}/,
    reason: "Deep relative path traversal attempt (escaping workspace root)",
  },

  // 4. Data Exfiltration via Network Egress & Remote Shells (STRIDE Information Disclosure)
  {
    category: "EXFILTRATION_COMMANDS",
    severity: "critical",
    regex: /\b(?:curl|wget)\b[^\n]*?(?:--data|--data-binary|--data-raw|-d|--post-file|--post-data|--upload-file)\s*[@$]/i,
    reason: "Network command attempting to exfiltrate local file contents or secrets via HTTP POST",
  },
  {
    category: "EXFILTRATION_COMMANDS",
    severity: "critical",
    regex: /\b(?:bash|sh|zsh)\s+-i\s+>&?\s*\/dev\/(?:tcp|udp)\/|\b(?:nc|netcat|ncat)\s+.*-e\s+\/(?:bin|usr)/i,
    reason: "Attempt to spawn an outbound reverse shell or socket exfiltration tunnel",
  },
  {
    category: "EXFILTRATION_COMMANDS",
    severity: "critical",
    regex: /\b(?:curl|wget)\b[^\n|;&]+?\|\s*(?:sh|bash|zsh|python|node)\b/i,
    reason: "Attempt to pipe unverified remote network script into execution shell",
  },

  // 5. Delimiter & Control Tag Injection (Prompt Hijacking / Boundary Breaking)
  {
    category: "DELIMITER_INJECTION",
    severity: "critical",
    regex: /(?:<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[\/?(?:SYSTEM|INST|ASSISTANT)\]|<<SYS>>|<\/?(?:system|system_prompt|role)>)/i,
    reason: "Attempting to inject raw LLM delimiter tags or pseudo-system framing",
  },
  {
    category: "DELIMITER_INJECTION",
    severity: "high",
    regex: /(?:---\s*(?:BEGIN|END)\s+(?:SYSTEM|ADMIN|INTERNAL)\s+(?:INSTRUCTIONS|PROMPT|DIRECTIVE)\s*---)/i,
    reason: "Attempting synthetic system instruction delimiter injection",
  },

  // 6. Known Jailbreak & Safety Override Patterns
  {
    category: "KNOWN_JAILBREAK_PATTERNS",
    severity: "critical",
    regex: /\b(?:DAN\s+mode|Do\s+Anything\s+Now|Developer\s+Mode\s+Output|AIM\s+mode|jailbreak\s+mode|unrestricted\s+AI\s+mode)\b/i,
    reason: "Known adversarial jailbreak framing detected",
  },
  {
    category: "KNOWN_JAILBREAK_PATTERNS",
    severity: "high",
    regex: /(?:you\s+must\s+ignore\s+(?:all\s+)?safety\s+filters|disable\s+(?:all\s+)?guardrails|act\s+as\s+an\s+unfiltered\s+AI)/i,
    reason: "Explicit instruction to disable safety controls or guardrails",
  },
];

export class InboundGuard {
  /**
   * Sanitizes input text by removing invisible/control characters,
   * normalizing unicode (NFKC), and standardizing whitespace.
   */
  static sanitize(text: string): string {
    if (!text) return "";
    return text
      .replace(INVISIBLE_AND_CONTROL_CHARACTERS, "")
      .normalize("NFKC")
      .trim();
  }

  /**
   * Normalizes homoglyphs (e.g. Cyrillic/Greek lookalikes) for security inspection.
   */
  static normalizeForInspection(text: string): string {
    const cleaned = this.sanitize(text);
    return cleaned.replace(HOMOGLYPH_REGEX, (match) => HOMOGLYPH_MAP[match] || match);
  }

  /**
   * Extracts and decodes potential URL-encoded and Base64-encoded strings for deep inspection.
   */
  static extractDecodedPayloads(text: string): string[] {
    const payloads: string[] = [];

    // 1. URL percent-decoding
    if (text.includes("%")) {
      try {
        const decodedUrl = decodeURIComponent(text);
        if (decodedUrl !== text) payloads.push(decodedUrl);
      } catch {
        // Ignore malformed URL sequences
      }
    }

    // 2. Base64 payload decoding
    const candidates = text.match(BASE64_CANDIDATE_REGEX) || [];
    for (const candidate of candidates) {
      try {
        const decoded = Buffer.from(candidate, "base64").toString("utf8");
        // Only consider if decoded string contains printable ASCII / UTF-8
        if (decoded && /^[\x20-\x7E\s]+$/.test(decoded) && decoded !== candidate) {
          payloads.push(decoded);
        }
      } catch {
        // Ignore invalid base64
      }
    }

    return payloads;
  }

  /**
   * Inspects a prompt against threat rules and security boundaries.
   */
  static inspect(rawPrompt: string): InspectionResult {
    const sanitizedPrompt = this.sanitize(rawPrompt);
    const normalizedForRules = this.normalizeForInspection(rawPrompt);
    const decodedPayloads = this.extractDecodedPayloads(sanitizedPrompt);
    const variants = [sanitizedPrompt, normalizedForRules, ...decodedPayloads];

    const threats: ThreatFinding[] = [];
    const recordedPatterns = new Set<string>();

    for (const variant of variants) {
      for (const rule of THREAT_RULES) {
        if (rule.regex.test(variant)) {
          const key = rule.category + ":" + rule.reason;
          if (!recordedPatterns.has(key)) {
            recordedPatterns.add(key);
            threats.push({
              category: rule.category,
              severity: rule.severity,
              pattern: rule.regex.source,
              reason: rule.reason,
            });
          }
        }
      }
    }

    const hasCritical = threats.some((t) => t.severity === "critical");
    const hasHigh = threats.some((t) => t.severity === "high");
    const allowed = threats.length === 0;

    let riskScore = 0;
    if (hasCritical) riskScore = 100;
    else if (hasHigh) riskScore = 75;
    else if (threats.length > 0) riskScore = 50;

    return {
      allowed,
      sanitizedPrompt,
      threats,
      riskScore,
    };
  }

  /**
   * Validates a prompt and returns the sanitized text.
   * Throws SecurityViolationError if any threat is identified.
   */
  static validateOrThrow(rawPrompt: string): string {
    const result = this.inspect(rawPrompt);
    if (!result.allowed) {
      const primaryThreat = result.threats[0];
      const category = primaryThreat?.category ?? "UNKNOWN";
      const reason = primaryThreat?.reason ?? "Security boundary violation";
      throw new SecurityViolationError(
        `Inbound prompt rejected by InboundGuard: ${reason} [${category}]`,
        category,
        reason,
      );
    }
    return result.sanitizedPrompt;
  }
}
