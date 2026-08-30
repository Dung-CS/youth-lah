import type { AppConfig } from "./config.js";

export type EgressNetworkMode = "none" | "restricted" | "bridge";

export interface EgressDecision {
  allowed: boolean;
  reason: string;
  destination: string;
  mode: EgressNetworkMode;
}

export interface EgressInspectionResult {
  allowed: boolean;
  violations: string[];
  commandsChecked: number;
}

// Default reputable developer package registries allowed in restricted mode
export const DEFAULT_ALLOWED_DOMAINS = [
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "pypi.org",
  "files.pythonhosted.org",
  "deb.debian.org",
  "security.debian.org",
  "archive.ubuntu.com",
  "security.ubuntu.com",
  "github.com",
  "api.github.com",
  "raw.githubusercontent.com",
] as const;

// Blocked internal & cloud metadata hostnames
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "instance-data",
  "instance-data.ec2.internal",
]);

export class EgressNetworkFilter {
  /**
   * Parses standard, hex, octal, decimal, or mixed IPv4 representations
   * into a canonical 32-bit unsigned integer (0 - 4294967295).
   * Returns null if the input is not a valid IPv4 representation.
   */
  static parseIpv4ToUint32(target: string): number | null {
    if (!target) return null;
    const clean = target.trim().replace(/\.+$/, "");

    // 1. Single integer representation (Decimal: 2852039166, Hex: 0xa9fea9fe, Octal: 025177524776)
    if (/^(?:0x[0-9a-fA-F]+|0[0-7]+|\d+)$/.test(clean)) {
      const parsed = clean.startsWith("0x") || clean.startsWith("0X")
        ? parseInt(clean, 16)
        : clean.startsWith("0") && clean.length > 1
          ? parseInt(clean, 8)
          : parseInt(clean, 10);

      if (!isNaN(parsed) && parsed >= 0 && parsed <= 0xffffffff) {
        return parsed >>> 0;
      }
    }

    // 2. Dotted notation (1 to 4 segments, each potentially dec, hex, or octal)
    const segments = clean.split(".");
    if (segments.length >= 1 && segments.length <= 4) {
      const parsedSegments: number[] = [];
      for (const seg of segments) {
        if (!/^(?:0x[0-9a-fA-F]+|0[0-7]+|\d+)$/.test(seg)) {
          return null;
        }
        const val = seg.startsWith("0x") || seg.startsWith("0X")
          ? parseInt(seg, 16)
          : seg.startsWith("0") && seg.length > 1
            ? parseInt(seg, 8)
            : parseInt(seg, 10);
        if (isNaN(val) || val < 0) return null;
        parsedSegments.push(val);
      }

      if (parsedSegments.length === 4) {
        if (parsedSegments.some((s) => s > 255)) return null;
        return (
          ((parsedSegments[0]! << 24) |
            (parsedSegments[1]! << 16) |
            (parsedSegments[2]! << 8) |
            parsedSegments[3]!) >>>
          0
        );
      } else if (parsedSegments.length === 3) {
        // a.b.c (where c is 16-bit)
        if (parsedSegments[0]! > 255 || parsedSegments[1]! > 255 || parsedSegments[2]! > 65535) {
          return null;
        }
        return (
          ((parsedSegments[0]! << 24) | (parsedSegments[1]! << 16) | parsedSegments[2]!) >>>
          0
        );
      } else if (parsedSegments.length === 2) {
        // a.b (where b is 24-bit)
        if (parsedSegments[0]! > 255 || parsedSegments[1]! > 16777215) return null;
        return ((parsedSegments[0]! << 24) | parsedSegments[1]!) >>> 0;
      }
    }

    return null;
  }

  /**
   * Checks if an IP address or hostname is a private/internal network address or cloud metadata endpoint.
   */
  static isPrivateOrMetadataAddress(target: string): boolean {
    if (!target) return false;
    let clean = target.trim().toLowerCase().replace(/^\[|\]$/g, "");
    clean = clean.replace(/\.+$/, ""); // Strip trailing FQDN dots

    // 1. Blocked static hostnames & domains
    if (BLOCKED_HOSTNAMES.has(clean)) return true;
    if (
      clean.endsWith(".localhost") ||
      clean.endsWith(".local") ||
      clean.endsWith(".internal") ||
      clean.endsWith(".localdomain")
    ) {
      return true;
    }

    // 2. IPv6 Private / Loopback / Metadata
    if (
      clean === "::1" ||
      clean === "0:0:0:0:0:0:0:1" ||
      clean === "::" ||
      clean.startsWith("fc") ||
      clean.startsWith("fd") ||
      clean.startsWith("fe80:") ||
      clean === "fd00:ec2::254"
    ) {
      return true;
    }

    // 3. IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254 or ::ffff:a9fe:a9fe)
    if (clean.startsWith("::ffff:") || clean.startsWith("0:0:0:0:0:ffff:")) {
      const remainder = clean.split("ffff:").at(-1) || "";
      if (remainder) {
        if (remainder.includes(".") || /^[0-9a-fA-F]+$/.test(remainder)) {
          return this.isPrivateOrMetadataAddress(remainder);
        }
      }
    }

    // 4. Canonical 32-bit IPv4 parsing & subnet evaluation
    const ip = this.parseIpv4ToUint32(clean);
    if (ip !== null) {
      // 0.0.0.0/8 (Local broadcast / current network)
      if ((ip >>> 24) === 0) return true;

      // 127.0.0.0/8 (Loopback)
      if ((ip >>> 24) === 127) return true;

      // 10.0.0.0/8 (Private RFC 1918)
      if ((ip >>> 24) === 10) return true;

      // 172.16.0.0/12 (Private RFC 1918: 172.16.0.0 - 172.31.255.255)
      if (ip >= 0xac100000 && ip <= 0xac1fffff) return true;

      // 192.168.0.0/16 (Private RFC 1918)
      if ((ip >>> 16) === 0xc0a8) return true;

      // 169.254.0.0/16 (Link-Local & Cloud IMDS 169.254.169.254)
      if ((ip >>> 16) === 0xa9fe) return true;

      // 100.64.0.0/10 (CGNAT / Shared Address Space - includes Volcengine IMDS 100.96.0.96 & Alibaba 100.100.100.200)
      if (ip >= 0x64400000 && ip <= 0x647fffff) return true;

      // 192.0.0.0/24 (IETF Protocol Assignments)
      if ((ip >>> 8) === 0xc00000) return true;

      // 198.18.0.0/15 (Network Interconnect Benchmark Testing)
      if (ip >= 0xc6120000 && ip <= 0xc613ffff) return true;

      // 224.0.0.0/3 (Multicast, Reserved, Broadcast: 224.0.0.0 - 255.255.255.255)
      if (ip >= 0xe0000000) return true;
    }

    return false;
  }

  /**
   * Extracts the canonical hostname from a URL, host:port string, or raw token.
   */
  static extractHost(destination: string): string {
    let raw = destination.trim();
    if (!raw) return "";

    // If it's a URL, parse hostname
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
      try {
        const parsed = new URL(raw);
        return parsed.hostname.toLowerCase().replace(/\.+$/, "");
      } catch {
        // Fallback to manual stripping if URL parse fails
      }
    }

    // Strip scheme, path, query, credentials if present
    raw = raw.replace(/^[a-zA-Z0-9+.-]+:\/\//, "");
    raw = raw.split("/")[0] || "";
    raw = raw.split("?")[0] || "";
    raw = raw.split("#")[0] || "";
    raw = raw.split("@").at(-1) || "";
    raw = raw.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
    raw = raw.split(":")[0] || "";
    raw = raw.replace(/\.+$/, ""); // strip trailing FQDN dot

    return raw.toLowerCase().trim();
  }

  /**
   * Builds the effective allowlist of domains from config and defaults.
   */
  static getEffectiveAllowlist(config: AppConfig): Set<string> {
    const allowlist = new Set<string>();

    // 1. Model provider host from Ark config (e.g. ark.cn-beijing.volces.com)
    if (config.arkBaseUrl) {
      try {
        const arkHost = new URL(config.arkBaseUrl).hostname.toLowerCase().replace(/\.+$/, "");
        if (arkHost) allowlist.add(arkHost);
      } catch {
        // Ignore invalid arkBaseUrl
      }
    }

    // 2. Default standard package registries
    for (const domain of DEFAULT_ALLOWED_DOMAINS) {
      allowlist.add(domain);
    }

    // 3. Custom operator allowlist
    if (Array.isArray(config.egressAllowlist)) {
      for (const domain of config.egressAllowlist) {
        if (domain) allowlist.add(domain.toLowerCase().trim().replace(/\.+$/, ""));
      }
    }

    return allowlist;
  }

  /**
   * Evaluates an outbound connection target against the configured egress policy.
   */
  static validateDestination(
    destination: string,
    config: AppConfig,
  ): EgressDecision {
    const mode = config.egressNetworkMode || "restricted";
    const host = this.extractHost(destination);

    // Mode: none (Complete network air-gapping)
    if (mode === "none") {
      return {
        allowed: false,
        reason: "Outbound network connection blocked: network mode is set to 'none' (air-gapped)",
        destination,
        mode,
      };
    }

    // Check for blocked private / metadata addresses (Blocked in all modes including bridge)
    if (this.isPrivateOrMetadataAddress(host)) {
      return {
        allowed: false,
        reason: `Outbound connection to private address or cloud metadata endpoint blocked (${host})`,
        destination,
        mode,
      };
    }

    // Mode: bridge (Standard network mode with SSRF/metadata protection)
    if (mode === "bridge") {
      return {
        allowed: true,
        reason: "Destination permitted in bridge network mode",
        destination,
        mode,
      };
    }

    // Mode: restricted (Enforce destination allowlist)
    const allowlist = this.getEffectiveAllowlist(config);

    // Direct match or parent domain match (e.g. sub.api.github.com allowed if api.github.com is allowlisted)
    const isAllowlisted = Array.from(allowlist).some(
      (allowed) => host === allowed || host.endsWith("." + allowed),
    );

    if (isAllowlisted) {
      return {
        allowed: true,
        reason: `Destination is permitted in egress allowlist (${host})`,
        destination,
        mode,
      };
    }

    return {
      allowed: false,
      reason: `Outbound connection blocked: destination '${host}' is not in egress allowlist`,
      destination,
      mode,
    };
  }

  /**
   * Generates container networking flags based on the configured egress mode.
   */
  static buildContainerNetworkArgs(config: AppConfig): string[] {
    const mode = config.egressNetworkMode || "restricted";

    if (mode === "none") {
      return ["--network", "none"];
    }

    return ["--network", "bridge"];
  }

  /**
   * Inspects command text for potential outbound network execution attempts
   * and verifies whether the targeted destinations conform to egress policy.
   */
  static inspectCommandEgress(
    command: string,
    config: AppConfig,
  ): EgressInspectionResult {
    if (!command) {
      return { allowed: true, violations: [], commandsChecked: 0 };
    }

    const violations: string[] = [];
    let commandsChecked = 0;

    // 1. Direct URL extraction across the entire command string (covers curl, git, pip, python, node, etc.)
    const urlMatches = command.match(/https?:\/\/[^\s"'`<>]+/gi) || [];
    for (const url of urlMatches) {
      commandsChecked++;
      const decision = this.validateDestination(url, config);
      if (!decision.allowed && !violations.includes(decision.reason)) {
        violations.push(decision.reason);
      }
    }

    // 2. Command-specific token inspection (for nc, socat, ssh, telnet, curl/wget without http://)
    const networkCmdRegex =
      /\b(?:curl|wget|fetch|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|ftp)\b(?:\s+[^\s;&|]+)*/gi;

    const matches = command.match(networkCmdRegex) || [];
    for (const match of matches) {
      commandsChecked++;
      const tokens = match.trim().split(/\s+/).slice(1);
      for (const token of tokens) {
        if (
          !token.startsWith("-") &&
          !token.startsWith("@") &&
          !token.startsWith("$") &&
          token.length > 2
        ) {
          // If token looks like an IP (dec/hex/octal/dotted), hostname, or metadata endpoint
          if (
            /^(\d{1,3}\.){1,3}\d{1,3}(:\d+)?$/.test(token) ||
            /^(?:0x[0-9a-fA-F]+|\d{4,})(:\d+)?$/.test(token) ||
            /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?$/.test(token) ||
            token === "localhost" ||
            token.startsWith("169.254.") ||
            token.startsWith("100.96.") ||
            token.startsWith("100.100.")
          ) {
            const decision = this.validateDestination(token, config);
            if (!decision.allowed && !violations.includes(decision.reason)) {
              violations.push(decision.reason);
            }
          }
        }
      }
    }

    return {
      allowed: violations.length === 0,
      violations,
      commandsChecked,
    };
  }
}
