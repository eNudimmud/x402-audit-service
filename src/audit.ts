/**
 * enki-x402-audit-service — local static audit engine.
 *
 * Pattern-based security/quality scanner. No LLM required, so the service
 * runs (and can be tested) without any paid API key. The LLM hook in
 * server.ts is an OPTIONAL enrichment layer gated behind LLM_PROVIDER.
 *
 * This is a real scanner: it detects concrete, named issue classes with
 * severity + a remediation hint. It is NOT a substitute for a full SAST
 * suite, and the output says so.
 */

import type { AuditFinding, AuditReport, AuditRequest } from "./types.js";

interface Rule {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  // regex matched against each line (case-insensitive where noted)
  pattern: RegExp;
  message: string;
  remediation: string;
  // only apply within these languages (undefined = all)
  languages?: string[];
}

const RULES: Rule[] = [
  {
    id: "hardcoded-secret",
    severity: "critical",
    category: "secrets",
    pattern: /(api[_-]?key|secret|token|passwd|password|private[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-]{8,}['"]/i,
    message: "Possible hardcoded credential or secret in source.",
    remediation: "Move secrets to env vars / a secret manager. Rotate any leaked key.",
  },
  {
    id: "eval-injection",
    severity: "critical",
    category: "injection",
    pattern: /\b(eval|Function|vm\.runInThisContext|setTimeout|setInterval)\s*\(/,
    message: "Dynamic code execution (eval/Function/vm) — code-injection surface.",
    remediation: "Avoid eval of untrusted input. Use safe parsers or sandboxed VMs.",
  },
  {
    id: "sql-concat",
    severity: "high",
    category: "injection",
    pattern: /(SELECT|INSERT|UPDATE|DELETE|query)\b.*\+.*(['"])/i,
    message: "String concatenation into a SQL statement — SQL injection risk.",
    remediation: "Use parameterized queries / prepared statements.",
  },
  {
    id: "shell-injection",
    severity: "high",
    category: "injection",
    pattern: /\b(exec|execSync|spawn|spawnSync|child_process\.exec)\b[^\n]*\+/,
    message: "Shell command built via string concatenation — command injection.",
    remediation: "Pass args as an array; never interpolate untrusted input into a shell string.",
  },
  {
    id: "xss-innerhtml",
    severity: "medium",
    category: "xss",
    pattern: /\.(innerHTML|outerHTML|insertAdjacentHTML)\s*=/,
    message: "Direct assignment to innerHTML — reflected XSS if input is untrusted.",
    remediation: "Use textContent or sanitize with DOMPurify.",
  },
  {
    id: "tls-verify-off",
    severity: "high",
    category: "transport",
    pattern: /(rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED)\s*[:=]\s*(false|0)/i,
    message: "TLS certificate verification disabled — MITM exposure.",
    remediation: "Keep verification on; use a proper CA bundle instead.",
  },
  {
    id: "weak-hash",
    severity: "medium",
    category: "crypto",
    pattern: /\b(md5|sha1)\s*\(/i,
    message: "Weak hash function (MD5/SHA1) used for integrity or passwords.",
    remediation: "Use SHA-256+ for integrity, bcrypt/argon2 for passwords.",
  },
  {
    id: "no-rate-limit",
    severity: "low",
    category: "availability",
    pattern: /app\.(get|post|put|delete)\s*\(['"]\/api/i,
    message: "Public API route detected with no visible rate-limiting in snippet.",
    remediation: "Add rate limiting (e.g. express-rate-limit) on public endpoints.",
  },
  {
    id: "console-log-prod",
    severity: "low",
    category: "hygiene",
    pattern: /\bconsole\.(log|debug|warn)\s*\(/,
    message: "console.* left in code — may leak data to logs in production.",
    remediation: "Use a structured logger with levels; strip debug logs in prod.",
  },
  {
    id: "todo-fixme",
    severity: "info",
    category: "hygiene",
    pattern: /\b(TODO|FIXME|XXX|HACK)\b/,
    message: "Unresolved TODO/FIXME marker.",
    remediation: "Track in an issue tracker; resolve before shipping sensitive code.",
  },
];

const SEVERITY_RANK: Record<AuditFinding["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function auditCode(req: AuditRequest): AuditReport {
  const code = req.code ?? "";
  const lang = (req.language ?? "unknown").toLowerCase();
  const lines = code.split(/\r?\n/);
  const findings: AuditFinding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of RULES) {
      if (rule.languages && !rule.languages.includes(lang)) continue;
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          category: rule.category,
          line: i + 1,
          snippet: line.trim().slice(0, 200),
          message: rule.message,
          remediation: rule.remediation,
        });
      }
    }
  }

  findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  const score = Math.max(
    0,
    100 - (counts.critical * 25 + counts.high * 12 + counts.medium * 5 + counts.low * 2),
  );

  const summary =
    findings.length === 0
      ? "No static patterns matched. Note: this is a lightweight pattern scan, not a full SAST — a clean result is not a guarantee of safety."
      : `Found ${findings.length} issue(s): ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info. Review the findings below.`;

  return {
    schemaVersion: "enki-audit/1.0",
    receivedAt: new Date().toISOString(),
    language: lang,
    scope: req.scope ?? "static-pattern-scan",
    linesScanned: lines.length,
    securityScore: score,
    severityCounts: counts,
    summary,
    findings,
    disclaimer:
      "Automated pattern-based scan. Not a substitute for manual review or a dedicated SAST/DAST pipeline.",
  };
}
