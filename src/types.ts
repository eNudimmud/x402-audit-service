export interface AuditRequest {
  code: string;
  language?: string;
  scope?: string;
}

export interface AuditFinding {
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  line: number;
  snippet: string;
  message: string;
  remediation: string;
}

export interface AuditReport {
  schemaVersion: string;
  receivedAt: string;
  language: string;
  scope: string;
  linesScanned: number;
  securityScore: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  summary: string;
  findings: AuditFinding[];
  disclaimer: string;
}
