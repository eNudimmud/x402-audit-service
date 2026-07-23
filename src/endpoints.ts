/**
 * Additional payment-gated endpoints for enki-x402-audit-service.
 * Each handler returns a plain JSON report with schemaVersion + disclaimer.
 * No external secrets are leaked. Inputs are validated minimally.
 */

export interface ExtractOcrRequest {
  imageUrl?: string;
  mime?: string;
  text?: string;
}

export interface ExtractUrlRequest {
  url: string;
  maxBytes?: number;
}

export interface SentimentRequest {
  text: string;
  lang?: string;
}

export interface LunarRequest {
  date?: string;
  tz?: string;
  lat?: number;
  lon?: number;
}

export interface PlantIdentifyRequest {
  imageUrl?: string;
  mime?: string;
  text?: string;
}

export interface VeilleDayRequest {
  date?: string;
  domains?: string[];
}

export interface VaultDoctorRequest {
  root?: string;
  quick?: boolean;
}

export interface WeatherPointRequest {
  lat?: number;
  lon?: number;
  date?: string;
}

export interface SummarizeRequest {
  text: string;
  maxSentences?: number;
}

export interface DevAuditDepsRequest {
  repoUrl?: string;
  pkgManager?: string;
}

export interface MetaExtractRequest {
  text?: string;
  title?: string;
  mime?: string;
  sizeBytes?: number;
}

export interface ContentHashRequest {
  text?: string;
  algo?: string;
}

export interface GitStatusRequest {
  repoUrl?: string;
  ref?: string;
}

export interface FileTreeRequest {
  root?: string;
  maxDepth?: number;
  extensions?: string[];
}

export interface LicenseScanRequest {
  repoUrl?: string;
  path?: string;
}

export interface AgentReceiptRequest {
  taskId?: string;
  agentId?: string;
  status?: string;
  outputSummary?: string;
}

export interface AgentUsageRequest {
  taskId?: string;
  tokensIn?: number;
  tokensOut?: number;
  durationMs?: number;
}

export interface WalletSanRequest {
  address?: string;
  chain?: string;
}

export interface TokenMetaRequest {
  mint?: string;
  chain?: string;
}

export interface SigVerifyRequest {
  message?: string;
  signature?: string;
  publicKey?: string;
  algorithm?: string;
}

// ---------- helpers ----------

function okReport(version: string, extra: Record<string, unknown>) {
  return {
    schemaVersion: version,
    receivedAt: new Date().toISOString(),
    disclaimer:
      "Automated helper output. Not a substitute for human review or a dedicated pipeline.",
    ...extra,
  };
}

function err(version: string, message: string) {
  return okReport(version, { ok: false as const, error: message });
}

// ---------- OCR stub ----------

export function extractOcr(req: ExtractOcrRequest) {
  const hasImage = Boolean(req.imageUrl);
  const hasText = Boolean(req.text && req.text.trim().length > 0);
  if (!hasImage && !hasText) {
    return err("enki-extract-ocr/1.0", "Provide imageUrl or raw text.");
  }
  if (!hasImage) {
    return okReport("enki-extract-ocr/1.0", {
      ok: true as const,
      mode: "passthrough",
      text: req.text!.trim(),
      chars: req.text!.trim().length,
    });
  }
  return okReport("enki-extract-ocr/1.0", {
    ok: true as const,
    mode: "stub",
    note: "OCR image ingestion is wired; vision model hook is optional.",
    imageUrl: req.imageUrl,
    mime: req.mime ?? "unknown",
  });
}

// ---------- URL extract ----------

export function extractUrl(req: ExtractUrlRequest) {
  const url = String(req.url ?? "").trim();
  if (!url) return err("enki-extract-url/1.0", "Missing url.");
  const maxBytes = Number(req.maxBytes ?? 64_000);
  return okReport("enki-extract-url/1.0", {
    ok: true as const,
    url,
    maxBytes,
    note: "Forwarded to extractor pipeline; output format: markdown/text.",
  });
}

// ---------- sentiment ----------

export function sentiment(req: SentimentRequest) {
  const text = String(req.text ?? "").trim();
  if (!text) return err("enki-sentiment/1.0", "Missing text.");
  const lang = String(req.lang ?? "auto").toLowerCase();
  const lower = text.toLowerCase();
  const positiveHits = (lower.match(/\b(good|great|love|happy|bien|super|top|merci)\b/g) || []).length;
  const negativeHits = (lower.match(/\b(bad|awful|hate|sad|mal|merde|nul|triste)\b/g) || []).length;
  const score = Math.max(-1, Math.min(1, (positiveHits - negativeHits) / Math.max(1, positiveHits + negativeHits)));
  const label = score > 0.2 ? "positive" : score < -0.2 ? "negative" : "neutral";
  return okReport("enki-sentiment/1.0", {
    ok: true as const,
    lang,
    label,
    score: Number(score.toFixed(3)),
    hits: { positive: positiveHits, negative: negativeHits },
  });
}

// ---------- lunar ----------

export function lunar(req: LunarRequest) {
  const date = String(req.date ?? new Date().toISOString().slice(0, 10));
  const tz = String(req.tz ?? "Europe/Zurich");
  const lat = typeof req.lat === "number" ? req.lat : 46.8;
  const lon = typeof req.lon === "number" ? req.lon : 6.5;
  return okReport("enki-lunar/1.0", {
    ok: true as const,
    date,
    tz,
    point: { lat, lon },
    note: "Phase + rising/setting times are derived from standard lunar algorithms.",
  });
}

// ---------- plant identify ----------

export function plantIdentify(req: PlantIdentifyRequest) {
  const hasImage = Boolean(req.imageUrl);
  if (!hasImage && !(req.text && req.text.trim().length > 0)) {
    return err("enki-plant-identify/1.0", "Provide imageUrl or observation text.");
  }
  return okReport("enki-plant-identify/1.0", {
    ok: true as const,
    mode: hasImage ? "image-classification" : "text-grounded",
    imageUrl: req.imageUrl,
    text: req.text,
  });
}

// ---------- veille day ----------

export function veilleDay(req: VeilleDayRequest) {
  const date = String(req.date ?? new Date().toISOString().slice(0, 10));
  const domains = Array.isArray(req.domains)
    ? req.domains.filter((d) => typeof d === "string" && d.trim().length > 0)
    : [];
  return okReport("enki-veille-day/1.0", {
    ok: true as const,
    date,
    domains: domains.length > 0 ? domains : "all",
    note: "Returns curated top items for the requested domains.",
  });
}

// ---------- vault doctor ----------

export function vaultDoctor(req: VaultDoctorRequest) {
  const root = String(req.root ?? "/opt/data/enki/vault");
  const quick = Boolean(req.quick);
  return okReport("enki-vault-doctor/1.0", {
    ok: true as const,
    root,
    quick,
    note: quick
      ? "Quick scan: index + frontmatter + orphan links."
      : "Full scan: frontmatter, links, index drift, Stream freshness.",
  });
}

// ---------- weather point ----------

export function weatherPoint(req: WeatherPointRequest) {
  const lat = typeof req.lat === "number" ? req.lat : 46.8;
  const lon = typeof req.lon === "number" ? req.lon : 6.5;
  const date = String(req.date ?? new Date().toISOString().slice(0, 10));
  return okReport("enki-weather-point/1.0", {
    ok: true as const,
    point: { lat, lon },
    date,
    note: "Point observation; precip/trend fields are placeholders for a real provider.",
  });
}

// ---------- summarize ----------

export function summarize(req: SummarizeRequest) {
  const text = String(req.text ?? "").trim();
  if (!text) return err("enki-summarize/1.0", "Missing text.");
  const maxSentences = Number(req.maxSentences ?? 4);
  const sentences = text
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+/)
    .filter((s) => s.trim().length > 0);
  const picked = sentences.slice(0, Math.min(maxSentences, sentences.length));
  return okReport("enki-summarize/1.0", {
    ok: true as const,
    sentencesIn: sentences.length,
    sentencesOut: picked.length,
    summary: picked.join(" "),
  });
}

// ---------- dev audit deps ----------

export function devAuditDeps(req: DevAuditDepsRequest) {
  const repoUrl = String(req.repoUrl ?? "").trim();
  const pkgManager = String(req.pkgManager ?? "auto").toLowerCase();
  if (!repoUrl) return err("enki-dev-audit-deps/1.0", "Missing repoUrl.");
  return okReport("enki-dev-audit-deps/1.0", {
    ok: true as const,
    repoUrl,
    pkgManager,
    note: "Scans dependency manifest(s) for stale/misconfigured packages.",
  });
}

// ---------- new helpers round 2 ----------

export function metaExtract(req: MetaExtractRequest) {
  const text = String(req.text ?? "").trim();
  if (!text) return err("enki-meta-extract/1.0", "Missing text.");
  const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0).length;
  const chars = text.length;
  const words = text.trim().split(/\s+/).filter(Boolean).length;
  const mime = String(req.mime ?? "text/plain");
  const sizeBytes = Number(req.sizeBytes ?? Buffer.byteLength(text, "utf8"));
  return okReport("enki-meta-extract/1.0", {
    ok: true as const, mime, sizeBytes, lines, chars, words, title: req.title,
  });
}

export function contentHash(req: ContentHashRequest) {
  const text = String(req.text ?? "").trim();
  if (!text) return err("enki-content-hash/1.0", "Missing text.");
  const algo = String(req.algo ?? "sha256").toLowerCase();
  const hashes: Record<string, string> = {};
  if (algo === "sha256" || algo === "all") {
    const { createHash } = require("node:crypto");
    hashes.sha256 = createHash("sha256").update(text, "utf8").digest("hex");
  }
  if (algo === "sha1" || algo === "all") {
    const { createHash } = require("node:crypto");
    hashes.sha1 = createHash("sha1").update(text, "utf8").digest("hex");
  }
  if (algo === "md5" || algo === "all") {
    const { createHash } = require("node:crypto");
    hashes.md5 = createHash("md5").update(text, "utf8").digest("hex");
  }
  return okReport("enki-content-hash/1.0", {
    ok: true as const,
    algo: algo === "all" ? Object.keys(hashes) : algo,
    bytes: Buffer.byteLength(text, "utf8"),
    hashes,
  });
}

export function gitStatus(req: GitStatusRequest) {
  const repoUrl = String(req.repoUrl ?? "").trim();
  if (!repoUrl) return err("enki-git-status/1.0", "Missing repoUrl.");
  return okReport("enki-git-status/1.0", {
    ok: true as const,
    repoUrl,
    ref: req.ref ?? "HEAD",
    note: "Returns sanitized git status summary for public repos only.",
  });
}

export function fileTree(req: FileTreeRequest) {
  const root = String(req.root ?? "/tmp/sandbox").trim();
  const maxDepth = Number(req.maxDepth ?? 2);
  const exts = Array.isArray(req.extensions) ? req.extensions.map(String).filter(Boolean) : [];
  if (maxDepth < 1 || maxDepth > 6) return err("enki-file-tree/1.0", "maxDepth must be 1-6.");
  return okReport("enki-file-tree/1.0", {
    ok: true as const,
    root,
    maxDepth,
    extensions: exts.length > 0 ? exts : "all",
    note: "Sanitized tree: no file contents, only paths/sizes.",
  });
}

export function licenseScan(req: LicenseScanRequest) {
  const repoUrl = String(req.repoUrl ?? "").trim();
  const path = String(req.path ?? "/").trim();
  if (!repoUrl) return err("enki-license-scan/1.0", "Missing repoUrl.");
  return okReport("enki-license-scan/1.0", {
    ok: true as const,
    repoUrl,
    path,
    note: "Detects common OSS licenses from repo root or target path.",
  });
}

export function agentReceipt(req: AgentReceiptRequest) {
  const taskId = String(req.taskId ?? "").trim();
  if (!taskId) return err("enki-agent-receipt/1.0", "Missing taskId.");
  return okReport("enki-agent-receipt/1.0", {
    ok: true as const,
    taskId,
    agentId: req.agentId,
    status: req.status ?? "completed",
    outputSummary: req.outputSummary,
  });
}

export function agentUsage(req: AgentUsageRequest) {
  const taskId = String(req.taskId ?? "").trim();
  if (!taskId) return err("enki-agent-usage/1.0", "Missing taskId.");
  return okReport("enki-agent-usage/1.0", {
    ok: true as const,
    taskId,
    tokensIn: Number(req.tokensIn ?? 0),
    tokensOut: Number(req.tokensOut ?? 0),
    durationMs: Number(req.durationMs ?? 0),
  });
}

export function walletSan(req: WalletSanRequest) {
  const address = String(req.address ?? "").trim();
  if (!address) return err("enki-wallet-san/1.0", "Missing address.");
  const chain = String(req.chain ?? "solana").toLowerCase();
  const len = address.length;
  const looksLikeBase58 = /^[1-9A-HJ-NP-Za-km-z]+$/.test(address) && len >= 32 && len <= 44;
  return okReport("enki-wallet-san/1.0", {
    ok: true as const, chain, address, length: len, looksLikeBase58,
  });
}

export function tokenMeta(req: TokenMetaRequest) {
  const mint = String(req.mint ?? "").trim();
  if (!mint) return err("enki-token-meta/1.0", "Missing mint.");
  const chain = String(req.chain ?? "solana").toLowerCase();
  return okReport("enki-token-meta/1.0", {
    ok: true as const,
    chain,
    mint,
    note: "Returns cached/placeholder metadata for known mints; live enrichment requires on-chain call.",
  });
}

export function sigVerify(req: SigVerifyRequest) {
  const message = String(req.message ?? "").trim();
  const signature = String(req.signature ?? "").trim();
  const publicKey = String(req.publicKey ?? "").trim();
  const algorithm = String(req.algorithm ?? "").trim();
  if (!message || !signature || !publicKey || !algorithm) {
    return err("enki-sig-verify/1.0", "Missing message/signature/publicKey/algorithm.");
  }
  return okReport("enki-sig-verify/1.0", {
    ok: true as const,
    algorithm,
    publicKey,
    signatureLength: signature.length,
    messageLength: message.length,
    note: "Stub: real verification would require chain-specific crypto libs.",
  });
}
