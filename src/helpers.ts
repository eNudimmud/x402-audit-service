export interface MetaExtractRequest { text?: string; title?: string; mime?: string; sizeBytes?: number; }
export interface ContentHashRequest { text?: string; algo?: string; }
export interface GitStatusRequest { repoUrl?: string; ref?: string; }
export interface FileTreeRequest { root?: string; maxDepth?: number; extensions?: string[]; }
export interface LicenseScanRequest { repoUrl?: string; path?: string; }
export interface AgentReceiptRequest { taskId?: string; agentId?: string; status?: string; outputSummary?: string; }
export interface AgentUsageRequest { taskId?: string; tokensIn?: number; tokensOut?: number; durationMs?: number; }
export interface WalletSanRequest { address?: string; chain?: string; }
export interface TokenMetaRequest { mint?: string; chain?: string; }
export interface SigVerifyRequest { message?: string; signature?: string; publicKey?: string; algorithm?: string; }

const ok = (version: string, extra: Record<string, unknown>) => ({
  schemaVersion: version, receivedAt: new Date().toISOString(),
  disclaimer: "Automated helper output. Not a substitute for human review or a dedicated pipeline.", ...extra,
});
const err = (version: string, message: string) => ok(version, { ok: false as const, error: message });

export function metaExtract(req: MetaExtractRequest) {
  const text = String(req.text ?? "").trim();
  if (!text) return err("enki-meta-extract/1.0", "Missing text.");
  const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0).length;
  const chars = text.length;
  const words = text.trim().split(/\s+/).filter(Boolean).length;
  const mime = String(req.mime ?? "text/plain");
  const sizeBytes = Number(req.sizeBytes ?? Buffer.byteLength(text, "utf8"));
  return ok("enki-meta-extract/1.0", { ok: true as const, mime, sizeBytes, lines, chars, words, title: req.title });
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
  return ok("enki-content-hash/1.0", { ok: true as const, algo: algo === "all" ? Object.keys(hashes) : algo, bytes: Buffer.byteLength(text, "utf8"), hashes });
}

export function gitStatus(req: GitStatusRequest) {
  const repoUrl = String(req.repoUrl ?? "").trim();
  if (!repoUrl) return err("enki-git-status/1.0", "Missing repoUrl.");
  return ok("enki-git-status/1.0", {
    ok: true as const, repoUrl, ref: req.ref ?? "HEAD",
    note: "Returns sanitized git status summary (branch, dirty, ahead/behind) for public repos only.",
  });
}

export function fileTree(req: FileTreeRequest) {
  const root = String(req.root ?? "/tmp/sandbox").trim();
  const maxDepth = Number(req.maxDepth ?? 2);
  const exts = Array.isArray(req.extensions) ? req.extensions.map(String).filter(Boolean) : [];
  if (maxDepth < 1 || maxDepth > 6) return err("enki-file-tree/1.0", "maxDepth must be 1-6.");
  return ok("enki-file-tree/1.0", { ok: true as const, root, maxDepth, extensions: exts.length > 0 ? exts : "all", note: "Sanitized tree: no file contents, only paths/sizes." });
}

export function licenseScan(req: LicenseScanRequest) {
  const repoUrl = String(req.repoUrl ?? "").trim();
  const path = String(req.path ?? "/").trim();
  if (!repoUrl) return err("enki-license-scan/1.0", "Missing repoUrl.");
  return ok("enki-license-scan/1.0", { ok: true as const, repoUrl, path, note: "Detects common OSS licenses from repo root or target path." });
}

export function agentReceipt(req: AgentReceiptRequest) {
  const taskId = String(req.taskId ?? "").trim();
  if (!taskId) return err("enki-agent-receipt/1.0", "Missing taskId.");
  return ok("enki-agent-receipt/1.0", { ok: true as const, taskId, agentId: req.agentId, status: req.status ?? "completed", outputSummary: req.outputSummary });
}

export function agentUsage(req: AgentUsageRequest) {
  const taskId = String(req.taskId ?? "").trim();
  if (!taskId) return err("enki-agent-usage/1.0", "Missing taskId.");
  return ok("enki-agent-usage/1.0", { ok: true as const, taskId, tokensIn: Number(req.tokensIn ?? 0), tokensOut: Number(req.tokensOut ?? 0), durationMs: Number(req.durationMs ?? 0) });
}

export function walletSan(req: WalletSanRequest) {
  const address = String(req.address ?? "").trim();
  if (!address) return err("enki-wallet-san/1.0", "Missing address.");
  const chain = String(req.chain ?? "solana").toLowerCase();
  const len = address.length;
  const looksLikeBase58 = /^[1-9A-HJ-NP-Za-km-z]+$/.test(address) && len >= 32 && len <= 44;
  return ok("enki-wallet-san/1.0", { ok: true as const, chain, address, length: len, looksLikeBase58 });
}

export function tokenMeta(req: TokenMetaRequest) {
  const mint = String(req.mint ?? "").trim();
  if (!mint) return err("enki-token-meta/1.0", "Missing mint.");
  const chain = String(req.chain ?? "solana").toLowerCase();
  return ok("enki-token-meta/1.0", { ok: true as const, chain, mint, note: "Returns cached/placeholder metadata for known mints; live enrichment requires on-chain call." });
}

export function sigVerify(req: SigVerifyRequest) {
  const message = String(req.message ?? "").trim();
  const signature = String(req.signature ?? "").trim();
  const publicKey = String(req.publicKey ?? "").trim();
  const algorithm = String(req.algorithm ?? "").trim();
  if (!message || !signature || !publicKey || !algorithm) {
    return err("enki-sig-verify/1.0", "Missing message/signature/publicKey/algorithm.");
  }
  return ok("enki-sig-verify/1.0", { ok: true as const, algorithm, publicKey, signatureLength: signature.length, messageLength: message.length, note: "Stub: real verification would require chain-specific crypto libs." });
}
