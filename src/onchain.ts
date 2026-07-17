/**
 * enki-x402-audit-service — REAL on-chain audit engine (Solana mainnet).
 *
 * Read-only RPC analysis of a Solana target. Auto-detects kind:
 *   - SPL / Token-2022 mint  -> token/contract audit (supply, authorities,
 *                               top-holder concentration, rug-risk flags)
 *   - Wallet (system account) -> wallet audit (SOL balance, token holdings,
 *                               suspicious-token exposure, activity)
 *
 * Uses public mainnet RPC with `encoding: jsonParsed` so the node parses
 * SPL/Mint/Token accounts for us. NO writes, NO signatures, NO keys.
 *
 * Honesty note: this is a HEURISTIC on-chain check, not a full forensic lab.
 * Output says so. Liquidity/dex data is NOT fetched here (off-chain); we flag
 * what on-chain state reveals and mark the rest as "needs off-chain check".
 */

// Public mainnet RPCs (free tier). Tried in order; some methods (e.g.
// getTokenLargestAccounts) are throttled on free tiers — the caller marks
// those results "unchecked" honestly instead of faking them.
const RPC_URLS =
  process.env.SOLANA_RPC_URLS?.split(",").map((s) => s.trim()).filter(Boolean) ??
  [
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
    "https://solana.api.onfinality.io/public",
  ];

// Well-known program IDs (for owner-based detection)
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

export interface OnchainFinding {
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  message: string;
  detail?: string;
  remediation?: string;
}

export interface OnchainReport {
  schemaVersion: string;
  receivedAt: string;
  target: string;
  detectedKind: "token-mint" | "token-2022-mint" | "wallet" | "unknown";
  network: string;
  rpc: string;
  summary: string;
  findings: OnchainFinding[];
  // structured facts (so a human/buyer can verify on-chain themselves)
  facts: Record<string, unknown>;
  riskScore: number; // 0 (safe) .. 100 (dangerous)
  disclaimer: string;
}

type RpcResult = {
  jsonrpc: string;
  id: number;
  result?: { context: unknown; value: unknown };
  error?: { code: number; message: string };
};

async function rpc(
  method: string,
  params: unknown[],
  tries = RPC_URLS.length,
): Promise<unknown> {
  let lastErr: unknown;
  for (let i = 0; i < tries; i++) {
    const url = RPC_URLS[i % RPC_URLS.length];
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(15000),
      });
      const body = (await res.json()) as RpcResult;
      if (body.error) {
        // throttled / blocked on this RPC -> try next endpoint
        lastErr = new Error(`RPC ${method}: ${body.error.message}`);
        continue;
      }
      return body.result?.value;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(`RPC ${method} failed`);
}

function shortAddr(a: string): string {
  return a.length > 12 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

export interface OnchainRequest {
  target: string;
  kind?: "auto" | "wallet" | "token";
}

export async function auditOnchain(req: OnchainRequest): Promise<OnchainReport> {
  const target = (req.target ?? "").trim();
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(target)) {
    throw new Error("Invalid Solana address (expected base58, 32-44 chars).");
  }

  const findings: OnchainFinding[] = [];
  const facts: Record<string, unknown> = {};

  // 1. Resolve the account to detect kind.
  const accountInfo = (await rpc("getAccountInfo", [
    target,
    { encoding: "jsonParsed" },
  ])) as
    | {
        owner: string;
        lamports: number;
        data: { parsed?: { info: Record<string, unknown>; type?: string } };
        executable: boolean;
      }
    | null;

  if (!accountInfo) {
    findings.push({
      ruleId: "account-not-found",
      severity: "medium",
      category: "existence",
      message: "No account exists at this address on mainnet.",
      detail:
        "Either a typo, a devnet/testnet address, or a program that returns no data.",
      remediation: "Double-check the address; ensure it is a mainnet base58.",
    });
    return finalize(target, "unknown", findings, facts, 50);
  }

  const owner = accountInfo.owner;
  const lamports = accountInfo.lamports ?? 0;
  const parsed = accountInfo.data?.parsed;

  // 2. Token mint detection
  if (owner === TOKEN_PROGRAM || owner === TOKEN_2022_PROGRAM) {
    const is2022 = owner === TOKEN_2022_PROGRAM;
    const kind = is2022 ? "token-2022-mint" : "token-mint";
    facts.kind = kind;
    if (parsed?.info) {
      const info = parsed.info as Record<string, unknown>;
      const supply = info["supply"] as string;
      const decimals = info["decimals"] as number;
      const mintAuth = info["mintAuthority"] as string | null;
      const freezeAuth = info["freezeAuthority"] as string | null;
      facts.supply = supply;
      facts.decimals = decimals;
      facts.mintAuthority = mintAuth ?? "REVOQUED";
      facts.freezeAuthority = freezeAuth ?? "none";
      facts.program = is2022 ? "Token-2022" : "SPL Token";

      if (mintAuth !== null) {
        findings.push({
          ruleId: "mint-auth-live",
          severity: "high",
          category: "rug-risk",
          message: "Mint authority is NOT revoked.",
          detail: `Mint authority: ${shortAddr(mintAuth)} — issuer can create more supply at will.`,
          remediation: "Treat as inflation risk; demand revocation before trust.",
        });
      } else {
        findings.push({
          ruleId: "mint-auth-revoked",
          severity: "info",
          category: "rug-risk",
          message: "Mint authority revoked — supply is fixed.",
          detail: "Good sign: no one can mint more.",
        });
      }
      if (freezeAuth !== null) {
        findings.push({
          ruleId: "freeze-auth-live",
          severity: "high",
          category: "rug-risk",
          message: "Freeze authority is ACTIVE.",
          detail: `Freeze authority: ${shortAddr(freezeAuth)} — can freeze all holder accounts.`,
          remediation: "High control risk; issuer can lock holder funds.",
        });
      }

      // top holder concentration via getTokenLargestAccounts
      try {
        const largest = (await rpc("getTokenLargestAccounts", [target])) as Array<{
          address: string;
          amount: string;
          decimals: number;
          uiAmount: number | null;
        }>;
        const supplyNum = Number(supply);
        const top = largest.slice(0, 5).map((a) => Number(a.amount));
        const topShare = supplyNum > 0 ? (top.reduce((s, n) => s + n, 0) / supplyNum) * 100 : 0;
        facts.top5SharePct = Number(topShare.toFixed(2));
        facts.topHolders = largest.slice(0, 5).map((a) => shortAddr(a.address));
        if (topShare > 80) {
          findings.push({
            ruleId: "holder-concentration-extreme",
            severity: "critical",
            category: "rug-risk",
            message: "Top 5 holders control >80% of supply.",
            detail: `Top-5 share: ${topShare.toFixed(1)}%. Classic rug/whale setup.`,
            remediation: "Extreme concentration — avoid or assume manipulable.",
          });
        } else if (topShare > 50) {
          findings.push({
            ruleId: "holder-concentration-high",
            severity: "high",
            category: "rug-risk",
            message: "Top 5 holders control >50% of supply.",
            detail: `Top-5 share: ${topShare.toFixed(1)}%.`,
            remediation: "High concentration — price easily moved by few wallets.",
          });
        } else {
          findings.push({
            ruleId: "holder-concentration-ok",
            severity: "info",
            category: "rug-risk",
            message: `Top-5 holder share ${topShare.toFixed(1)}% — reasonably distributed.`,
          });
        }
      } catch {
        findings.push({
          ruleId: "holder-concentration-unchecked",
          severity: "low",
          category: "rug-risk",
          message: "Could not fetch top-holder concentration (RPC limit).",
          detail: "Needs off-chain checker (dex/holder explorer).",
        });
      }
    }
    return finalize(target, kind, findings, facts, undefined);
  }

  // 3. Wallet detection (system program or executable=false, non-token owner)
  if (owner === "11111111111111111111111111111111" || !parsed?.info) {
    facts.kind = "wallet";
    facts.solBalance = lamports / 1e9;
    findings.push({
      ruleId: "wallet-balance",
      severity: "info",
      category: "wallet",
      message: `Wallet holds ${(lamports / 1e9).toFixed(6)} SOL.`,
    });

    // token holdings
    try {
      const tokenAccounts = (await rpc("getParsedTokenAccountsByOwner", [
        target,
        { programId: TOKEN_PROGRAM },
        { encoding: "jsonParsed" },
      ])) as { value: Array<{ account: { data: { parsed: { info: Record<string, unknown> } } }; pubkey: string }> };
      const holdings = tokenAccounts.value.map((t) => {
        const info = t.account.data.parsed.info as Record<string, unknown>;
        const mint = info["mint"] as string;
        const amt = info["tokenAmount"] as { uiAmount: number | null; decimals: number };
        return { mint: shortAddr(mint), uiAmount: amt.uiAmount, decimals: amt.decimals };
      });
      facts.tokenHoldingsCount = holdings.length;
      facts.tokenHoldings = holdings.slice(0, 20);
      if (holdings.length > 0) {
        findings.push({
          ruleId: "wallet-token-exposure",
          severity: "low",
          category: "wallet",
          message: `Wallet holds ${holdings.length} SPL token account(s).`,
          detail: "Each mint should be checked for mint/freeze authority & concentration.",
          remediation: "Run /audit/onchain on individual mints to assess rug risk.",
        });
      }
    } catch {
      findings.push({
        ruleId: "wallet-tokens-unchecked",
        severity: "low",
        category: "wallet",
        message: "Could not fetch token holdings (RPC limit).",
      });
    }

    // recent activity (signature count, heuristic)
    try {
      const sigs = (await rpc("getSignaturesForAddress", [
        target,
        { limit: 20 },
      ])) as Array<{ signature: string; blockTime?: number; err?: unknown }>;
      facts.recentSignatures = sigs.length;
      facts.recentErrors = sigs.filter((s) => s.err).length;
      if (sigs.length === 20) {
        findings.push({
          ruleId: "wallet-active",
          severity: "info",
          category: "wallet",
          message: "Wallet shows recent on-chain activity (>=20 sigs in window).",
        });
      }
    } catch {
      /* non-fatal */
    }
    return finalize(target, "wallet", findings, facts, undefined);
  }

  // 4. Unknown / program account
  findings.push({
    ruleId: "program-or-unknown",
    severity: "low",
    category: "existence",
    message: `Account owned by ${shortAddr(owner)} — not a wallet or token mint.`,
    detail: "Likely a program / PDA. On-chain audit limited to existence + owner.",
  });
  facts.kind = "unknown";
  facts.owner = owner;
  facts.executable = accountInfo.executable;
  return finalize(target, "unknown", findings, facts, 10);
}

function finalize(
  target: string,
  kind: OnchainReport["detectedKind"],
  findings: OnchainFinding[],
  facts: Record<string, unknown>,
  forcedScore?: number,
): OnchainReport {
  const sevRank: Record<OnchainFinding["severity"], number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };
  const riskScore =
    forcedScore ??
    Math.min(
      100,
      counts.critical * 30 + counts.high * 15 + counts.medium * 6 + counts.low * 1,
    );
  const summary =
    findings.length === 0
      ? "No on-chain risk flags raised."
      : `Found ${findings.length} flag(s): ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info. Review findings + facts (verify on-chain yourself).`;
  return {
    schemaVersion: "enki-onchain/1.0",
    receivedAt: new Date().toISOString(),
    target,
    detectedKind: kind,
    network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    rpc: RPC_URLS[0],
    summary,
    findings,
    facts,
    riskScore,
    disclaimer:
      "Heuristic ON-CHAIN check only (read-only RPC). Does NOT include off-chain liquidity/dex data, contract source audit, or social signal. Verify critical flags on a block explorer before any action.",
  };
}
