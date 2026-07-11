/**
 * enki-x402-audit-service — x402 seller server.
 *
 * POST /audit  -> payment-gated code security/quality audit.
 * GET  /       -> service metadata (no payment).
 * GET  /health -> liveness (no payment).
 *
 * Payment: x402 v2, exact scheme, Solana mainnet.
 * Recipient (payTo): the Enki agent's Sponge Solana wallet.
 *
 * Facilitator:
 *  - Production: CDP facilitator (requires CDP_API_KEY + CDP_API_SECRET).
 *  - Fallback (no CDP keys): x402.org public facilitator (testnet, no signup)
 *    so the service runs and can be tested locally without an account.
 */

import express from "express";
import { createHmac, createHash } from "node:crypto";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { auditCode } from "./audit.js";
import type { AuditReport } from "./types.js";

// ---- Config from env -------------------------------------------------------
const PORT = Number(process.env.PORT ?? 4021);
const PAY_TO = process.env.PAY_TO ?? "EAMNyeugCfvCyXX4SZ3tUXM6fWxovYJWTCw2JbqmeueR";
const PRICE = process.env.AUDIT_PRICE_USD ?? "$0.05";
// Default: Solana mainnet (production). Override for local testing, e.g.
// X402_NETWORK=solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 (Solana Devnet, testnet facilitator).
const NETWORK = (process.env.X402_NETWORK ??
  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp") as `${string}:${string}`; // CAIP-2

const CDP_KEY = process.env.CDP_API_KEY;
const CDP_SECRET = process.env.CDP_API_SECRET;
const USE_CDP = Boolean(CDP_KEY && CDP_SECRET);
const FACILITATOR_URL = USE_CDP
  ? "https://api.cdp.coinbase.com/platform/v2/x402"
  : "https://x402.org/facilitator"; // testnet fallback, no signup

const LLM_PROVIDER = process.env.LLM_PROVIDER ?? "none"; // none | openai | anthropic

// ---- CDP facilitator auth (HMAC-SHA256 over timestamp.method.path) --------
// Required only for the CDP production facilitator; the x402.org testnet
// facilitator needs no auth.
function cdpAuthHeaders(): {
  verify: Record<string, string>;
  settle: Record<string, string>;
  supported: Record<string, string>;
} {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const method = "POST";
  const path = "/platform/v2/x402";
  const payload = `${timestamp}${method}${path}`;
  const signature = createHmac("sha256", CDP_SECRET!).update(payload).digest("hex");
  const headers = {
    "CDP-API-KEY": CDP_KEY!,
    "CDP-API-TIMESTAMP": timestamp,
    "CDP-API-SIGNATURE": signature,
  };
  return { verify: headers, settle: headers, supported: headers };
}

// ---- Facilitator + resource server ----------------------------------------
const facilitatorClient = new HTTPFacilitatorClient({
  url: FACILITATOR_URL,
  ...(USE_CDP
    ? { createAuthHeaders: async () => cdpAuthHeaders() }
    : {}),
});

const server = new x402ResourceServer(facilitatorClient).register(
  NETWORK,
  new ExactSvmScheme(),
);

// ---- App -------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: "1mb" }));

// Public metadata (no payment required)
app.get("/", (_req, res) => {
  res.json({
    service: "enki-x402-audit-service",
    version: "0.1.0",
    description: "Payment-gated code security/quality audit via x402 (Solana/USDC).",
    network: NETWORK,
    payTo: PAY_TO,
    price: PRICE,
    facilitator: FACILITATOR_URL,
    llmEnrichment: LLM_PROVIDER,
    endpoints: {
      "POST /audit": "Body: { code, language?, scope? } -> AuditReport (payment required)",
      "GET /health": "Liveness probe (no payment)",
    },
  });
});

app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

// Payment-gated audit endpoint
app.use(
  paymentMiddleware(
    {
      "POST /audit": {
        accepts: [
          {
            scheme: "exact",
            price: PRICE,
            network: NETWORK,
            payTo: PAY_TO,
          },
        ],
        description: "Automated code security & quality audit (pattern-based + optional LLM).",
        mimeType: "application/json",
      },
    },
    server,
  ),
);

app.post("/audit", async (req, res) => {
  const { code, language, scope } = req.body ?? {};
  if (typeof code !== "string" || code.length === 0) {
    return res.status(400).json({ error: "Missing 'code' string in body." });
  }
  if (code.length > 200_000) {
    return res.status(413).json({ error: "Code too large (max 200k chars)." });
  }

  const report: AuditReport = auditCode({ code, language, scope });

  // Optional LLM enrichment (kept separate so the service works without keys)
  if (LLM_PROVIDER !== "none") {
    try {
      report.summary = `[${LLM_PROVIDER} enrichment unavailable in this build] ` + report.summary;
    } catch {
      /* non-fatal */
    }
  }

  res.json(report);
});

app.listen(PORT, () => {
  console.log(`[enki-x402] audit service listening on http://localhost:${PORT}`);
  console.log(`[enki-x402] payTo=${PAY_TO} network=${NETWORK} price=${PRICE}`);
  console.log(`[enki-x402] facilitator=${FACILITATOR_URL}${CDP_KEY ? " (CDP)" : " (x402.org testnet fallback)"}`);
});
