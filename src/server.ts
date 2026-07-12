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
import { createHash } from "node:crypto";
import { generateJwt } from "@coinbase/cdp-sdk/auth";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { auditCode } from "./audit.js";
import type { AuditReport } from "./types.js";

// ---- Config from env -------------------------------------------------------
const PORT = Number(process.env.PORT ?? 4021);
const PAY_TO = process.env.PAY_TO ?? "EAMNyeugCfvCyXX4SZ3tUXM6fWxovYJWTCw2JbqmeueR";
const PRICE = process.env.AUDIT_PRICE_USD ?? "$0.05";
const CDP_KEY = process.env.CDP_API_KEY;
const CDP_SECRET = process.env.CDP_API_SECRET;
// Only use CDP (mainnet) when explicitly enabled AND keys present.
// Without X402_MAINNET=1 we run on Solana devnet via the public x402.org
// facilitator — this keeps the service LIVE even if CDP keys are missing.
const WANT_CDP = process.env.X402_MAINNET === "1" && Boolean(CDP_KEY && CDP_SECRET);

// Network selection:
const MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

// The x402.org testnet facilitator only supports `exact` on solana devnet,
// not on mainnet (would crash at boot). Default to devnet.
const FACILITATOR_URL_DEVNET = "https://x402.org/facilitator";
const FACILITATOR_URL_CDP = "https://api.cdp.coinbase.com/platform/v2/x402";

let USE_CDP = false;
let NETWORK = DEVNET as `${string}:${string}`;
let FACILITATOR_URL = FACILITATOR_URL_DEVNET;
let CDP_BLOCKED_REASON = "";

// Probe the CDP facilitator BEFORE building the server. If it returns 401
// (e.g. IP-allowlist not opted out) we MUST fall back to devnet, otherwise
// paymentMiddleware.initialize() throws at boot and Render marks the
// service as crashed (red). This keeps the service LIVE regardless of CDP
// account state.
async function resolveFacilitator(): Promise<void> {
  if (!WANT_CDP) {
    if (CDP_KEY) {
      console.warn(
        "[enki-x402] CDP_API_KEY present but X402_MAINNET != '1' — running on devnet (x402.org). " +
          "Set X402_MAINNET=1 (with valid CDP keys + IP-allowlist opt-out) for mainnet USDC.",
      );
    }
    return;
  }
  try {
    // The CDP facilitator requires a Bearer JWT generated from the Secret API
    // Key (not HMAC). We use the official CDP SDK to mint a short-lived token.
    const jwt = await generateJwt({
      apiKeyId: CDP_KEY!,
      apiKeySecret: CDP_SECRET!,
      requestMethod: "POST",
      requestHost: "api.cdp.coinbase.com",
      requestPath: "/platform/v2/x402/supported",
      expiresIn: 120,
    });
    const res = await fetch(`${FACILITATOR_URL_CDP}/supported`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${jwt}`,
      },
      signal: AbortSignal.timeout(8000),
    });
    if (res.status === 200) {
      USE_CDP = true;
      NETWORK = (process.env.X402_NETWORK ?? MAINNET) as `${string}:${string}`;
      FACILITATOR_URL = FACILITATOR_URL_CDP;
      console.log("[enki-x402] CDP facilitator reachable — running MAINNET USDC.");
    } else {
      CDP_BLOCKED_REASON = `CDP facilitator responded ${res.status}`;
      throw new Error(CDP_BLOCKED_REASON);
    }
  } catch (err) {
    USE_CDP = false;
    NETWORK = DEVNET;
    FACILITATOR_URL = FACILITATOR_URL_DEVNET;
    console.warn(
      `[enki-x402] CDP facilitator blocked (${CDP_BLOCKED_REASON || String(err)}). ` +
        "Falling back to DEVNET (x402.org). Service stays LIVE. " +
        "To enable mainnet: opt out of CDP IP-allowlist + set X402_MAINNET=1.",
    );
  }
}

const LLM_PROVIDER = process.env.LLM_PROVIDER ?? "none"; // none | openai | anthropic

// ---- CDP facilitator auth (Bearer JWT via CDP SDK) -------------------------
// The CDP production facilitator requires a short-lived Bearer JWT minted from
// the Secret API Key. We generate it per-request so it never expires at boot.
async function cdpAuthHeaders(): Promise<{
  verify: Record<string, string>;
  settle: Record<string, string>;
  supported: Record<string, string>;
}> {
  const jwt = await generateJwt({
    apiKeyId: CDP_KEY!,
    apiKeySecret: CDP_SECRET!,
    requestMethod: "POST",
    requestHost: "api.cdp.coinbase.com",
    requestPath: "/platform/v2/x402",
    expiresIn: 120,
  });
  const headers = { Authorization: `Bearer ${jwt}` };
  return { verify: headers, settle: headers, supported: headers };
}

// ---- Facilitator + resource server ----------------------------------------
// Resolve facilitator mode (mainnet CDP vs devnet fallback) BEFORE building.
async function boot(): Promise<void> {
  await resolveFacilitator();

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
    console.log(`[enki-x402] facilitator=${FACILITATOR_URL}${USE_CDP ? " (CDP mainnet)" : " (x402.org devnet fallback)"}`);
  });
}

boot().catch((err) => {
  console.error("[enki-x402] fatal boot error:", err);
  process.exit(1);
});
