/**
 * enki-x402-audit-service — x402 seller server.
 *
 * POST /audit  -> payment-gated code security/quality audit.
 * GET  /       -> service metadata (no payment).
 * GET  /health -> liveness (no payment).
 * GET  /debug  -> config resolution (no secrets leaked).
 *
 * Payment: x402 v2, exact scheme, Solana mainnet.
 * Recipient (payTo): the Enki agent's Sponge Solana wallet.
 *
 * Facilitator:
 *  - Production: CDP facilitator (requires CDP_API_KEY + CDP_API_SECRET).
 *  - Fallback (no CDP keys / blocked): x402.org public facilitator (devnet)
 *    so the service runs and stays LIVE regardless of CDP account state.
 */

import express from "express";
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

const MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

// Use CDP (mainnet) when CDP keys are present AND the network is mainnet.
// Mainnet is signalled by X402_NETWORK=solana:5eykt... (the value you already
// set on Render). Without that we run on Solana devnet via the public
// x402.org facilitator, so the service stays LIVE regardless.
const WANT_MAINNET = process.env.X402_NETWORK === MAINNET;
const WANT_CDP = WANT_MAINNET && Boolean(CDP_KEY && CDP_SECRET);

const FACILITATOR_URL_DEVNET = "https://x402.org/facilitator";
const FACILITATOR_URL_CDP = "https://api.cdp.coinbase.com/platform/v2/x402";

let USE_CDP = false;
let NETWORK = DEVNET as `${string}:${string}`;
let FACILITATOR_URL = FACILITATOR_URL_DEVNET;
let CDP_BLOCKED_REASON = "";

// Probe the CDP facilitator BEFORE building the server. If it returns a
// non-200 we fall back to devnet, so the service stays LIVE on Render
// regardless of CDP account state. Uses GET /supported (the SDK's method).
async function resolveFacilitator(): Promise<void> {
  if (!WANT_CDP) {
    if (CDP_KEY) {
      console.warn(
        "[enki-x402] CDP_API_KEY present but network is not mainnet — running on devnet (x402.org). " +
          "Set X402_NETWORK=solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp for mainnet USDC.",
      );
    }
    return;
  }
  try {
    const jwt = await generateJwt({
      apiKeyId: CDP_KEY!,
      apiKeySecret: CDP_SECRET!,
      requestMethod: "GET",
      requestHost: "api.cdp.coinbase.com",
      requestPath: "/platform/v2/x402/supported",
      expiresIn: 120,
    });
    const res = await fetch(`${FACILITATOR_URL_CDP}/supported`, {
      method: "GET",
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
        "To enable mainnet: set X402_NETWORK=solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp + valid CDP keys.",
    );
  }
}

const LLM_PROVIDER = process.env.LLM_PROVIDER ?? "none"; // none | openai | anthropic

// ---- CDP facilitator auth (Bearer JWT via CDP SDK) -------------------------
// The CDP production facilitator requires a short-lived Bearer JWT minted from
// the Secret API Key, signed PER OPERATION (the SDK calls createAuthHeaders with
// the operation kind: "supported" | "verify" | "settle"). Each has its own
// method + path, so we mint a fresh JWT for each. The SDK reads `.headers`.
const CDP_OPS: Record<string, { method: "GET" | "POST"; path: string }> = {
  supported: { method: "GET", path: "/platform/v2/x402/supported" },
  verify: { method: "POST", path: "/platform/v2/x402/verify" },
  settle: { method: "POST", path: "/platform/v2/x402/settle" },
};

async function cdpAuthHeaders(_kind?: string): Promise<{ headers: Record<string, string> }> {
  const kind = _kind ?? "verify";
  const op = CDP_OPS[kind] ?? CDP_OPS.verify;
  const jwt = await generateJwt({
    apiKeyId: CDP_KEY!,
    apiKeySecret: CDP_SECRET!,
    requestMethod: op.method,
    requestHost: "api.cdp.coinbase.com",
    requestPath: op.path,
    expiresIn: 120,
  });
  return { headers: { Authorization: `Bearer ${jwt}` } };
}

// ---- Facilitator + resource server ----------------------------------------
async function boot(): Promise<void> {
  await resolveFacilitator();

  // Build the facilitator client (with per-operation CDP JWT auth when live).
  const facilitatorClient = new HTTPFacilitatorClient({
    url: FACILITATOR_URL,
    ...(USE_CDP
      ? {
          createAuthHeaders: cdpAuthHeaders as unknown as () => Promise<{
            verify: Record<string, string>;
            settle: Record<string, string>;
            supported: Record<string, string>;
          }>,
        }
      : {}),
  });

  // NOTE: the published @x402 .d.mts types for x402ResourceServer.register()
  // are stale (declares 0 args). The runtime + official docs use
  // `new x402ResourceServer(client).register(network, scheme)`. Cast through
  // `any` so tsc stops fighting the real runtime shape.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const server: any = new (x402ResourceServer as any)(facilitatorClient);
  server.register(NETWORK, new (ExactSvmScheme as any)(PAY_TO));

  // ---- App -----------------------------------------------------------------
  const app = express();
  app.use(express.json({ limit: "1mb" }));

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
        "GET /debug": "Config resolution (no secrets)",
      },
    });
  });

  app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

  // Debug endpoint: shows config resolution WITHOUT leaking secrets.
  app.get("/debug", (_req, res) =>
    res.json({
      WANT_MAINNET,
      WANT_CDP,
      USE_CDP,
      NETWORK,
      FACILITATOR_URL,
      CDP_BLOCKED_REASON,
      env: {
        X402_NETWORK: process.env.X402_NETWORK ?? null,
        CDP_API_KEY_present: Boolean(CDP_KEY),
        CDP_API_KEY_prefix: CDP_KEY ? CDP_KEY.slice(0, 6) + "…" : null,
        CDP_API_SECRET_present: Boolean(CDP_SECRET),
        PAY_TO,
        AUDIT_PRICE_USD: PRICE,
        LLM_PROVIDER,
      },
      expectedMainnet: MAINNET,
    }),
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
    console.log("[enki-x402] audit service listening on http://localhost:" + PORT);
    console.log("[enki-x402] payTo=" + PAY_TO + " network=" + NETWORK + " price=" + PRICE);
    const mode = USE_CDP ? " (CDP mainnet)" : " (x402.org devnet fallback)";
    console.log("[enki-x402] facilitator=" + FACILITATOR_URL + mode);
  });
}

boot().catch((err) => {
  console.error("[enki-x402] fatal boot error:", err);
  process.exit(1);
});
