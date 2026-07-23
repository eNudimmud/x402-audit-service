# ENKI x402 Audit Service

A payment-gated code **security & quality audit API**, built on the
[x402 protocol](https://www.x402.org) (Coinbase). Any agent or client that
knows how to pay with x402 can call `POST /audit` and receive a structured
audit report. Payment settles in **USDC on Solana** to the ENKI wallet — no
account, no API key, no signup for the caller.

This is the **seller side**. You deploy it, expose it publicly, and get paid
per call. The service runs with **zero paid dependencies**: the audit engine
is a real pattern-based scanner (no LLM required). An optional LLM enrichment
layer can be enabled via `LLM_PROVIDER`.

---

## How it works (x402 flow)

1. Caller hits `POST /audit` with no payment header.
2. Service responds `402 Payment Required` + a `PAYMENT-REQUIRED` header
   containing the exact payment instructions (amount, asset, network, payTo).
3. Caller's x402 client signs & sends a Solana USDC transfer (exact scheme;
   facilitator pays the network fee — caller needs no SOL).
4. Caller retries with the `X-PAYMENT` header.
5. Service verifies via the facilitator, runs the audit, returns the report,
   and the facilitator settles the payment to the seller wallet.

---

## Endpoints

| Method | Path         | Auth            | Body                              | Returns            |
|--------|--------------|-----------------|-----------------------------------|--------------------|
|| POST   | `/audit`       | **x402 payment**| `{ code, language?, scope? }`     | `AuditReport` JSON (code scanner) |
|| POST   | `/audit/onchain`| **x402 payment**| `{ target }` (Solana address)     | `OnchainReport` JSON (real on-chain audit) ||
|| POST   | `/audit/forensic`| **x402 payment**| `{ url, follow?, maxBytes? }` | `ForensicReport` JSON (HTTP forensics) ||
| GET    | `/`          | none            | —                                 | service metadata   |
| GET    | `/health`    | none            | —                                 | `{ ok: true }`     |

### `POST /audit` — code scanner (pattern-based)
`{ schemaVersion, receivedAt, language, scope, linesScanned, securityScore (0-100), severityCounts, summary, findings[], disclaimer }`

`findings[]` entries: `{ ruleId, severity, category, line, snippet, message, remediation }`

Scanned issue classes: hardcoded secrets, eval/Function injection, SQL
concatenation, shell injection, XSS (innerHTML), disabled TLS verify, weak
hashes (MD5/SHA1), missing rate limiting, leftover console.*, TODO/FIXME.

> **Honest scope:** this is a lightweight pattern scan, not a full SAST/DAST
> suite. A clean result is not a guarantee of safety. It is meant to be a
> cheap, automated first pass that agents can call per-snippet.

### `POST /audit/onchain` — REAL on-chain Solana audit (read-only RPC)
Auto-detects the target kind and returns an `OnchainReport`:
- **Token / Token-2022 mint** → supply, decimals, mint authority state
  (revoked = good), freeze authority state, top-5 holder concentration %,
  rug-risk flags (critical/high).
- **Wallet** → SOL balance, SPL token-holding count, recent activity (sig count).
- **Unknown / program** → existence + owner only.

`facts` object exposes raw on-chain values so a buyer can verify on a
block explorer themselves. `riskScore` 0–100.

> **Honest scope:** read-only RPC heuristics. Does NOT include off-chain
> liquidity/dex data, contract *source* audit, or social signal. Some calls
> (`getTokenLargestAccounts`) are throttled on free public RPCs — when that
> happens the report marks concentration as "unchecked" rather than guessing.
> Set a paid RPC URL via `SOLANA_RPC_URLS` (comma-separated) for full coverage.

---

## Deploy

### 1. Build
```bash
npm install
npm run build
```

### 2. Configure (env)
Copy `.env.example` to `.env` and adjust. **For production you only NEED:**

| Var                 | Default                                   | Notes |
|---------------------|-------------------------------------------|-------|
| `PAY_TO`            | ENKI Sponge wallet (see below)            | Your receiving Solana address. |
| `AUDIT_PRICE_USD`   | `$0.05`                                   | Price per audit, micro-USDC units accepted. |
| `X402_NETWORK`      | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | Solana **mainnet** by default. |

If you leave `CDP_API_KEY` / `CDP_API_SECRET` **unset**, the service uses the
public `https://x402.org/facilitator` testnet facilitator. **That fallback
only supports Base Sepolia + Solana Devnet**, so for mainnet USDC you MUST
set CDP credentials (free tier: 1000 settles/month):

| Var              | Notes |
|------------------|-------|
| `CDP_API_KEY`    | From [coinbase.com/developer-platform](https://www.coinbase.com/developer-platform) |
| `CDP_API_SECRET`| Paired secret |

When both are set, the service switches to the CDP production facilitator
(`api.cdp.coinbase.com/platform/v2/x402`) with HMAC-signed requests.

Optional:
| Var            | Default | Notes |
|----------------|---------|-------|
| `PORT`         | `4021`  | Listen port. |
| `LLM_PROVIDER` | `none`  | `none` \| `openai` \| `anthropic` — optional enrichment (not wired to a paid call by default). |

### 3. Run
```bash
npm start
# or for dev with auto-reload: npm run dev
```

### 4. Host it (1-click)

The repo is now packaged for one-command deploys. The service needs **no
inbound port beyond the HTTP port** and **no database** — x402 settles
off-chain via the facilitator, so you don't run an RPC node. No money moves
without a caller paying x402 first.

| Host | What to do |
|---|---|
| **Render** | Push to GitHub → New → Blueprint → pick the repo (`render.yaml` auto-detected). It prompts for `PAY_TO`, `CDP_API_KEY`, `CDP_API_SECRET`; the rest is prefilled. Free plan works (spins down when idle). |
| **Railway** | `railway.json` present → "Deploy on Railway" button / `railway up`. Set the 3 secret env vars in the dashboard. |
| **Fly.io / VPS** | `docker build -t enki-x402 . && docker run -p 4021:4021 --env-file .env enki-x402` |

After deploy, verify: `curl https://<your-url>/health` → `{"ok":true}`.

> Note: developed on a host with no public IP, so it was only verified locally
> (402 + payment instructions + audit engine + endpoint contract). The production
> mainnet path (CDP facilitator + real USDC) requires your CDP credentials and a
> publicly reachable URL.

---

## Local verification (no CDP account needed)

Run against **Solana Devnet** so the testnet facilitator accepts it:
```bash
X402_NETWORK=solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 npm start
# in another shell:
curl -s -i -X POST http://localhost:4021/audit \
  -H 'Content-Type: application/json' \
  -d '{"code":"const apiKey=\"sk_live_xxx\"; eval(x);","language":"js"}'
# -> 402 + PAYMENT-REQUIRED header (instructions to pay on devnet)
```

Run the endpoint contract tests (no payment needed):
```bash
npm run build && node test/endpoint.test.mjs
```

---

## ENKI receiving wallet
`EAMNyeugCfvCyXX4SZ3tUXM6fWxovYJWTCw2JbqmeueR` (Solana / Sponge wallet).
Override with `PAY_TO` if you fork this for your own wallet.

---

## Project layout
```
src/
  types.ts    — AuditReport / AuditRequest / AuditFinding
  audit.ts    — pattern-based scanner (no LLM dependency)
  onchain.ts  — Solana read-only RPC audit
  forensic.ts — HTTP forensics (headers/fingerprints/timing)
  server.ts   — Express + x402 paymentMiddleware (seller)
test/
  endpoint.test.mjs — request/response contract tests
  forensic.test.mjs — HTTP forensics unit tests
```
