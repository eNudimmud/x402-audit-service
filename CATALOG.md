# x402 SKU Catalog — `enki-x402-audit-service`

Service: **enki-x402-audit-service**
Network: `solana:5eykt4UsFvP8NJdTREpY1vzqKqZKvdp` (mainnet) or devnet fallback via `x402.org`
Facilitator: `https://api.cdp.coinbase.com/platform/v2/x402` (mainnet) or `https://x402.org/facilitator` (devnet)
PayTo: `EAMNyeugCfvCyXX4SZ3tUXM6fWxovYJWTCw2JbqmeueR`

## Public discovery

- `GET /` — service metadata
- `GET /catalog` — **this SKU catalog** (no payment required)
- `GET /health` — liveness probe
- `GET /debug` — config resolution (no secrets leaked)

## SKUs

All paid endpoints use the `exact` scheme on Solana. Prices are env-overridable (e.g. `EXTRACT_URL_PRICE_USD`).

| Method | Path | Default price | Description |
|---|---|---|---|
| POST | `/audit` | `$0.05` | Automated code security & quality audit |
| POST | `/audit/onchain` | `$0.05` | Real on-chain Solana audit (read-only RPC) |
| POST | `/audit/forensic` | `$0.05` | Off-chain HTTP forensics: headers, TLS, fingerprints, timing |
| POST | `/extract/ocr` | `$0.05` | Image→text extraction or passthrough |
| POST | `/extract/url` | `$0.05` | URL→markdown/text extraction |
| POST | `/sentiment/en` | `$0.05` | Lightweight sentiment scoring |
| POST | `/calendar/lunar` | `$0.03` | Machine lunar calendar helper |
| POST | `/plant/identify` | `$0.05` | Image/text plant identification helper |
| POST | `/veille/day` | `$0.04` | Daily veille digest across 8 domains |
| POST | `/vault/doctor` | `$0.03` | Vault health report |
| POST | `/weather/point` | `$0.04` | Point weather observation |
| POST | `/summarize` | `$0.04` | Extractive summary |
| POST | `/dev/audit-deps` | `$0.04` | Dependency manifest scan |

## Request/response reference

Shared fields:
- `schemaVersion`: semver for the report schema
- `receivedAt`: ISO timestamp
- `disclaimer`: honesty notice (not a substitute for human review/dedicated tooling)

Common error shape (HTTP 400):
```json
{ "error": "Missing 'text' in body." }
```

## Notes

- Default prices are deliberately conservative for volume.
- Illegal/certified-unsafe requests are rejected by the host/operator policy, not by price alone.
- `POST /audit` rejects code > 200,000 characters.
