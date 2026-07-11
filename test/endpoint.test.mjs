/**
 * Lightweight endpoint test — mounts the audit handler WITHOUT the x402
 * payment middleware so we can validate the request/response contract
 * (input -> AuditReport) without needing a funded Solana wallet.
 *
 * The 402 + PAYMENT-REQUIRED behaviour is validated separately by hitting
 * POST /audit with no payment header (run the server, curl it).
 *
 * Run: node test/endpoint.test.mjs
 */
import express from "express";
import { auditCode } from "../dist/audit.js";

// Mirror of the protected handler in src/server.ts (minus the payment gate).
function auditHandler(req, res) {
  const { code, language, scope } = req.body ?? {};
  if (typeof code !== "string" || code.length === 0) {
    return res.status(400).json({ error: "Missing 'code' (string) in request body." });
  }
  if (code.length > 200_000) {
    return res.status(413).json({ error: "Code exceeds 200000 char limit." });
  }
  const report = auditCode({ code, language, scope });
  return res.status(200).json(report);
}

async function main() {
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.post("/audit", auditHandler);

  const server = app.listen(0);
  const port = server.address().port;
  const base = `http://localhost:${port}`;

  let pass = 0;
  let fail = 0;
  const check = (name, cond) => {
    if (cond) { pass++; console.log(`  PASS  ${name}`); }
    else { fail++; console.log(`  FAIL  ${name}`); }
  };

  // 1) valid vulnerable code -> 200 + findings
  const r1 = await fetch(`${base}/audit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: 'const apiKey="sk_live_xxxxxxxx"; eval(x);', language: "js" }),
  });
  const j1 = await r1.json();
  check("valid audit returns 200", r1.status === 200);
  check("valid audit returns findings array", Array.isArray(j1.findings) && j1.findings.length >= 2);
  check("valid audit has securityScore", typeof j1.securityScore === "number");

  // 2) missing code -> 400
  const r2 = await fetch(`${base}/audit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ language: "js" }),
  });
  check("missing code returns 400", r2.status === 400);

  // 3) empty code -> 400
  const r3 = await fetch(`${base}/audit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: "" }),
  });
  check("empty code returns 400", r3.status === 400);

  server.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main();
