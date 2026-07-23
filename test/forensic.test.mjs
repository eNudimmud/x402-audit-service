import { auditForensic } from "../dist/forensic.js";

const cases = [
  { url: "https://httpbin.org/get", expectOk: true },
  { url: "https://example.com", expectOk: true },
  { url: "http://thisdoesnotexist.invalid", expectOk: false },
];

let pass = 0;
for (const c of cases) {
  const r = await auditForensic({ url: c.url, follow: true, maxBytes: 4000 });
  const ok = r.ok === c.expectOk && r.schemaVersion === "enki-forensic/1.0" && typeof r.timingMs === "number";
  console.log(`${ok ? "✅" : "❌"} ${c.url} -> ok=${r.ok} status=${r.statusCode ?? "-"} ms=${r.timingMs}`);
  if (ok) pass++;
}
console.log(`PASS ${pass}/${cases.length}`);
process.exit(pass === cases.length ? 0 : 1);
