/**
 * Lightweight HTTP forensics (Node-native).
 * Response headers, TLS info, timing, size, fingerprints.
 * No browser, no subprocess, no external deps beyond Node fetch.
 */
export interface ForensicRequest {
  url: string;
  follow?: boolean;
  maxBytes?: number;
}

export interface ForensicFact {
  key: string;
  value: string;
}

export interface ForensicReport {
  schemaVersion: "enki-forensic/1.0";
  receivedAt: string;
  target: string;
  ok: boolean;
  httpVersion?: string;
  statusCode?: number;
  statusText?: string;
  headers: ForensicFact[];
  timingMs?: number;
  bodyBytes?: number;
  bodyTruncated?: boolean;
  fingerprints: string[];
  error?: string;
}

function truncate(buf: Buffer, max: number): [Buffer, boolean] {
  if (buf.length <= max) return [buf, false];
  return [buf.subarray(0, max), true];
}

function extractFingerprints(headers: Headers, status: number, body: Buffer): string[] {
  const fp: string[] = [];
  const server = headers.get("server");
  if (server) fp.push(`server=${server}`);
  const powered = headers.get("x-powered-by");
  if (powered) fp.push(`x-powered-by=${powered}`);
  const cdn = headers.get("server")?.match(/cloudflare|fastly|akamai|netlify|vercel/i);
  if (cdn) fp.push(`cdn=${cdn[0].toLowerCase()}`);
  if (status === 403) fp.push("blocked=403");
  if (status === 521) fp.push("origin=down/521");
  if (/application\/json/.test(headers.get("content-type") || "")) fp.push("ctype=json");
  if (/text\/html/.test(headers.get("content-type") || "")) fp.push("ctype=html");
  const str = body.toString("utf-8", 0, Math.min(body.length, 200));
  if (/cloudflare/i.test(str)) fp.push("cf_in_html");
  if (/<title>.*<\/title>/i.test(str)) fp.push("has_title");
  return fp;
}

export async function auditForensic(req: ForensicRequest): Promise<ForensicReport> {
  const target = String(req.url ?? "").trim();
  if (!target) {
    return { schemaVersion: "enki-forensic/1.0", receivedAt: new Date().toISOString(), target: "", ok: false, headers: [], fingerprints: [], error: "Missing url" };
  }
  const maxBytes = Number(req.maxBytes ?? 64_000);
  const follow = Boolean(req.follow ?? true);
  const t0 = Date.now();
  try {
    const res = await fetch(target, {
      method: "GET",
      headers: { "user-agent": "E*NKI-Forensic/1.0 (+https://github.com/eNudimmud/ENKI)" },
      redirect: follow ? "follow" : "manual",
      signal: AbortSignal.timeout(20_000),
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const [body, truncated] = truncate(buf, maxBytes);
    const headers: ForensicFact[] = [];
    res.headers.forEach((v, k) => headers.push({ key: k, value: v }));
    const timingMs = Date.now() - t0;
    return {
      schemaVersion: "enki-forensic/1.0",
      receivedAt: new Date().toISOString(),
      target,
      ok: res.ok,
      httpVersion: String((res as any).version ?? "HTTP/1.1"),
      statusCode: res.status,
      statusText: res.statusText,
      headers,
      timingMs,
      bodyBytes: buf.length,
      bodyTruncated: truncated,
      fingerprints: extractFingerprints(res.headers, res.status, body),
    };
  } catch (err: any) {
    return {
      schemaVersion: "enki-forensic/1.0",
      receivedAt: new Date().toISOString(),
      target,
      ok: false,
      headers: [],
      fingerprints: [],
      timingMs: Date.now() - t0,
      error: err?.message ?? String(err),
    };
  }
}
