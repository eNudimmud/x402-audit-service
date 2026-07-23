import express from "express";
import {
  extractOcr,
  extractUrl,
  sentiment,
  lunar,
  plantIdentify,
  veilleDay,
  vaultDoctor,
  weatherPoint,
  summarize,
  devAuditDeps,
} from "../dist/endpoints.js";

function mount(app) {
  app.use(express.json({ limit: "1mb" }));
  const wrap = (handler) => (req, res) => {
    const out = handler(req.body ?? {});
    if (out && typeof out === "object" && "error" in out) {
      return res.status(400).json(out);
    }
    return res.json(out);
  };
  app.post("/extract/ocr", wrap(extractOcr));
  app.post("/extract/url", wrap(extractUrl));
  app.post("/sentiment/en", wrap(sentiment));
  app.post("/calendar/lunar", wrap(lunar));
  app.post("/plant/identify", wrap(plantIdentify));
  app.post("/veille/day", wrap(veilleDay));
  app.post("/vault/doctor", wrap(vaultDoctor));
  app.post("/weather/point", wrap(weatherPoint));
  app.post("/summarize", wrap(summarize));
  app.post("/dev/audit-deps", wrap(devAuditDeps));
}

async function run() {
  const app = express();
  mount(app);
  const server = app.listen(0);
  const port = server.address().port;
  const base = `http://localhost:${port}`;

  let pass = 0;
  let fail = 0;
  const check = (name, cond) => {
    if (cond) { pass++; console.log(`  PASS  ${name}`); }
    else { fail++; console.log(`  FAIL  ${name}`); }
  };

  const expect = async (path, body) => {
    const r = await fetch(`${base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const j = await r.json();
    return [r.status, j];
  };

  // OCR
  let [s, j] = await expect("/extract/ocr", { text: "Hello OCR" });
  check("ocr passthrough 200", s === 200);
  check("ocr schemaVersion", j.schemaVersion === "enki-extract-ocr/1.0");
  check("ocr text returned", j.text === "Hello OCR");

  [s, j] = await expect("/extract/ocr", {});
  check("ocr empty guard 400", s === 400 && typeof j.error === "string");

  // URL
  [s, j] = await expect("/extract/url", { url: "https://example.com" });
  check("extract/url 200", s === 200 && j.schemaVersion === "enki-extract-url/1.0");

  [s, j] = await expect("/extract/url", {});
  check("extract/url missing guard 400", s === 400 && typeof j.error === "string");

  // Sentiment
  [s, j] = await expect("/sentiment/en", { text: "top super bien" });
  check("sentiment positive", s === 200 && j.label === "positive" && typeof j.score === "number");

  [s, j] = await expect("/sentiment/en", { text: "awful bad sad nul" });
  check("sentiment negative", s === 200 && j.label === "negative");

  [s, j] = await expect("/sentiment/en", { text: "ok then" });
  check("sentiment neutral", s === 200 && j.label === "neutral");

  [s, j] = await expect("/sentiment/en", {});
  check("sentiment missing guard 400", s === 400 && typeof j.error === "string");

  // Summarize
  [s, j] = await expect("/summarize", {
    text: "Sentence one. Sentence two. Sentence three. Sentence four. Sentence five.",
  });
  check("summarize ok", s === 200 && typeof j.summary === "string");

  [s, j] = await expect("/summarize", {});
  check("summarize missing guard 400", s === 400 && typeof j.error === "string");

  // Lunar
  [s, j] = await expect("/calendar/lunar", {});
  check("lunar default shape", s === 200 && typeof j.date === "string" && typeof j.tz === "string");

  // Veille/day
  [s, j] = await expect("/veille/day", {});
  check("veille/day shape", s === 200 && typeof j.date === "string");

  // Vault/doctor
  [s, j] = await expect("/vault/doctor", {});
  check("vault/doctor default root", s === 200 && typeof j.root === "string");

  [s, j] = await expect("/vault/doctor", { quick: true });
  check("vault/doctor quick", s === 200 && j.quick === true);

  // Weather/point
  [s, j] = await expect("/weather/point", {});
  check("weather/point default", s === 200 && typeof j.point.lat === "number");

  // Plant identify
  [s, j] = await expect("/plant/identify", {});
  check("plant identify missing guard 400", s === 400 && typeof j.error === "string");

  [s, j] = await expect("/plant/identify", { text: "pissenlit?" });
  check("plant identify text mode", s === 200 && j.mode === "text-grounded");

  // dev/audit-deps
  [s, j] = await expect("/dev/audit-deps", {});
  check("dev/audit-deps missing guard 400", s === 400 && typeof j.error === "string");

  [s, j] = await expect("/dev/audit-deps", { repoUrl: "https://github.com/eNudimmud/tamagotchi-app", pkgManager: "npm" });
  check("dev/audit-deps ok", s === 200 && j.repoUrl.includes("tamagotchi-app"));

  server.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

run();
