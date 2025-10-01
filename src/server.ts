// src/server.ts
import express from "express";
import cors from "cors";
import forge from "node-forge";
import { Agent, setGlobalDispatcher } from "undici";

const app = express();

// Acepta XML crudo (necesario para EnvioBOLETA)
app.use(cors());
app.use(express.text({ type: "*/*", limit: "2mb" }));

// -------- mTLS desde P12 (SII_CERT_P12_B64 + SII_CERT_PASSWORD) --------
function p12ToPem(b64: string, pass: string) {
  if (!b64 || !pass) throw new Error("Falta SII_CERT_P12_B64 o SII_CERT_PASSWORD");

  const p12Der = forge.util.decode64(b64);
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pass);

  // Bags
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const keyBagsPkcs8 = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
  const keyBagsPkcs1 = p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || [];

  const certBag = certBags[0];
  const keyBag = keyBagsPkcs8[0] ?? keyBagsPkcs1[0];

  if (!certBag || !('cert' in certBag) || !certBag.cert) {
    throw new Error("No se encontró certificado en el P12");
  }
  if (!keyBag || !('key' in keyBag) || !keyBag.key) {
    throw new Error("No se encontró clave privada en el P12");
  }

  // TS: afirmar tipos explícitos
  const cert = certBag.cert as forge.pki.Certificate;
  const key = keyBag.key as forge.pki.PrivateKey;

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem  = forge.pki.privateKeyToPem(key);

  return { certPem, keyPem };
}

const { certPem, keyPem } = p12ToPem(
  process.env.SII_CERT_P12_B64 || "",
  process.env.SII_CERT_PASSWORD || ""
);

// Dispatcher global mTLS (se conserva en redirects)
setGlobalDispatcher(
  new Agent({
    connect: {
      cert: Buffer.from(certPem),
      key: Buffer.from(keyPem),
      servername: "maullin.sii.cl",
      rejectUnauthorized: true,
      // ca: fs.readFileSync("/app/sii-ca.pem") // opcional
    },
  })
);

// Endpoint SII (boleta certificación por defecto)
const SII_UPLOAD_URL =
  process.env.SII_UPLOAD_URL || "https://maullin.sii.cl/cgi_dte/UPL/EnvioBOLETA.jws";

// -------- helper: POST al SII con cookie opcional --------
async function postSII(xmlLatin1: string) {
  if (!xmlLatin1?.trim()) throw new Error("XML vacío");
  const body = Buffer.from(xmlLatin1, "latin1");

  // Preflight: algunas rutas entregan cookie
  const pre = await fetch(SII_UPLOAD_URL, { method: "GET", redirect: "follow" });
  const cookie = pre.headers.get("set-cookie") ?? "";

  const r = await fetch(SII_UPLOAD_URL, {
    method: "POST",
    body,
    headers: {
      "Content-Type": "text/xml; charset=ISO-8859-1",
      "Content-Length": String(body.byteLength),
      "User-Agent": "railway-dte/1.0",
      Accept: "*/*",
      ...(cookie && { Cookie: cookie }),
    },
    redirect: "follow",
  });

  const text = await r.text();
  return {
    ok: r.ok || r.status < 400,
    status: r.status,
    headers: Object.fromEntries(r.headers.entries()),
    body: text,
  };
}

// -------- Rutas --------
app.get("/health", (_req, res) => res.json({ ok: true }));

// Test de handshake mTLS hacia SII (200/403 esperado; no “handshake failure”)
app.get("/token", async (_req, res) => {
  try {
    const r = await fetch("https://maullin.sii.cl/", { method: "GET" });
    res.json({ ok: true, status: r.status });
  } catch (e: any) {
    res.status(500).json({ ok: false, error: e?.message ?? String(e) });
  }
});

// Envío: acepta XML crudo y lo sube tal cual al SII
app.post("/send", async (req, res) => {
  try {
    const ct = String(req.headers["content-type"] || "");
    if (!ct.includes("text/xml")) {
      return res
        .status(415)
        .json({ ok: false, error: "Envia XML crudo con Content-Type: text/xml; charset=ISO-8859-1" });
    }

    const xml = req.body?.toString() ?? "";
    const out = await postSII(xml);

    return res.status(200).json({
      ok: out.ok,
      status: out.status,
      headers: out.headers,
      bodyPreview: out.body.slice(0, 2000),
    });
  } catch (err: any) {
    res.status(500).json({ ok: false, error: err?.message ?? String(err) });
  }
});

// -------- Arranque --------
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log("DTE server on :" + PORT);
  console.log("uploadUrl", SII_UPLOAD_URL);
  console.log("certLoaded", !!certPem?.length, "keyLoaded", !!keyPem?.length);
});
