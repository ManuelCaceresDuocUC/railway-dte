// src/lib/cert.ts
import fs from "node:fs";
import path from "node:path";
import forge from "node-forge";
import { Agent, setGlobalDispatcher } from "undici";

function loadP12Buffer(): Buffer {
  const b64 = process.env.SII_CERT_P12_B64?.trim();
  if (b64) return Buffer.from(b64, "base64");
  const p = process.env.SII_CERT_P12_PATH?.trim();
  if (!p) throw new Error("SII_CERT_P12_B64 o SII_CERT_P12_PATH no configurado");
  return fs.readFileSync(path.resolve(p));
}

export function loadP12Pem() {
  const pfx = loadP12Buffer();
  const pass = process.env.SII_CERT_PASSWORD ?? "";
  const der = forge.util.createBuffer(pfx.toString("binary"));
  const asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, pass);
  const cert = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]?.[0]?.cert;
  const key  = (p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key) ||
               (p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]?.[0]?.key);
  if (!cert || !key) throw new Error("P12 sin cert o sin private key");
  return { keyPem: forge.pki.privateKeyToPem(key), certPem: forge.pki.certificateToPem(cert) };
}

let _agent: Agent | null = null;
export function getMtlsAgent(): Agent {
  if (_agent) return _agent;
  _agent = new Agent({
    connect: {
      tls: {
        pfx: loadP12Buffer(),
        passphrase: process.env.SII_CERT_PASSWORD ?? "",
        servername: (process.env.SII_ENV?.toLowerCase() === "prod" ? "maullin.sii.cl" : "palena.sii.cl"),
        minVersion: "TLSv1.2",
        ALPNProtocols: ["http/1.1"],
      },
    },
  } as any);
  return _agent;
}

let mtlsSet = false;
export function ensureMtlsDispatcher() {
  if (mtlsSet) return;
  setGlobalDispatcher(getMtlsAgent());
  mtlsSet = true;
}
