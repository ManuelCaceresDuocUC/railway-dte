// src/lib/dte.ts
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { create } from "xmlbuilder2";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";
import { ensureMtlsDispatcher, getMtlsAgent, loadP12Pem } from "./cert.js";
import { fetch as ufetch } from "undici";

ensureMtlsDispatcher();

/* ==================== Tipos ==================== */
type Caf = {
  folioIni: number; folioFin: number;
  rsask: string; rsapk: string;
  rutEmisor: string; razon: string; xml: string;
};
type XEl = { localName: string; textContent: string | null };

/* ==================== Utilidades ==================== */
const SII_ENV = (process.env.SII_ENV || "cert").toLowerCase();
const BASE = SII_ENV === "prod" ? "https://maullin.sii.cl" : "https://palena.sii.cl";
console.log("SII_ENV", SII_ENV, "BASE", BASE);

const soapEnv = (inner: string) =>
  `<?xml version="1.0" encoding="ISO-8859-1"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>${inner}</soapenv:Body></soapenv:Envelope>`;

function stripXmlDecl(s: string) { return s.replace(/^\s*<\?xml[^?]*\?>\s*/i, ""); }
function unescapeXml(s: string) { return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"); }
function getTipoFromDte(xml: string){const m=xml.match(/<TipoDTE>(\d+)<\/TipoDTE>/i); if(!m)throw new Error("TipoDTE no encontrado"); return Number(m[1]);}
function assertHasId(xml: string, id: string) {
  if (!new RegExp(`\\b(Id|ID)="${id}"`).test(xml)) throw new Error(`Nodo a firmar sin Id="${id}"`);
}

/* ==================== HTTP SOAP (mTLS) ==================== */
function hasClientCert() { return !!process.env.SII_CERT_P12_B64 || !!process.env.SII_CERT_P12_PATH; }

async function postSOAP(p:string, body:string, extra?:Record<string,string>){
  const url = `${BASE}${p}`;
  const res = await ufetch(url, {
    method: "POST",
    headers: {
      "Host": BASE.replace(/^https?:\/\//, ""),   // palena.sii.cl / maullin.sii.cl
      "Content-Type": "text/xml; charset=ISO-8859-1",
      "Accept": "text/xml,application/xml,text/plain",
      "SOAPAction": "",
      ...(extra ?? {}),
    },
    body: Buffer.from(body, "latin1"),
    dispatcher: getMtlsAgent(),
    redirect: "manual",
  });
  const txt = await res.text();
  console.log("[SII SOAP]", p, "status", res.status, "ctype:", res.headers.get("content-type"));
  if (/^\s*<html/i.test(txt)) {
    console.error("HTML_HEAD", txt.slice(0,200));
    throw new Error("HTML del SII: Transacción Rechazada. Probable mTLS ausente o endpoint errado.");
  }
  if (!res.ok) throw new Error(`SOAP ${p} ${res.status}: ${txt.slice(0,400)}`);
  return txt;
}

/* ==================== CAF ==================== */
export function loadCAF(tipo: 39 | 41): Caf {
  const b64 = tipo === 39 ? process.env.CAF_39_B64 : process.env.CAF_41_B64;
  let xml: string;
  if (b64 && b64.trim()) xml = Buffer.from(b64, "base64").toString("latin1");
  else {
    const p = tipo === 39 ? process.env.CAF_39_PATH : process.env.CAF_41_PATH;
    if (!p) throw new Error(`CAF_${tipo}_B64/CAF_${tipo}_PATH no configurado`);
    xml = fs.readFileSync(path.resolve(p), "latin1");
  }
  const folioIni = Number(xml.match(/<DA>[\s\S]*?<RNG>[\s\S]*?<D>(\d+)<\/D>/)![1]);
  const folioFin = Number(xml.match(/<DA>[\s\S]*?<RNG>[\s\S]*?<H>(\d+)<\/H>/)![1]);
  const rsask = xml.match(/<RSASK>([\s\S]*?)<\/RSASK>/)![1].trim();
  const rsapk = xml.match(/<RSAPK>([\s\S]*?)<\/RSAPK>/)![1].trim();
  const rutEmisor = xml.match(/<RE>([\s\S]*?)<\/RE>/)![1].trim();
  const razon = xml.match(/<RS>([\s\S]*?)<\/RS>/)![1].trim();
  return { folioIni, folioFin, rsask, rsapk, rutEmisor, razon, xml };
}

/* ==================== Construcción DTE ==================== */
export function buildDTE({
  tipo, folio, emisor, receptor, items, fecha,
}: {
  tipo: 39 | 41;
  folio: number;
  emisor: { rut: string; rz: string; giro: string; dir: string; cmna: string };
  receptor?: { rut?: string; rz?: string };
  items: Array<{ nombre: string; qty: number; precioNeto: number; exento?: boolean }>;
  fecha: string;
}) {
  const netoAfecto = Math.round(items.filter(i => !i.exento).reduce((a, i) => a + i.qty * i.precioNeto, 0));
  const exento = Math.round(items.filter(i => !!i.exento).reduce((a, i) => a + i.qty * i.precioNeto, 0));
  const iva = Math.round(netoAfecto * 0.19);
  const total = netoAfecto + iva + exento;

  const root = create({ version: "1.0", encoding: "ISO-8859-1" })
    .ele("DTE", { version: "1.0" })
      .ele("Documento", { ID: `R${folio}` })
        .ele("Encabezado")
          .ele("IdDoc")
            .ele("TipoDTE").txt(String(tipo)).up()
            .ele("Folio").txt(String(folio)).up()
            .ele("FchEmis").txt(fecha).up()
          .up()
          .ele("Emisor")
            .ele("RUTEmisor").txt(emisor.rut).up()
            .ele("RznSoc").txt(emisor.rz).up()
            .ele("GiroEmis").txt(emisor.giro).up()
            .ele("DirOrigen").txt(emisor.dir).up()
            .ele("CmnaOrigen").txt(emisor.cmna).up()
          .up()
          .ele("Receptor")
            .ele("RUTRecep").txt(receptor?.rut ?? "66666666-6").up()
            .ele("RznSocRecep").txt(receptor?.rz ?? "Cliente").up()
          .up()
          .ele("Totales");

  if (tipo === 39 && netoAfecto > 0) {
    root.ele("MntNeto").txt(String(netoAfecto)).up()
        .ele("IVA").txt(String(iva)).up();
  }
  if (exento > 0) root.ele("MntExe").txt(String(exento)).up();
  root.ele("MntTotal").txt(String(total)).up().up(); // </Totales>

  // Detalles directamente bajo <Documento>
  const documento = root.up().up(); // Totales -> Encabezado -> Documento
  items.forEach((it, idx) => {
    const det = documento.ele("Detalle");
    det.ele("NroLinDet").txt(String(idx + 1)).up();
    det.ele("NmbItem").txt(it.nombre).up();
    det.ele("QtyItem").txt(String(it.qty)).up();
    if (tipo === 41 || it.exento) det.ele("IndExe").txt("1").up();
    det.ele("PrcItem").txt(String(it.precioNeto)).up();
    det.up();
  });

  const xml = documento.doc().end({ prettyPrint: true });
  return { xml, neto: netoAfecto, iva, total };
}

/* ==================== TED y firma Documento ==================== */
type DteHead = { RE: string; TD: number; F: number; FE: string; RR: string; RSR: string; MNT: number; IT1: string; };

function buildDDXML(cafXml: string, head: DteHead, ts: string): string {
  const cafOnly = cafXml.match(/<CAF[\s\S]*<\/CAF>/)![0];
  const dd = create({ version: "1.0", encoding: "ISO-8859-1" }).ele("DD");
  dd.ele("RE").txt(head.RE).up()
    .ele("TD").txt(String(head.TD)).up()
    .ele("F").txt(String(head.F)).up()
    .ele("FE").txt(head.FE).up()
    .ele("RR").txt(head.RR).up()
    .ele("RSR").txt(head.RSR).up()
    .ele("MNT").txt(String(head.MNT)).up()
    .ele("IT1").txt(head.IT1.slice(0, 40)).up();
  dd.import(create(cafOnly).root());
  dd.ele("TSTED").txt(ts).up();
  return dd.up().end({ headless: true });
}

function signDDwithRSASK(ddXml: string, rsaskPem: string): string {
  const signer = crypto.createSign("RSA-SHA1");
  signer.update(Buffer.from(ddXml, "latin1"));
  return signer.sign(rsaskPem).toString("base64");
}

function injectTEDandTmst(dteXml: string, tedXml: string, ts: string) {
  return dteXml.replace(
    /<\/Documento>\s*<\/DTE>/i,
    `\n${tedXml}\n<TmstFirma>${ts}</TmstFirma>\n</Documento>\n</DTE>`
  );
}

function addRefById(sig: SignedXml, id: string) {
  const xpath = `//*[@Id='${id}' or @ID='${id}']`;
  sig.addReference({
    xpath,
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    uri: `#${id}`,
  });
}

function forcePlainKeyInfo(signedXml: string, certB64: string): string {
  let xml = signedXml
    .replace(/<ds:KeyInfo[\s\S]*?<\/ds:KeyInfo>/g, "")
    .replace(/<KeyInfo[\s\S]*?<\/KeyInfo>/g, "");
  const keyInfo = `<KeyInfo><X509Data><X509Certificate>${certB64}</X509Certificate></X509Data></KeyInfo>`;
  if (/(<\/ds:Signature>\s*)$/i.test(xml)) return xml.replace(/(<\/ds:Signature>\s*)$/i, `${keyInfo}$1`);
  if (/(<\/Signature>\s*)$/i.test(xml)) return xml.replace(/(<\/Signature>\s*)$/i, `${keyInfo}$1`);
  return xml.replace(/(<\/(?:ds:)?SignatureValue>\s*)/i, `$1${keyInfo}`);
}

function signXmlEnveloped(xml: string, idToSign: string): string {
  const { keyPem, certPem } = loadP12Pem();
  const certB64 = certPem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, "");
  assertHasId(xml, idToSign);

  const sig = new SignedXml({
    idAttribute: "Id",
    privateKey: keyPem,
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    signatureNamespacePrefix: "ds",
  } as any);

  (sig as any).keyInfoProvider = {
    getKeyInfo: () =>
      `<ds:X509Data xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
         <ds:X509Certificate>${certB64}</ds:X509Certificate>
       </ds:X509Data>`
  };

  addRefById(sig as any, idToSign);
  const ref = `//*[@Id='${idToSign}' or @ID='${idToSign}']`;
  (sig as any).computeSignature(xml, { location: { reference: ref, action: "append" } });
  return forcePlainKeyInfo((sig as any).getSignedXml(), certB64);
}

function signDocumento(dteXml: string): string {
  const m = dteXml.match(/<Documento[^>]*\bID="([^"]+)"/i);
  if (!m) throw new Error("Documento sin ID");
  return signXmlEnveloped(dteXml, m[1]);
}

export function stampDTEWithCAF(dteXml: string, caf: Caf): string {
  const TD = Number(dteXml.match(/<TipoDTE>(\d+)<\/TipoDTE>/)![1]);
  const F  = Number(dteXml.match(/<Folio>(\d+)<\/Folio>/)![1]);
  const FE = dteXml.match(/<FchEmis>([^<]+)<\/FchEmis>/)![1];
  const RE = dteXml.match(/<RUTEmisor>([^<]+)<\/RUTEmisor>/)![1];
  const RR = dteXml.match(/<RUTRecep>([^<]+)<\/RUTRecep>/)![1];
  const RSR= dteXml.match(/<RznSocRecep>([^<]+)<\/RznSocRecep>/)![1];
  const MNT= Number(dteXml.match(/<MntTotal>(\d+)<\/MntTotal>/)![1]);
  const IT1= dteXml.match(/<NmbItem>([^<]+)<\/NmbItem>/)![1];

  const ts = new Date().toISOString().replace("T"," ").slice(0,19);
  const ddXml = buildDDXML(caf.xml, { RE, TD, F, FE, RR, RSR, MNT, IT1 }, ts);
  const frmtB64 = signDDwithRSASK(ddXml, caf.rsask);
  const tedXml = `<TED version="1.0"><DD>${ddXml}</DD><FRMT algoritmo="SHA1withRSA">${frmtB64}</FRMT></TED>`;
  return signDocumento(injectTEDandTmst(dteXml, tedXml, ts));
}

/* ==================== Seed + Token ==================== */
export async function getSeed(): Promise<string> {
  const env = soapEnv(`<getSeed/>`);
  const resp = await postSOAP(`/DTEWS/CrSeed.jws`, env);
  const doc = new DOMParser().parseFromString(resp, "text/xml");
  const nodes = Array.from(doc.getElementsByTagName("*")) as XEl[];
  const ret = nodes.find(n => n.localName === "getSeedReturn");
  if (!ret?.textContent) throw new Error(`No <getSeedReturn>. Head: ${resp.slice(0,200)}`);
  const decoded = unescapeXml(ret.textContent);
  const m = decoded.match(/<SEMILLA>([^<]+)<\/SEMILLA>/i);
  if (!m) throw new Error(`No <SEMILLA>. Head: ${decoded.slice(0,200)}`);
  return m[1].trim();
}

function buildSeedXML(seed: string) {
  return `<getToken xmlns="http://www.sii.cl/SiiDte" ID="GT" Id="GT"><item><Semilla>${seed}</Semilla></item></getToken>`;
}

async function getTokenFromSeed(signedXml: string): Promise<string> {
  const inner = stripXmlDecl(signedXml);
  const env = soapEnv(`<SII:getToken xmlns:SII="http://www.sii.cl/SiiDte"><pszXml><![CDATA[${inner}]]></pszXml></SII:getToken>`);
  const resp = await postSOAP(`/DTEWS/GetTokenFromSeed.jws`, env);
  const doc = new DOMParser().parseFromString(resp, "text/xml");
  const nodes = Array.from(doc.getElementsByTagName("*")) as XEl[];
  const ret = nodes.find(n => n.localName === "getTokenReturn");
  if (!ret?.textContent) throw new Error(`No <getTokenReturn>. Head: ${resp.slice(0,200)}`);
  const decoded = unescapeXml(ret.textContent);
  console.log("GETTOKEN_RAW", decoded.slice(0, 600));
  const m = decoded.match(/<TOKEN>([^<]+)<\/TOKEN>/i);
  console.log("MATCH_LEN", m?.[1]?.length);
  if (!m) throw new Error(`No <TOKEN>. Head: ${decoded.slice(0,200)}`);
  return m[1].trim();
}

export async function getToken(): Promise<string> {
  if (!hasClientCert() || !process.env.SII_CERT_PASSWORD) return "TOKEN_FAKE_CERT";
  const seed = await getSeed();
  const signed = signXmlEnveloped(buildSeedXML(seed), "GT");
  console.log("GETTOKEN_SIGNED_HEAD", signed.slice(0, 400));
  return getTokenFromSeed(signed);
}

/* ==================== Envío DTE ==================== */
function buildSobreEnvio(dteXml:string){
  const now=new Date().toISOString().slice(0,19);
  const tipo=getTipoFromDte(dteXml);
  const root=(tipo===39||tipo===41)?"EnvioBOLETA":"EnvioDTE";
  return `<?xml version="1.0" encoding="ISO-8859-1"?>
<${root} xmlns="http://www.sii.cl/SiiDte" version="1.0" ID="ENV" Id="ENV">
  <SetDTE ID="SetDoc" Id="SetDoc">
    <Caratula version="1.0">
      <RutEmisor>${process.env.BILLING_RUT}</RutEmisor>
      <RutEnvia>${process.env.SII_RUT_ENVIA}</RutEnvia>
      <RutReceptor>60803000-K</RutReceptor>
      <FchResol>2014-01-01</FchResol><NroResol>0</NroResol>
      <TmstFirmaEnv>${now}</TmstFirmaEnv>
      <SubTotDTE><TpoDTE>${tipo}</TpoDTE><NroDTE>1</NroDTE></SubTotDTE>
    </Caratula>
    ${dteXml}
  </SetDTE>
</${root}>`;
}

function signSobre(xmlSobre: string): string { return signXmlEnveloped(xmlSobre, "ENV"); }

function extractTrackIdFromUpload(respSoap: string): string {
  const doc = new DOMParser().parseFromString(respSoap, "text/xml");
  const nodes = Array.from(doc.getElementsByTagName("*")) as XEl[];
  const ret = nodes.find(n => n.localName === "uploadReturn");
  if (!ret?.textContent) throw new Error(`No <uploadReturn>. Head: ${respSoap.slice(0,400)}`);
  const inner = unescapeXml(ret.textContent);
  const m = inner.match(/<TRACKID>(\d+)<\/TRACKID>/i);
  if (!m) {
    const estado = inner.match(/<ESTADO>([^<]+)<\/ESTADO>/i)?.[1];
    const glosa  = inner.match(/<GLOSA>([^<]+)<\/GLOSA>/i)?.[1];
    throw new Error(`Sin TRACKID. ESTADO=${estado ?? "?"} GLOSA=${glosa ?? inner.slice(0,200)}`);
  }
  return m[1];
}

export async function sendEnvioDTE(xmlDte:string, token:string){
  const firmado=signSobre(buildSobreEnvio(xmlDte));
  const tipo=getTipoFromDte(xmlDte);
  const path=(tipo===39||tipo===41)?"/DTEWS/EnvioBOLETA.jws":"/DTEWS/EnvioDTE.jws";
  const env=soapEnv(`<upload><fileName>SetDTE.xml</fileName><contentFile><![CDATA[${firmado}]]></contentFile></upload>`);
  const txt=await postSOAP(path, env, {Cookie:`TOKEN=${token}`});
  const trackid=extractTrackIdFromUpload(txt);
  return {trackid};
}

export function buildSoapUploadFromDte(dteXml: string) {
  const firmado = signSobre(buildSobreEnvio(dteXml));
  return soapEnv(
    `<upload><fileName>SetDTE.xml</fileName><contentFile><![CDATA[${firmado}]]></contentFile></upload>`
  );
}