import express, { Request, Response } from "express";
import cors from "cors";
import { getToken, buildDTE, loadCAF, stampDTEWithCAF, sendEnvioDTE,buildSoapUploadFromDte } from "./lib/dte.js";

const EMISOR = {
  rut:  process.env.BILLING_RUT ?? "",
  rz:   process.env.BILLING_BUSINESS_NAME ?? "",
  giro: process.env.BILLING_GIRO ?? "",
  dir:  process.env.BILLING_ADDRESS ?? "",
  cmna: process.env.BILLING_COMMUNE ?? "",
};
const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cors({
  origin: (process.env.CORS_ORIGIN?.split(",").map(s => s.trim()) ?? ["*"])
}));

app.get("/health", (_req: Request, res: Response) => {
  res.json({ ok: true });
});

app.get("/token", async (_req, res) => {
  const token = await getToken();
  console.log("TOKEN_LEN", token.length, "HEAD", token.slice(0, 25), "TAIL", token.slice(-25));
  res.json({ ok: true, token, len: token.length });
});

app.post("/send", async (req, res) => {
  try {
    const { tipo, folio, fecha, receptor, items } = req.body;
    const dryRun = req.query.dryRun === "1";

    const caf = loadCAF(tipo);
    const { xml } = buildDTE({ tipo, folio, emisor: EMISOR, receptor, items, fecha });
    const dteTimbrado = stampDTEWithCAF(xml, caf);

    if (dryRun) {
      const env = buildSoapUploadFromDte(dteTimbrado);
      return res.type("text/xml; charset=ISO-8859-1").send(env);
    }

    const token = await getToken();
    const { trackid } = await sendEnvioDTE(dteTimbrado, token);
    res.json({ ok: true, trackid });
  } catch (e:any) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`DTE up on :${port}`);
});
