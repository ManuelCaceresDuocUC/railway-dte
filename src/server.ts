import express, { Request, Response } from "express";
import cors from "cors";
import { getToken, buildDTE, loadCAF, stampDTEWithCAF, sendEnvioDTE } from "./lib/dte.js";

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

app.post("/send", async (req: Request, res: Response) => {
  try {
    const { tipo = 39, folio = 1, receptor, items, fecha } = req.body as any;
    if (!Array.isArray(items) || items.length === 0) throw new Error("items requerido");

    const { xml } = buildDTE({
      tipo,
      folio,
      emisor: {
        rut: process.env.BILLING_RUT || "",
        rz: process.env.BILLING_BUSINESS_NAME || "",
        giro: process.env.BILLING_GIRO || "",
        dir: process.env.BILLING_ADDRESS || "",
        cmna: process.env.BILLING_COMMUNE || "Valparaíso",
      },
      receptor: receptor ?? { rut: "66666666-6", rz: "Cliente" },
      fecha: fecha ?? new Date().toISOString().slice(0, 10),
      items,
    });

    const caf = loadCAF(tipo);
    const dteFirmado = stampDTEWithCAF(xml, caf);
    const token = await getToken();
    const { trackid } = await sendEnvioDTE(dteFirmado, token);
    res.json({ ok: true, trackid });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    res.status(500).json({ ok: false, error: msg });
  }
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`DTE up on :${port}`);
});
