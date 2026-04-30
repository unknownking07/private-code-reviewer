import dotenv from "dotenv";
dotenv.config({ override: true });

import http from "http";
import https from "https";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import path from "path";
import rateLimit from "express-rate-limit";
import { createAPIRouter } from "./routes/api";
import { ReviewOrchestrator } from "./services/review-orchestrator";
import { logger } from "./utils/logger";

const app = express();
const PORT = parseInt(process.env.PORT || "8000");
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT || "443");

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
}));
// CORS: in dev allow any origin; in prod lock to CORS_ORIGIN (comma-separated list).
const corsOrigins = (process.env.CORS_ORIGIN ?? "").split(",").map((s) => s.trim()).filter(Boolean);
app.use(cors({
  origin: corsOrigins.length > 0 ? corsOrigins : true,
  credentials: false,
}));
app.use(express.json());

// Rate limiting — apply ONLY to uploads (POST /api/review). Polling
// (GET /api/review/:jobId) runs every 1.5s during a job and must not be
// throttled; otherwise the UI gets a 429 mid-poll and stalls forever.
const uploadLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "900000"),
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || "20"),
  message: { error: "Too many uploads — please wait before submitting another review" },
});
app.use((req, res, next) => {
  if (req.method === "POST" && req.path === "/api/review") return uploadLimiter(req, res, next);
  next();
});

// Health check (used by TEE monitoring)
app.get("/health", (_req, res) => {
  res.json({
    status: "healthy",
    service: "private-code-reviewer",
    tee: "EigenCompute",
    timestamp: new Date().toISOString(),
  });
});

// TEE attestation info
app.get("/attestation", (_req, res) => {
  res.json({
    teeProvider: "EigenCompute (Intel TDX)",
    service: "Private Code Reviewer",
    description: "Code uploaded to this service is processed entirely within a Trusted Execution Environment. The code is never persisted and is securely deleted after analysis.",
    guarantees: [
      "Code never leaves the TEE enclave",
      "No code is stored after analysis completes",
      "Report includes SHA-256 hash of analyzed code",
      "All AI inference runs via EigenAI (deterministic, verifiable)",
    ],
  });
});

// API routes
const orchestrator = new ReviewOrchestrator();
app.use("/api", createAPIRouter(orchestrator));

// Drop malformed-URL scanner traffic early. Public IPs constantly get
// probed for /cgi-bin/, /.env, etc. with bogus URL-encoding; serve-static
// throws URIError on those and pollutes logs with stacks. We have no CGI;
// just 400 silently and move on.
app.use((req, res, next) => {
  try {
    decodeURIComponent(req.path);
    next();
  } catch {
    res.status(400).end();
  }
});

// Serve React frontend in production
const frontendPath = path.resolve(__dirname, "../frontend/dist");
app.use(express.static(frontendPath));
app.get("*", (_req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// Final-resort error handler: catches anything unhandled (including any
// URIErrors that slip past the early filter) and returns 400/500 without
// dumping stacks to the public log stream.
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err instanceof URIError) {
    res.status(400).end();
    return;
  }
  logger.error(`Unhandled error: ${err?.message ?? err}`);
  if (!res.headersSent) res.status(500).end();
});

// TLS: when TLS_CERT_B64 + TLS_KEY_B64 are provided (a Let's Encrypt cert
// issued OUTSIDE the TEE via DNS-01 and base64-injected as KMS secrets),
// terminate HTTPS directly inside the enclave. No proxy in the network
// path means raw bytes traverse only Browser ↔ TEE — no CF, no edge.
const tlsCertB64 = process.env.TLS_CERT_B64;
const tlsKeyB64 = process.env.TLS_KEY_B64;
const httpsEnabled = !!(tlsCertB64 && tlsKeyB64);

if (httpsEnabled) {
  const cert = Buffer.from(tlsCertB64!, "base64").toString("utf-8");
  const key = Buffer.from(tlsKeyB64!, "base64").toString("utf-8");
  https.createServer({ cert, key }, app).listen(HTTPS_PORT, "0.0.0.0", () => {
    logger.info(`HTTPS listening on ${HTTPS_PORT} (TLS terminated inside TEE)`);
  });

  // HTTP listener: redirects everything to HTTPS so plaintext can't be sniffed.
  http
    .createServer((req, res) => {
      const host = req.headers.host?.split(":")[0] ?? "";
      res.writeHead(301, { Location: `https://${host}${req.url}` });
      res.end();
    })
    .listen(PORT, "0.0.0.0", () => {
      logger.info(`HTTP listening on ${PORT} (redirects → HTTPS)`);
    });
} else {
  app.listen(PORT, "0.0.0.0", () => {
    logger.warn(`HTTP only on port ${PORT} — set TLS_CERT_B64 + TLS_KEY_B64 for HTTPS`);
  });
}

logger.info(`Private Code Reviewer running`);
logger.info(`Environment: ${process.env.NODE_ENV || "development"}`);
logger.info(`TEE: EigenCompute (Intel TDX)`);
