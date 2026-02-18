import dotenv from "dotenv";
dotenv.config();

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

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "900000"),
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || "20"),
  message: { error: "Too many requests — please try again later" },
});
app.use("/api/", limiter);

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

// Serve React frontend in production
const frontendPath = path.resolve(__dirname, "../frontend/dist");
app.use(express.static(frontendPath));
app.get("*", (_req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// Bind to 0.0.0.0 for TEE accessibility
app.listen(PORT, "0.0.0.0", () => {
  logger.info(`Private Code Reviewer running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || "development"}`);
  logger.info(`TEE: EigenCompute (Intel TDX)`);
  logger.info(`EigenAI model: ${process.env.EIGENAI_MODEL || "gpt-oss-120b-f16"}`);
});
