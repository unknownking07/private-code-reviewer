import { Router, Request, Response } from "express";
import multer from "multer";
import path from "path";
import { ReviewOrchestrator } from "../services/review-orchestrator";
import { logger } from "../utils/logger";

const upload = multer({
  dest: path.resolve(__dirname, "../../uploads"),
  limits: {
    fileSize: (parseInt(process.env.MAX_UPLOAD_SIZE_MB || "50") || 50) * 1024 * 1024,
  },
  fileFilter: (_req, file, cb) => {
    const allowed = [".zip", ".tar", ".gz", ".tgz", ".sol", ".rs", ".move", ".vy", ".vyper", ".cairo", ".go", ".ts", ".tsx", ".js", ".jsx"];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${ext} not supported. Upload .zip, .tar.gz, or individual source files (.sol, .rs, .move, .vy, .cairo, .go, .ts, .js).`));
    }
  },
});

export function createAPIRouter(orchestrator: ReviewOrchestrator): Router {
  const router = Router();

  // Upload code and start review
  router.post("/review", upload.single("code"), async (req: Request, res: Response) => {
    try {
      if (!req.file) {
        res.status(400).json({ error: "No file uploaded. Send a .zip, .tar.gz, or source file (.sol, .rs, .move, .vy, .cairo, .go, .ts, .js)." });
        return;
      }

      const job = orchestrator.createJob();
      logger.info(`New review job ${job.id} — file: ${req.file.originalname}`);

      // Rename upload to preserve original extension (multer strips it)
      const originalExt = path.extname(req.file.originalname).toLowerCase();
      const uploadPathWithExt = req.file.path + originalExt;
      const fs = await import("fs");
      fs.renameSync(req.file.path, uploadPathWithExt);

      // Start review in background
      orchestrator.runReview(job.id, uploadPathWithExt).catch((err) => {
        logger.error(`Background review failed for ${job.id}: ${err}`);
      });

      res.status(202).json({
        jobId: job.id,
        status: job.status,
        message: "Review started. Poll /api/review/:jobId for progress.",
      });
    } catch (err: any) {
      logger.error(`Upload failed: ${err}`);
      res.status(500).json({ error: err.message });
    }
  });

  // Get review status/result
  router.get("/review/:jobId", (req: Request, res: Response) => {
    const job = orchestrator.getJob(req.params.jobId);
    if (!job) {
      res.status(404).json({ error: "Job not found" });
      return;
    }

    const response: any = {
      jobId: job.id,
      status: job.status,
      progress: job.progress,
      createdAt: job.createdAt,
    };

    if (job.status === "complete" && job.report) {
      response.completedAt = job.completedAt;
      response.report = job.report;
    }

    if (job.status === "error") {
      response.error = job.error;
    }

    res.json(response);
  });

  // Download PDF report
  router.get("/review/:jobId/pdf", async (req: Request, res: Response) => {
    const job = orchestrator.getJob(req.params.jobId);
    if (!job) {
      res.status(404).json({ error: "Job not found" });
      return;
    }

    if (job.status !== "complete") {
      res.status(400).json({ error: "Review not yet complete" });
      return;
    }

    try {
      const pdf = await orchestrator.generatePDF(req.params.jobId);
      if (!pdf) {
        res.status(500).json({ error: "Failed to generate PDF" });
        return;
      }

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="audit-${req.params.jobId}.pdf"`);
      res.send(pdf);
    } catch (err: any) {
      logger.error(`PDF generation failed: ${err}`);
      res.status(500).json({ error: "PDF generation failed" });
    }
  });

  return router;
}
