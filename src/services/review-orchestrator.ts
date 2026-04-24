import { v4 as uuidv4 } from "uuid";
import { FileProcessor } from "./file-processor";
import { StaticAnalyzer } from "../analyzers/static-analyzer";
import { EigenAIReviewer } from "./eigenai";
import { ClaudeReviewer } from "./claude-reviewer";
import { ReportGenerator } from "./report-generator";
import { ReviewJob, LLMFinding, FileEntry } from "../utils/types";
import { logger } from "../utils/logger";

interface LLMReviewer {
  reviewFiles(files: FileEntry[]): Promise<LLMFinding[]>;
}

export class ReviewOrchestrator {
  private jobs: Map<string, ReviewJob> = new Map();
  private fileProcessor: FileProcessor;
  private staticAnalyzer: StaticAnalyzer;
  private llmReviewer: LLMReviewer;
  private reportGenerator: ReportGenerator;

  constructor() {
    this.fileProcessor = new FileProcessor();
    this.staticAnalyzer = new StaticAnalyzer();
    // LLM_PROVIDER=claude routes raw code through the Anonymizer before any
    // byte leaves the TEE; anything else keeps the original EigenAI path.
    const provider = (process.env.LLM_PROVIDER ?? "eigenai").toLowerCase();
    this.llmReviewer = provider === "claude" ? new ClaudeReviewer() : new EigenAIReviewer();
    logger.info(`LLM reviewer: ${provider}`);
    this.reportGenerator = new ReportGenerator();
  }

  createJob(): ReviewJob {
    const job: ReviewJob = {
      id: uuidv4(),
      status: "uploading",
      progress: 0,
      createdAt: new Date().toISOString(),
    };
    this.jobs.set(job.id, job);
    return job;
  }

  getJob(id: string): ReviewJob | undefined {
    return this.jobs.get(id);
  }

  async runReview(jobId: string, uploadPath: string): Promise<void> {
    const job = this.jobs.get(jobId);
    if (!job) throw new Error(`Job ${jobId} not found`);

    try {
      // Phase 1: Process uploaded files
      this.updateJob(job, "analyzing", 10);
      const { files, codeHash } = await this.fileProcessor.processUpload(uploadPath);

      if (files.length === 0) {
        throw new Error("No Solidity or Rust files found in the upload");
      }

      logger.info(`Job ${jobId}: ${files.length} files extracted, starting analysis`);

      // Phase 2: Static pattern analysis
      this.updateJob(job, "analyzing", 30);
      const staticFindings = this.staticAnalyzer.analyze(files);
      this.updateJob(job, "analyzing", 50);

      // Phase 3: LLM deep review (either EigenAI or Claude+anonymizer, per LLM_PROVIDER)
      this.updateJob(job, "reviewing", 55);
      let llmFindings: LLMFinding[] = [];
      try {
        llmFindings = await this.llmReviewer.reviewFiles(files);
      } catch (err) {
        logger.warn(`LLM review failed, continuing with static-only: ${err}`);
      }
      this.updateJob(job, "reviewing", 85);

      // Phase 4: Generate report
      this.updateJob(job, "generating", 90);
      const report = this.reportGenerator.generateReport(
        jobId,
        files,
        codeHash,
        staticFindings,
        llmFindings
      );

      // Complete
      job.report = report;
      this.updateJob(job, "complete", 100);
      job.completedAt = new Date().toISOString();

      logger.info(`Job ${jobId} complete: risk=${report.summary.riskLevel}, findings=${report.summary.totalFindings}`);
    } catch (err: any) {
      job.status = "error";
      job.error = err.message || "Unknown error during review";
      logger.error(`Job ${jobId} failed: ${err}`);
    }
  }

  async generatePDF(jobId: string): Promise<Buffer | null> {
    const job = this.jobs.get(jobId);
    if (!job?.report) return null;
    return this.reportGenerator.generatePDF(job.report);
  }

  private updateJob(job: ReviewJob, status: ReviewJob["status"], progress: number): void {
    job.status = status;
    job.progress = progress;
  }
}
