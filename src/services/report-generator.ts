import PDFDocument from "pdfkit";
import { createHash } from "crypto";
import { AuditReport, PatternMatch, LLMFinding, Severity } from "../utils/types";
import { logger } from "../utils/logger";

export class ReportGenerator {
  generateReport(
    id: string,
    files: { path: string; language: string }[],
    codeHash: string,
    staticFindings: PatternMatch[],
    llmFindings: LLMFinding[]
  ): AuditReport {
    const languages = [...new Set(files.map((f) => f.language).filter((l) => l !== "unknown"))];

    const criticalCount =
      staticFindings.filter((f) => f.severity === "critical").length +
      llmFindings.filter((f) => f.severity === "critical").length;
    const highCount =
      staticFindings.filter((f) => f.severity === "high").length +
      llmFindings.filter((f) => f.severity === "high").length;
    const mediumCount =
      staticFindings.filter((f) => f.severity === "medium").length +
      llmFindings.filter((f) => f.severity === "medium").length;
    const lowCount =
      staticFindings.filter((f) => f.severity === "low").length +
      llmFindings.filter((f) => f.severity === "low").length;

    const totalFindings = criticalCount + highCount + mediumCount + lowCount;

    // Risk score: 0 (safe) to 100 (extremely dangerous)
    const riskScore = Math.min(
      100,
      criticalCount * 25 + highCount * 12 + mediumCount * 5 + lowCount * 2
    );

    let riskLevel: AuditReport["summary"]["riskLevel"];
    if (riskScore >= 75) riskLevel = "critical";
    else if (riskScore >= 50) riskLevel = "high";
    else if (riskScore >= 25) riskLevel = "medium";
    else if (riskScore > 0) riskLevel = "low";
    else riskLevel = "safe";

    const report: AuditReport = {
      id,
      timestamp: new Date().toISOString(),
      summary: {
        totalFiles: files.length,
        filesAnalyzed: files.filter((f) => f.language !== "unknown").length,
        languages,
        riskScore,
        riskLevel,
        totalFindings,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
      },
      staticAnalysis: staticFindings,
      llmAnalysis: llmFindings,
      attestation: {
        teeProvider: "EigenCompute (Intel TDX)",
        timestamp: new Date().toISOString(),
        codeHash,
        reportHash: "", // Filled below
      },
    };

    // Hash the report itself for attestation
    report.attestation.reportHash = createHash("sha256")
      .update(JSON.stringify({ ...report, attestation: { ...report.attestation, reportHash: "" } }))
      .digest("hex");

    logger.info(`Report generated: risk=${riskLevel} (${riskScore}/100), findings=${totalFindings}`);
    return report;
  }

  async generatePDF(report: AuditReport): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({ margin: 50, size: "A4" });
      const chunks: Buffer[] = [];

      doc.on("data", (chunk: Buffer) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);

      // Header
      doc
        .fontSize(24)
        .font("Helvetica-Bold")
        .text("Private Code Review", { align: "center" })
        .fontSize(12)
        .font("Helvetica")
        .text("Audit Report", { align: "center" })
        .moveDown(0.5)
        .fontSize(9)
        .fillColor("#666")
        .text(`Generated inside TEE (EigenCompute) — Code never left the enclave`, { align: "center" })
        .moveDown(0.3)
        .text(`Report ID: ${report.id}`, { align: "center" })
        .text(`Date: ${new Date(report.timestamp).toLocaleString()}`, { align: "center" })
        .moveDown(1);

      // Risk Score Banner
      const riskColor = this.getRiskColor(report.summary.riskLevel);
      doc
        .rect(50, doc.y, 495, 60)
        .fill(riskColor);
      doc
        .fontSize(18)
        .fillColor("#fff")
        .font("Helvetica-Bold")
        .text(
          `Risk Level: ${report.summary.riskLevel.toUpperCase()} (${report.summary.riskScore}/100)`,
          70,
          doc.y - 50,
          { align: "center" }
        );
      doc.y += 30;
      doc.moveDown(1);

      // Summary Stats
      doc
        .fillColor("#000")
        .fontSize(14)
        .font("Helvetica-Bold")
        .text("Summary")
        .moveDown(0.5)
        .fontSize(10)
        .font("Helvetica");

      const summaryLines = [
        `Files Analyzed: ${report.summary.filesAnalyzed} / ${report.summary.totalFiles}`,
        `Languages: ${report.summary.languages.join(", ")}`,
        `Total Findings: ${report.summary.totalFindings}`,
        `  Critical: ${report.summary.criticalCount} | High: ${report.summary.highCount} | Medium: ${report.summary.mediumCount} | Low: ${report.summary.lowCount}`,
      ];

      for (const line of summaryLines) {
        doc.text(line).moveDown(0.2);
      }
      doc.moveDown(1);

      // Static Analysis Findings
      if (report.staticAnalysis.length > 0) {
        doc
          .fontSize(14)
          .font("Helvetica-Bold")
          .text("Static Analysis Findings")
          .moveDown(0.5);

        for (const finding of report.staticAnalysis) {
          this.addFindingToPDF(doc, {
            title: finding.patternName,
            severity: finding.severity,
            description: finding.description,
            location: `${finding.file}:${finding.line}`,
            code: finding.matchedCode,
            recommendation: finding.recommendation,
          });
        }
      }

      // LLM Analysis Findings
      if (report.llmAnalysis.length > 0) {
        doc
          .addPage()
          .fontSize(14)
          .font("Helvetica-Bold")
          .fillColor("#000")
          .text("AI-Powered Deep Analysis (EigenAI)")
          .moveDown(0.5);

        for (const finding of report.llmAnalysis) {
          this.addFindingToPDF(doc, {
            title: finding.title,
            severity: finding.severity,
            description: finding.description,
            location: `${finding.file}${finding.lineRange ? `:${finding.lineRange}` : ""}`,
            code: finding.codeSnippet,
            recommendation: finding.recommendation,
            confidence: finding.confidence,
          });
        }
      }

      // Attestation Footer
      doc
        .addPage()
        .fontSize(14)
        .font("Helvetica-Bold")
        .fillColor("#000")
        .text("TEE Attestation")
        .moveDown(0.5)
        .fontSize(10)
        .font("Helvetica");

      const attestLines = [
        `TEE Provider: ${report.attestation.teeProvider}`,
        `Timestamp: ${report.attestation.timestamp}`,
        `Code Hash (SHA-256): ${report.attestation.codeHash}`,
        `Report Hash (SHA-256): ${report.attestation.reportHash}`,
        "",
        "This report was generated inside a Trusted Execution Environment.",
        "The uploaded code was processed entirely within the TEE enclave and was",
        "securely deleted after analysis. The code hash can be used to verify that",
        "this report corresponds to a specific codebase without revealing the code.",
      ];

      for (const line of attestLines) {
        doc.text(line).moveDown(0.2);
      }

      doc.end();
    });
  }

  private addFindingToPDF(
    doc: PDFKit.PDFDocument,
    finding: {
      title: string;
      severity: Severity;
      description: string;
      location: string;
      code?: string;
      recommendation: string;
      confidence?: string;
    }
  ): void {
    // Check if we need a new page
    if (doc.y > 650) doc.addPage();

    const severityColor = this.getSeverityColor(finding.severity);

    doc
      .fontSize(11)
      .font("Helvetica-Bold")
      .fillColor(severityColor)
      .text(`[${finding.severity.toUpperCase()}] ${finding.title}`)
      .fontSize(9)
      .fillColor("#333")
      .font("Helvetica")
      .text(finding.location)
      .moveDown(0.2)
      .text(finding.description)
      .moveDown(0.2);

    if (finding.code) {
      doc
        .fontSize(8)
        .font("Courier")
        .fillColor("#444")
        .text(finding.code.substring(0, 500), { indent: 10 })
        .moveDown(0.2);
    }

    doc
      .fontSize(9)
      .font("Helvetica-Bold")
      .fillColor("#006600")
      .text(`Fix: ${finding.recommendation}`)
      .font("Helvetica")
      .fillColor("#000");

    if (finding.confidence) {
      doc.fontSize(8).fillColor("#666").text(`Confidence: ${finding.confidence}`);
    }

    doc.moveDown(0.8);
  }

  private getRiskColor(level: string): string {
    switch (level) {
      case "critical": return "#cc0000";
      case "high": return "#e65100";
      case "medium": return "#f9a825";
      case "low": return "#2e7d32";
      case "safe": return "#1565c0";
      default: return "#666";
    }
  }

  private getSeverityColor(severity: Severity): string {
    switch (severity) {
      case "critical": return "#cc0000";
      case "high": return "#e65100";
      case "medium": return "#f9a825";
      case "low": return "#2e7d32";
      default: return "#333";
    }
  }
}
