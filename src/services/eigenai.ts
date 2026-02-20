import OpenAI from "openai";
import { FileEntry, LLMFinding, Severity } from "../utils/types";
import { logger } from "../utils/logger";

const SYSTEM_PROMPT = `You are an expert smart contract and blockchain security auditor. Review code for:

1. BACKDOORS: Hidden admin functions, upgradeable proxies without timelocks, delegatecall to mutable addresses, hidden minting, kill switches
2. RUG PULL MECHANISMS: Removable liquidity locks, adjustable fees to 100%, pause/freeze without governance, hidden transfer-to-owner, self-destruct
3. EXPLOITABLE VULNERABILITIES: Reentrancy, flash loan attacks, oracle manipulation, integer overflow, access control issues, front-running
4. SUSPICIOUS PATTERNS: Obfuscated code, misleading function names, unnecessary complexity hiding malicious intent

For each finding provide: title, severity (critical/high/medium/low), file, lineRange, codeSnippet, description, recommendation, confidence (high/medium/low).

IMPORTANT: Respond with ONLY a valid JSON array. No markdown, no code fences, no explanation text.

Example: [{"title":"Reentrancy","description":"External call before state update","severity":"critical","file":"Token.sol","lineRange":"45-52","codeSnippet":"msg.sender.call{value: bal}(\\"\\")","recommendation":"Use checks-effects-interactions","confidence":"high"}]

If no issues: []`;

export class EigenAIReviewer {
  private client: OpenAI;
  private model: string;

  constructor() {
    const apiKey = process.env.OPENROUTER_API_KEY || process.env.EIGENAI_API_KEY || "";
    const baseURL = process.env.LLM_BASE_URL || "https://openrouter.ai/api/v1";
    this.model = process.env.LLM_MODEL || "google/gemini-2.0-flash-001";

    this.client = new OpenAI({
      apiKey,
      baseURL,
    });

    logger.info(`LLM provider: ${baseURL}`);
    logger.info(`LLM model: ${this.model}`);
  }

  async reviewFiles(files: FileEntry[]): Promise<LLMFinding[]> {
    const allFindings: LLMFinding[] = [];
    const batches = this.batchFiles(files, 30000);

    for (let i = 0; i < batches.length; i++) {
      logger.info(`LLM review batch ${i + 1}/${batches.length}`);
      try {
        const findings = await this.reviewBatch(batches[i]);
        allFindings.push(...findings);
      } catch (err) {
        logger.error(`LLM review batch ${i + 1} failed: ${err}`);
      }
    }

    logger.info(`LLM review complete: ${allFindings.length} findings`);
    return allFindings;
  }

  private async reviewBatch(files: FileEntry[]): Promise<LLMFinding[]> {
    const codeContent = files
      .map((f) => `--- FILE: ${f.path} (${f.language}) ---\n${f.content}\n--- END FILE ---`)
      .join("\n\n");

    const response = await this.client.chat.completions.create({
      model: this.model,
      max_tokens: 4096,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        {
          role: "user",
          content: `Review this code for security vulnerabilities. Respond with ONLY a JSON array.\n\n${codeContent}`,
        },
      ],
    });

    const content = response.choices[0]?.message?.content ?? null;
    if (!content) return [];

    return this.parseFindings(content);
  }

  private parseFindings(raw: string): LLMFinding[] {
    // Strip markdown code fences if present
    let cleaned = raw.trim();
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");

    // Try direct JSON parse
    try {
      const parsed = JSON.parse(cleaned);
      const findings = parsed.findings || parsed;
      if (Array.isArray(findings)) return this.mapFindings(findings);
    } catch {
      // Direct parse failed
    }

    // Try to extract JSON array from response
    const arrayMatch = cleaned.match(/\[[\s\S]*\]/);
    if (arrayMatch) {
      try {
        const parsed = JSON.parse(arrayMatch[0]);
        if (Array.isArray(parsed)) {
          logger.info(`Extracted ${parsed.length} findings from LLM response`);
          return this.mapFindings(parsed);
        }
      } catch {
        // Extraction failed
      }
    }

    logger.error(`Failed to parse LLM response`);
    logger.debug(`Raw response (first 500 chars): ${raw.substring(0, 500)}`);
    return [];
  }

  private mapFindings(findings: any[]): LLMFinding[] {
    return findings
      .filter((f) => f && f.title && f.severity)
      .map((f: any) => ({
        title: f.title || "Unknown",
        description: f.description || "",
        severity: (f.severity || "medium") as Severity,
        file: f.file || "unknown",
        lineRange: f.lineRange || f.line_range || f.lines || "",
        codeSnippet: f.codeSnippet || f.code_snippet || f.code || "",
        recommendation: f.recommendation || f.fix || "",
        confidence: f.confidence || "medium",
      }));
  }

  private batchFiles(files: FileEntry[], maxCharsPerBatch: number): FileEntry[][] {
    const batches: FileEntry[][] = [];
    let currentBatch: FileEntry[] = [];
    let currentSize = 0;

    for (const file of files) {
      if (currentSize + file.content.length > maxCharsPerBatch && currentBatch.length > 0) {
        batches.push(currentBatch);
        currentBatch = [];
        currentSize = 0;
      }
      currentBatch.push(file);
      currentSize += file.content.length;
    }

    if (currentBatch.length > 0) {
      batches.push(currentBatch);
    }

    return batches;
  }
}
