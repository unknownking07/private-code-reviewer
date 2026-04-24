import Anthropic from "@anthropic-ai/sdk";
import { z } from "zod/v4";
import { zodOutputFormat } from "@anthropic-ai/sdk/helpers/zod";
import {
  Anonymizer,
  AnonymizerConfig,
  AnonymizedFile,
} from "./anonymizer";
import { FileEntry, LLMFinding, Severity } from "../utils/types";
import { logger } from "../utils/logger";

/**
 * ClaudeReviewer runs INSIDE the TEE. It anonymizes source code with the
 * Anonymizer, sends only the anonymized version to the Claude API for
 * security analysis, then deanonymizes findings back to real file paths
 * and real code snippets (using the originals that never left the enclave).
 *
 * Raw code never crosses the TEE boundary. The external model sees
 * placeholders in place of addresses, secrets, string literals, URLs,
 * emails, large numbers, and file paths.
 */

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const CONFIDENCES = ["high", "medium", "low"] as const;

const FindingSchema = z.object({
  title: z.string(),
  description: z.string(),
  severity: z.enum(SEVERITIES),
  file: z.string(),
  lineRange: z.string(),
  codeSnippet: z.string(),
  recommendation: z.string(),
  confidence: z.enum(CONFIDENCES),
});

const FindingsResponseSchema = z.object({
  findings: z.array(FindingSchema),
});

// Large, frozen. Goes first + cached — repeat audits pay cache-read rates.
const SYSTEM_PROMPT = `You are an expert smart contract and blockchain security auditor.

Review code for:

1. BACKDOORS — hidden admin functions, upgradeable proxies without timelocks, delegatecall to mutable addresses, hidden minting, kill switches, renounceable-but-reclaimable ownership patterns.
2. RUG-PULL MECHANISMS — removable liquidity locks, adjustable fees to 100%, pause/freeze without governance, hidden transfer-to-owner, self-destruct, token-recovery functions that drain users.
3. EXPLOITABLE VULNERABILITIES — reentrancy, flash-loan attacks, oracle manipulation, integer overflow / underflow, access control issues, front-running (MEV), unchecked external calls, signature replay, missing slippage protection.
4. SUSPICIOUS PATTERNS — obfuscated code, misleading function names, unnecessary complexity hiding malicious intent, inline assembly bypassing normal checks.

IMPORTANT CONFIDENTIALITY CONTEXT:

The code you are reviewing has been anonymized inside a Trusted Execution Environment before being sent to you. You will see placeholders in place of real values:

- Hex addresses appear as 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANNNN (36 As + 4-digit counter).
- 64+ char hex blobs (private keys, signatures, bytes32 constants) appear as HEX_SECRET_N.
- String literals appear as "STR_N" or 'STR_N'.
- URLs appear as URL_N.
- Email addresses appear as emailN@redacted.local.
- Numeric literals above 1000 appear as NUM_N.
- File paths appear as FILE_N.<ext>.

Do NOT flag the placeholders themselves as suspicious — reason about the structure and semantics of the surrounding code. Function names, contract names, control flow, modifiers, inheritance, and language keywords are preserved so you can do real analysis. Use file+lineRange coordinates exactly as they appear in the anonymized source; they will be mapped back to the real file inside the enclave.

Output ONLY findings that are genuinely actionable. If the code is clean, return an empty findings array.`;

export interface ClaudeReviewerOptions {
  anonymizerConfig?: Partial<AnonymizerConfig>;
  model?: string;
  maxCharsPerBatch?: number;
  maxTokens?: number;
}

export class ClaudeReviewer {
  private client: Anthropic;
  private anonymizer: Anonymizer;
  private model: string;
  private maxCharsPerBatch: number;
  private maxTokens: number;

  constructor(opts: ClaudeReviewerOptions = {}) {
    // Reads ANTHROPIC_API_KEY from env.
    this.client = new Anthropic();
    this.anonymizer = new Anonymizer(opts.anonymizerConfig);
    this.model = opts.model ?? process.env.CLAUDE_MODEL ?? "claude-opus-4-7";
    this.maxCharsPerBatch = opts.maxCharsPerBatch ?? 200_000;
    this.maxTokens = opts.maxTokens ?? 16_000;

    logger.info(`Claude reviewer: model=${this.model}`);
  }

  async reviewFiles(files: FileEntry[]): Promise<LLMFinding[]> {
    const { files: anonFiles, map, stats } = this.anonymizer.anonymize(files);
    logger.info(
      `Anonymized ${files.length} files for external review (${stats.originalBytes}B → ${stats.anonymizedBytes}B, ${stats.replacements} replacements)`,
    );

    const batches = this.batchFiles(anonFiles, this.maxCharsPerBatch);
    const allFindings: LLMFinding[] = [];

    for (let i = 0; i < batches.length; i++) {
      logger.info(`Claude review batch ${i + 1}/${batches.length}`);
      try {
        const findings = await this.reviewBatch(batches[i]);
        allFindings.push(...this.anonymizer.deanonymizeAll(findings, map, files));
      } catch (err) {
        this.logApiError(i + 1, err);
      }
    }

    logger.info(`Claude review complete: ${allFindings.length} findings`);
    return allFindings;
  }

  private async reviewBatch(files: AnonymizedFile[]): Promise<LLMFinding[]> {
    const codeContent = files
      .map((f) => `--- FILE: ${f.path} (${f.language}) ---\n${f.content}\n--- END FILE ---`)
      .join("\n\n");

    const response = await this.client.messages.parse({
      model: this.model,
      max_tokens: this.maxTokens,
      thinking: { type: "adaptive" },
      // Large static system prompt → cache it. The anonymized user content
      // varies per batch and goes after the last breakpoint.
      system: [
        {
          type: "text",
          text: SYSTEM_PROMPT,
          cache_control: { type: "ephemeral" },
        },
      ],
      messages: [
        {
          role: "user",
          content: `Review the following anonymized source files for security vulnerabilities. Return findings per the configured output format.\n\n${codeContent}`,
        },
      ],
      output_config: {
        format: zodOutputFormat(FindingsResponseSchema),
      },
    });

    if (response.usage) {
      logger.info(
        `Claude usage: input=${response.usage.input_tokens}, output=${response.usage.output_tokens}, cache_read=${response.usage.cache_read_input_tokens ?? 0}, cache_write=${response.usage.cache_creation_input_tokens ?? 0}`,
      );
    }

    const parsed = response.parsed_output;
    if (!parsed) {
      logger.error(
        `Claude returned non-parseable output (stop_reason=${response.stop_reason})`,
      );
      return [];
    }

    return parsed.findings.map((f) => ({
      title: f.title,
      description: f.description,
      severity: f.severity as Severity,
      file: f.file,
      lineRange: f.lineRange,
      codeSnippet: f.codeSnippet,
      recommendation: f.recommendation,
      confidence: f.confidence,
    }));
  }

  private batchFiles(files: AnonymizedFile[], maxCharsPerBatch: number): AnonymizedFile[][] {
    const batches: AnonymizedFile[][] = [];
    let currentBatch: AnonymizedFile[] = [];
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
    if (currentBatch.length > 0) batches.push(currentBatch);

    return batches;
  }

  private logApiError(batchNum: number, err: unknown): void {
    if (err instanceof Anthropic.RateLimitError) {
      logger.error(`Claude batch ${batchNum}: rate limited — retry later`);
    } else if (err instanceof Anthropic.AuthenticationError) {
      logger.error(`Claude batch ${batchNum}: invalid ANTHROPIC_API_KEY`);
    } else if (err instanceof Anthropic.APIError) {
      logger.error(`Claude batch ${batchNum}: API error ${err.status} — ${err.message}`);
    } else {
      logger.error(`Claude batch ${batchNum}: ${err}`);
    }
  }
}
