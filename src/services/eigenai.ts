import OpenAI from "openai";
import { FileEntry, LLMFinding, Severity } from "../utils/types";
import { logger } from "../utils/logger";

const SYSTEM_PROMPT = `You are an expert smart contract and blockchain security auditor running inside a Trusted Execution Environment (TEE). Your job is to review code for:

1. BACKDOORS: Hidden functionality that gives developers/owners unauthorized control (hidden admin functions, upgradeable proxies without timelocks, delegatecall to mutable addresses, hidden minting, etc.)

2. RUG PULL MECHANISMS: Code designed to steal user funds or devalue their holdings (removable liquidity locks, adjustable fees to 100%, pause/freeze without governance, hidden transfer-to-owner logic, self-destruct, etc.)

3. EXPLOITABLE VULNERABILITIES: Security flaws that could be exploited (reentrancy, flash loan attacks, oracle manipulation, integer overflow, access control issues, etc.)

4. SUSPICIOUS PATTERNS: Anything that looks intentionally deceptive — obfuscated code, misleading function names, unnecessary complexity hiding malicious intent, etc.

For each finding, provide:
- A clear title
- Severity: critical, high, medium, or low
- The specific file and approximate line range
- A code snippet showing the issue
- Why it's dangerous
- A concrete recommendation to fix it
- Your confidence level: high, medium, or low

Be thorough but avoid false positives. If the code looks clean, say so. Focus on intentional backdoors and rug-pull mechanisms first, then vulnerabilities.

Respond in JSON format as an array of findings.`;

type AuthMode = "apikey" | "grant";

interface GrantAuth {
  walletAddress: string;
  grantMessage: string;
  grantSignature: string;
}

export class EigenAIReviewer {
  private model: string;
  private authMode: AuthMode;

  // API key mode
  private client?: OpenAI;

  // Grant mode
  private grantBaseURL: string;
  private grantAuth?: GrantAuth;

  constructor() {
    this.model = process.env.EIGENAI_MODEL || "gpt-oss-120b-f16";
    this.grantBaseURL = process.env.EIGENAI_GRANT_API_URL || "https://determinal-api.eigenarcade.com";

    // Determine auth mode
    if (process.env.EIGENAI_GRANT_WALLET_ADDRESS) {
      this.authMode = "grant";
      this.grantAuth = {
        walletAddress: process.env.EIGENAI_GRANT_WALLET_ADDRESS || "",
        grantMessage: process.env.EIGENAI_GRANT_MESSAGE || "",
        grantSignature: process.env.EIGENAI_GRANT_SIGNATURE || "",
      };
      logger.info("EigenAI auth: deTERMinal grant (wallet-based)");
    } else {
      this.authMode = "apikey";
      this.client = new OpenAI({
        apiKey: process.env.EIGENAI_API_KEY || "",
        baseURL: process.env.EIGENAI_BASE_URL || "https://eigenai.eigencloud.xyz/v1",
        defaultHeaders: { "x-api-key": process.env.EIGENAI_API_KEY || "" },
      });
      logger.info("EigenAI auth: API key");
    }
  }

  async reviewFiles(files: FileEntry[]): Promise<LLMFinding[]> {
    const allFindings: LLMFinding[] = [];
    const batches = this.batchFiles(files, 12000);

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

    const messages = [
      { role: "system" as const, content: SYSTEM_PROMPT },
      {
        role: "user" as const,
        content: `Review the following code for backdoors, rug-pull mechanisms, and exploitable vulnerabilities:\n\n${codeContent}`,
      },
    ];

    let content: string | null = null;

    if (this.authMode === "grant" && this.grantAuth) {
      content = await this.callGrantAPI(messages);
    } else if (this.client) {
      const response = await this.client.chat.completions.create({
        model: this.model,
        seed: 42,
        max_tokens: 4096,
        messages,
      });
      content = response.choices[0]?.message?.content ?? null;
    }

    if (!content) return [];

    try {
      const parsed = JSON.parse(content);
      const findings = parsed.findings || parsed;
      return (Array.isArray(findings) ? findings : []).map((f: any) => ({
        title: f.title,
        description: f.description,
        severity: f.severity as Severity,
        file: f.file,
        lineRange: f.lineRange,
        codeSnippet: f.codeSnippet,
        recommendation: f.recommendation,
        confidence: f.confidence,
      }));
    } catch (err) {
      logger.error(`Failed to parse LLM response: ${err}`);
      logger.debug(`Raw response: ${content?.substring(0, 500)}`);
      return [];
    }
  }

  private async callGrantAPI(
    messages: Array<{ role: string; content: string }>
  ): Promise<string | null> {
    const body = {
      model: this.model,
      max_tokens: 4096,
      seed: 42,
      messages,
      walletAddress: this.grantAuth!.walletAddress,
      grantMessage: this.grantAuth!.grantMessage,
      grantSignature: this.grantAuth!.grantSignature,
    };

    const res = await fetch(`${this.grantBaseURL}/api/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Grant API error ${res.status}: ${errText}`);
    }

    const data: any = await res.json();
    return data.choices?.[0]?.message?.content ?? null;
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
