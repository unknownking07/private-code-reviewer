import dotenv from "dotenv";
dotenv.config({ override: true });
import { readFileSync } from "fs";
import { ClaudeReviewer } from "../src/services/claude-reviewer";
import { FileEntry } from "../src/utils/types";

const path = "test-samples/VulnerableToken.sol";
const content = readFileSync(path, "utf-8");

const files: FileEntry[] = [
  { path, content, language: "solidity", size: content.length },
];

async function main() {
  const reviewer = new ClaudeReviewer();

  console.log(`Reviewing ${path} via Claude (model=${process.env.CLAUDE_MODEL ?? "claude-opus-4-7"})\n`);
  const start = Date.now();

  const findings = await reviewer.reviewFiles(files);

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`\nCompleted in ${elapsed}s. Found ${findings.length} finding(s).\n`);

  findings.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
    return order[a.severity] - order[b.severity];
  });

  for (const [i, f] of findings.entries()) {
    console.log(`--- [${i + 1}] ${f.severity.toUpperCase()} -- ${f.title}`);
    console.log(`    file: ${f.file}:${f.lineRange}`);
    console.log(`    confidence: ${f.confidence}`);
    console.log(`    description: ${f.description}`);
    console.log(`    recommendation: ${f.recommendation}`);
    if (f.codeSnippet) {
      const snippet = f.codeSnippet.split("\n").map((l) => `      ${l}`).join("\n");
      console.log(`    snippet (from original source in TEE):\n${snippet}`);
    }
    console.log("");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
