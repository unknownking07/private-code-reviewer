import { readFileSync } from "fs";
import { AstAnonymizer } from "../src/services/ast-anonymizer";
import { FileEntry } from "../src/utils/types";

const path = "test-samples/VulnerableToken.sol";
const content = readFileSync(path, "utf-8");

const files: FileEntry[] = [
  { path, content, language: "solidity", size: content.length },
];

const anonymizer = new AstAnonymizer();
const { files: anon, map, stats } = anonymizer.anonymize(files);

console.log("AST anonymizer output:");
console.log("=".repeat(78));
console.log(anon[0].content);

console.log("\nStats:");
console.log(`  ${stats.originalBytes}B → ${stats.anonymizedBytes}B, ${stats.replacements} replacements`);
console.log(`  strings=${map.strings.size} addresses=${map.addresses.size} secrets=${map.hexSecrets.size} numbers=${map.numbers.size}`);

// Leak audit
const anonText = anon[0].content;
const checks: Array<[string, RegExp]> = [
  ["hex address (0x + 40 hex)", /0x[a-fA-F0-9]{40}(?!A)/],
  ["hex blob (64+ hex)", /0x[a-fA-F0-9]{64,}/],
  ["URL", /https?:\/\/[^\s"']+/],
  ["email", /\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b/i],
];
let leaks = 0;
for (const [name, re] of checks) {
  const m = anonText.match(re);
  if (m) {
    console.log(`  LEAK (${name}): ${m[0].slice(0, 80)}`);
    leaks++;
  }
}
console.log(leaks === 0 ? "  ✓ No residual secrets" : `  ✗ ${leaks} leak(s)`);
