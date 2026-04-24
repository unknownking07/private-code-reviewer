import { readFileSync } from "fs";
import { Anonymizer } from "../src/services/anonymizer";
import { FileEntry } from "../src/utils/types";

const path = "test-samples/VulnerableToken.sol";
const content = readFileSync(path, "utf-8");

const files: FileEntry[] = [
  { path, content, language: "solidity", size: content.length },
];

const anonymizer = new Anonymizer();
const { files: anon, map, stats } = anonymizer.anonymize(files);

console.log("=".repeat(78));
console.log("ORIGINAL (stays inside TEE — never sent to Claude)");
console.log("=".repeat(78));
console.log(content);

console.log("\n" + "=".repeat(78));
console.log("ANONYMIZED (what Claude actually sees)");
console.log("=".repeat(78));
console.log(anon[0].content);

console.log("\n" + "=".repeat(78));
console.log("CONFIDENTIALITY REPORT");
console.log("=".repeat(78));
console.log(`Original size:    ${stats.originalBytes} bytes`);
console.log(`Anonymized size:  ${stats.anonymizedBytes} bytes`);
console.log(`Replacements:     ${stats.replacements}`);
console.log(`File paths hidden: ${map.filePaths.size}`);
console.log(`Addresses hidden:  ${map.addresses.size}`);
console.log(`Hex secrets hidden: ${map.hexSecrets.size}`);
console.log(`Strings hidden:    ${map.strings.size}`);
console.log(`Numbers hidden:    ${map.numbers.size}`);
console.log(`URLs hidden:       ${map.urls.size}`);
console.log(`Emails hidden:     ${map.emails.size}`);

console.log("\n--- Mapping samples (TEE-only, never leaves enclave) ---");
for (const [placeholder, original] of [...map.strings.entries()].slice(0, 5)) {
  console.log(`  ${placeholder}  ←  ${original}`);
}
for (const [placeholder, original] of map.filePaths.entries()) {
  console.log(`  ${placeholder}  ←  ${original}`);
}

console.log("\n--- Leak audit: scanning anonymized output for residual secrets ---");
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
  } else {
    console.log(`  ok  (${name}): no residual matches`);
  }
}
console.log(leaks === 0 ? "\n✓ Clean. External model sees no raw secrets." : `\n✗ ${leaks} leak(s) detected.`);
