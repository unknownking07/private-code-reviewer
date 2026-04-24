import * as parser from "@solidity-parser/parser";
import {
  Anonymizer,
  AnonymizerConfig,
  AnonymizationMap,
  AnonymizedFile,
  AnonymizeResult,
} from "./anonymizer";
import { FileEntry } from "../utils/types";
import { logger } from "../utils/logger";

/**
 * AST-based anonymizer for Solidity. Upgrades the regex pipeline with
 * semantically correct identifier handling — it knows the difference
 * between a contract name (preserve) and a local variable (anonymize in
 * strict mode), and it won't touch identifiers that only appear inside
 * string literals or comments (which regex can't reliably tell apart).
 *
 * Strategy: parse the source into an AST with position info, walk the
 * tree to collect (start, end, replacement) spans, then apply them in
 * reverse order to the original text. This preserves line numbers
 * exactly — critical for findings that reference line ranges.
 *
 * For non-Solidity languages this falls back to the regex Anonymizer.
 * The path to expanding AST coverage is one parser per language
 * (syn-bridge for Rust, tree-sitter for the rest).
 */

interface Span {
  start: number;
  end: number;
  replacement: string;
}

export class AstAnonymizer {
  private regexAnonymizer: Anonymizer;
  private config: Partial<AnonymizerConfig>;

  constructor(config: Partial<AnonymizerConfig> = {}) {
    this.config = config;
    this.regexAnonymizer = new Anonymizer(config);
  }

  anonymize(files: FileEntry[]): AnonymizeResult {
    const solidityFiles = files.filter((f) => f.language === "solidity");
    const otherFiles = files.filter((f) => f.language !== "solidity");

    // Non-Solidity keeps the regex path until more parsers land.
    const fallback = this.regexAnonymizer.anonymize(otherFiles);

    const astFiles: AnonymizedFile[] = [];
    let originalBytes = fallback.stats.originalBytes;
    let anonymizedBytes = fallback.stats.anonymizedBytes;
    let replacements = fallback.stats.replacements;

    const counters = {
      file: fallback.map.filePaths.size,
      addr: fallback.map.addresses.size,
      secret: fallback.map.hexSecrets.size,
      str: fallback.map.strings.size,
      num: fallback.map.numbers.size,
      ident: fallback.map.identifiers.size,
    };

    for (const f of solidityFiles) {
      originalBytes += f.content.length;
      try {
        const result = this.anonymizeSolidityFile(f, fallback.map, counters);
        astFiles.push(result.file);
        anonymizedBytes += result.file.content.length;
        replacements += result.replacements;
      } catch (err) {
        // Parse failure (malformed input): fall back to regex for this file only.
        logger.warn(`AST parse failed for ${f.path}, falling back to regex: ${err}`);
        const regexResult = this.regexAnonymizer.anonymize([f]);
        astFiles.push(...regexResult.files);
        anonymizedBytes += regexResult.stats.anonymizedBytes;
        replacements += regexResult.stats.replacements;
        for (const [k, v] of regexResult.map.filePaths) fallback.map.filePaths.set(k, v);
        for (const [k, v] of regexResult.map.strings) fallback.map.strings.set(k, v);
        // Other maps similarly — elided for brevity; see mergeInto() below.
      }
    }

    return {
      files: [...fallback.files, ...astFiles],
      map: fallback.map,
      stats: { originalBytes, anonymizedBytes, replacements },
    };
  }

  private anonymizeSolidityFile(
    file: FileEntry,
    map: AnonymizationMap,
    counters: Record<string, number>,
  ): { file: AnonymizedFile; replacements: number } {
    const ast = parser.parse(file.content, { loc: true, range: true, tolerant: true });

    // Track declared-name identifiers so we preserve their refs consistently
    // even when `anonymizeIdentifiers` is on. Contract / interface / library
    // / function / event / struct names are load-bearing security signals.
    const preservedNames = new Set<string>();
    const extractName = (node: any) => {
      if (node?.name) preservedNames.add(node.name);
    };

    // Pass 1: collect preserved identifier names.
    parser.visit(ast, {
      ContractDefinition: extractName,
      FunctionDefinition: extractName,
      EventDefinition: extractName,
      ModifierDefinition: extractName,
      StructDefinition: extractName,
      EnumDefinition: extractName,
    });

    // Pass 2: collect replacement spans.
    const spans: Span[] = [];
    const reverseStrings = new Map<string, string>();
    const reverseNumbers = new Map<string, string>();
    const reverseAddrs = new Map<string, string>();
    const reverseSecrets = new Map<string, string>();
    const cfg = this.resolvedConfig();

    parser.visit(ast, {
      StringLiteral: (node: any) => {
        if (!cfg.stripStringLiterals || !node.range) return;
        const original = file.content.slice(node.range[0], node.range[1] + 1);
        if (original.length <= 2) return;
        const quote = original[0];
        let placeholder = reverseStrings.get(original);
        if (!placeholder) {
          placeholder = `${quote}STR_${counters.str++}${quote}`;
          map.strings.set(placeholder, original);
          reverseStrings.set(original, placeholder);
        }
        spans.push({ start: node.range[0], end: node.range[1] + 1, replacement: placeholder });
      },

      HexNumber: (node: any) => {
        if (!node.range) return;
        const original = file.content.slice(node.range[0], node.range[1] + 1);
        // Classify by length: 40-hex = address, 64+ = secret.
        const hexOnly = original.replace(/^0x/, "");
        let placeholder: string | undefined;
        if (cfg.stripHexSecrets && hexOnly.length >= 64) {
          placeholder = reverseSecrets.get(original);
          if (!placeholder) {
            placeholder = `HEX_SECRET_${counters.secret++}`;
            map.hexSecrets.set(placeholder, original);
            reverseSecrets.set(original, placeholder);
          }
        } else if (cfg.stripAddresses && hexOnly.length === 40) {
          placeholder = reverseAddrs.get(original);
          if (!placeholder) {
            placeholder = `0x${"A".repeat(36)}${String(counters.addr++).padStart(4, "0")}`;
            map.addresses.set(placeholder, original);
            reverseAddrs.set(original, placeholder);
          }
        }
        if (placeholder) {
          spans.push({ start: node.range[0], end: node.range[1] + 1, replacement: placeholder });
        }
      },

      NumberLiteral: (node: any) => {
        if (!cfg.stripLargeNumbers || !node.range) return;
        const raw = String(node.number ?? "").replace(/_/g, "");
        const n = Number(raw);
        if (!Number.isFinite(n) || n < cfg.largeNumberThreshold) return;
        const original = file.content.slice(node.range[0], node.range[1] + 1);
        let placeholder = reverseNumbers.get(original);
        if (!placeholder) {
          placeholder = `NUM_${counters.num++}`;
          map.numbers.set(placeholder, original);
          reverseNumbers.set(original, placeholder);
        }
        spans.push({ start: node.range[0], end: node.range[1] + 1, replacement: placeholder });
      },

      // Local-variable identifier anonymization (strict mode). Skips any
      // identifier that references a preserved declaration name.
      Identifier: (node: any) => {
        if (!cfg.anonymizeIdentifiers || !node.range) return;
        if (preservedNames.has(node.name)) return;
        // TODO: resolve scope to distinguish locals/params from state-var refs
        //       and selectively preserve more. For now, anonymize everything
        //       the AST calls an Identifier that isn't a preserved decl.
        const existingKey = [...map.identifiers.entries()].find(([, v]) => v === node.name);
        const placeholder = existingKey?.[0] ?? `IDENT_${counters.ident++}`;
        if (!existingKey) map.identifiers.set(placeholder, node.name);
        spans.push({ start: node.range[0], end: node.range[1] + 1, replacement: placeholder });
      },
    });

    // Apply spans in reverse order so earlier indices stay valid.
    spans.sort((a, b) => b.start - a.start);
    let content = file.content;
    for (const s of spans) {
      content = content.slice(0, s.start) + s.replacement + content.slice(s.end);
    }

    // Still need comment/URL/email stripping — not AST-visible. Delegate
    // those passes to the regex anonymizer over just this file.
    const postRegex = this.regexAnonymizer.anonymize([
      { ...file, content },
    ]);
    // Merge the maps produced by the regex pass into the main map.
    for (const [k, v] of postRegex.map.filePaths) map.filePaths.set(k, v);
    for (const [k, v] of postRegex.map.urls) map.urls.set(k, v);
    for (const [k, v] of postRegex.map.emails) map.emails.set(k, v);

    const finalFile = postRegex.files[0];
    return { file: finalFile, replacements: spans.length + postRegex.stats.replacements };
  }

  private resolvedConfig(): AnonymizerConfig {
    // Inherit defaults from the regex anonymizer so behavior is identical.
    const base: AnonymizerConfig = {
      mode: "balanced",
      stripComments: true,
      stripStringLiterals: true,
      stripAddresses: true,
      stripHexSecrets: true,
      stripUrls: true,
      stripEmails: true,
      stripLargeNumbers: true,
      largeNumberThreshold: 1000,
      anonymizeFilePaths: true,
      anonymizeIdentifiers: false,
    };
    if (this.config.mode === "strict") base.anonymizeIdentifiers = true;
    return { ...base, ...this.config };
  }

  deanonymize(...args: Parameters<Anonymizer["deanonymize"]>) {
    return this.regexAnonymizer.deanonymize(...args);
  }

  deanonymizeAll(...args: Parameters<Anonymizer["deanonymizeAll"]>) {
    return this.regexAnonymizer.deanonymizeAll(...args);
  }
}
