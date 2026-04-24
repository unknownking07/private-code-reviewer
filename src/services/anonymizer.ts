import { FileEntry, LLMFinding } from "../utils/types";
import { logger } from "../utils/logger";

/**
 * Anonymizer runs INSIDE the TEE. It strips PII, secrets, and identity signals
 * from source code before any bytes leave the enclave for an external LLM
 * (e.g. the Claude API). Findings come back referencing placeholders; the
 * deanonymizer maps them back to original file paths and snippets so the
 * final report shown to the user has real coordinates.
 *
 * Confidentiality boundary: everything returned by `anonymize()` is what the
 * external model will see. Anything the anonymizer misses IS the leak.
 */

export type AnonymizationMode = "balanced" | "strict";

export interface AnonymizerConfig {
  mode: AnonymizationMode;
  stripComments: boolean;
  stripStringLiterals: boolean;
  stripAddresses: boolean;
  stripHexSecrets: boolean;
  stripUrls: boolean;
  stripEmails: boolean;
  stripLargeNumbers: boolean;
  largeNumberThreshold: number;
  anonymizeFilePaths: boolean;
  anonymizeIdentifiers: boolean;
}

const DEFAULT_CONFIG: AnonymizerConfig = {
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

const STRICT_OVERRIDES: Partial<AnonymizerConfig> = {
  anonymizeIdentifiers: true,
};

export interface AnonymizedFile {
  path: string;
  language: FileEntry["language"];
  content: string;
  originalLineCount: number;
}

export interface AnonymizationMap {
  filePaths: Map<string, string>;
  identifiers: Map<string, string>;
  addresses: Map<string, string>;
  hexSecrets: Map<string, string>;
  strings: Map<string, string>;
  numbers: Map<string, string>;
  urls: Map<string, string>;
  emails: Map<string, string>;
}

export interface AnonymizeResult {
  files: AnonymizedFile[];
  map: AnonymizationMap;
  stats: {
    originalBytes: number;
    anonymizedBytes: number;
    replacements: number;
  };
}

// Reserved identifiers that must never be anonymized — doing so would break
// the external model's ability to reason about the code at all.
const SOLIDITY_RESERVED = new Set([
  "pragma", "solidity", "contract", "library", "interface", "abstract",
  "function", "modifier", "event", "struct", "enum", "mapping", "address",
  "uint", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
  "int", "int8", "int16", "int32", "int64", "int128", "int256",
  "bool", "string", "bytes", "bytes1", "bytes2", "bytes4", "bytes8",
  "bytes16", "bytes32", "public", "private", "internal", "external",
  "pure", "view", "payable", "returns", "return", "if", "else", "for",
  "while", "do", "break", "continue", "throw", "emit", "new", "delete",
  "require", "assert", "revert", "this", "super", "msg", "block", "tx",
  "now", "gasleft", "blockhash", "keccak256", "sha256", "sha3", "ripemd160",
  "ecrecover", "addmod", "mulmod", "selfdestruct", "suicide", "type",
  "import", "using", "is", "as", "from", "constructor", "fallback",
  "receive", "override", "virtual", "immutable", "constant", "memory",
  "storage", "calldata", "indexed", "anonymous", "try", "catch", "true",
  "false", "wei", "gwei", "ether", "seconds", "minutes", "hours", "days",
  "weeks", "years", "abi", "encode", "decode", "encodePacked",
  "encodeWithSelector", "encodeWithSignature", "sender", "value",
  "gas", "data", "sig", "timestamp", "number", "coinbase", "difficulty",
  "gaslimit", "chainid", "basefee", "origin", "gasprice", "balance",
  "transfer", "send", "call", "delegatecall", "staticcall", "code", "codehash",
]);

const RUST_RESERVED = new Set([
  "fn", "let", "mut", "const", "static", "struct", "enum", "trait", "impl",
  "pub", "crate", "mod", "use", "as", "in", "ref", "if", "else", "match",
  "for", "while", "loop", "break", "continue", "return", "move", "async",
  "await", "dyn", "where", "self", "Self", "Some", "None", "Ok", "Err",
  "Option", "Result", "Vec", "String", "str", "bool", "u8", "u16", "u32",
  "u64", "u128", "i8", "i16", "i32", "i64", "i128", "f32", "f64", "usize",
  "isize", "char", "true", "false", "unsafe", "extern", "type", "Box",
  "Rc", "Arc", "Cell", "RefCell", "HashMap", "BTreeMap", "Default", "Clone",
  "Copy", "Debug", "PartialEq", "Eq", "Hash", "Serialize", "Deserialize",
]);

const TYPESCRIPT_RESERVED = new Set([
  "function", "const", "let", "var", "class", "interface", "type", "enum",
  "extends", "implements", "public", "private", "protected", "static",
  "readonly", "abstract", "async", "await", "return", "if", "else", "for",
  "while", "do", "switch", "case", "break", "continue", "throw", "try",
  "catch", "finally", "new", "delete", "typeof", "instanceof", "in", "of",
  "import", "export", "from", "as", "default", "this", "super", "null",
  "undefined", "true", "false", "void", "any", "unknown", "never", "number",
  "string", "boolean", "object", "symbol", "bigint", "Array", "Promise",
  "Record", "Map", "Set", "Date", "console", "process", "require", "module",
  "exports", "Error", "JSON", "Math", "Object",
]);

const MOVE_RESERVED = new Set([
  "module", "script", "public", "friend", "entry", "fun", "struct", "has",
  "copy", "drop", "store", "key", "let", "mut", "move", "copy", "return",
  "if", "else", "while", "loop", "break", "continue", "abort", "assert",
  "use", "as", "address", "signer", "u8", "u64", "u128", "u256", "bool",
  "vector", "true", "false", "spec", "pragma", "ensures", "requires",
]);

const VYPER_RESERVED = new Set([
  "def", "return", "if", "elif", "else", "for", "while", "pass", "break",
  "continue", "assert", "raise", "log", "struct", "interface", "event",
  "enum", "implements", "import", "from", "as", "public", "private",
  "external", "internal", "view", "pure", "payable", "nonpayable",
  "constant", "immutable", "uint256", "int128", "int256", "address",
  "bool", "bytes32", "decimal", "String", "Bytes", "self", "msg", "block",
  "tx", "chain", "send", "raw_call", "create_forwarder_to", "empty",
  "convert", "True", "False",
]);

const GO_RESERVED = new Set([
  "package", "import", "func", "var", "const", "type", "struct", "interface",
  "map", "chan", "go", "defer", "select", "case", "default", "if", "else",
  "for", "range", "switch", "return", "break", "continue", "goto", "fallthrough",
  "nil", "true", "false", "iota", "int", "int8", "int16", "int32", "int64",
  "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "byte", "rune",
  "float32", "float64", "complex64", "complex128", "string", "bool", "error",
  "new", "make", "len", "cap", "append", "copy", "delete", "close", "panic",
  "recover", "print", "println",
]);

const CAIRO_RESERVED = new Set([
  "fn", "func", "let", "const", "mut", "if", "else", "match", "return",
  "loop", "while", "for", "break", "continue", "struct", "enum", "trait",
  "impl", "pub", "use", "mod", "ref", "true", "false", "felt252", "u8",
  "u16", "u32", "u64", "u128", "u256", "bool", "ContractAddress", "get_caller_address",
  "get_contract_address", "get_block_timestamp", "storage_read", "storage_write",
  "assert", "emit", "event", "external", "view", "constructor",
]);

function reservedFor(lang: FileEntry["language"]): Set<string> {
  switch (lang) {
    case "solidity": return SOLIDITY_RESERVED;
    case "rust":     return RUST_RESERVED;
    case "typescript": return TYPESCRIPT_RESERVED;
    case "move":     return MOVE_RESERVED;
    case "vyper":    return VYPER_RESERVED;
    case "go":       return GO_RESERVED;
    case "cairo":    return CAIRO_RESERVED;
    default:         return new Set();
  }
}

export class Anonymizer {
  private config: AnonymizerConfig;

  constructor(config: Partial<AnonymizerConfig> = {}) {
    const base = config.mode === "strict"
      ? { ...DEFAULT_CONFIG, ...STRICT_OVERRIDES }
      : DEFAULT_CONFIG;
    this.config = { ...base, ...config };
  }

  anonymize(files: FileEntry[]): AnonymizeResult {
    const map: AnonymizationMap = {
      filePaths: new Map(),
      identifiers: new Map(),
      addresses: new Map(),
      hexSecrets: new Map(),
      strings: new Map(),
      numbers: new Map(),
      urls: new Map(),
      emails: new Map(),
    };

    const counters = {
      file: 0, ident: 0, addr: 0, secret: 0, str: 0, num: 0, url: 0, email: 0,
    };
    let originalBytes = 0;
    let anonymizedBytes = 0;
    let replacements = 0;

    const anonymized: AnonymizedFile[] = files.map((f) => {
      originalBytes += f.content.length;
      const extension = f.path.split(".").pop() ?? "";
      const anonPath = this.config.anonymizeFilePaths
        ? `FILE_${counters.file++}.${extension}`
        : f.path;
      map.filePaths.set(anonPath, f.path);

      const { content, changes } = this.anonymizeContent(f.content, f.language, map, counters);
      replacements += changes;
      anonymizedBytes += content.length;

      return {
        path: anonPath,
        language: f.language,
        content,
        originalLineCount: f.content.split("\n").length,
      };
    });

    logger.info(`Anonymized ${files.length} files: ${replacements} replacements, ${originalBytes}B → ${anonymizedBytes}B`);

    return {
      files: anonymized,
      map,
      stats: { originalBytes, anonymizedBytes, replacements },
    };
  }

  private anonymizeContent(
    content: string,
    language: FileEntry["language"],
    map: AnonymizationMap,
    counters: Record<string, number>,
  ): { content: string; changes: number } {
    let changes = 0;
    const cfg = this.config;

    // Order matters: strip comments before literals before addresses before identifiers.
    // Otherwise we'd anonymize content inside comments as if it were live code.

    // 1. Strip line + block comments (preserving line breaks so line numbers stay stable).
    if (cfg.stripComments) {
      content = content.replace(/\/\/[^\n]*/g, () => { changes++; return "//"; });
      content = content.replace(/\/\*[\s\S]*?\*\//g, (m) => {
        changes++;
        const lines = m.split("\n").length - 1;
        return "/**/" + "\n".repeat(lines);
      });
      if (language === "vyper") {
        content = content.replace(/#[^\n]*/g, () => { changes++; return "#"; });
      }
    }

    // Reverse lookup for stable dedup (same original value → same placeholder).
    const reverseAddr = new Map<string, string>();
    const reverseSecret = new Map<string, string>();

    // 2. Long hex blobs first (64+ chars — private keys, signatures, bytes32 literals).
    //    Must run before the 40-char address pass, otherwise the address regex
    //    would eat the leading 40 chars of a 64-char blob.
    if (cfg.stripHexSecrets) {
      content = content.replace(/0x[a-fA-F0-9]{64,}/g, (m) => {
        changes++;
        const existing = reverseSecret.get(m);
        if (existing) return existing;
        const placeholder = `HEX_SECRET_${counters.secret++}`;
        map.hexSecrets.set(placeholder, m);
        reverseSecret.set(m, placeholder);
        return placeholder;
      });
    }

    // 3. Hex addresses (Ethereum 40-char, always 0x-prefixed).
    if (cfg.stripAddresses) {
      content = content.replace(/0x[a-fA-F0-9]{40}\b/g, (m) => {
        changes++;
        const existing = reverseAddr.get(m);
        if (existing) return existing;
        const placeholder = `0x${"A".repeat(36)}${String(counters.addr++).padStart(4, "0")}`;
        map.addresses.set(placeholder, m);
        reverseAddr.set(m, placeholder);
        return placeholder;
      });
    }

    // 4. URLs.
    if (cfg.stripUrls) {
      content = content.replace(/https?:\/\/[^\s"'<>)]+/g, (m) => {
        const placeholder = `URL_${counters.url++}`;
        map.urls.set(placeholder, m);
        changes++;
        return placeholder;
      });
    }

    // 5. Emails.
    if (cfg.stripEmails) {
      content = content.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, (m) => {
        const placeholder = `email${counters.email++}@redacted.local`;
        map.emails.set(placeholder, m);
        changes++;
        return placeholder;
      });
    }

    // 6. String literals — both double- and single-quoted, non-greedy, escape-aware.
    if (cfg.stripStringLiterals) {
      content = content.replace(/"(?:[^"\\]|\\.)*"/g, (m) => {
        if (m.length <= 2) return m; // empty string, preserve
        const placeholder = `"STR_${counters.str++}"`;
        map.strings.set(placeholder, m);
        changes++;
        return placeholder;
      });
      content = content.replace(/'(?:[^'\\]|\\.)*'/g, (m) => {
        if (m.length <= 2) return m;
        const placeholder = `'STR_${counters.str++}'`;
        map.strings.set(placeholder, m);
        changes++;
        return placeholder;
      });
    }

    // 7. Large numeric literals (underscores allowed in Rust/TS: 1_000_000).
    if (cfg.stripLargeNumbers) {
      content = content.replace(/\b\d[\d_]*\b/g, (m) => {
        const n = Number(m.replace(/_/g, ""));
        if (!Number.isFinite(n) || n < cfg.largeNumberThreshold) return m;
        const placeholder = `NUM_${counters.num++}`;
        map.numbers.set(placeholder, m);
        changes++;
        return placeholder;
      });
    }

    // 8. Identifier anonymization (strict mode only — preserves language keywords).
    if (cfg.anonymizeIdentifiers) {
      const reserved = reservedFor(language);
      content = content.replace(/\b[a-zA-Z_][a-zA-Z0-9_]*\b/g, (m) => {
        if (reserved.has(m)) return m;
        if (m.startsWith("STR_") || m.startsWith("NUM_") || m.startsWith("URL_") || m.startsWith("HEX_SECRET_")) return m;
        const existing = [...map.identifiers.entries()].find(([, v]) => v === m);
        if (existing) return existing[0];
        const placeholder = `IDENT_${counters.ident++}`;
        map.identifiers.set(placeholder, m);
        changes++;
        return placeholder;
      });
    }

    return { content, changes };
  }

  /**
   * Map a finding back to its original file path. If `originalFiles` is
   * provided, also replace the anonymized `codeSnippet` with the real code
   * at the reported line range — pulled from the originals inside the TEE,
   * so the user's report shows their actual code, not placeholders.
   */
  deanonymize(
    finding: LLMFinding,
    map: AnonymizationMap,
    originalFiles?: FileEntry[],
  ): LLMFinding {
    const originalFile = map.filePaths.get(finding.file) ?? finding.file;
    const result: LLMFinding = { ...finding, file: originalFile };

    if (originalFiles && finding.lineRange) {
      const source = originalFiles.find((f) => f.path === originalFile);
      const snippet = source ? extractLineRange(source.content, finding.lineRange) : null;
      if (snippet) result.codeSnippet = snippet;
    }

    return result;
  }

  deanonymizeAll(
    findings: LLMFinding[],
    map: AnonymizationMap,
    originalFiles?: FileEntry[],
  ): LLMFinding[] {
    return findings.map((f) => this.deanonymize(f, map, originalFiles));
  }
}

function extractLineRange(content: string, lineRange: string): string | null {
  const match = lineRange.match(/(\d+)(?:\s*-\s*(\d+))?/);
  if (!match) return null;
  const start = parseInt(match[1], 10);
  const end = match[2] ? parseInt(match[2], 10) : start;
  if (!Number.isFinite(start) || start < 1) return null;
  const lines = content.split("\n");
  return lines.slice(start - 1, end).join("\n");
}
