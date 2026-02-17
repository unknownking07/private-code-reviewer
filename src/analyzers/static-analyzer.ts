import fs from "fs";
import path from "path";
import { FileEntry, PatternMatch, Severity } from "../utils/types";
import { logger } from "../utils/logger";

interface PatternDef {
  id: string;
  name: string;
  description: string;
  regex: string;
  severity: Severity;
  recommendation: string;
}

interface CategoryDef {
  id: string;
  name: string;
  severity: Severity;
  patterns: PatternDef[];
}

interface PatternFile {
  language: string;
  categories: CategoryDef[];
}

export class StaticAnalyzer {
  private patterns: Map<string, PatternFile> = new Map();

  constructor() {
    this.loadPatterns();
  }

  private loadPatterns(): void {
    const patternsDir = path.resolve(
      __dirname,
      process.env.NODE_ENV === "production" ? "../../patterns" : "../../patterns"
    );

    for (const file of fs.readdirSync(patternsDir)) {
      if (!file.endsWith(".json")) continue;
      const content = fs.readFileSync(path.join(patternsDir, file), "utf-8");
      const patternFile: PatternFile = JSON.parse(content);
      this.patterns.set(patternFile.language, patternFile);
      logger.info(`Loaded ${patternFile.categories.reduce((a, c) => a + c.patterns.length, 0)} patterns for ${patternFile.language}`);
    }
  }

  analyze(files: FileEntry[]): PatternMatch[] {
    const findings: PatternMatch[] = [];

    for (const file of files) {
      if (file.language === "unknown") continue;

      const patternFile = this.patterns.get(file.language);
      if (!patternFile) continue;

      for (const category of patternFile.categories) {
        for (const pattern of category.patterns) {
          const matches = this.matchPattern(file, pattern, category.id);
          findings.push(...matches);
        }
      }
    }

    findings.sort((a, b) => {
      const severityOrder: Record<Severity, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4,
      };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

    logger.info(`Static analysis complete: ${findings.length} findings across ${files.length} files`);
    return findings;
  }

  private matchPattern(
    file: FileEntry,
    pattern: PatternDef,
    categoryId: string
  ): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const lines = file.content.split("\n");

    try {
      const regex = new RegExp(pattern.regex, "gm");
      let match: RegExpExecArray | null;

      while ((match = regex.exec(file.content)) !== null) {
        const lineNumber = file.content.substring(0, match.index).split("\n").length;
        const column = match.index - file.content.lastIndexOf("\n", match.index - 1);

        const contextStart = Math.max(0, lineNumber - 3);
        const contextEnd = Math.min(lines.length, lineNumber + 2);
        const matchedCode = lines.slice(contextStart, contextEnd).join("\n");

        matches.push({
          patternId: pattern.id,
          patternName: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          file: file.path,
          line: lineNumber,
          column,
          matchedCode,
          recommendation: pattern.recommendation,
          category: categoryId,
        });

        // Prevent infinite loops on zero-length matches
        if (match[0].length === 0) regex.lastIndex++;
      }
    } catch (err) {
      logger.warn(`Regex error for pattern ${pattern.id}: ${err}`);
    }

    return matches;
  }
}
