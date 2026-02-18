export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface PatternMatch {
  patternId: string;
  patternName: string;
  description: string;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  matchedCode: string;
  recommendation: string;
  category: string;
}

export interface LLMFinding {
  title: string;
  description: string;
  severity: Severity;
  file: string;
  lineRange?: string;
  codeSnippet?: string;
  recommendation: string;
  confidence: "high" | "medium" | "low";
}

export interface AuditReport {
  id: string;
  timestamp: string;
  summary: {
    totalFiles: number;
    filesAnalyzed: number;
    languages: string[];
    riskScore: number; // 0-100
    riskLevel: "critical" | "high" | "medium" | "low" | "safe";
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  staticAnalysis: PatternMatch[];
  llmAnalysis: LLMFinding[];
  attestation: {
    teeProvider: string;
    timestamp: string;
    codeHash: string;
    reportHash: string;
  };
}

export interface ReviewJob {
  id: string;
  status: "uploading" | "analyzing" | "reviewing" | "generating" | "complete" | "error";
  progress: number; // 0-100
  createdAt: string;
  completedAt?: string;
  error?: string;
  report?: AuditReport;
}

export interface FileEntry {
  path: string;
  content: string;
  language: "solidity" | "rust" | "move" | "vyper" | "cairo" | "go" | "typescript" | "unknown";
  size: number;
}
