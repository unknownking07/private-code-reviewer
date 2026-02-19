interface Finding {
  patternId?: string;
  patternName?: string;
  title?: string;
  description: string;
  severity: string;
  file: string;
  line?: number;
  lineRange?: string;
  matchedCode?: string;
  codeSnippet?: string;
  recommendation: string;
  confidence?: string;
  category?: string;
}

interface ReportData {
  id: string;
  timestamp: string;
  summary: {
    totalFiles: number;
    filesAnalyzed: number;
    languages: string[];
    riskScore: number;
    riskLevel: string;
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  staticAnalysis: Finding[];
  llmAnalysis: Finding[];
  attestation: {
    teeProvider: string;
    timestamp: string;
    codeHash: string;
    reportHash: string;
  };
}

interface Props {
  report: ReportData;
  onDownloadPDF: () => void;
  onReset: () => void;
}

function FindingCard({ finding }: { finding: Finding }) {
  const title = finding.patternName || finding.title || "Finding";
  const code = finding.matchedCode || finding.codeSnippet;
  const location = finding.line
    ? `${finding.file}:${finding.line}`
    : `${finding.file}${finding.lineRange ? `:${finding.lineRange}` : ""}`;

  return (
    <div className={`finding finding--${finding.severity}`}>
      <div className="finding__header">
        <span className="finding__title">{title}</span>
        <span className={`finding__severity finding__severity--${finding.severity}`}>
          {finding.severity}
        </span>
      </div>
      <div className="finding__location">{location}</div>
      <div className="finding__description">{finding.description}</div>
      {code && <pre className="finding__code">{code}</pre>}
      <div className="finding__recommendation">
        {finding.recommendation}
      </div>
    </div>
  );
}

export function Report({ report, onDownloadPDF, onReset }: Props) {
  const { summary, staticAnalysis, llmAnalysis, attestation } = report;
  const scanDate = new Date(report.timestamp).toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit",
  });

  return (
    <div className="report">
      {/* Audit Report Header */}
      <div className="report__header">
        <div className="report__header-label">Audit Report</div>
        <h2 className="report__header-title">
          Vulnerabilities Found in Your Project
        </h2>
        <div className="report__header-meta">
          {summary.filesAnalyzed} files analyzed &middot; {summary.languages.join(", ")} &middot; {scanDate}
        </div>
      </div>

      {/* Total Vulnerabilities Count */}
      <div className="report__total">
        <div className="report__total-count">{summary.totalFindings}</div>
        <div className="report__total-label">
          {summary.totalFindings === 1 ? "Vulnerability" : "Vulnerabilities"} Detected
        </div>
      </div>

      {/* Risk Banner */}
      <div className={`report__risk-banner report__risk-banner--${summary.riskLevel}`}>
        <div className="report__risk-level">{summary.riskLevel} Risk</div>
        <div className="report__risk-score">
          Overall Risk Score: {summary.riskScore}/100
        </div>
      </div>

      {/* Severity Breakdown */}
      <div className="report__breakdown-title">Severity Breakdown</div>
      <div className="stats">
        <div className="stat">
          <div className="stat__value stat__value--critical">{summary.criticalCount}</div>
          <div className="stat__label">Critical</div>
        </div>
        <div className="stat">
          <div className="stat__value stat__value--high">{summary.highCount}</div>
          <div className="stat__label">High</div>
        </div>
        <div className="stat">
          <div className="stat__value stat__value--medium">{summary.mediumCount}</div>
          <div className="stat__label">Medium</div>
        </div>
        <div className="stat">
          <div className="stat__value stat__value--low">{summary.lowCount}</div>
          <div className="stat__label">Low</div>
        </div>
      </div>

      {/* Static Analysis Findings */}
      {staticAnalysis.length > 0 && (
        <div className="findings">
          <div className="findings__title">Static Analysis ({staticAnalysis.length})</div>
          {staticAnalysis.map((f, i) => (
            <FindingCard key={`static-${i}`} finding={f} />
          ))}
        </div>
      )}

      {/* LLM Findings */}
      {llmAnalysis.length > 0 && (
        <div className="findings">
          <div className="findings__title">AI Deep Review — EigenAI ({llmAnalysis.length})</div>
          {llmAnalysis.map((f, i) => (
            <FindingCard key={`llm-${i}`} finding={f} />
          ))}
        </div>
      )}

      {/* Attestation */}
      <div className="attestation">
        <div className="attestation__title">TEE Attestation</div>
        <div className="attestation__item">
          <span className="attestation__label">Provider</span>
          <span className="attestation__value">{attestation.teeProvider}</span>
        </div>
        <div className="attestation__item">
          <span className="attestation__label">Timestamp</span>
          <span className="attestation__value">{attestation.timestamp}</span>
        </div>
        <div className="attestation__item">
          <span className="attestation__label">Code Hash</span>
          <span className="attestation__value">{attestation.codeHash}</span>
        </div>
        <div className="attestation__item">
          <span className="attestation__label">Report Hash</span>
          <span className="attestation__value">{attestation.reportHash}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="actions">
        <button className="btn btn--primary" onClick={onDownloadPDF}>
          Download PDF Report
        </button>
        <button className="btn btn--secondary" onClick={onReset}>
          Review Another Codebase
        </button>
      </div>
    </div>
  );
}
