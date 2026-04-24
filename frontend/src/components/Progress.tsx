interface Props {
  status: string;
  progress: number;
}

const STATUS_LABELS: Record<string, string> = {
  uploading: "Uploading code to TEE...",
  analyzing: "Running static analysis (pattern matching)...",
  reviewing: "Deep review via Claude (anonymized code, inside TEE)...",
  generating: "Generating audit report...",
};

export function Progress({ status, progress }: Props) {
  return (
    <div className="progress">
      <div className="progress__bar-container">
        <div className="progress__bar" style={{ width: `${progress}%` }} />
      </div>
      <div className="progress__status">
        <span className="progress__label">{STATUS_LABELS[status] || status}</span>
        <span className="progress__percent">{progress}%</span>
      </div>
    </div>
  );
}
