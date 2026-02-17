import { UploadZone } from "./components/UploadZone";
import { Progress } from "./components/Progress";
import { Report } from "./components/Report";
import { useReview } from "./hooks/useReview";

export default function App() {
  const { status, progress, report, error, startReview, downloadPDF, reset } = useReview();

  const isProcessing = !["idle", "complete", "error"].includes(status);

  return (
    <div className="app">
      <header className="header">
        <h1 className="header__title">
          Private <span className="header__accent">Code Reviewer</span>
        </h1>
        <p className="header__subtitle">
          Upload your code for a confidential security audit.
          <br />
          Scans for backdoors, rug-pull mechanisms, and exploitable vulnerabilities.
        </p>
        <div className="header__badge">
          EigenCompute TEE &middot; Code never leaves the enclave
        </div>
      </header>

      {status === "idle" && (
        <UploadZone onUpload={startReview} disabled={false} />
      )}

      {isProcessing && <Progress status={status} progress={progress} />}

      {status === "complete" && report && (
        <Report report={report} onDownloadPDF={downloadPDF} onReset={reset} />
      )}

      {status === "error" && (
        <>
          <div className="error">{error || "An error occurred during review"}</div>
          <div className="actions">
            <button className="btn btn--secondary" onClick={reset}>
              Try Again
            </button>
          </div>
        </>
      )}
    </div>
  );
}
