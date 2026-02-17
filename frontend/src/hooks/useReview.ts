import { useState, useCallback, useRef } from "react";

interface ReviewStatus {
  jobId: string | null;
  status: "idle" | "uploading" | "analyzing" | "reviewing" | "generating" | "complete" | "error";
  progress: number;
  report: any | null;
  error: string | null;
}

export function useReview() {
  const [state, setState] = useState<ReviewStatus>({
    jobId: null,
    status: "idle",
    progress: 0,
    report: null,
    error: null,
  });
  const pollingRef = useRef<number | null>(null);

  const startReview = useCallback(async (file: File) => {
    setState({ jobId: null, status: "uploading", progress: 5, report: null, error: null });

    try {
      const formData = new FormData();
      formData.append("code", file);

      const res = await fetch("/api/review", { method: "POST", body: formData });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || "Upload failed");

      setState((prev) => ({
        ...prev,
        jobId: data.jobId,
        status: data.status,
        progress: 10,
      }));

      // Start polling
      const poll = async () => {
        try {
          const pollRes = await fetch(`/api/review/${data.jobId}`);
          const pollData = await pollRes.json();

          setState((prev) => ({
            ...prev,
            status: pollData.status,
            progress: pollData.progress,
            report: pollData.report || null,
            error: pollData.error || null,
          }));

          if (pollData.status !== "complete" && pollData.status !== "error") {
            pollingRef.current = window.setTimeout(poll, 1500);
          }
        } catch {
          pollingRef.current = window.setTimeout(poll, 3000);
        }
      };

      pollingRef.current = window.setTimeout(poll, 1000);
    } catch (err: any) {
      setState((prev) => ({
        ...prev,
        status: "error",
        error: err.message || "Something went wrong",
      }));
    }
  }, []);

  const downloadPDF = useCallback(async () => {
    if (!state.jobId) return;
    const res = await fetch(`/api/review/${state.jobId}/pdf`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-${state.jobId}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  }, [state.jobId]);

  const reset = useCallback(() => {
    if (pollingRef.current) clearTimeout(pollingRef.current);
    setState({ jobId: null, status: "idle", progress: 0, report: null, error: null });
  }, []);

  return { ...state, startReview, downloadPDF, reset };
}
