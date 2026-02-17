import { useState, useRef, DragEvent } from "react";

interface Props {
  onUpload: (file: File) => void;
  disabled: boolean;
}

export function UploadZone({ onUpload, disabled }: Props) {
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDragIn = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragOut = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (disabled) return;
    const file = e.dataTransfer.files[0];
    if (file) onUpload(file);
  };

  const handleClick = () => {
    if (!disabled) inputRef.current?.click();
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) onUpload(file);
  };

  return (
    <div
      className={`upload-zone ${isDragging ? "upload-zone--active" : ""}`}
      onClick={handleClick}
      onDragOver={handleDrag}
      onDragEnter={handleDragIn}
      onDragLeave={handleDragOut}
      onDrop={handleDrop}
      style={{ opacity: disabled ? 0.5 : 1, pointerEvents: disabled ? "none" : "auto" }}
    >
      <div className="upload-zone__icon">
        {isDragging ? "\u{1F4E5}" : "\u{1F512}"}
      </div>
      <div className="upload-zone__title">
        {isDragging ? "Drop your code here" : "Upload code for private review"}
      </div>
      <div className="upload-zone__hint">
        Drop a file or click to browse. Your code stays inside the TEE — always.
      </div>
      <div className="upload-zone__formats">
        <span className="upload-zone__format">.zip</span>
        <span className="upload-zone__format">.tar.gz</span>
        <span className="upload-zone__format">.sol</span>
        <span className="upload-zone__format">.rs</span>
      </div>
      <input
        ref={inputRef}
        type="file"
        accept=".zip,.tar,.gz,.tgz,.sol,.rs"
        onChange={handleChange}
        style={{ display: "none" }}
      />
    </div>
  );
}
