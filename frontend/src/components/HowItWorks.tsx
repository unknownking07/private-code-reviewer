export function HowItWorks() {
  return (
    <section className="how">
      <h2 className="how__title">How your code stays confidential</h2>
      <ol className="how__steps">
        <li>
          <span className="how__step">1</span>
          <div>
            <strong>Uploaded into an EigenCompute TEE.</strong> Your code
            enters an Intel TDX enclave over TLS. Memory and disk are
            hardware-encrypted; the host OS cannot read them.
          </div>
        </li>
        <li>
          <span className="how__step">2</span>
          <div>
            <strong>Static analysis runs entirely in the enclave.</strong>{" "}
            Language-specific rules scan the raw source for known backdoor
            and rug-pull patterns. Zero external calls in this phase.
          </div>
        </li>
        <li>
          <span className="how__step">3</span>
          <div>
            <strong>Anonymizer strips identity before anything leaves.</strong>{" "}
            Addresses, hex secrets, string literals, URLs, emails, large
            numbers, file paths, and comments are replaced with placeholders.
            Your <em>raw</em> code never leaves the TEE.
          </div>
        </li>
        <li>
          <span className="how__step">4</span>
          <div>
            <strong>Claude Opus reviews the anonymized abstractions.</strong>{" "}
            Only the structural skeleton of your code — function and contract
            names, control flow, keywords — reaches Anthropic's API. No
            addresses, secrets, or literals are exposed.
          </div>
        </li>
        <li>
          <span className="how__step">5</span>
          <div>
            <strong>Findings are re-mapped inside the TEE.</strong> Claude's
            responses come back referencing the placeholders; the enclave
            swaps them for your real file paths and code snippets before
            showing you the report. Uploaded files are then wiped from disk.
          </div>
        </li>
      </ol>
      <p className="how__footnote">
        The report is signed with a SHA-256 hash of your code and the report
        contents, so you can verify nothing was tampered with after the fact.
      </p>
    </section>
  );
}
