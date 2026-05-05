export type AttestedFieldRow = {
  key: string;
  signedHash: string;
  localHash: string;
  source: string;
  plaintext: string;
  verified: boolean | null;
  value?: string;
};

export function AttestedFieldCards({
  rows,
  plaintextTitle,
}: {
  rows: readonly AttestedFieldRow[];
  plaintextTitle: string;
}) {
  return (
    <>
      {rows.map((row) => (
        <div className="field-card" key={row.key}>
          <div className="field-card-header">
            <strong>
              {row.key}{" "}
              <span
                className={`match-pill match-${String(row.verified)}`}
                title="local sha256(plaintext) vs signed hash"
              >
                {row.verified === true
                  ? "match"
                  : row.verified === false
                    ? "mismatch"
                    : "unchecked"}
              </span>
            </strong>
            <code title="signed sha256">{row.signedHash}</code>
          </div>
          {row.localHash ? (
            <p className="field-value">
              <span>local sha256</span>
              <code>{row.localHash}</code>
            </p>
          ) : null}
          <p className="field-value">
            <span>source</span>
            <code>{row.source}</code>
          </p>
          {row.value ? (
            <p className="field-value">
              <span>value</span>
              <code>{row.value}</code>
            </p>
          ) : null}
          <pre title={plaintextTitle}>{row.plaintext}</pre>
        </div>
      ))}
    </>
  );
}
