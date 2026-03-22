import { useState } from "react";

import { motion } from "framer-motion";

import {
  getFindingDetails,
  getFindingDisplaySource,
  getFindingExposedFields,
  getFindingHighlightTokens,
  getFindingSummary,
  getOptOutUrl,
  getSeverityTone,
  isHttpUrl,
  isSevereFinding,
  titleCase,
} from "../lib/results";
import type { Finding } from "../lib/types";

interface FindingsRailProps {
  findings: Finding[];
}

function FindingRow({ finding }: { finding: Finding }) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const data = finding.data ?? {};
  const source = getFindingDisplaySource(finding);
  const summary = getFindingSummary(finding);
  const details = getFindingDetails(finding);
  const exposedFields = getFindingExposedFields(finding);
  const highlightTokens = getFindingHighlightTokens(finding);
  const optOutUrl = getOptOutUrl(finding);
  const severe = isSevereFinding(finding);
  const severityTone = getSeverityTone(finding.severity);

  return (
    <motion.article
      id={finding.finding_id ? `finding-${finding.finding_id}` : undefined}
      className={`finding-row ${severe ? "is-severe" : ""}`}
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18 }}
    >
      <div className="finding-row__topline">
        <span className="finding-row__source">{source}</span>
        <span className={`severity-pill ${severityTone}`}>{String(finding.severity ?? "info").toUpperCase()}</span>
      </div>
      <div className="finding-row__type">{titleCase(finding.finding_type ?? "exposure signal")}</div>
      <p className="finding-row__summary">{summary}</p>

      {exposedFields.length ? (
        <div className="finding-row__exposed">
          <span className="finding-row__exposed-label">Exposed</span>
          <div className="finding-row__exposed-list">
            {exposedFields.map((field) => (
              <span key={`${finding.finding_id ?? source}-${field}`} className="finding-field-chip">
                {field}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {highlightTokens.length ? (
        <div className="finding-row__tokens">
          {highlightTokens.map((token) => (
            <span key={`${token.kind}-${token.value}`} className={`token-chip token-chip--${token.kind}`}>
              <span className="token-chip__label">{token.label}</span>
              <span>{token.value}</span>
            </span>
          ))}
        </div>
      ) : null}

      <div className="finding-row__actions">
        {isHttpUrl(finding.source_url) ? (
          <a className="action-chip" href={finding.source_url} target="_blank" rel="noreferrer">
            Source
          </a>
        ) : null}
        {optOutUrl ? (
          <a className="action-chip action-chip--primary" href={optOutUrl} target="_blank" rel="noreferrer">
            Opt Out
          </a>
        ) : null}
        {(details.length > 0 || Object.keys(data).length > 0) ? (
          <button className="action-chip" type="button" onClick={() => setDetailsOpen((current) => !current)}>
            {detailsOpen ? "Hide details" : "Show details"}
          </button>
        ) : null}
      </div>

      {detailsOpen ? (
        <div className="finding-row__details">
          <div className="finding-row__meta">
            {finding.finding_id ? <span>ID {finding.finding_id}</span> : null}
            <span>{titleCase(finding.confidence ?? "unknown")} confidence</span>
            {finding.leads_to && finding.leads_to.length ? (
              <span>Leads to: {finding.leads_to.slice(0, 3).join(", ")}</span>
            ) : null}
          </div>

          {details.length ? (
            <div className="finding-detail-grid">
              {details.map((detail) => (
                <div key={`${finding.finding_id ?? source}-${detail.label}`} className="finding-detail-grid__row">
                  <span className="finding-detail-grid__label">{detail.label}</span>
                  <span className="finding-detail-grid__value">{detail.value}</span>
                </div>
              ))}
            </div>
          ) : null}

          {Object.keys(data).length ? (
            <details className="code-disclosure">
              <summary>Source payload</summary>
              <pre>{JSON.stringify(data, null, 2)}</pre>
            </details>
          ) : null}
        </div>
      ) : null}
    </motion.article>
  );
}

export function FindingsRail({ findings }: FindingsRailProps) {
  return (
    <aside className="workspace-panel workspace-panel--secondary">
      <div className="workspace-panel__rail-header">
        <div>
          <p className="eyebrow">Prioritized findings</p>
          <h2 className="rail-title">Strongest exposure signals in a compact live queue.</h2>
        </div>
        <span className="rail-count">{findings.length}</span>
      </div>

      {findings.length ? (
        <div className="finding-list finding-list--scrollable">
          {findings.map((finding) => (
            <FindingRow key={JSON.stringify([finding.finding_id, finding.source, finding.source_url])} finding={finding} />
          ))}
        </div>
      ) : (
        <div className="panel-empty">No findings yet. New exposures will appear here as the scan progresses.</div>
      )}
    </aside>
  );
}
