import { useEffect, useState } from "react";

import { motion } from "framer-motion";

import {
  formatEntryType,
  hasTraceDetails,
  titleCase,
} from "../lib/results";
import type { AuditEntry } from "../lib/types";
import { TextShimmer } from "./TextShimmer";

interface TraceStepProps {
  entry: AuditEntry;
  highlighted: boolean;
  isLive: boolean;
}

function renderLead(entry: AuditEntry) {
  if (!entry.lead) return null;
  const parts = [];
  if (entry.lead.type || entry.lead.value) {
    parts.push(`${entry.lead.type ?? "lead"}: ${entry.lead.value ?? ""}`);
  }
  if (entry.lead.confidence) {
    parts.push(`confidence ${entry.lead.confidence}`);
  }
  if (entry.lead.reason) {
    parts.push(entry.lead.reason);
  }
  if (!parts.length) return null;
  return <div className="trace-step__detail-block">Lead: {parts.join(" · ")}</div>;
}

function renderList(label: string, items: string[]) {
  if (!items.length) return null;
  return (
    <div className="trace-step__detail-group">
      <div className="trace-step__detail-label">{label}</div>
      <ul className="trace-step__detail-list">
        {items.map((item) => (
          <li key={`${label}-${item}`}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

export function TraceStep({ entry, highlighted, isLive }: TraceStepProps) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const entryType = formatEntryType(entry.entry_type);
  const shouldShimmer = highlighted && isLive;
  const hasDetails = hasTraceDetails(entry);

  useEffect(() => {
    if (highlighted && hasDetails) {
      setDetailsOpen(true);
    }
  }, [highlighted, hasDetails]);

  return (
    <motion.article
      className={`trace-step ${highlighted ? "is-highlighted" : ""}`}
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
    >
      {hasDetails ? (
        <button
          className={`trace-step__surface trace-step__surface--interactive ${detailsOpen ? "is-open" : ""}`}
          type="button"
          onClick={() => setDetailsOpen((current) => !current)}
        >
          <div className="trace-step__header">
            <span className="trace-step__index">{entry.step ?? "•"}</span>
            {entryType ? <span className="trace-step__type">{entryType}</span> : null}
            {shouldShimmer ? (
              <TextShimmer as="span" className="trace-step__action">
                {entry.action ?? "Tracing step"}
              </TextShimmer>
            ) : (
              <span className="trace-step__action">{entry.action ?? "Tracing step"}</span>
            )}
            <span className="trace-step__toggle">{detailsOpen ? "Hide details" : "Open details"}</span>
          </div>

          {entry.result_summary ? <p className="trace-step__summary">{entry.result_summary}</p> : null}
          <div className="trace-step__hint">
            {detailsOpen
              ? "Tool inputs, reasoning, connections, and new leads are expanded below."
              : "Click to inspect tool inputs, reasoning, connections, and new leads."}
          </div>
        </button>
      ) : (
        <div className="trace-step__surface">
          <div className="trace-step__header">
            <span className="trace-step__index">{entry.step ?? "•"}</span>
            {entryType ? <span className="trace-step__type">{entryType}</span> : null}
            {shouldShimmer ? (
              <TextShimmer as="span" className="trace-step__action">
                {entry.action ?? "Tracing step"}
              </TextShimmer>
            ) : (
              <span className="trace-step__action">{entry.action ?? "Tracing step"}</span>
            )}
          </div>

          {entry.result_summary ? <p className="trace-step__summary">{entry.result_summary}</p> : null}
        </div>
      )}

      <motion.div
        className="trace-step__details"
        initial={false}
        animate={{ height: detailsOpen ? "auto" : 0, opacity: detailsOpen ? 1 : 0 }}
      >
        <div className="trace-step__details-inner">
          {renderLead(entry)}
          {renderList("Hypotheses", entry.hypotheses ?? [])}
          {renderList(
            "Lead decisions",
            (entry.lead_decisions ?? []).map((decision) => {
              const supports = Array.isArray(decision.supports) && decision.supports.length
                ? ` [${decision.supports.join(", ")}]`
                : "";
              return `${decision.type ?? "lead"}:${decision.value ?? ""} → ${decision.decision ?? "review"} — ${decision.why ?? "no reason"}${supports}`;
            }),
          )}
          {renderList(
            "Planned tools",
            (entry.planned_tools ?? []).map(
              (tool) => `${tool.tool ?? "tool"} on ${tool.input ?? "input"} — ${tool.purpose ?? "planned search"}`,
            ),
          )}
          {renderList("Supports", entry.supports ?? [])}
          {renderList("New leads", entry.new_leads ?? [])}
          {entry.connection ? (
            <div className="trace-step__detail-block">
              Connection: {entry.connection.from ?? "unknown"} → {entry.connection.to ?? "unknown"} ·{" "}
              {entry.connection.why ?? ""}
            </div>
          ) : null}
          {renderList(
            "Connections",
            (entry.connections ?? []).map(
              (connection) => `${connection.from ?? "unknown"} → ${connection.to ?? "unknown"} — ${connection.why ?? ""}`,
            ),
          )}
          {entry.confidence_change ? (
            <div className="trace-step__detail-block">
              Confidence: {titleCase(entry.confidence_change.from)} → {titleCase(entry.confidence_change.to)}
            </div>
          ) : null}
          {entry.reasoning ? <div className="trace-step__reasoning">{entry.reasoning}</div> : null}
        </div>
      </motion.div>
    </motion.article>
  );
}
