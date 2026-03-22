import { startTransition, type ReactNode, useDeferredValue, useEffect, useReducer, useState } from "react";

import { FindingsRail } from "./components/FindingsRail";
import { LiveWorkspace } from "./components/LiveWorkspace";
import { ReportLoading } from "./components/ReportLoading";
import { ReportSummary } from "./components/ReportSummary";
import { ResultsHeader } from "./components/ResultsHeader";
import { UtilityOverlay } from "./components/UtilityOverlay";
import {
  auditKey,
  buildEvidencePacket,
  confidenceBadgeClass,
  confidenceLabel,
  findingKey,
  findingSortKey,
  getActionSubtitle,
  getActiveRound,
  getEvidenceSources,
  getFindingById,
  getFindingDisplaySource,
  getLawSubtitle,
  getPrivacySubtitle,
  getSafetySubtitle,
  isCompletedReport,
  isHttpUrl,
  titleCase,
} from "./lib/results";
import type {
  ActionItem,
  ApplicableLaw,
  AuditEntry,
  ConclusionItem,
  ConnectionMode,
  Finding,
  PrivacyResource,
  ResultsReport,
  ScanInputs,
  SafetyBoundary,
  ScanEvent,
  ScanProgressPayload,
} from "./lib/types";

interface ResultsUiState {
  scanId: string;
  scanStatus: string;
  statusTitle: string;
  statusDetail: string;
  findings: Finding[];
  auditEntries: AuditEntry[];
  report: ResultsReport | null;
  error: string | null;
  connectionMode: ConnectionMode;
  currentRound: number | null;
  currentToolLabel: string | null;
  highlightedAuditKey: string | null;
  scanInputs: ScanInputs | null;
}

type ResultsAction =
  | { type: "init"; scanId: string }
  | { type: "hydrate"; payload: ScanProgressPayload }
  | { type: "set_connection_mode"; mode: ConnectionMode }
  | { type: "report_loaded"; report: ResultsReport }
  | { type: "event"; event: ScanEvent }
  | { type: "set_error"; message: string };

const initialState: ResultsUiState = {
  scanId: "",
  scanStatus: "loading",
  statusTitle: "Preparing results view...",
  statusDetail: "Connecting to scan state",
  findings: [],
  auditEntries: [],
  report: null,
  error: null,
  connectionMode: "connecting",
  currentRound: null,
  currentToolLabel: null,
  highlightedAuditKey: null,
  scanInputs: null,
};

function mergeFindings(current: Finding[], next: Finding[]) {
  const merged = [...current];
  const seen = new Set(current.map((finding) => findingKey(finding)));
  next.forEach((finding) => {
    const key = findingKey(finding);
    if (seen.has(key)) return;
    seen.add(key);
    merged.push(finding);
  });
  return merged;
}

function mergeAuditEntries(current: ResultsUiState["auditEntries"], next: ResultsUiState["auditEntries"]) {
  const merged = [...current];
  const seen = new Set(current.map((entry) => auditKey(entry)));
  next.forEach((entry) => {
    const key = auditKey(entry);
    if (seen.has(key)) return;
    seen.add(key);
    merged.push(entry);
  });
  return merged;
}

function loadCompletedReport(state: ResultsUiState, report: ResultsReport): ResultsUiState {
  return {
    ...state,
    scanId: report.scan_id ?? state.scanId,
    scanStatus: "complete",
    statusTitle: "Scan complete",
    statusDetail: "Final report ready",
    findings: mergeFindings(state.findings, report.findings ?? []),
    report,
    error: null,
    connectionMode: "complete",
    currentToolLabel: null,
    highlightedAuditKey: null,
    scanInputs: report.inputs ?? state.scanInputs,
  };
}

function resultsReducer(state: ResultsUiState, action: ResultsAction): ResultsUiState {
  switch (action.type) {
    case "init":
      return {
        ...state,
        scanId: action.scanId,
      };
    case "hydrate": {
      const findings = mergeFindings(state.findings, action.payload.findings ?? []);
      const auditEntries = mergeAuditEntries(state.auditEntries, action.payload.audit_trail ?? []);
      return {
        ...state,
        scanId: action.payload.scan_id ?? state.scanId,
        scanStatus: action.payload.status ?? state.scanStatus,
        statusTitle: `Status: ${action.payload.status ?? state.scanStatus ?? "running"}`,
        statusDetail: `Findings so far: ${action.payload.findings_count ?? findings.length}`,
        findings,
        auditEntries,
        currentRound: getActiveRound(auditEntries) ?? state.currentRound,
        scanInputs: action.payload.inputs ?? state.scanInputs,
      };
    }
    case "set_connection_mode":
      if (state.connectionMode === "complete") {
        return state;
      }
      return {
        ...state,
        connectionMode: action.mode,
      };
    case "report_loaded":
      return loadCompletedReport(state, action.report);
    case "event": {
      const { event } = action;
      switch (event.type) {
        case "status":
          return {
            ...state,
            scanStatus: event.status ?? state.scanStatus,
            statusTitle: `Status: ${event.status ?? state.scanStatus ?? "running"}`,
            statusDetail: `Findings so far: ${event.findings_count ?? state.findings.length}`,
            scanInputs: event.inputs ?? state.scanInputs,
          };
        case "scan_started":
          return {
            ...state,
            scanId: event.scan_id ?? state.scanId,
            scanStatus: "running",
            statusTitle: `Scan running (${event.sources_count ?? "multiple"} tools available)`,
            statusDetail: "Round 1 starting...",
            connectionMode: "live",
          };
        case "round_start":
          return {
            ...state,
            scanStatus: "running",
            statusTitle: `Round ${event.round} in progress...`,
            statusDetail: `Findings: ${state.findings.length}`,
            currentRound: event.round,
            currentToolLabel: null,
            highlightedAuditKey: null,
          };
        case "tool_call":
          return {
            ...state,
            statusTitle: `Calling ${event.tool ?? "tool"}...`,
            statusDetail: `Findings: ${state.findings.length}`,
            currentToolLabel: event.tool ?? null,
            connectionMode: state.connectionMode === "complete" ? "complete" : "live",
          };
        case "tool_result":
          return state;
        case "finding": {
          const findings = mergeFindings(state.findings, [event.finding]);
          return {
            ...state,
            findings,
            statusTitle: "New finding received",
            statusDetail: `Findings: ${findings.length}`,
          };
        }
        case "audit_step": {
          const auditEntries = mergeAuditEntries(state.auditEntries, [event.step]);
          return {
            ...state,
            auditEntries,
            currentRound: typeof event.step.round === "number" ? event.step.round : state.currentRound,
            highlightedAuditKey: auditKey(event.step),
          };
        }
        case "round_complete":
          return {
            ...state,
            statusTitle: `Round ${event.round} complete`,
            statusDetail: `Total findings: ${event.findings_count ?? state.findings.length}${event.new_leads !== undefined ? `, New leads: ${event.new_leads}` : ""}`,
            currentRound: event.round,
            currentToolLabel: null,
            highlightedAuditKey: null,
          };
        case "risk_assessment":
          return {
            ...state,
            statusTitle: "Risk assessment complete",
            statusDetail: `Score: ${event.score ?? 0}/100`,
            currentToolLabel: null,
            highlightedAuditKey: null,
          };
        case "scan_complete":
          return loadCompletedReport(state, event.report);
        case "error":
          return {
            ...state,
            statusTitle: `Error: ${event.message ?? "Scan failed unexpectedly"}`,
            statusDetail: "Refreshing latest report state...",
            error: event.message ?? "Scan failed unexpectedly",
            connectionMode: "error",
            currentToolLabel: null,
            highlightedAuditKey: null,
          };
        case "ping":
          return state;
      }
    }
    case "set_error":
      return {
        ...state,
        error: action.message,
        statusTitle: action.message,
        statusDetail: "Check the scan ID or refresh the page.",
        connectionMode: "error",
      };
  }
}

async function copyTextToClipboard(text: string) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall through to the textarea copy path.
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "absolute";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch {
    copied = false;
  }
  document.body.removeChild(textarea);
  return copied;
}

function downloadTextFile(filename: string, text: string, contentType = "text/plain;charset=utf-8") {
  const blob = new Blob([text], { type: contentType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

function CopyButton({
  text,
  label,
  successLabel,
}: {
  text: string;
  label: string;
  successLabel?: string;
}) {
  const [buttonLabel, setButtonLabel] = useState(label);

  return (
    <button
      className="action-chip"
      type="button"
      onClick={async () => {
        const copied = await copyTextToClipboard(text);
        setButtonLabel(copied ? successLabel ?? "Copied" : "Copy failed");
        window.setTimeout(() => setButtonLabel(label), 1800);
      }}
    >
      {buttonLabel}
    </button>
  );
}

function EvidenceDetails({
  item,
  findings,
}: {
  item: ConclusionItem;
  findings: Finding[];
}) {
  const ids = Array.isArray(item.supporting_finding_ids) ? item.supporting_finding_ids : [];

  if (!ids.length) {
    const sources = getEvidenceSources(item);
    if (!sources.length) return null;
    return (
      <details className="evidence-disclosure">
        <summary>Evidence used</summary>
        <div className="evidence-links evidence-links--stack">
          {sources.map((source) => (
            <span key={source} className="evidence-chip">
              {source}
            </span>
          ))}
        </div>
      </details>
    );
  }

  return (
    <details className="evidence-disclosure">
      <summary>Evidence used</summary>
      <div className="evidence-links">
        {ids.map((findingId) => {
          const finding = getFindingById(findings, findingId);
          const label = finding ? `[${findingId}] ${getFindingDisplaySource(finding)}` : `[${findingId}] Finding`;
          return (
            <div key={findingId} className="evidence-link-row">
              <a className="evidence-chip" href={`#finding-${findingId}`}>
                {label}
              </a>
              {finding?.source_url && isHttpUrl(finding.source_url) ? (
                <a
                  className="evidence-chip evidence-chip--external"
                  href={finding.source_url}
                  target="_blank"
                  rel="noreferrer"
                >
                  Source
                </a>
              ) : null}
            </div>
          );
        })}
      </div>
    </details>
  );
}

interface ConclusionMetaOptions {
  showBadges?: boolean;
  showReason?: boolean;
  showEvidence?: boolean;
  showOfficialSource?: boolean;
  showUncertainty?: boolean;
}

function ConclusionMeta({
  item,
  findings,
  options,
}: {
  item: ConclusionItem;
  findings: Finding[];
  options?: ConclusionMetaOptions;
}) {
  const {
    showBadges = true,
    showReason = false,
    showEvidence = false,
    showOfficialSource = false,
    showUncertainty = false,
  } = options ?? {};
  const badges = showBadges
    ? [
        item.confidence ? (
          <span key="confidence" className={`conclusion-badge ${confidenceBadgeClass(item.confidence)}`}>
            {confidenceLabel(item.confidence)}
          </span>
        ) : null,
        item.human_review_required ? (
          <span key="review" className="conclusion-badge is-review">
            Human review required
          </span>
        ) : null,
        item.rule_id ? (
          <span key="rule" className="conclusion-badge">
            {item.rule_id}
          </span>
        ) : null,
      ].filter(Boolean)
    : [];
  const hasVisibleMeta = Boolean(
    badges.length ||
      (showReason && item.reason) ||
      (showOfficialSource && item.official_url && isHttpUrl(item.official_url)) ||
      (showUncertainty && item.uncertainty_note) ||
      (showEvidence && (item.supporting_finding_ids?.length || getEvidenceSources(item).length)),
  );

  if (!hasVisibleMeta) {
    return null;
  }

  return (
    <div className="conclusion-meta">
      {badges.length ? <div className="conclusion-badges">{badges}</div> : null}
      {showReason && item.reason ? <p className="conclusion-copy conclusion-copy--compact">{item.reason}</p> : null}
      {showOfficialSource && item.official_url && isHttpUrl(item.official_url) ? (
        <p className="conclusion-copy">
          <a className="inline-link" href={item.official_url} target="_blank" rel="noreferrer">
            Open official source
          </a>
        </p>
      ) : null}
      {showUncertainty && item.uncertainty_note ? (
        <p className="conclusion-copy conclusion-copy--compact">{item.uncertainty_note}</p>
      ) : null}
      {showEvidence ? <EvidenceDetails item={item} findings={findings} /> : null}
    </div>
  );
}

function DecisionSummaryList({ items, findings }: { items: ConclusionItem[]; findings: Finding[] }) {
  if (!items.length) {
    return <div className="panel-empty panel-empty--inline">No decision summary was generated for this scan.</div>;
  }

  return (
    <div className="report-card-list">
      {items.map((item, index) => (
        <article key={`${item.title ?? "decision"}-${index}`} className="report-card">
          <h4>{item.title ?? "Decision"}</h4>
          {item.summary ? <p>{item.summary}</p> : null}
          <ConclusionMeta item={item} findings={findings} options={{ showEvidence: true }} />
        </article>
      ))}
    </div>
  );
}

function AttackPathList({
  items,
  findings,
}: {
  items: ResultsReport["kill_chains"];
  findings: Finding[];
}) {
  if (!items?.length) {
    return <div className="panel-empty panel-empty--inline">No attack paths were identified.</div>;
  }

  return (
    <div className="report-card-list">
      {items.map((item, index) => (
        <article key={`${item.name ?? "chain"}-${index}`} className="report-card">
          <h4>{item.name ?? "Attack path"}</h4>
          {item.steps?.length ? (
            <ol className="path-list">
              {item.steps.map((step) => (
                <li key={`${item.name}-${step}`}>{step}</li>
              ))}
            </ol>
          ) : null}
          {(item.likelihood || item.impact) ? (
            <p className="report-card__subcopy">
              Likelihood: {item.likelihood ?? "unknown"} · Impact: {item.impact ?? "unknown"}
            </p>
          ) : null}
          <ConclusionMeta item={item} findings={findings} />
        </article>
      ))}
    </div>
  );
}

function ActionList({ items, findings }: { items: ActionItem[]; findings: Finding[] }) {
  if (!items.length) {
    return <div className="panel-empty panel-empty--inline">No remediation actions were generated.</div>;
  }

  const sortedItems = [...items].sort((left, right) => (left.priority ?? 999) - (right.priority ?? 999));

  return (
    <div className="report-card-list">
      {sortedItems.map((item, index) => {
        const hasExplainability = Boolean(
          item.category ||
            item.effort ||
            item.reason ||
            item.supporting_finding_ids?.length ||
            item.supporting_sources?.length ||
            item.confidence ||
            item.rule_id ||
            item.human_review_required ||
            item.addresses_findings?.length,
        );

        return (
          <article key={`${item.action ?? "action"}-${index}`} className="report-card report-card--action">
            <div className="report-card__title-row">
              <h4>{item.action ?? "Action"}</h4>
              <span className="priority-badge">#{item.priority ?? "?"}</span>
            </div>

            {item.summary ? <p className="report-card__subcopy">{item.summary}</p> : null}

            {(item.links?.length || (item.official_url && isHttpUrl(item.official_url))) ? (
              <div className="action-chip-row">
                {(item.links ?? [])
                  .filter((link) => isHttpUrl(link.url))
                  .map((link) => (
                    <a
                      key={`${item.action}-${link.url}`}
                      className="action-chip action-chip--primary"
                      href={link.url}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {link.label ?? "Open resource"}
                    </a>
                  ))}
                {!item.links?.length && item.official_url && isHttpUrl(item.official_url) ? (
                  <a className="action-chip action-chip--primary" href={item.official_url} target="_blank" rel="noreferrer">
                    Open official source
                  </a>
                ) : null}
              </div>
            ) : null}

            {hasExplainability ? (
              <details className="action-disclosure">
                <summary>
                  <span>Explainability</span>
                  <span className="action-disclosure__icon">+</span>
                </summary>
                <div className="action-disclosure__body">
                  {item.category || item.effort ? (
                    <div className="conclusion-badges">
                      {item.category ? <span className="conclusion-badge">{titleCase(item.category)}</span> : null}
                      {item.effort ? <span className="conclusion-badge">{titleCase(item.effort)}</span> : null}
                    </div>
                  ) : null}

                  {item.addresses_findings?.length ? (
                    <div className="action-disclosure__list">
                      <div className="trace-step__detail-label">Addresses findings</div>
                      <ul className="report-bullet-list">
                        {item.addresses_findings.slice(0, 5).map((findingRef) => (
                          <li key={`${item.action}-${findingRef}`}>{findingRef}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}

                  <ConclusionMeta item={item} findings={findings} options={{ showReason: true, showEvidence: true }} />
                </div>
              </details>
            ) : null}
          </article>
        );
      })}
    </div>
  );
}

function GlossarySection({ report }: { report: ResultsReport }) {
  const actionCategories = Array.from(
    new Set((report.actions ?? []).map((item) => item.category).filter(Boolean) as string[]),
  );
  const efforts = Array.from(
    new Set((report.actions ?? []).map((item) => item.effort).filter(Boolean) as string[]),
  );

  const glossaryItems = [
    {
      term: "Priority numbers",
      definition: "Lower numbers indicate the remediation actions Leakipedia recommends doing first, with #1 being the most urgent.",
    },
    {
      term: "Exposure score bands",
      definition: "1-25 is low urgency, 26-50 signals meaningful exposure, 51-75 indicates high urgency, and 76-100 needs immediate attention.",
    },
    {
      term: "Kill chain",
      definition: "A step-by-step path showing how exposed data can be turned into misuse, fraud, or account takeover.",
    },
    {
      term: "Attack path",
      definition: "A concrete route from the exposed information to a harmful outcome.",
    },
    {
      term: "Data exposure",
      definition: "Score points added when sensitive identity or credential data is confirmed exposed.",
    },
    {
      term: "Attack surfaces",
      definition: "Score points added when the exposed data enables escalation, impersonation, fraud, or account access.",
    },
    {
      term: "Accessibility",
      definition: "Score points added when the exposed data is easy for other people to discover or search.",
    },
    {
      term: "Evidence used",
      definition: "The findings and sources used to support a recommendation, score factor, or conclusion.",
    },
    {
      term: "Complaint template",
      definition: "Copy-ready language you can adapt when filing a privacy complaint or removal request.",
    },
    ...actionCategories.map((category) => ({
      term: titleCase(category),
      definition:
        category === "account_security"
          ? "A remediation category focused on reducing account takeover, password reuse, or SIM-swap risk."
          : category === "monitoring"
            ? "A remediation category focused on alerts, freezes, watchlists, or post-exposure monitoring."
            : category === "privacy"
              ? "A remediation category focused on removals, public visibility reduction, and shrinking future collection."
              : category === "legal"
                ? "A remediation category focused on complaints, statutory rights, or regulator-facing requests."
                : "A remediation category used to group related next steps in the report.",
    })),
    ...efforts.map((effort) => ({
      term: titleCase(effort),
      definition:
        effort === "quick_win"
          ? "A relatively fast action that can reduce risk quickly."
          : effort === "moderate"
            ? "An action that usually takes some coordination, account access, or follow-through."
            : effort === "significant"
              ? "A larger action that may require repeated requests, cleanup, or more time."
              : "An effort label showing how much work the action may require.",
    })),
  ];

  return (
    <div className="reference-footer">
      <div className="reference-footer__intro">
        <p className="eyebrow">Terms and information</p>
        <h3>Definitions for the score labels, action priorities, and attack-path language used in the report.</h3>
      </div>
      <div className="reference-footer__grid">
        {glossaryItems.map((item) => (
          <article key={item.term} className="reference-footer__item">
            <h4>{item.term}</h4>
            <p>{item.definition}</p>
          </article>
        ))}
      </div>
    </div>
  );
}

function ExpandableReportSection({
  title,
  subtitle,
  countLabel,
  icon = "plus",
  children,
}: {
  title: string;
  subtitle: string;
  countLabel?: string;
  icon?: "plus" | "info";
  children: ReactNode;
}) {
  return (
    <details className={`report-disclosure ${icon === "info" ? "report-disclosure--info" : ""}`}>
      <summary className="report-disclosure__summary">
        <div className="report-disclosure__summary-copy">
          <span
            className={`report-disclosure__icon ${icon === "info" ? "report-disclosure__icon--info" : ""}`}
            aria-hidden="true"
          >
            {icon === "info" ? "i" : "+"}
          </span>
          <div>
            <p className="eyebrow">{title}</p>
            <h3>{subtitle}</h3>
          </div>
        </div>
        <div className="report-disclosure__summary-meta">
          {countLabel ? <span className="summary-pill">{countLabel}</span> : null}
          <span className="report-disclosure__toggle">Open</span>
        </div>
      </summary>
      <div className="report-disclosure__content">{children}</div>
    </details>
  );
}

function ApplicableLawsList({ items, findings }: { items: ApplicableLaw[]; findings: Finding[] }) {
  if (!items.length) {
    return <div className="panel-empty panel-empty--inline">No state-specific law guidance was generated for this scan.</div>;
  }

  return (
    <div className="report-card-list">
      {items.map((item, index) => (
        <article key={`${item.law ?? "law"}-${index}`} className="report-card">
          <h4>{item.law ?? "Law"}</h4>
          {getLawSubtitle(item) ? <p className="report-card__subcopy">{getLawSubtitle(item)}</p> : null}
          <ConclusionMeta item={item} findings={findings} options={{ showReason: true, showEvidence: true }} />

          {item.user_rights?.length ? (
            <ul className="report-bullet-list">
              {item.user_rights.map((right) => (
                <li key={`${item.law}-${right}`}>{right}</li>
              ))}
            </ul>
          ) : null}

          {(item.complaint_portal?.url || item.links?.length || (item.official_url && isHttpUrl(item.official_url))) ? (
            <div className="action-chip-row">
              {item.complaint_portal?.url && isHttpUrl(item.complaint_portal.url) ? (
                <a className="action-chip action-chip--primary" href={item.complaint_portal.url} target="_blank" rel="noreferrer">
                  Open {item.complaint_portal.label ?? "complaint portal"}
                </a>
              ) : null}
              {item.links
                ?.filter((link) => isHttpUrl(link.url))
                .map((link) => (
                  <a
                    key={`${item.law}-${link.url}`}
                    className="action-chip"
                    href={link.url}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {link.label ?? "Official resource"}
                  </a>
                ))}
              {!item.complaint_portal?.url && !item.links?.length && item.official_url && isHttpUrl(item.official_url) ? (
                <a className="action-chip" href={item.official_url} target="_blank" rel="noreferrer">
                  Open official source
                </a>
              ) : null}
            </div>
          ) : null}
        </article>
      ))}
    </div>
  );
}

function ComplaintTemplateList({ items }: { items: ApplicableLaw[] }) {
  const templates = items.filter((item) => item.complaint_template);

  if (!templates.length) {
    return <div className="panel-empty panel-empty--inline">No copy-ready complaint language was generated for this scan.</div>;
  }

  return (
    <div className="report-card-list">
      {templates.map((item, index) => (
        <article key={`${item.law ?? "template"}-${index}`} className="report-card report-card--template">
          <div className="report-card__title-row">
            <h4>{item.law ?? "Complaint template"}</h4>
            {item.jurisdiction ? <span className="summary-pill">{titleCase(item.jurisdiction)}</span> : null}
          </div>
          <p className="report-card__subcopy">Copy-ready complaint language kept separate from the law guidance.</p>
          <div className="code-block-wrapper">
            <pre>{item.complaint_template}</pre>
            <div className="action-chip-row action-chip-row--flush">
              <CopyButton text={item.complaint_template ?? ""} label="Copy complaint template" />
              {item.complaint_portal?.url && isHttpUrl(item.complaint_portal.url) ? (
                <a className="action-chip action-chip--primary" href={item.complaint_portal.url} target="_blank" rel="noreferrer">
                  Open {item.complaint_portal.label ?? "complaint portal"}
                </a>
              ) : null}
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

function PrivacyResourceList({ items, findings }: { items: PrivacyResource[]; findings: Finding[] }) {
  if (!items.length) {
    return <div className="panel-empty panel-empty--inline">No privacy guidance was generated for this scan.</div>;
  }

  return (
    <div className="report-card-grid report-card-grid--privacy">
      {items.map((item, index) => (
        <article key={`${item.title ?? "resource"}-${index}`} className="report-card report-card--compact">
          <div className="report-card__title-row">
            <h4>{item.title ?? "Resource"}</h4>
            {item.recommended ? <span className="priority-badge priority-badge--recommended">Recommended</span> : null}
          </div>
          {getPrivacySubtitle(item) ? <p className="report-card__subcopy">{getPrivacySubtitle(item)}</p> : null}
          {item.blurb ? <p>{item.blurb}</p> : null}
          <ConclusionMeta item={item} findings={findings} options={{ showBadges: false }} />
          {item.links?.length ? (
            <div className="action-chip-row">
              {item.links
                .filter((link) => isHttpUrl(link.url))
                .map((link) => (
                  <a
                    key={`${item.title}-${link.url}`}
                    className="action-chip action-chip--primary"
                    href={link.url}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {link.label ?? "Open resource"}
                  </a>
                ))}
            </div>
          ) : null}
        </article>
      ))}
    </div>
  );
}

function SafetyBoundariesList({ items }: { items: SafetyBoundary[] }) {
  if (!items.length) {
    return <div className="panel-empty panel-empty--inline">No safety boundaries were attached to this report.</div>;
  }

  return (
    <div className="report-card-list">
      {items.map((item, index) => (
        <article key={`${getSafetySubtitle(item)}-${index}`} className="report-card">
          <h4>{item.title ?? "Boundary"}</h4>
          {item.will_do ? <p><strong>Leakipedia will:</strong> {item.will_do}</p> : null}
          {item.will_not_do ? <p><strong>Leakipedia will not:</strong> {item.will_not_do}</p> : null}
          {item.details ? <p className="report-card__subcopy">{item.details}</p> : null}
        </article>
      ))}
    </div>
  );
}

function DeveloperDataSection({
  report,
  scanId,
}: {
  report: ResultsReport;
  scanId: string;
}) {
  const reportJson = JSON.stringify(report, null, 2);
  const evidencePacket = buildEvidencePacket(report);

  return (
    <div className="developer-section">
      <p className="developer-section__copy">
        Download the evidence packet first. Raw JSON stays available for debugging, exports, and future automation.
      </p>
      <div className="action-chip-row">
        <button
          className="action-chip action-chip--primary"
          type="button"
          onClick={() =>
            downloadTextFile(
              `${scanId ? `leakipedia-evidence-packet-${scanId}` : "leakipedia-evidence-packet"}.md`,
              evidencePacket,
              "text/markdown;charset=utf-8",
            )
          }
        >
          Download evidence packet
        </button>
        <CopyButton text={reportJson} label="Copy JSON" />
        <button
          className="action-chip"
          type="button"
          onClick={() =>
            downloadTextFile(
              `${scanId ? `leakipedia-report-${scanId}` : "leakipedia-report"}.json`,
              reportJson,
              "application/json",
            )
          }
        >
          Download JSON
        </button>
      </div>
      <details className="code-disclosure">
        <summary>Expand raw report JSON</summary>
        <pre>{reportJson}</pre>
      </details>
    </div>
  );
}

function ReportSurface({
  title,
  subtitle,
  wide = false,
  scrollable = false,
  children,
}: {
  title: string;
  subtitle: string;
  wide?: boolean;
  scrollable?: boolean;
  children: ReactNode;
}) {
  return (
    <section className={`report-surface ${wide ? "report-surface--wide" : ""} ${scrollable ? "report-surface--scrollable" : ""}`}>
      <div className="report-surface__header">
        <div>
          <p className="eyebrow">{title}</p>
          <h3>{subtitle}</h3>
        </div>
      </div>
      <div className={`report-surface__body ${scrollable ? "report-surface__body--scrollable" : ""}`}>{children}</div>
    </section>
  );
}

export function ResultsApp() {
  const [state, dispatch] = useReducer(resultsReducer, initialState);
  const [activeOverlay, setActiveOverlay] = useState<"safety" | "developer" | null>(null);
  const deferredFindings = useDeferredValue(state.findings);
  const sortedFindings = [...deferredFindings].sort((left, right) => findingSortKey(left) - findingSortKey(right));

  useEffect(() => {
    const scanId = new URLSearchParams(window.location.search).get("scan_id");
    if (!scanId) {
      startTransition(() => {
        dispatch({
          type: "set_error",
          message: "Missing scan ID. Start a new scan from the home page.",
        });
      });
      return;
    }

    dispatch({ type: "init", scanId });

    let cancelled = false;
    let pollingStarted = false;
    let completed = false;
    let websocket: WebSocket | null = null;
    let pollTimer: number | undefined;

    async function fetchScan() {
      const response = await fetch(`/scan/${scanId}`);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail ?? "Unable to load scan");
      }
      return data;
    }

    async function fetchLatestReport() {
      try {
        const data = await fetchScan();
        if (isCompletedReport(data)) {
          completed = true;
          startTransition(() => {
            dispatch({ type: "report_loaded", report: data });
          });
        }
      } catch {
        // Ignore refresh failures during error recovery.
      }
    }

    async function pollResults() {
      if (pollingStarted || cancelled || completed) return;
      pollingStarted = true;

      startTransition(() => {
        dispatch({ type: "set_connection_mode", mode: "polling" });
      });

      for (let attempt = 0; attempt < 60; attempt += 1) {
        await new Promise<void>((resolve) => {
          pollTimer = window.setTimeout(() => resolve(), 3000);
        });

        if (cancelled || completed) return;

        try {
          const data = await fetchScan();
          if (isCompletedReport(data)) {
            completed = true;
            startTransition(() => {
              dispatch({ type: "report_loaded", report: data });
            });
            return;
          }

          startTransition(() => {
            dispatch({ type: "hydrate", payload: data });
          });
        } catch {
          // Keep polling.
        }
      }

      if (!cancelled && !completed) {
        startTransition(() => {
          dispatch({
            type: "set_error",
            message: "Timed out waiting for scan completion. Refresh the page to try again.",
          });
        });
      }
    }

    function connectWebSocket() {
      if (cancelled || completed) return;

      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      websocket = new WebSocket(`${protocol}://${window.location.host}/scan/${scanId}/stream`);

      websocket.onopen = () => {
        if (cancelled || completed) return;
        startTransition(() => {
          dispatch({ type: "set_connection_mode", mode: "live" });
        });
      };

      websocket.onmessage = (message) => {
        if (cancelled) return;

        const event = JSON.parse(message.data) as ScanEvent;
        if (event.type === "ping") return;
        if (event.type === "scan_complete") {
          completed = true;
        }

        startTransition(() => {
          dispatch({ type: "event", event });
        });

        if (event.type === "error") {
          void fetchLatestReport();
        }
      };

      websocket.onerror = () => {
        if (!cancelled && !completed) {
          void pollResults();
        }
      };

      websocket.onclose = () => {
        if (!cancelled && !completed) {
          void pollResults();
        }
      };
    }

    async function initialize() {
      try {
        const data = await fetchScan();
        if (cancelled) return;

        if (isCompletedReport(data)) {
          completed = true;
          startTransition(() => {
            dispatch({ type: "report_loaded", report: data });
          });
          return;
        }

        startTransition(() => {
          dispatch({ type: "hydrate", payload: data });
        });
        connectWebSocket();
      } catch (error) {
        if (cancelled) return;
        startTransition(() => {
          dispatch({
            type: "set_error",
            message: error instanceof Error ? error.message : "Unable to load scan results",
          });
        });
      }
    }

    void initialize();

    return () => {
      cancelled = true;
      if (pollTimer) window.clearTimeout(pollTimer);
      if (websocket && websocket.readyState < WebSocket.CLOSING) {
        websocket.close();
      }
    };
  }, []);

  const report = state.report;
  const complaintTemplateCount = report?.applicable_laws?.filter((item) => item.complaint_template).length ?? 0;

  return (
    <div className="results-shell">
      <div className="results-shell__backdrop" />
      <div className="results-shell__grid" />

      <ResultsHeader
        scanId={state.scanId || "—"}
        statusTitle={state.statusTitle}
        connectionMode={state.connectionMode}
        isComplete={Boolean(report)}
        utilityActions={
          report
            ? [
                {
                  label: "Safety",
                  count: report.safety_boundaries?.length ?? 0,
                  onClick: () => setActiveOverlay("safety"),
                },
                {
                  label: "Developer Data",
                  onClick: () => setActiveOverlay("developer"),
                },
              ]
            : []
        }
      />

      <main className="results-main">
        {state.error ? <div className="error-banner">{state.error}</div> : null}

        <div className="results-main__layout">
          <LiveWorkspace
            statusTitle={state.statusTitle}
            statusDetail={state.statusDetail}
            currentRound={state.currentRound}
            currentToolLabel={state.currentToolLabel}
            connectionMode={state.connectionMode}
            auditEntries={state.auditEntries}
            highlightedAuditKey={state.highlightedAuditKey}
            isComplete={Boolean(report)}
            scanInputs={state.scanInputs ?? report?.inputs ?? null}
          />

          <FindingsRail findings={sortedFindings} />
        </div>

        {report ? (
          <>
            <ReportSummary report={report} />
            <div className="report-grid">
            <ReportSurface
              title="Remediation actions"
              subtitle={`${report.actions?.length ?? 0} prioritized next step${(report.actions?.length ?? 0) === 1 ? "" : "s"} ready to act on`}
              wide
              scrollable
              >
                <ActionList items={report.actions ?? []} findings={sortedFindings} />
              </ReportSurface>

              <ReportSurface
                title="Applicable laws"
                subtitle={`${report.applicable_laws?.length ?? 0} legal resource${(report.applicable_laws?.length ?? 0) === 1 ? "" : "s"} focused on rights and filing paths`}
                scrollable
              >
                <ApplicableLawsList items={report.applicable_laws ?? []} findings={sortedFindings} />
              </ReportSurface>

              <ReportSurface
                title="Complaint templates"
                subtitle={`${complaintTemplateCount} copy-ready template${complaintTemplateCount === 1 ? "" : "s"} separated from the law guidance`}
                scrollable
              >
                <ComplaintTemplateList items={report.applicable_laws ?? []} />
              </ReportSurface>

              <ReportSurface
                title="Privacy next steps"
                subtitle={`${report.privacy_resources?.length ?? 0} broader privacy move${(report.privacy_resources?.length ?? 0) === 1 ? "" : "s"} to reduce future exposure`}
                wide
              >
                <PrivacyResourceList items={report.privacy_resources ?? []} findings={sortedFindings} />
              </ReportSurface>
            </div>
            <div className="report-disclosure-stack">
              <ExpandableReportSection
                title="Decision summary"
                subtitle="Higher-level interpretation (LLM reasoning layer)"
                countLabel={`${report.decision_summary?.length ?? 0} conclusion${(report.decision_summary?.length ?? 0) === 1 ? "" : "s"}`}
              >
                <DecisionSummaryList items={report.decision_summary ?? []} findings={sortedFindings} />
              </ExpandableReportSection>

              <ExpandableReportSection
                title="Kill chains"
                subtitle="Escalation paths and attack scenarios"
                countLabel={`${report.kill_chains?.length ?? 0} path${(report.kill_chains?.length ?? 0) === 1 ? "" : "s"}`}
              >
                <AttackPathList items={report.kill_chains ?? []} findings={sortedFindings} />
              </ExpandableReportSection>

              <ExpandableReportSection
                title="Terms and information"
                subtitle="Open the definitions for priorities, score bands, kill-chain labels, and report terminology."
                icon="info"
              >
                <GlossarySection report={report} />
              </ExpandableReportSection>
            </div>
          </>
        ) : (
          <ReportLoading
            statusTitle={state.statusTitle}
            statusDetail={state.statusDetail}
            connectionMode={state.connectionMode}
            currentRound={state.currentRound}
            findingsCount={state.findings.length}
            auditEntryCount={state.auditEntries.length}
          />
        )}
      </main>

      {report ? (
        <>
          <UtilityOverlay
            open={activeOverlay === "safety"}
            title="Safety and boundaries"
            subtitle="Guardrails and explicit limits stay accessible from the header without taking report space."
            onClose={() => setActiveOverlay(null)}
          >
            <SafetyBoundariesList items={report.safety_boundaries ?? []} />
          </UtilityOverlay>

          <UtilityOverlay
            open={activeOverlay === "developer"}
            title="Raw developer data"
            subtitle="Evidence packet, exports, and raw report JSON for debugging or follow-up automation."
            onClose={() => setActiveOverlay(null)}
          >
            <DeveloperDataSection report={report} scanId={state.scanId} />
          </UtilityOverlay>
        </>
      ) : null}
    </div>
  );
}
