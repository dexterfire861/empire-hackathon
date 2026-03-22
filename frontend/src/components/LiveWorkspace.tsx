import { getSubmittedInputItems, groupAuditEntries } from "../lib/results";
import type { AuditEntry, ConnectionMode, ScanInputs } from "../lib/types";
import { TextShimmer } from "./TextShimmer";
import { TraceRoundList } from "./TraceRoundList";

interface LiveWorkspaceProps {
  statusTitle: string;
  statusDetail: string;
  currentRound: number | null;
  currentToolLabel: string | null;
  connectionMode: ConnectionMode;
  auditEntries: AuditEntry[];
  highlightedAuditKey: string | null;
  isComplete: boolean;
  scanInputs: ScanInputs | null;
}

export function LiveWorkspace({
  statusTitle,
  statusDetail,
  currentRound,
  currentToolLabel,
  connectionMode,
  auditEntries,
  highlightedAuditKey,
  isComplete,
  scanInputs,
}: LiveWorkspaceProps) {
  const isLive = connectionMode === "live" && !isComplete;
  const rounds = groupAuditEntries(auditEntries);
  const submittedInputs = getSubmittedInputItems(scanInputs);

  return (
    <section className="workspace-panel workspace-panel--primary">
      <div className="workspace-panel__scroll">
        <div className="workspace-panel__intro">
          <div className="workspace-intro-copy">
            <p className="eyebrow">Live scan workspace</p>
            <h1 className="workspace-title">Track what the agent is testing, confirming, and discarding.</h1>
            {submittedInputs.length ? (
              <div className="workspace-inputs">
                <span className="workspace-inputs__label">Inputs provided</span>
                <div className="workspace-inputs__list">
                  {submittedInputs.map((item) => (
                    <div key={item.label} className="workspace-inputs__item">
                      <span className="workspace-inputs__item-label">{item.label}</span>
                      <span className="workspace-inputs__item-value">{item.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
          <div className="workspace-summary">
            <div className="workspace-summary__item">
              <span className="workspace-summary__label">Current state</span>
              {isLive ? (
                <TextShimmer as="span" className="workspace-summary__value">
                  {statusTitle}
                </TextShimmer>
              ) : (
                <span className="workspace-summary__value">{statusTitle}</span>
              )}
            </div>
            <div className="workspace-summary__item">
              <span className="workspace-summary__label">Active tool</span>
              {currentToolLabel && isLive ? (
                <TextShimmer as="span" className="workspace-summary__value">
                  {currentToolLabel}
                </TextShimmer>
              ) : (
                <span className="workspace-summary__value">{currentToolLabel ?? "Waiting for next tool call"}</span>
              )}
            </div>
          </div>
        </div>

        <div className="workspace-status-banner">
          <div>
            {!isComplete ? <div className="workspace-status-banner__title">{statusTitle}</div> : null}
            <div className="workspace-status-banner__detail">{statusDetail}</div>
          </div>
          <span className={`status-pill status-pill--${connectionMode}`}>
            {isComplete ? "Frozen" : connectionMode === "polling" ? "Polling backup" : "Live stream"}
          </span>
        </div>

        <div className="workspace-trace">
          <div className="workspace-trace__header">
            <div>
              <p className="workspace-trace__eyebrow">Decision trace</p>
              <h2 className="workspace-trace__title">Rounds, tool calls, and agent reasoning</h2>
              <p className="workspace-trace__copy">Open any round or step to inspect tool activity, reasoning, and new leads.</p>
            </div>
            <span className="workspace-trace__count">{rounds.length} {rounds.length === 1 ? "round" : "rounds"}</span>
          </div>

          <div className="workspace-trace__body">
            <TraceRoundList
              rounds={rounds}
              activeRound={currentRound}
              highlightedAuditKey={highlightedAuditKey}
              isLive={isLive}
            />
          </div>
        </div>
      </div>
    </section>
  );
}
