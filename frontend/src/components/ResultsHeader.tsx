import { TextShimmer } from "./TextShimmer";
import type { ConnectionMode } from "../lib/types";

interface HeaderUtilityAction {
  label: string;
  onClick: () => void;
  count?: number;
  disabled?: boolean;
}

interface ResultsHeaderProps {
  scanId: string;
  statusTitle: string;
  connectionMode: ConnectionMode;
  isComplete: boolean;
  utilityActions?: HeaderUtilityAction[];
}

function connectionLabel(connectionMode: ConnectionMode) {
  switch (connectionMode) {
    case "live":
      return "Live";
    case "polling":
      return "Polling";
    case "complete":
      return "Complete";
    case "error":
      return "Error";
    default:
      return "Loading";
  }
}

export function ResultsHeader({
  scanId,
  statusTitle,
  connectionMode,
  isComplete,
  utilityActions = [],
}: ResultsHeaderProps) {
  const shouldShimmer = connectionMode === "live" && !isComplete;

  return (
    <header className="results-header">
      <div className="results-header__brand-row">
        <a className="results-header__brand" href="/">
          <img src="/static/logo-long.png" alt="Leakipedia" />
        </a>
        <div className="results-header__status">
          <span className={`status-pill status-pill--${connectionMode}`}>{connectionLabel(connectionMode)}</span>
          {shouldShimmer ? (
            <TextShimmer as="span" className="results-header__status-text">
              {statusTitle}
            </TextShimmer>
          ) : (
            <span className="results-header__status-text">{statusTitle}</span>
          )}
          <span className="results-header__scan-id">Scan {scanId}</span>
        </div>
      </div>
      <div className="results-header__actions">
        {utilityActions.map((action) => (
          <button
            key={action.label}
            className="results-header__utility"
            type="button"
            onClick={action.onClick}
            disabled={action.disabled}
          >
            <span>{action.label}</span>
            {typeof action.count === "number" ? (
              <span className="results-header__utility-count">{action.count}</span>
            ) : null}
          </button>
        ))}
        <a className="results-header__link" href="/">
          New Scan
        </a>
        <a className="results-header__link" href="/extension/install">
          Install Leak Prevent
        </a>
      </div>
    </header>
  );
}
