import { getReportLoadProgress } from "../lib/results";
import type { ConnectionMode } from "../lib/types";
import { Progress } from "./ui/progress";

interface ReportLoadingProps {
  statusTitle: string;
  statusDetail: string;
  connectionMode: ConnectionMode;
  currentRound: number | null;
  findingsCount: number;
  auditEntryCount: number;
}

export function ReportLoading({
  statusTitle,
  statusDetail,
  connectionMode,
  currentRound,
  findingsCount,
  auditEntryCount,
}: ReportLoadingProps) {
  const progress = getReportLoadProgress({
    connectionMode,
    currentRound,
    findingsCount,
    auditEntryCount,
  });

  const loadingSteps = [
    {
      label: "Collecting findings",
      state: findingsCount > 0 ? "active" : "pending",
    },
    {
      label: "Scoring exposure",
      state: auditEntryCount > 0 ? "active" : "pending",
    },
    {
      label: "Building report sections",
      state: connectionMode === "live" || connectionMode === "polling" ? "active" : "pending",
    },
  ] as const;

  return (
    <section className="report-loading">
      <div className="report-loading__content">
        <div>
          <p className="eyebrow">Report loading</p>
          <h2>Building the final score, response plan, and legal guidance.</h2>
          <p>{statusTitle}. {statusDetail}.</p>
        </div>

        <Progress
          value={progress}
          showValue
          label="Report assembly"
          className="report-loading__progress"
        />

        <div className="report-loading__steps">
          {loadingSteps.map((step) => (
            <div key={step.label} className={`report-loading__step report-loading__step--${step.state}`}>
              <span className="report-loading__step-dot" />
              <span>{step.label}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
