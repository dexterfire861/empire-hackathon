import { getCompletionSummary, getTopFactors, scoreTone, titleCase } from "../lib/results";
import type { ResultsReport } from "../lib/types";
import { GlowingEffect } from "./ui/glowing-effect";

interface ReportSummaryProps {
  report: ResultsReport;
}

export function ReportSummary({ report }: ReportSummaryProps) {
  const score = report.exposure_score ?? 0;
  const riskLabel = titleCase(report.score_breakdown?.label ?? "unknown");
  const summaryPills = getCompletionSummary(report);
  const topFactors = getTopFactors(report);

  return (
    <section className="report-summary">
      <GlowingEffect blur={16} spread={54} glow proximity={126} inactiveZone={0.12} borderWidth={3} />
      <div className="report-summary__score">
        <p className="eyebrow">Exposure summary</p>
        <div className={`report-summary__score-value ${scoreTone(score, report.score_breakdown?.label)}`}>
          {score}
        </div>
        <div className="report-summary__score-caption">{riskLabel} exposure risk</div>
      </div>

      <div className="report-summary__body">
        <div className="report-summary__pills">
          {summaryPills.map((pill) => (
            <span key={pill} className="summary-pill">
              {pill}
            </span>
          ))}
        </div>

        <div className="report-summary__factors">
          {topFactors.length ? (
            topFactors.map((factor) => (
              <article key={`${factor.label}-${factor.points}`} className="factor-row">
                <span className="factor-row__points">+{factor.points ?? 0}</span>
                <div>
                  <div className="factor-row__label">{factor.label ?? "Triggered factor"}</div>
                  {factor.detail ? <div className="factor-row__detail">{factor.detail}</div> : null}
                </div>
              </article>
            ))
          ) : (
            <div className="panel-empty panel-empty--inline">No score factors were triggered.</div>
          )}
        </div>
      </div>
    </section>
  );
}
