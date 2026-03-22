import {
  getCompletionSummary,
  getScoreCountSummary,
  getScoreFactorTotal,
  getScoreFactors,
  getScoreInventorySummary,
  scoreTone,
  titleCase,
} from "../lib/results";
import type { ResultsReport } from "../lib/types";
import { GlowingEffect } from "./ui/glowing-effect";

interface ReportSummaryProps {
  report: ResultsReport;
}

export function ReportSummary({ report }: ReportSummaryProps) {
  const score = report.exposure_score ?? 0;
  const breakdown = report.score_breakdown ?? {};
  const riskLabel = titleCase(report.score_breakdown?.label ?? "unknown");
  const tone = scoreTone(score, report.score_breakdown?.label);
  const meterFill = Math.min(Math.max(score, 6), 100);
  const meterMarker = Math.min(Math.max(score, 8), 94);
  const summaryPills = getCompletionSummary(report);
  const inventoryPills = getScoreInventorySummary(report);
  const countPills = getScoreCountSummary(report);
  const scoreFactors = getScoreFactors(report);
  const displayedFactorTotal = getScoreFactorTotal(report);
  const wasCapped =
    typeof breakdown.raw_total === "number" &&
    typeof breakdown.total === "number" &&
    breakdown.raw_total > breakdown.total;
  const hasTagGroups = Boolean(summaryPills.length || inventoryPills.length || countPills.length);

  return (
    <section className="report-summary">
      <GlowingEffect blur={16} spread={54} glow proximity={126} inactiveZone={0.12} borderWidth={3} />
      <div className={`report-summary__score-float ${tone}`}>
        <div className="report-summary__score-main">
          <div className={`report-summary__score-value ${tone}`}>{score}</div>
          <div className="report-summary__score-caption">{riskLabel} exposure risk</div>
        </div>

        <div className="report-summary__score-side">
          <div className="report-summary__thermometer-wrap" aria-hidden="true">
            <div className="report-summary__thermometer">
              <div className="report-summary__thermometer-zones">
                <span className="is-critical" />
                <span className="is-high" />
                <span className="is-medium" />
                <span className="is-low" />
              </div>
              <div className={`report-summary__thermometer-fill ${tone}`} style={{ height: `${meterFill}%` }} />
              <div className={`report-summary__thermometer-marker ${tone}`} style={{ bottom: `calc(${meterMarker}% - 0.28rem)` }} />
            </div>
            <div className="report-summary__thermometer-scale">
              <span>100</span>
              <span>75</span>
              <span>50</span>
              <span>25</span>
              <span>0</span>
            </div>
          </div>
        </div>
      </div>

      <div className="report-summary__body">
        <div className="report-summary__body-header">
          <p className="eyebrow">Score rationale</p>
          <h3>What pushed this score higher</h3>
        </div>

        {breakdown.methodology ? <p className="report-summary__meta">{breakdown.methodology}</p> : null}

        {breakdown.notes?.length ? (
          <div className="report-summary__notes">
            {breakdown.notes.map((note) => (
              <div key={note} className="report-summary__note">
                {note}
              </div>
            ))}
          </div>
        ) : null}

        {hasTagGroups ? (
          <details className="report-summary__tags-disclosure">
            <summary>
              <span>Tags and counts</span>
              <span className="report-summary__tags-icon">+</span>
            </summary>

            <div className="report-summary__tags-body">
              {summaryPills.length ? (
                <div className="report-summary__tag-group">
                  <div className="report-summary__tag-label">Score summary</div>
                  <div className="report-summary__pills">
                    {summaryPills.map((pill) => (
                      <span key={pill} className="summary-pill">
                        {pill}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}

              {inventoryPills.length ? (
                <div className="report-summary__tag-group">
                  <div className="report-summary__tag-label">Data inventory</div>
                  <div className="report-summary__pills report-summary__pills--secondary">
                    {inventoryPills.map((pill) => (
                      <span key={pill} className="summary-pill">
                        {pill}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}

              {countPills.length ? (
                <div className="report-summary__tag-group">
                  <div className="report-summary__tag-label">Counts</div>
                  <div className="report-summary__pills report-summary__pills--secondary">
                    {countPills.map((pill) => (
                      <span key={pill} className="summary-pill">
                        {pill}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          </details>
        ) : null}

        <div className="report-summary__factor-meta">
          <span>Displayed factor points: +{displayedFactorTotal}</span>
          {wasCapped ? <span>Final score capped at {breakdown.total}/100</span> : null}
        </div>

        <div className="report-summary__factors">
          {scoreFactors.length ? (
            scoreFactors.map((factor) => (
              <article key={`${factor.label}-${factor.points}`} className="factor-row">
                <span className="factor-row__points">+{factor.points ?? 0}</span>
                <div>
                  <div className="factor-row__label-row">
                    <div className="factor-row__label">{factor.label ?? "Triggered factor"}</div>
                    {factor.category ? <span className="factor-row__category">{titleCase(factor.category)}</span> : null}
                  </div>
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
