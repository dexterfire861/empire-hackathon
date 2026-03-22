import { useEffect, useState } from "react";

import { AnimatePresence, motion } from "framer-motion";

import { auditKey, getRoundKeyFromNumber } from "../lib/results";
import type { RoundGroup } from "../lib/types";
import { TextShimmer } from "./TextShimmer";
import { TraceStep } from "./TraceStep";

interface TraceRoundListProps {
  rounds: RoundGroup[];
  activeRound: number | null;
  highlightedAuditKey: string | null;
  isLive: boolean;
}

export function TraceRoundList({
  rounds,
  activeRound,
  highlightedAuditKey,
  isLive,
}: TraceRoundListProps) {
  const [openRoundKey, setOpenRoundKey] = useState<string | null>(null);
  const activeRoundKey =
    getRoundKeyFromNumber(activeRound) ?? (rounds.length ? rounds[rounds.length - 1]?.key ?? null : null);

  useEffect(() => {
    if (!activeRoundKey) return;
    setOpenRoundKey(activeRoundKey);
  }, [activeRoundKey]);

  if (!rounds.length) {
    return <div className="panel-empty">Waiting for decision trace data to arrive.</div>;
  }

  return (
    <div className="trace-rounds">
      {rounds.map((round) => {
        const isOpen = openRoundKey === round.key;
        const isActiveRound = activeRoundKey === round.key && isLive;

        return (
          <motion.section key={round.key} className={`trace-round ${isOpen ? "is-open" : ""}`} layout>
            <button
              className="trace-round__header"
              type="button"
              onClick={() => setOpenRoundKey((current) => (current === round.key ? null : round.key))}
            >
              <div className="trace-round__heading">
                {isActiveRound ? (
                  <TextShimmer as="span" className="trace-round__label">
                    {round.label}
                  </TextShimmer>
                ) : (
                  <span className="trace-round__label">{round.label}</span>
                )}
                <span className="trace-round__badge">{round.badgeText}</span>
              </div>
              <p className="trace-round__summary">{round.summary || "Scanning for new leads..."}</p>
            </button>

            <AnimatePresence initial={false}>
              {isOpen ? (
                <motion.div
                  className="trace-round__body"
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                >
                  {round.entries.map((entry) => (
                    <TraceStep
                      key={auditKey(entry)}
                      entry={entry}
                      highlighted={highlightedAuditKey !== null && highlightedAuditKey === auditKey(entry)}
                      isLive={isLive}
                    />
                  ))}
                </motion.div>
              ) : null}
            </AnimatePresence>
          </motion.section>
        );
      })}
    </div>
  );
}
