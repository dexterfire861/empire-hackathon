import { useState } from "react";

import { AnimatePresence, motion } from "framer-motion";

import type { ReportSection } from "../lib/types";

interface ReportAccordionGroupProps {
  sections: ReportSection[];
}

export function ReportAccordionGroup({ sections }: ReportAccordionGroupProps) {
  const [openSectionIds, setOpenSectionIds] = useState(
    () => new Set(sections.filter((section) => section.defaultOpen).map((section) => section.id)),
  );

  return (
    <div className="report-accordion">
      {sections.map((section) => {
        const isOpen = openSectionIds.has(section.id);

        return (
          <motion.section key={section.id} className={`report-panel ${isOpen ? "is-open" : ""}`} layout>
            <button
              className="report-panel__header"
              type="button"
              onClick={() => {
                setOpenSectionIds((current) => {
                  const next = new Set(current);
                  if (next.has(section.id)) {
                    next.delete(section.id);
                  } else {
                    next.add(section.id);
                  }
                  return next;
                });
              }}
            >
              <div>
                <h3>{section.title}</h3>
                {section.subtitle ? <p>{section.subtitle}</p> : null}
              </div>
              <span className="report-panel__toggle">{isOpen ? "Collapse" : "Expand"}</span>
            </button>

            <AnimatePresence initial={false}>
              {isOpen ? (
                <motion.div
                  className="report-panel__body"
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                >
                  <div className="report-panel__body-inner">{section.content}</div>
                </motion.div>
              ) : null}
            </AnimatePresence>
          </motion.section>
        );
      })}
    </div>
  );
}
