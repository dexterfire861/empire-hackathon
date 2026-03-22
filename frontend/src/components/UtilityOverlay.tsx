import { useEffect, type ReactNode } from "react";

import { AnimatePresence, motion } from "framer-motion";
import { GlowingEffect } from "./ui/glowing-effect";

interface UtilityOverlayProps {
  open: boolean;
  title: string;
  subtitle: string;
  onClose: () => void;
  children: ReactNode;
}

export function UtilityOverlay({
  open,
  title,
  subtitle,
  onClose,
  children,
}: UtilityOverlayProps) {
  useEffect(() => {
    if (!open) return;

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        onClose();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose, open]);

  return (
    <AnimatePresence>
      {open ? (
        <>
          <motion.button
            aria-label="Close overlay"
            className="utility-overlay__backdrop"
            type="button"
            onClick={onClose}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          />
          <motion.section
            aria-modal="true"
            className="utility-overlay"
            role="dialog"
            initial={{ opacity: 0, y: -12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -10, scale: 0.98 }}
            transition={{ duration: 0.16, ease: [0.16, 1, 0.3, 1] }}
          >
            <GlowingEffect blur={18} spread={56} glow proximity={136} inactiveZone={0.12} borderWidth={3} />
            <div className="utility-overlay__header">
              <div>
                <p className="eyebrow">Quick access</p>
                <h3>{title}</h3>
                <p>{subtitle}</p>
              </div>
              <button className="utility-overlay__close" type="button" onClick={onClose}>
                Close
              </button>
            </div>
            <div className="utility-overlay__body">{children}</div>
          </motion.section>
        </>
      ) : null}
    </AnimatePresence>
  );
}
