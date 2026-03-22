"use client";

import { motion } from "framer-motion";

import { cn } from "../../lib/utils";

interface ProgressProps {
  value?: number;
  label?: string;
  showValue?: boolean;
  animated?: boolean;
  indeterminate?: boolean;
  className?: string;
  size?: "sm" | "default" | "lg";
}

function clampProgress(value: number) {
  return Math.min(Math.max(value, 0), 100);
}

export function Progress({
  value = 0,
  label,
  showValue = false,
  animated = true,
  indeterminate = false,
  className,
  size = "default",
}: ProgressProps) {
  const progress = clampProgress(value);

  return (
    <div className={cn("ui-progress", `ui-progress--${size}`, className)}>
      {label || showValue ? (
        <div className="ui-progress__meta">
          {label ? <span className="ui-progress__label">{label}</span> : <span />}
          {showValue && !indeterminate ? <span className="ui-progress__value">{Math.round(progress)}%</span> : null}
        </div>
      ) : null}

      <div className="ui-progress__track">
        {indeterminate ? (
          <motion.div
            className="ui-progress__indicator ui-progress__indicator--indeterminate"
            animate={{ x: ["-55%", "115%"] }}
            transition={{
              duration: animated ? 1.35 : 0,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
        ) : (
          <motion.div
            className="ui-progress__indicator"
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{
              duration: animated ? 1.05 : 0,
              ease: [0.22, 1, 0.36, 1],
            }}
          />
        )}
      </div>
    </div>
  );
}
