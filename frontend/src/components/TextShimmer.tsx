import type { CSSProperties, ElementType } from "react";

import { motion, useReducedMotion } from "framer-motion";

interface TextShimmerProps {
  children: string;
  as?: ElementType;
  className?: string;
  duration?: number;
  spread?: number;
  active?: boolean;
}

export function TextShimmer({
  children,
  as: Component = "span",
  className,
  duration = 2,
  spread = 2,
  active = true,
}: TextShimmerProps) {
  const prefersReducedMotion = useReducedMotion();
  const dynamicSpread = `${Math.max(children.length * spread, 56)}px`;
  const classes = ["text-shimmer", className].filter(Boolean).join(" ");
  const style = {
    "--text-shimmer-spread": dynamicSpread,
  } as CSSProperties;

  if (prefersReducedMotion || !active) {
    return <Component className={classes}>{children}</Component>;
  }

  return (
    <Component className={classes} style={style}>
      <motion.span
        className="text-shimmer__inner"
        initial={{ backgroundPosition: "100% center" }}
        animate={{ backgroundPosition: "0% center" }}
        transition={{
          repeat: Infinity,
          duration,
          ease: "linear",
        }}
      >
        {children}
      </motion.span>
    </Component>
  );
}
