"use client";

import { memo, useCallback, useEffect, useRef, type CSSProperties } from "react";

import { animate } from "framer-motion";

import { cn } from "../../lib/utils";

interface GlowingEffectProps {
  blur?: number;
  inactiveZone?: number;
  proximity?: number;
  spread?: number;
  variant?: "default" | "white";
  glow?: boolean;
  className?: string;
  disabled?: boolean;
  movementDuration?: number;
  borderWidth?: number;
}

const BLUE_GRADIENT = `radial-gradient(circle at 50% 50%, rgba(220, 247, 255, 0.98) 6%, rgba(220, 247, 255, 0) 18%),
  radial-gradient(circle at 32% 32%, rgba(154, 223, 255, 0.94) 0%, rgba(154, 223, 255, 0) 22%),
  radial-gradient(circle at 72% 62%, rgba(61, 161, 255, 0.96) 0%, rgba(61, 161, 255, 0) 25%),
  radial-gradient(circle at 48% 72%, rgba(20, 102, 229, 0.92) 0%, rgba(20, 102, 229, 0) 24%),
  repeating-conic-gradient(
    from 236.84deg at 50% 50%,
    #f2fbff 0%,
    #c9eeff 18%,
    #7fd0ff 42%,
    #2f9aff 72%,
    #f2fbff 100%
  )`;

const WHITE_GRADIENT = `repeating-conic-gradient(
  from 236.84deg at 50% 50%,
  rgba(255, 255, 255, 0.85),
  rgba(255, 255, 255, 0.85) 20%
)`;

const GlowingEffect = memo(function GlowingEffect({
  blur = 0,
  inactiveZone = 0.68,
  proximity = 88,
  spread = 40,
  variant = "default",
  glow = true,
  className,
  movementDuration = 0.62,
  borderWidth = 2.4,
  disabled = false,
}: GlowingEffectProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const lastPosition = useRef({ x: 0, y: 0 });
  const animationFrameRef = useRef<number>(0);
  const angleAnimationRef = useRef<{ stop: () => void } | null>(null);

  const handleMove = useCallback(
    (event?: MouseEvent | PointerEvent | { x: number; y: number }) => {
      const element = containerRef.current;
      if (!element) return;

      const restingOpacity = glow ? 0.32 : 0;

      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }

      animationFrameRef.current = requestAnimationFrame(() => {
        const currentElement = containerRef.current;
        if (!currentElement) return;

        const { left, top, width, height } = currentElement.getBoundingClientRect();
        const mouseX = event?.x ?? lastPosition.current.x;
        const mouseY = event?.y ?? lastPosition.current.y;

        if (event) {
          lastPosition.current = { x: mouseX, y: mouseY };
        }

        const centerX = left + width * 0.5;
        const centerY = top + height * 0.5;
        const distanceFromCenter = Math.hypot(mouseX - centerX, mouseY - centerY);
        const inactiveRadius = 0.5 * Math.min(width, height) * inactiveZone;

        if (distanceFromCenter < inactiveRadius) {
          currentElement.style.setProperty("--glow-active", String(restingOpacity));
          return;
        }

        const isActive =
          mouseX > left - proximity &&
          mouseX < left + width + proximity &&
          mouseY > top - proximity &&
          mouseY < top + height + proximity;

        currentElement.style.setProperty("--glow-active", String(isActive ? 1 : restingOpacity));

        if (!isActive) return;

        const currentAngle = parseFloat(currentElement.style.getPropertyValue("--glow-start")) || 0;
        const targetAngle = (180 * Math.atan2(mouseY - centerY, mouseX - centerX)) / Math.PI + 90;
        const angleDiff = ((targetAngle - currentAngle + 180) % 360) - 180;
        const nextAngle = currentAngle + angleDiff;

        angleAnimationRef.current?.stop();
        angleAnimationRef.current = animate(currentAngle, nextAngle, {
          duration: movementDuration,
          ease: [0.16, 1, 0.3, 1],
          onUpdate: (value) => {
            currentElement.style.setProperty("--glow-start", String(value));
          },
        });
      });
    },
    [glow, inactiveZone, movementDuration, proximity],
  );

  useEffect(() => {
    const element = containerRef.current;
    if (!element) return;

    const restingOpacity = glow ? 0.32 : 0;
    element.style.setProperty("--glow-active", String(restingOpacity));

    if (disabled) {
      return;
    }

    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const hasFinePointer = window.matchMedia("(pointer: fine)").matches;

    if (prefersReducedMotion || !hasFinePointer) {
      return;
    }

    const handleScroll = () => handleMove();
    const handlePointerMove = (event: PointerEvent) => handleMove(event);

    handleMove();
    window.addEventListener("scroll", handleScroll, { passive: true });
    document.body.addEventListener("pointermove", handlePointerMove, { passive: true });

    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
      angleAnimationRef.current?.stop();
      window.removeEventListener("scroll", handleScroll);
      document.body.removeEventListener("pointermove", handlePointerMove);
    };
  }, [disabled, glow, handleMove]);

  return (
    <div
      ref={containerRef}
      style={
        {
          "--glow-blur": `${blur}px`,
          "--glow-spread": spread,
          "--glow-start": "0",
          "--glow-active": glow ? "0.32" : "0",
          "--glow-border-width": `${borderWidth}px`,
          "--glow-gradient": variant === "white" ? WHITE_GRADIENT : BLUE_GRADIENT,
        } as CSSProperties
      }
      className={cn(
        "glowing-effect",
        glow && "glowing-effect--ambient",
        blur > 0 && "glowing-effect--blurred",
        disabled && "glowing-effect--disabled",
        className,
      )}
      aria-hidden="true"
    >
      <div className="glowing-effect__ring" />
    </div>
  );
});

export { GlowingEffect };
