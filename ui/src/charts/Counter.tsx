import { useEffect, useRef } from "react";

interface Props {
  value: number;
  /** How long the count takes to reach a new value, in milliseconds. */
  ms?: number;
}

/** A number that counts up or down to each new value, instead of jumping. */
export function Counter({ value, ms = 900 }: Props) {
  const element = useRef<HTMLSpanElement>(null);
  const shown = useRef(0);

  useEffect(() => {
    const from = shown.current;
    const started = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const progress = Math.min((now - started) / ms, 1);
      const eased = 1 - (1 - progress) ** 3;
      shown.current = from + (value - from) * eased;
      if (element.current) {
        element.current.textContent = Math.round(shown.current).toLocaleString("en-US");
      }
      if (progress < 1) {
        frame = requestAnimationFrame(tick);
      }
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [value, ms]);

  return <span ref={element}>0</span>;
}
