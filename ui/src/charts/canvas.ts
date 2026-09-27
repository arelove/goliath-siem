// Drawing on a canvas every frame: sizing for the display, easing, smooth
// curves, and the colours charts share.

import { useEffect, useRef } from "react";

/** A canvas's drawing context, sized in CSS pixels. */
export interface Surface {
  context: CanvasRenderingContext2D;
  width: number;
  height: number;
}

/**
 * Calls `draw` on every animation frame, with the canvas sized to its box
 * at the display's pixel density, and the milliseconds since the last frame.
 * Nothing is drawn while the tab is hidden: the browser pauses frames.
 */
export function useFrames(draw: (surface: Surface, elapsed: number) => void) {
  const canvas = useRef<HTMLCanvasElement>(null);
  // The latest `draw` without restarting the loop when it changes.
  const latest = useRef(draw);
  latest.current = draw;

  useEffect(() => {
    const element = canvas.current;
    const context = element?.getContext("2d");
    if (!element || !context) {
      return;
    }
    let frame = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const ratio = window.devicePixelRatio || 1;
      const width = element.clientWidth;
      const height = element.clientHeight;
      if (element.width !== Math.round(width * ratio)) {
        element.width = Math.round(width * ratio);
      }
      if (element.height !== Math.round(height * ratio)) {
        element.height = Math.round(height * ratio);
      }
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      context.clearRect(0, 0, width, height);
      // A long pause, such as a hidden tab, is not one step of animation.
      latest.current({ context, width, height }, Math.min(now - last, 100));
      last = now;
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, []);

  return canvas;
}

/** Moves `current` toward `target`, covering most of the way in `ms`. */
export function approach(current: number, target: number, elapsed: number, ms = 250): number {
  const next = current + (target - current) * (1 - Math.exp(-elapsed / (ms / 3)));
  return Math.abs(next - target) < 1e-3 ? target : next;
}

/**
 * Traces a smooth line through `points`, sorted by x, that never overshoots
 * them: a monotone cubic, so a count never dips below zero between steps.
 */
export function traceMonotone(context: CanvasRenderingContext2D, points: [number, number][]) {
  const count = points.length;
  const first = points[0];
  if (!first) {
    return;
  }
  context.lineTo(first[0], first[1]);
  if (count < 2) {
    return;
  }
  const slopes: number[] = [];
  const tangents: number[] = [];
  for (let index = 0; index < count - 1; index += 1) {
    const [x0, y0] = points[index] ?? first;
    const [x1, y1] = points[index + 1] ?? first;
    slopes.push(x1 === x0 ? 0 : (y1 - y0) / (x1 - x0));
  }
  for (let index = 0; index < count; index += 1) {
    const before = slopes[index - 1];
    const after = slopes[index];
    if (before === undefined) {
      tangents.push(after ?? 0);
    } else if (after === undefined) {
      tangents.push(before);
    } else if (before * after <= 0) {
      tangents.push(0);
    } else {
      tangents.push((3 * before * after) / (Math.max(before, after) + 2 * Math.min(before, after)));
    }
  }
  for (let index = 0; index < count - 1; index += 1) {
    const [x0, y0] = points[index] ?? first;
    const [x1, y1] = points[index + 1] ?? first;
    const third = (x1 - x0) / 3;
    context.bezierCurveTo(
      x0 + third,
      y0 + third * (tangents[index] ?? 0),
      x1 - third,
      y1 - third * (tangents[index + 1] ?? 0),
      x1,
      y1,
    );
  }
}

/** A round number at or above `value`, for the top of an axis. */
export function niceCeiling(value: number): number {
  if (value <= 0) {
    return 1;
  }
  const power = 10 ** Math.floor(Math.log10(value));
  const scaled = value / power;
  const nice = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((step) => step >= scaled) ?? 10;
  return nice * power;
}

/** A count in few characters: 1234 as 1.2k. */
export function compact(value: number): string {
  if (value >= 1e9) {
    return `${(value / 1e9).toFixed(1)}B`;
  }
  if (value >= 1e6) {
    return `${(value / 1e6).toFixed(1)}M`;
  }
  if (value >= 1e4) {
    return `${Math.round(value / 1e3)}k`;
  }
  if (value >= 1e3) {
    return `${(value / 1e3).toFixed(1)}k`;
  }
  return String(Math.round(value));
}

/** A CSS custom property of the document, such as a theme colour. */
export function token(name: string, fallback: string): string {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

/** OCSF `severity_id`s, lowest first, with their names and colours. */
export const SEVERITIES: { id: string; name: string; color: string }[] = [
  { id: "0", name: "Unknown", color: "#5b6573" },
  { id: "1", name: "Informational", color: "#3d7eff" },
  { id: "2", name: "Low", color: "#22b8cf" },
  { id: "3", name: "Medium", color: "#f2c94c" },
  { id: "4", name: "High", color: "#f2994a" },
  { id: "5", name: "Critical", color: "#eb5757" },
  { id: "6", name: "Fatal", color: "#c74bd9" },
  { id: "99", name: "Other", color: "#8792a2" },
];

/** Colours for lists of values, in order. */
export const PALETTE = ["#3d7eff", "#22b8cf", "#9b7bff", "#f2c94c", "#f2994a", "#5b6573"];
