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
 * Nothing is drawn while the tab is hidden, as the browser pauses frames, or
 * while the canvas is scrolled out of view.
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
    let visible = true;
    const watcher =
      typeof IntersectionObserver === "undefined"
        ? null
        : new IntersectionObserver(([entry]) => {
            visible = entry?.isIntersecting ?? true;
          });
    watcher?.observe(element);
    const tick = (now: number) => {
      if (!visible) {
        last = now;
        frame = requestAnimationFrame(tick);
        return;
      }
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
    return () => {
      cancelAnimationFrame(frame);
      watcher?.disconnect();
    };
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

/** A series of counts to draw as layers, such as severities or hosts. */
export interface Layer {
  key: string;
  name: string;
  color: string;
}

/** OCSF `severity_id`s, lowest first, with their names and colours. */
export const SEVERITIES: Layer[] = [
  { key: "0", name: "Unknown", color: "#9aa5b5" },
  { key: "1", name: "Informational", color: "#3b7ddd" },
  { key: "2", name: "Low", color: "#1f4fbf" },
  { key: "3", name: "Medium", color: "#f1c232" },
  { key: "4", name: "High", color: "#f08c3a" },
  { key: "5", name: "Critical", color: "#e0533d" },
  { key: "6", name: "Fatal", color: "#a23b8f" },
  { key: "99", name: "Other", color: "#6cc5b0" },
];

/** Colours for lists of values, in order: blues first, as the eye reads them. */
export const PALETTE = ["#3b7ddd", "#1f4fbf", "#9cc0f5", "#f1c232", "#6cc5b0", "#b39ddb"];

/** Where a chart plots, inside its canvas. */
export interface Plot {
  left: number;
  top: number;
  width: number;
  height: number;
}

export function plotIn(width: number, height: number): Plot {
  const left = 40;
  const top = 8;
  return { left, top, width: width - left - 8, height: height - top - 20 };
}

/** The colours a chart draws with, read from the theme once a frame. */
export interface Ink {
  line: string;
  muted: string;
  text: string;
  panel: string;
}

export function ink(): Ink {
  return {
    line: token("--grid", "#262c35"),
    muted: token("--muted", "#8a94a3"),
    text: token("--text", "#d8dee6"),
    panel: token("--panel", "#161a20"),
  };
}

/** Horizontal grid lines with counts on the left, and times along the bottom. */
export function drawGrid(
  context: CanvasRenderingContext2D,
  plot: Plot,
  top: number,
  times: { x: number; text: string }[],
  colors: Ink,
) {
  context.font = "11px system-ui, sans-serif";
  context.fillStyle = colors.muted;
  context.strokeStyle = colors.line;
  context.lineWidth = 1;
  context.textAlign = "right";
  context.textBaseline = "middle";
  for (let tick = 0; tick <= 4; tick += 1) {
    const value = (top * tick) / 4;
    const level = Math.round(plot.top + plot.height - (tick / 4) * plot.height) + 0.5;
    context.beginPath();
    context.moveTo(plot.left, level);
    context.lineTo(plot.left + plot.width, level);
    context.stroke();
    context.fillText(compact(value), plot.left - 6, level);
  }
  context.textAlign = "center";
  context.textBaseline = "top";
  for (const time of times) {
    if (time.x >= plot.left - 1 && time.x <= plot.left + plot.width + 1) {
      context.fillText(time.text, time.x, plot.top + plot.height + 6);
    }
  }
}

/** A box of labelled counts beside the pointer, kept inside the canvas. */
export function drawTooltip(
  context: CanvasRenderingContext2D,
  at: { x: number; y: number },
  bounds: { width: number; height: number },
  heading: string,
  rows: { color: string; name: string; count: number }[],
  colors: Ink,
) {
  context.font = "12px system-ui, sans-serif";
  const nameWidth = Math.max(0, ...rows.map((row) => context.measureText(row.name).width));
  const boxWidth = Math.max(140, nameWidth + 90);
  const boxHeight = 12 + (rows.length + 1) * 18;
  const left = at.x + 14 + boxWidth > bounds.width ? at.x - 14 - boxWidth : at.x + 14;
  const upper = Math.min(Math.max(at.y - boxHeight / 2, 0), bounds.height - boxHeight);
  context.fillStyle = colors.panel;
  context.strokeStyle = colors.line;
  context.lineWidth = 1;
  context.beginPath();
  context.roundRect(left + 0.5, upper + 0.5, boxWidth, boxHeight, 6);
  context.fill();
  context.stroke();
  context.textBaseline = "top";
  context.textAlign = "left";
  context.fillStyle = colors.muted;
  context.fillText(heading, left + 10, upper + 8);
  rows.forEach((row, index) => {
    const rowTop = upper + 8 + (index + 1) * 18;
    context.fillStyle = row.color;
    context.beginPath();
    context.arc(left + 14, rowTop + 6, 4, 0, Math.PI * 2);
    context.fill();
    context.fillStyle = colors.text;
    context.textAlign = "left";
    context.fillText(row.name, left + 24, rowTop);
    context.textAlign = "right";
    context.fillText(row.count.toLocaleString("en-US"), left + boxWidth - 10, rowTop);
  });
}

/** A time label that suits the span: hours and minutes, or a date. */
export function clock(at: number, span: number): string {
  const date = new Date(at);
  if (span > 2 * 24 * 3_600_000) {
    return date.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
  }
  return date.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    ...(span <= 15 * 60_000 ? { second: "2-digit" } : {}),
  });
}

/** A step's length in words, as a chart's caption says it. */
export function per(step: number): string {
  const units: [number, string][] = [
    [24 * 3_600_000, "day"],
    [3_600_000, "hour"],
    [60_000, "minute"],
    [1000, "second"],
  ];
  for (const [size, unit] of units) {
    if (step >= size && step % size === 0) {
      const count = step / size;
      return count === 1 ? unit : `${count} ${unit}s`;
    }
  }
  return `${step} ms`;
}
