import { useEffect, useRef } from "react";
import type { Overview } from "../api";
import {
  approach,
  compact,
  niceCeiling,
  SEVERITIES,
  token,
  traceMonotone,
  useFrames,
} from "./canvas";

interface Props {
  overview: Overview | undefined;
  /** Whether the range ends now, so the chart moves with the clock. */
  live: boolean;
}

/** Counts by severity, lowest first, as drawn and as last fetched. */
interface Column {
  shown: number[];
  target: number[];
}

/**
 * Events by severity over time, stacked. Every value eases toward the last
 * fetch each frame, and a range that ends now slides with the clock between
 * fetches, so the chart moves continuously rather than in steps.
 */
export function StackedArea({ overview, live }: Props) {
  const columns = useRef(new Map<number, Column>());
  const range = useRef({ span: 3_600_000, step: 30_000, to: 0, skew: 0 });
  const top = useRef(1);
  const pointer = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => {
    if (!overview) {
      return;
    }
    range.current = {
      span: overview.to - overview.from,
      step: overview.step_ms,
      to: overview.to,
      skew: overview.to - Date.now(),
    };
    const seen = new Set<number>();
    for (const step of overview.series) {
      seen.add(step.at);
      const target = SEVERITIES.map((severity) => step.counts[severity.id] ?? 0);
      const column = columns.current.get(step.at);
      if (column) {
        column.target = target;
      } else {
        columns.current.set(step.at, { shown: target.map(() => 0), target });
      }
    }
    // Steps no longer in range fade to nothing, then go.
    for (const [at, column] of columns.current) {
      if (!seen.has(at)) {
        column.target = column.target.map(() => 0);
      }
    }
  }, [overview]);

  const canvas = useFrames(({ context, width, height }, elapsed) => {
    const line = token("--line", "#262c35");
    const muted = token("--muted", "#8a94a3");
    const text = token("--text", "#d8dee6");
    const panel = token("--panel", "#161a20");
    const pad = { left: 44, right: 12, top: 12, bottom: 22 };
    const plotWidth = width - pad.left - pad.right;
    const plotHeight = height - pad.top - pad.bottom;
    const { span, step, to, skew } = range.current;
    const end = live ? Date.now() + skew : to;
    const start = end - span;
    const x = (at: number) => pad.left + ((at - start) / span) * plotWidth;

    // Ease every value, and drop steps that have faded out of range.
    const ordered = [...columns.current.entries()].sort(([a], [b]) => a - b);
    let highest = 0;
    for (const [at, column] of ordered) {
      let sum = 0;
      column.shown = column.shown.map((value, index) => {
        const next = approach(value, column.target[index] ?? 0, elapsed, 500);
        sum += next;
        return next;
      });
      if (sum === 0 && column.target.every((value) => value === 0) && at < start - step) {
        columns.current.delete(at);
      }
      highest = Math.max(highest, sum);
    }
    top.current = approach(top.current, niceCeiling(highest * 1.1), elapsed, 600);
    const y = (count: number) => pad.top + plotHeight - (count / top.current) * plotHeight;

    context.font = "11px system-ui, sans-serif";
    context.fillStyle = muted;
    context.strokeStyle = line;
    context.lineWidth = 1;
    context.textAlign = "right";
    context.textBaseline = "middle";
    for (let tick = 0; tick <= 4; tick += 1) {
      const value = (top.current * tick) / 4;
      const level = Math.round(y(value)) + 0.5;
      context.beginPath();
      context.moveTo(pad.left, level);
      context.lineTo(width - pad.right, level);
      context.stroke();
      context.fillText(compact(value), pad.left - 8, level);
    }
    context.textAlign = "center";
    context.textBaseline = "top";
    for (let tick = 0; tick <= 4; tick += 1) {
      const at = start + (span * tick) / 4;
      context.fillText(clock(at, span), x(at), height - pad.bottom + 6);
    }

    // Layers from the top severity down, each drawn as the sum of those
    // below it, so lower layers paint over the upper ones' bases.
    context.save();
    context.beginPath();
    context.rect(pad.left, pad.top - 2, plotWidth, plotHeight + 4);
    context.clip();
    for (let layer = SEVERITIES.length - 1; layer >= 0; layer -= 1) {
      const severity = SEVERITIES[layer];
      if (!severity || ordered.every(([, column]) => (column.shown[layer] ?? 0) === 0)) {
        continue;
      }
      const points: [number, number][] = ordered.map(([at, column]) => {
        let sum = 0;
        for (let below = 0; below <= layer; below += 1) {
          sum += column.shown[below] ?? 0;
        }
        return [x(at + step / 2), y(sum)];
      });
      const first = points[0];
      const last = points[points.length - 1];
      if (!first || !last) {
        continue;
      }
      context.beginPath();
      context.moveTo(first[0], y(0));
      traceMonotone(context, points);
      context.lineTo(last[0], y(0));
      context.closePath();
      context.fillStyle = `${severity.color}cc`;
      context.fill();
      context.beginPath();
      context.moveTo(first[0], first[1]);
      traceMonotone(context, points);
      context.strokeStyle = severity.color;
      context.lineWidth = 1.5;
      context.stroke();
    }
    context.restore();

    // The step under the pointer, with its counts.
    const at = pointer.current;
    if (!at || at.x < pad.left || at.x > width - pad.right) {
      return;
    }
    const time = start + ((at.x - pad.left) / plotWidth) * span;
    const hovered = ordered.find(([stepAt]) => time >= stepAt && time < stepAt + step);
    context.strokeStyle = muted;
    context.setLineDash([3, 3]);
    context.beginPath();
    context.moveTo(Math.round(at.x) + 0.5, pad.top);
    context.lineTo(Math.round(at.x) + 0.5, pad.top + plotHeight);
    context.stroke();
    context.setLineDash([]);
    if (!hovered) {
      return;
    }
    const [stepAt, column] = hovered;
    const rows = SEVERITIES.map((severity, index) => ({
      severity,
      count: Math.round(column.target[index] ?? 0),
    })).filter((row) => row.count > 0);
    const lines = [clock(stepAt, span), ...rows.map((row) => row.severity.name)];
    const boxWidth = 150;
    const boxHeight = 10 + lines.length * 16;
    const left = at.x + 12 + boxWidth > width ? at.x - 12 - boxWidth : at.x + 12;
    const upper = Math.min(Math.max(at.y - boxHeight / 2, 0), height - boxHeight);
    context.fillStyle = `${panel}f0`;
    context.strokeStyle = line;
    context.beginPath();
    context.roundRect(left, upper, boxWidth, boxHeight, 6);
    context.fill();
    context.stroke();
    context.textAlign = "left";
    context.textBaseline = "top";
    context.fillStyle = muted;
    context.fillText(lines[0] ?? "", left + 10, upper + 6);
    rows.forEach((row, index) => {
      const rowTop = upper + 6 + (index + 1) * 16;
      context.fillStyle = row.severity.color;
      context.fillRect(left + 10, rowTop + 2, 8, 8);
      context.fillStyle = text;
      context.fillText(row.severity.name, left + 24, rowTop);
      context.textAlign = "right";
      context.fillText(row.count.toLocaleString("en-US"), left + boxWidth - 10, rowTop);
      context.textAlign = "left";
    });
  });

  return (
    <canvas
      ref={canvas}
      className="chart"
      onPointerMove={(event) => {
        const box = event.currentTarget.getBoundingClientRect();
        pointer.current = { x: event.clientX - box.left, y: event.clientY - box.top };
      }}
      onPointerLeave={() => {
        pointer.current = null;
      }}
    />
  );
}

/** A time label that suits the span: hours and minutes, or a date. */
function clock(at: number, span: number): string {
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
