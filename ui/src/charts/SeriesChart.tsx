import { useEffect, useRef } from "react";
import type { Step } from "../api";
import type { Layer } from "./canvas";
import {
  approach,
  clock,
  drawGrid,
  drawTooltip,
  faded,
  ink,
  niceCeiling,
  plotIn,
  traceMonotone,
  useFrames,
} from "./canvas";

interface Props {
  /** Counts by step, each keyed by a layer's key. */
  steps: Step[] | undefined;
  /** What to stack, bottom first. */
  layers: Layer[];
  kind: "area" | "bars";
  /** The range the steps cover, in milliseconds since the epoch. */
  from: number;
  to: number;
  step: number;
  /** Whether the range ends now, so the chart moves with the clock. */
  live: boolean;
}

/** One step's counts by layer, as drawn and as last fetched. */
interface Column {
  shown: Map<string, number>;
  target: Map<string, number>;
}

/**
 * Counts over time, stacked by layer, as areas or bars. Values ease toward
 * each fetch, and a range that ends now slides with the clock between
 * fetches, so the chart moves continuously rather than in steps.
 */
export function SeriesChart({ steps, layers, kind, from, to, step, live }: Props) {
  const columns = useRef(new Map<number, Column>());
  const range = useRef({ span: to - from, step, to, skew: 0 });
  const top = useRef(1);
  const pointer = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => {
    if (!steps) {
      return;
    }
    range.current = { span: to - from, step, to, skew: to - Date.now() };
    const seen = new Set<number>();
    for (const entry of steps) {
      seen.add(entry.at);
      const target = new Map(Object.entries(entry.counts));
      const column = columns.current.get(entry.at);
      if (column) {
        column.target = target;
      } else {
        columns.current.set(entry.at, { shown: new Map(), target });
      }
    }
    // Steps no longer in range fade to nothing, then go.
    for (const [at, column] of columns.current) {
      if (!seen.has(at)) {
        column.target = new Map();
      }
    }
  }, [steps, from, to, step]);

  const canvas = useFrames(({ context, width, height }, elapsed) => {
    const colors = ink();
    const plot = plotIn(width, height);
    const { span, step: stepMs, to: end0, skew } = range.current;
    const end = live ? Date.now() + skew : end0;
    const start = end - span;
    const x = (at: number) => plot.left + ((at - start) / span) * plot.width;

    // Ease every value, and drop steps that have faded out of range.
    const ordered = [...columns.current.entries()].sort(([a], [b]) => a - b);
    let highest = 0;
    for (const [at, column] of ordered) {
      let sum = 0;
      let settled = column.target.size === 0;
      for (const layer of layers) {
        const next = approach(
          column.shown.get(layer.key) ?? 0,
          column.target.get(layer.key) ?? 0,
          elapsed,
          500,
        );
        column.shown.set(layer.key, next);
        sum += next;
        settled &&= next === 0;
      }
      if (settled && at < start - stepMs) {
        columns.current.delete(at);
      }
      highest = Math.max(highest, sum);
    }
    top.current = approach(top.current, niceCeiling(highest * 1.1), elapsed, 600);
    const y = (count: number) => plot.top + plot.height - (count / top.current) * plot.height;

    const times = [0, 1, 2, 3, 4].map((tick) => {
      const at = start + (span * tick) / 4;
      return { x: x(at), text: clock(at, span) };
    });
    drawGrid(context, plot, top.current, times, colors);

    context.save();
    context.beginPath();
    context.rect(plot.left, plot.top - 1, plot.width, plot.height + 2);
    context.clip();
    const hoverAt = pointer.current
      ? start + ((pointer.current.x - plot.left) / plot.width) * span
      : null;
    if (kind === "bars") {
      const barWidth = Math.max(2, (stepMs / span) * plot.width * 0.72);
      for (const [at, column] of ordered) {
        const center = x(at + stepMs / 2);
        const hovered = hoverAt !== null && hoverAt >= at && hoverAt < at + stepMs;
        let base = 0;
        for (const layer of layers) {
          const value = column.shown.get(layer.key) ?? 0;
          if (value <= 0) {
            continue;
          }
          const upper = y(base + value);
          const lower = y(base);
          context.globalAlpha = hoverAt === null || hovered ? 1 : 0.55;
          context.fillStyle = layer.color;
          context.beginPath();
          context.roundRect(
            center - barWidth / 2,
            upper,
            barWidth,
            Math.max(lower - upper - 1, 0.5),
            Math.min(2, barWidth / 2),
          );
          context.fill();
          base += value;
        }
      }
      context.globalAlpha = 1;
    } else {
      // Top layer first, each drawn as the sum of those below it, so lower
      // layers paint over the upper ones' bases.
      for (let index = layers.length - 1; index >= 0; index -= 1) {
        const layer = layers[index];
        if (!layer || ordered.every(([, column]) => (column.shown.get(layer.key) ?? 0) === 0)) {
          continue;
        }
        const points: [number, number][] = ordered.map(([at, column]) => {
          let sum = 0;
          for (let below = 0; below <= index; below += 1) {
            const under = layers[below];
            sum += under ? (column.shown.get(under.key) ?? 0) : 0;
          }
          return [x(at + stepMs / 2), y(sum)];
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
        // Over what the layers above drew, a fill that fades to the
        // ground, and the layer's own line along its top.
        context.fillStyle = colors.panel;
        context.fill();
        const fade = context.createLinearGradient(0, plot.top, 0, plot.top + plot.height);
        fade.addColorStop(0, faded(layer.color, 0.5));
        fade.addColorStop(1, faded(layer.color, 0.04));
        context.fillStyle = fade;
        context.fill();
        context.beginPath();
        context.moveTo(first[0], first[1]);
        traceMonotone(context, points);
        context.strokeStyle = layer.color;
        context.lineWidth = 1.5;
        context.stroke();
      }
    }
    context.restore();

    // The step under the pointer, with its counts, topmost layer first.
    const at = pointer.current;
    if (!at || hoverAt === null || at.x < plot.left || at.x > plot.left + plot.width) {
      return;
    }
    const hovered = ordered.find(([stepAt]) => hoverAt >= stepAt && hoverAt < stepAt + stepMs);
    if (kind === "area") {
      context.strokeStyle = colors.muted;
      context.setLineDash([3, 3]);
      context.beginPath();
      context.moveTo(Math.round(at.x) + 0.5, plot.top);
      context.lineTo(Math.round(at.x) + 0.5, plot.top + plot.height);
      context.stroke();
      context.setLineDash([]);
    }
    if (!hovered) {
      return;
    }
    const [stepAt, column] = hovered;
    const rows = [...layers]
      .reverse()
      .map((layer) => ({
        color: layer.color,
        name: layer.name,
        count: Math.round(column.target.get(layer.key) ?? 0),
      }))
      .filter((row) => row.count > 0);
    if (rows.length > 0) {
      const heading = `${clock(stepAt, span)} to ${clock(stepAt + stepMs, span)}`;
      drawTooltip(context, at, { width, height }, heading, rows, colors);
    }
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
