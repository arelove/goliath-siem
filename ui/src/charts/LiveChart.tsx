import { type RefObject, useEffect, useRef } from "react";
import type { Arrivals } from "../api";
import {
  approach,
  drawGrid,
  drawTooltip,
  ink,
  niceCeiling,
  plotIn,
  token,
  traceMonotone,
  useFrames,
} from "./canvas";

/** Seconds the chart spans. */
const SPAN = 120;
/**
 * How far behind the clock the chart draws, in milliseconds: a second is
 * complete only once its events are stored, about a second after it ends.
 */
const BEHIND = 2500;

interface Props {
  arrivals: Arrivals | undefined;
  /** Where to write the current rate, events a second, as it is drawn. */
  rate?: RefObject<HTMLElement | null>;
}

/**
 * Events stored each second over the last two minutes, drawn every frame:
 * the time axis moves continuously and the scale eases to fit, so new data
 * slides in rather than jumping.
 */
export function LiveChart({ arrivals, rate }: Props) {
  // Counts by second, and the server's clock less the browser's.
  const counts = useRef(new Map<number, number>());
  const skew = useRef(0);
  const shown = useRef({ top: 1, rate: 0 });
  const pointer = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => {
    if (!arrivals) {
      return;
    }
    skew.current = arrivals.now - Date.now();
    for (const second of arrivals.seconds) {
      counts.current.set(second.at, second.count);
    }
    const oldest = arrivals.now - (SPAN + 30) * 1000;
    for (const at of counts.current.keys()) {
      if (at < oldest) {
        counts.current.delete(at);
      }
    }
  }, [arrivals]);

  const canvas = useFrames(({ context, width, height }, elapsed) => {
    const colors = ink();
    const accent = token("--accent", "#c98a4b");
    const plot = plotIn(width, height);
    const end = Date.now() + skew.current - BEHIND;
    const start = end - SPAN * 1000;
    const x = (at: number) => plot.left + ((at - start) / (SPAN * 1000)) * plot.width;

    // One point per whole second in view and one beyond each edge, so the
    // line runs off the plot instead of ending inside it.
    const points: [number, number][] = [];
    let highest = 0;
    const first = Math.floor(start / 1000) * 1000 - 1000;
    for (let at = first; at <= end + 1000; at += 1000) {
      const count = counts.current.get(at) ?? 0;
      highest = Math.max(highest, count);
      points.push([x(at + 500), count]);
    }
    const state = shown.current;
    state.top = approach(state.top, niceCeiling(highest * 1.15), elapsed, 600);
    const y = (count: number) => plot.top + plot.height - (count / state.top) * plot.height;

    const times = [120, 90, 60, 30, 0].map((ago) => ({
      x: x(end - ago * 1000),
      text: ago === 0 ? "now" : `-${ago}s`,
    }));
    drawGrid(context, plot, state.top, times, colors);

    const traced: [number, number][] = points.map(([px, count]) => [px, y(count)]);
    const [startX, startY] = traced[0] ?? [plot.left, plot.top + plot.height];
    context.save();
    context.beginPath();
    context.rect(plot.left, plot.top - 2, plot.width, plot.height + 4);
    context.clip();
    context.beginPath();
    context.moveTo(startX, plot.top + plot.height);
    traceMonotone(context, traced);
    context.lineTo(traced[traced.length - 1]?.[0] ?? plot.left, plot.top + plot.height);
    context.closePath();
    context.globalAlpha = 0.22;
    context.fillStyle = accent;
    context.fill();
    context.globalAlpha = 1;
    context.beginPath();
    context.moveTo(startX, startY);
    traceMonotone(context, traced);
    context.strokeStyle = accent;
    context.lineWidth = 1.5;
    context.stroke();
    context.restore();

    // The rate: the last five complete seconds, eased.
    const newest = Math.floor(end / 1000) * 1000 - 1000;
    let recent = 0;
    for (let ago = 0; ago < 5; ago += 1) {
      recent += counts.current.get(newest - ago * 1000) ?? 0;
    }
    state.rate = approach(state.rate, recent / 5, elapsed, 800);
    if (rate?.current) {
      rate.current.textContent = Math.round(state.rate).toLocaleString("en-US");
    }

    // The second under the pointer.
    const at = pointer.current;
    if (at && at.x >= plot.left && at.x <= plot.left + plot.width) {
      const second = Math.floor((start + ((at.x - plot.left) / plot.width) * SPAN * 1000) / 1000);
      const count = counts.current.get(second * 1000) ?? 0;
      const px = x(second * 1000 + 500);
      context.fillStyle = accent;
      context.beginPath();
      context.arc(px, y(count), 3.5, 0, Math.PI * 2);
      context.fill();
      const heading = new Date(second * 1000).toLocaleTimeString("en-GB");
      drawTooltip(
        context,
        at,
        { width, height },
        heading,
        [{ color: accent, name: "Events", count }],
        colors,
      );
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
