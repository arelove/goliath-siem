import { useEffect, useRef } from "react";
import type { Arrivals } from "../api";
import { approach, compact, niceCeiling, token, traceMonotone, useFrames } from "./canvas";

/** Seconds the chart spans. */
const SPAN = 120;
/**
 * How far behind the clock the chart draws, in milliseconds: a second is
 * complete only once its events are stored, about a second after it ends.
 */
const BEHIND = 2500;

interface Props {
  arrivals: Arrivals | undefined;
}

/**
 * Events stored each second over the last two minutes, drawn every frame:
 * the time axis moves continuously, and the scale eases to fit, so new
 * data slides in rather than jumping.
 */
export function LiveChart({ arrivals }: Props) {
  // Counts by second, and the server's clock less the browser's.
  const counts = useRef(new Map<number, number>());
  const skew = useRef(0);
  const shown = useRef({ top: 1, rate: 0 });
  // Written every frame without rendering again.
  const rateText = useRef<HTMLSpanElement>(null);

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
    const accent = token("--accent", "#3d7eff");
    const line = token("--line", "#262c35");
    const muted = token("--muted", "#8a94a3");
    const pad = { left: 44, right: 12, top: 12, bottom: 22 };
    const plotWidth = width - pad.left - pad.right;
    const plotHeight = height - pad.top - pad.bottom;
    const end = Date.now() + skew.current - BEHIND;
    const start = end - SPAN * 1000;
    const x = (at: number) => pad.left + ((at - start) / (SPAN * 1000)) * plotWidth;

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
    const y = (count: number) => pad.top + plotHeight - (count / state.top) * plotHeight;

    // Grid and labels.
    context.font = "11px system-ui, sans-serif";
    context.fillStyle = muted;
    context.strokeStyle = line;
    context.lineWidth = 1;
    context.textAlign = "right";
    context.textBaseline = "middle";
    for (let step = 0; step <= 4; step += 1) {
      const value = (state.top * step) / 4;
      const level = Math.round(y(value)) + 0.5;
      context.beginPath();
      context.moveTo(pad.left, level);
      context.lineTo(width - pad.right, level);
      context.stroke();
      context.fillText(compact(value), pad.left - 8, level);
    }
    context.textAlign = "center";
    context.textBaseline = "top";
    for (let ago = 0; ago <= SPAN; ago += 30) {
      const at = end - ago * 1000;
      context.fillText(ago === 0 ? "now" : `-${ago}s`, x(at), height - pad.bottom + 6);
    }

    // The line and the area under it, clipped to the plot.
    const traced: [number, number][] = points.map(([px, count]) => [px, y(count)]);
    context.save();
    context.beginPath();
    context.rect(pad.left, pad.top - 2, plotWidth, plotHeight + 4);
    context.clip();
    const fill = context.createLinearGradient(0, pad.top, 0, pad.top + plotHeight);
    fill.addColorStop(0, `${accent}66`);
    fill.addColorStop(1, `${accent}00`);
    context.beginPath();
    context.moveTo(traced[0]?.[0] ?? pad.left, pad.top + plotHeight);
    traceMonotone(context, traced);
    context.lineTo(traced[traced.length - 1]?.[0] ?? width, pad.top + plotHeight);
    context.closePath();
    context.fillStyle = fill;
    context.fill();
    context.beginPath();
    const [startX, startY] = traced[0] ?? [pad.left, pad.top + plotHeight];
    context.moveTo(startX, startY);
    traceMonotone(context, traced);
    context.strokeStyle = accent;
    context.lineWidth = 2;
    context.shadowColor = accent;
    context.shadowBlur = 8;
    context.stroke();
    context.restore();

    // The newest complete second, marked with a pulse.
    const newest = Math.floor(end / 1000) * 1000 - 1000;
    const newestCount = counts.current.get(newest) ?? 0;
    const pulse = (Math.sin(performance.now() / 300) + 1) / 2;
    context.beginPath();
    context.arc(x(newest + 500), y(newestCount), 3 + pulse * 2, 0, Math.PI * 2);
    context.fillStyle = accent;
    context.fill();

    // The rate: the last five complete seconds, eased.
    let recent = 0;
    for (let ago = 1; ago <= 5; ago += 1) {
      recent += counts.current.get(newest - (ago - 1) * 1000) ?? 0;
    }
    state.rate = approach(state.rate, recent / 5, elapsed, 800);
    if (rateText.current) {
      rateText.current.textContent = Math.round(state.rate).toLocaleString("en-US");
    }
  });

  return (
    <section className="panel live">
      <header>
        <h2>Events stored</h2>
        <p className="rate">
          <span ref={rateText}>0</span> <small>events/s</small>
        </p>
      </header>
      <canvas ref={canvas} className="chart" />
    </section>
  );
}
