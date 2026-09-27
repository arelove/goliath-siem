import { useRef, useState } from "react";
import type { Frequent } from "../api";
import { approach, compact, PALETTE, token, useFrames } from "./canvas";

interface Props {
  title: string;
  entries: Frequent[];
  /** A readable name for a key, such as a class's name for its uid. */
  label?: (key: string) => string;
}

/**
 * Shares of the most frequent values, as a ring. Shares ease toward each
 * fetch, and the segment under the pointer stands out.
 */
export function Donut({ title, entries, label = (key) => key }: Props) {
  const shown = useRef(new Map<string, number>());
  const lift = useRef(new Map<string, number>());
  const pointer = useRef<{ x: number; y: number } | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const hoveredRef = useRef<string | null>(null);

  const canvas = useFrames(({ context, width, height }, elapsed) => {
    const panel = token("--panel", "#161a20");
    const text = token("--text", "#d8dee6");
    const muted = token("--muted", "#8a94a3");
    const keys = new Set(entries.map((entry) => entry.key));
    for (const entry of entries) {
      shown.current.set(
        entry.key,
        approach(shown.current.get(entry.key) ?? 0, entry.count, elapsed, 600),
      );
    }
    for (const [key, value] of shown.current) {
      if (!keys.has(key)) {
        const next = approach(value, 0, elapsed, 400);
        if (next === 0) {
          shown.current.delete(key);
        } else {
          shown.current.set(key, next);
        }
      }
    }
    const order = [...shown.current.keys()];
    const total = [...shown.current.values()].reduce((sum, value) => sum + value, 0);
    const centerX = width / 2;
    const centerY = height / 2;
    const outer = Math.min(width, height) / 2 - 8;
    const inner = outer * 0.68;

    // Which segment the pointer is over, by its angle within the ring.
    let over: string | null = null;
    const at = pointer.current;
    if (at && total > 0) {
      const distance = Math.hypot(at.x - centerX, at.y - centerY);
      if (distance >= inner && distance <= outer + 6) {
        let angle = Math.atan2(at.y - centerY, at.x - centerX) + Math.PI / 2;
        if (angle < 0) {
          angle += Math.PI * 2;
        }
        let from = 0;
        for (const key of order) {
          const sweep = ((shown.current.get(key) ?? 0) / total) * Math.PI * 2;
          if (angle >= from && angle < from + sweep) {
            over = key;
            break;
          }
          from += sweep;
        }
      }
    }
    if (over !== hoveredRef.current) {
      hoveredRef.current = over;
      setHovered(over);
    }

    context.beginPath();
    context.arc(centerX, centerY, (outer + inner) / 2, 0, Math.PI * 2);
    context.strokeStyle = token("--line", "#262c35");
    context.lineWidth = outer - inner;
    context.stroke();

    let from = -Math.PI / 2;
    order.forEach((key, index) => {
      const value = shown.current.get(key) ?? 0;
      const sweep = total > 0 ? (value / total) * Math.PI * 2 : 0;
      const raised = approach(lift.current.get(key) ?? 0, key === over ? 6 : 0, elapsed, 150);
      lift.current.set(key, raised);
      const middle = from + sweep / 2;
      const shiftX = Math.cos(middle) * raised;
      const shiftY = Math.sin(middle) * raised;
      context.beginPath();
      context.arc(centerX + shiftX, centerY + shiftY, outer, from, from + sweep);
      context.arc(centerX + shiftX, centerY + shiftY, inner, from + sweep, from, true);
      context.closePath();
      context.fillStyle = colorOf(entries, key, index);
      context.fill();
      context.strokeStyle = panel;
      context.lineWidth = 2;
      context.stroke();
      from += sweep;
    });

    // The total, or the hovered share, in the middle.
    const focus = over === null ? null : (shown.current.get(over) ?? 0);
    context.textAlign = "center";
    context.textBaseline = "middle";
    context.fillStyle = text;
    context.font = "600 20px system-ui, sans-serif";
    context.fillText(
      focus === null ? compact(total) : `${Math.round((focus / Math.max(total, 1)) * 100)}%`,
      centerX,
      centerY - 6,
    );
    context.fillStyle = muted;
    context.font = "11px system-ui, sans-serif";
    context.fillText(focus === null ? "events" : compact(focus), centerX, centerY + 14);
  });

  return (
    <section className="panel donut">
      <h2>{title}</h2>
      <div className="donut-body">
        <canvas
          ref={canvas}
          className="ring"
          onPointerMove={(event) => {
            const box = event.currentTarget.getBoundingClientRect();
            pointer.current = { x: event.clientX - box.left, y: event.clientY - box.top };
          }}
          onPointerLeave={() => {
            pointer.current = null;
          }}
        />
        <ul className="legend">
          {entries.map((entry, index) => (
            <li key={entry.key} className={hovered === entry.key ? "hovered" : undefined}>
              <span className="swatch" style={{ background: colorOf(entries, entry.key, index) }} />
              <span className="name" title={label(entry.key)}>
                {label(entry.key)}
              </span>
              <span className="count">{compact(entry.count)}</span>
            </li>
          ))}
        </ul>
      </div>
      {entries.length === 0 && <p className="note">Nothing in this range.</p>}
    </section>
  );
}

/** A value's colour: by its place in the current list, stable while it stays. */
function colorOf(entries: Frequent[], key: string, fallback: number): string {
  const index = entries.findIndex((entry) => entry.key === key);
  return PALETTE[(index === -1 ? fallback : index) % PALETTE.length] ?? "#5b6573";
}
