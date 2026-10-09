import { useRef, useState } from "react";
import type { Frequent } from "../api";
import { approach, compact, ink, PALETTE, useFrames } from "./canvas";

interface Props {
  entries: Frequent[];
  /** A readable name for a key, such as a class's name for its uid. */
  label?: (key: string) => string;
}

/**
 * Shares of the most frequent values as a ring, with a legend beside it.
 * Shares ease toward each fetch; the segment under the pointer, or the
 * legend entry, stands out, and the centre says its share.
 */
export function Donut({ entries, label = (key) => key }: Props) {
  const shown = useRef(new Map<string, number>());
  const lift = useRef(new Map<string, number>());
  const pointer = useRef<{ x: number; y: number } | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const hoveredRef = useRef<string | null>(null);
  const picked = useRef<string | null>(null);
  const total = entries.reduce((sum, entry) => sum + entry.count, 0);

  const canvas = useFrames(({ context, width, height }, elapsed) => {
    const colors = ink();
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
    const sum = [...shown.current.values()].reduce((all, value) => all + value, 0);
    const centerX = width / 2;
    const centerY = height / 2;
    const outer = Math.min(width, height) / 2 - 6;
    const inner = outer - Math.max(14, outer * 0.22);

    // The segment under the pointer, by its angle within the ring.
    let over: string | null = picked.current;
    const at = pointer.current;
    if (at && sum > 0) {
      over = null;
      const distance = Math.hypot(at.x - centerX, at.y - centerY);
      if (distance >= inner - 4 && distance <= outer + 6) {
        let angle = Math.atan2(at.y - centerY, at.x - centerX) + Math.PI / 2;
        if (angle < 0) {
          angle += Math.PI * 2;
        }
        let from = 0;
        for (const key of order) {
          const sweep = ((shown.current.get(key) ?? 0) / sum) * Math.PI * 2;
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

    let from = -Math.PI / 2;
    for (const key of order) {
      const value = shown.current.get(key) ?? 0;
      const sweep = sum > 0 ? (value / sum) * Math.PI * 2 : 0;
      const raised = approach(lift.current.get(key) ?? 0, key === over ? 4 : 0, elapsed, 150);
      lift.current.set(key, raised);
      context.beginPath();
      context.arc(centerX, centerY, outer + raised, from, from + sweep);
      context.arc(centerX, centerY, inner - raised / 2, from + sweep, from, true);
      context.closePath();
      context.globalAlpha = over === null || key === over ? 1 : 0.45;
      context.fillStyle = colorOf(entries, key);
      context.fill();
      from += sweep;
    }
    context.globalAlpha = 1;

    const focus = over === null ? null : (shown.current.get(over) ?? 0);
    context.textAlign = "center";
    context.textBaseline = "middle";
    context.fillStyle = colors.text;
    context.font = "600 18px system-ui, sans-serif";
    context.fillText(
      focus === null ? compact(sum) : `${((focus / Math.max(sum, 1)) * 100).toFixed(1)}%`,
      centerX,
      centerY - 7,
    );
    context.fillStyle = colors.muted;
    context.font = "11px system-ui, sans-serif";
    context.fillText(focus === null ? "events" : `${compact(focus)} events`, centerX, centerY + 12);
  });

  // The canvas is there from the first render, shown or not: the frames
  // are started once, and a canvas that came later would never be drawn.
  const empty = entries.length === 0;
  return (
    <div className="donut">
      {empty && <p className="note">Nothing in this range.</p>}
      <canvas
        ref={canvas}
        className="ring"
        hidden={empty}
        onPointerMove={(event) => {
          const box = event.currentTarget.getBoundingClientRect();
          pointer.current = { x: event.clientX - box.left, y: event.clientY - box.top };
        }}
        onPointerLeave={() => {
          pointer.current = null;
        }}
      />
      <ul className="legend">
        {entries.map((entry) => (
          <li
            key={entry.key}
            className={hovered === entry.key ? "hovered" : undefined}
            onPointerEnter={() => {
              picked.current = entry.key;
            }}
            onPointerLeave={() => {
              picked.current = null;
            }}
          >
            <span className="dot" style={{ background: colorOf(entries, entry.key) }} />
            <span className="name" title={label(entry.key)}>
              {label(entry.key)}
            </span>
            <span className="count">{compact(entry.count)}</span>
            <span className="share">{((entry.count / Math.max(total, 1)) * 100).toFixed(0)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** A value's colour, by its place in the current list. */
export function colorOf(entries: Frequent[], key: string): string {
  const index = Math.max(
    0,
    entries.findIndex((entry) => entry.key === key),
  );
  return PALETTE[index % PALETTE.length] ?? "#98989d";
}
