// What a row of results shows of an event: the few attributes an analyst
// reads first, whichever class it is.

import type { OcsfEvent } from "./api";

/** The value at a dotted path, if there is one. */
export function at(event: OcsfEvent, path: string): unknown {
  let value: unknown = event;
  for (const segment of path.split(".")) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return undefined;
    }
    value = (value as Record<string, unknown>)[segment];
  }
  return value;
}

/** Tried in order; the first present is the event's summary. */
const SUMMARY = [
  "finding_info.title",
  "process.cmd_line",
  "actor.process.cmd_line",
  "file.path",
  "module.file.path",
  "reg_value.path",
  "dst_endpoint.ip",
  "user.name",
  "message",
] as const;

/** Who or what acted. */
const ACTOR = ["actor.user.name", "process.user.name", "user.name", "actor.process.name"] as const;

/** Where it happened. */
const HOST = ["device.hostname", "device.name", "src_endpoint.ip"] as const;

function first(event: OcsfEvent, paths: readonly string[]): string {
  for (const path of paths) {
    const value = at(event, path);
    if (typeof value === "string" && value !== "") {
      return value;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
  }
  return "";
}

export interface Summary {
  host: string;
  actor: string;
  what: string;
}

export function summarize(event: OcsfEvent): Summary {
  return { host: first(event, HOST), actor: first(event, ACTOR), what: first(event, SUMMARY) };
}

/** A class name as people read it: `process_activity` as Process Activity. */
export function className(name: string): string {
  return name
    .split("_")
    .map((word) => (word ? (word[0] ?? "").toUpperCase() + word.slice(1) : word))
    .join(" ");
}

/** A time in milliseconds as local ISO-like text, to the millisecond. */
export function when(milliseconds: unknown): string {
  if (typeof milliseconds !== "number") {
    return "";
  }
  const date = new Date(milliseconds);
  const pad = (value: number, width = 2) => String(value).padStart(width, "0");
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.` +
    pad(date.getMilliseconds(), 3)
  );
}
