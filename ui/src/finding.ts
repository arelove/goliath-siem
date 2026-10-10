// What the queue and the panel read of a finding: an OCSF Detection
// Finding as the detector writes it, see crates/goliath-intel.

import type { Found, OcsfEvent } from "./api";
import { at } from "./summary";

/** How the interface shows each `severity_id` a finding may have. */
export const LEVELS: { id: number; name: string; tone: string }[] = [
  { id: 6, name: "Fatal", tone: "critical" },
  { id: 5, name: "Critical", tone: "critical" },
  { id: 4, name: "High", tone: "high" },
  { id: 3, name: "Medium", tone: "medium" },
  { id: 2, name: "Low", tone: "low" },
  { id: 1, name: "Informational", tone: "info" },
];

const UNKNOWN = { id: 0, name: "Unknown", tone: "" };

export function level(severity: number): { id: number; name: string; tone: string } {
  return LEVELS.find((entry) => entry.id === severity) ?? { ...UNKNOWN, id: severity };
}

/** What one feed asserts of the indicator. */
export interface Assertion {
  feed: string;
  version: string;
  confidence: number | null;
  firstSeen: number | null;
  lastSeen: number | null;
}

/** What the site knows of something the event names. */
export interface Enrichment {
  /** The kind of thing, such as `hostname`. */
  name: string;
  value: string;
  /** The kind of record, such as `asset`. */
  type: string;
  provider: string;
  data: [string, string][];
}

/** The event a finding was made of. */
export interface Evidence {
  /** Where the event is, for `GET /events/{at}`, if the finding says. */
  at: string | null;
  classUid: number | null;
  /** The attribute of the event that held the value. */
  path: string;
}

export interface Finding {
  at: string;
  time: number | null;
  severity: number;
  title: string;
  message: string;
  /** The kind of indicator, such as `domain`. */
  kind: string;
  /** The value that matched. */
  value: string;
  confidence: number | null;
  /** Why it is not an alert, if an allowlist suppressed it. */
  suppressed: string | null;
  assertions: Assertion[];
  enrichments: Enrichment[];
  evidence: Evidence;
}

function text(value: unknown): string {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean"
    ? String(value)
    : "";
}

function number(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function list(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is Record<string, unknown> =>
          item !== null && typeof item === "object" && !Array.isArray(item),
      )
    : [];
}

/** Seconds since the epoch, as the feeds give times, in milliseconds. */
function seconds(value: unknown): number | null {
  const count = number(value);
  return count === null ? null : count * 1000;
}

function shown(value: unknown): string {
  if (Array.isArray(value)) {
    return value.map(shown).join(", ");
  }
  return value !== null && typeof value === "object" ? JSON.stringify(value) : text(value);
}

function evidence(event: OcsfEvent): Evidence {
  const first = list(event.evidences)[0] ?? {};
  const data = (first.data ?? {}) as Record<string, unknown>;
  const uid = text(first.uid);
  const time = number(data.time);
  return {
    at: time !== null && /^[0-9a-f]{32}$/.test(uid) ? `${time}-${uid}` : null,
    classUid: number(data.class_uid),
    path: text(first.name),
  };
}

/** A finding as the interface reads it. What is absent is empty, not a failure. */
export function read(found: Found): Finding {
  const event = found.event;
  const observable = list(event.observables)[0] ?? {};
  const assertions = list(at(event, "unmapped.assertions")).map((entry) => ({
    feed: text(entry.feed),
    version: text(entry.version),
    confidence: number(entry.confidence),
    firstSeen: seconds(entry.first_seen),
    lastSeen: seconds(entry.last_seen),
  }));
  const suppressed = event.is_alert === false || event.status_id === 3;
  return {
    at: found.at,
    time: number(event.time),
    severity: number(event.severity_id) ?? 0,
    title: text(at(event, "finding_info.title")) || text(event.message) || "Finding",
    message: text(event.message),
    kind: text(at(event, "unmapped.indicator_kind")),
    value: text(at(event, "unmapped.indicator_value")) || text(observable.value),
    confidence: number(event.confidence_score),
    suppressed: suppressed ? text(event.status_detail) || "Suppressed" : null,
    assertions,
    enrichments: list(event.enrichments).map((entry) => ({
      name: text(entry.name),
      value: text(entry.value),
      type: text(entry.type),
      provider: text(entry.provider),
      data: Object.entries((entry.data ?? {}) as Record<string, unknown>).map(
        ([key, value]): [string, string] => [key, shown(value)],
      ),
    })),
    evidence: evidence(event),
  };
}

/** The findings of `all` that name the value `finding` does, but for itself. */
export function sameValue(all: Finding[], finding: Finding): Finding[] {
  return finding.value === ""
    ? []
    : all.filter((other) => other.at !== finding.at && other.value === finding.value);
}
