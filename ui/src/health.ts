import type { Status } from "./api";

/** How the interface shows each status, and what it means. */
export const STATUSES: Record<Status, { label: string; tone: string; meaning: string }> = {
  rejecting: {
    label: "Rejecting",
    tone: "bad",
    meaning: "Many of its records in the last hour could not be read.",
  },
  waiting: { label: "Waiting", tone: "warn", meaning: "No event of it has been stored yet." },
  silent: {
    label: "Silent",
    tone: "bad",
    meaning: "No event for longer than it may be quiet.",
  },
  low: {
    label: "Low",
    tone: "warn",
    meaning: "Under a quarter of its usual events for this hour.",
  },
  high: {
    label: "High",
    tone: "warn",
    meaning: "Over four times its usual events for this hour.",
  },
  learning: {
    label: "Learning",
    tone: "quiet",
    meaning: "Fewer than three days counted, so nothing to compare with yet.",
  },
  ok: { label: "OK", tone: "good", meaning: "Sending as usual." },
};

/** How long before `now` a time was, as people say it. */
export function ago(at: number | null, now: number): string {
  if (at === null) {
    return "never";
  }
  const seconds = Math.max(0, Math.floor((now - at) / 1000));
  if (seconds < 60) {
    return "just now";
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes} min ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 48) {
    return `${hours} h ago`;
  }
  return `${Math.floor(hours / 24)} days ago`;
}

/** The dead letters of a day, by stage, as one line. */
export function stages(byStage: Record<string, number>): string {
  return Object.entries(byStage)
    .filter(([, count]) => count > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([stage, count]) => `${stage} ${count}`)
    .join(", ");
}
