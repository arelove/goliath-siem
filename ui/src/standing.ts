import type { Flow, Standing } from "./api";

/** How the interface shows each standing. */
export const STANDINGS: Record<Standing, { label: string; tone: string }> = {
  ok: { label: "OK", tone: "good" },
  degraded: { label: "Degraded", tone: "warn" },
  failing: { label: "Failing", tone: "bad" },
};

/** What each question a condition answers is called. */
const QUESTIONS: Record<string, string> = {
  storing: "Storing events",
  storing_findings: "Storing findings",
  storing_graph: "Storing the graph",
  resolving: "Resolving entities",
  keeping_up: "Keeping up with",
  normalizing: "Normalizing",
  feeds_current: "Feed is current",
};

/**
 * A condition's type as people read it. A type may name what it is about
 * after a colon, such as `keeping_up:normalized`.
 */
export function question(type: string): { asks: string; of: string | null } {
  const at = type.indexOf(":");
  const name = at < 0 ? type : type.slice(0, at);
  return {
    asks: QUESTIONS[name] ?? name.replaceAll("_", " "),
    of: at < 0 ? null : type.slice(at + 1),
  };
}

/** How long a state has lasted at `now`, as people say it. */
export function lasting(since: number, now: number): string {
  const seconds = Math.max(0, Math.floor((now - since) / 1000));
  if (seconds < 60) {
    return `${seconds} s`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes} min`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 48) {
    return `${hours} h`;
  }
  return `${Math.floor(hours / 24)} days`;
}

/** The share of the longest backlog each flow has, from 0 to 1. */
export function shares(flows: Flow[]): number[] {
  const longest = Math.max(0, ...flows.map((flow) => flow.backlog));
  return flows.map((flow) => (longest === 0 ? 0 : flow.backlog / longest));
}
