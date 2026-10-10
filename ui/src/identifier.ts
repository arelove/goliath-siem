// How the interface reads an identifier and a link of the entity graph:
// see docs/adr/0025-entity-graph.md.

export type Kind = "user" | "host" | "address" | "domain" | "file";

const KINDS: readonly string[] = ["user", "host", "address", "domain", "file"];

/** An identifier taken apart: `kind:form:value`. */
export interface Named {
  kind: Kind;
  form: string;
  value: string;
}

/** The parts of an identifier, if the text is one. */
export function parts(identifier: string): Named | null {
  const first = identifier.indexOf(":");
  const second = identifier.indexOf(":", first + 1);
  if (first < 1 || second < 0 || second === identifier.length - 1) {
    return null;
  }
  const kind = identifier.slice(0, first);
  const form = identifier.slice(first + 1, second);
  if (!KINDS.includes(kind) || !/^[a-z]+$/.test(form)) {
    return null;
  }
  return { kind: kind as Kind, form, value: identifier.slice(second + 1) };
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:.]*$/;
const HASH = /^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$/;
const SID = /^s-1-\d+(-\d+)+$/;

/**
 * The identifiers a value may be, the likeliest first. A value says its
 * form but not always its kind: a name with dots is a machine or a domain,
 * and a bare name a machine or an account. An identifier is itself.
 */
export function candidates(written: string): string[] {
  const value = written.trim().toLowerCase();
  if (value === "") {
    return [];
  }
  if (parts(value)) {
    return [value];
  }
  if (IPV4.test(value) || IPV6.test(value)) {
    return [`address:ip:${value}`];
  }
  if (SID.test(value)) {
    return [`user:sid:${value}`];
  }
  if (HASH.test(value)) {
    return [`file:hash:${value}`];
  }
  if (value.includes("@")) {
    return [`user:email:${value}`];
  }
  if (value.includes("\\")) {
    return [`user:name:${value}`];
  }
  if (value.includes(".")) {
    return [`domain:name:${value}`, `host:name:${value}`];
  }
  return [`host:name:${value}`, `user:name:${value}`];
}

/** Each kind of link, as it reads from its source and from its target. */
const LINKS: Record<string, { out: string; in: string }> = {
  logged_on_to: { out: "logged on to", in: "logged on from" },
  ran_on: { out: "ran programs on", in: "programs run by" },
  ran: { out: "ran", in: "run by" },
  wrote: { out: "wrote", in: "written by" },
  connected_to: { out: "connected to", in: "connected from" },
  resolved: { out: "looked up", in: "looked up by" },
  resolved_to: { out: "resolved to", in: "address of" },
  held: { out: "held address", in: "held by" },
};

export const LINK_KINDS: readonly string[] = Object.keys(LINKS);

/** A link as a person reads it, from the side of the entity shown. */
export function reads(link: string, direction: string): string {
  const known = LINKS[link];
  if (!known) {
    return direction === "in" ? `${link} (from)` : link;
  }
  return direction === "in" ? known.in : known.out;
}

/** A kind of link by its name alone, for what is chosen. */
export function linkName(link: string): string {
  return LINKS[link]?.out ?? link;
}
