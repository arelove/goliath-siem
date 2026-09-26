// A search as the interface holds it, and as the address bar keeps it, so
// that a search can be shared as a link.

import type { Filter, Op, Scalar, Search } from "./api";

/** A time range: relative to now, such as the last hour, or fixed. */
export type Range = { last: string } | { from: string; to: string };

/** A search as the person writes it; values stay text until it runs. */
export interface Draft {
  range: Range;
  classUid: number | null;
  filters: DraftFilter[];
}

export interface DraftFilter {
  path: string;
  op: Op;
  value: string;
}

export const LAST: Record<string, number> = {
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  "7d": 7 * 24 * 60 * 60_000,
  "30d": 30 * 24 * 60 * 60_000,
};

export const EMPTY: Draft = { range: { last: "24h" }, classUid: null, filters: [] };

const OPS: readonly Op[] = [
  "equals",
  "not_equals",
  "contains",
  "starts_with",
  "ends_with",
  "in",
  "gt",
  "gte",
  "lt",
  "lte",
  "exists",
  "missing",
];

function isOp(text: string): text is Op {
  return (OPS as readonly string[]).includes(text);
}

/** Reads a draft from the address's query string. Unknown parts are ignored. */
export function fromParams(params: URLSearchParams): Draft {
  const last = params.get("last");
  const from = params.get("from");
  const to = params.get("to");
  const range: Range = from && to ? { from, to } : { last: last && last in LAST ? last : "24h" };
  const classText = params.get("class");
  const classUid = classText && /^\d+$/.test(classText) ? Number(classText) : null;
  const filters: DraftFilter[] = [];
  for (const written of params.getAll("f")) {
    const [path, op, ...rest] = written.split("|");
    if (path && op && isOp(op)) {
      filters.push({ path, op, value: rest.join("|") });
    }
  }
  return { range, classUid, filters };
}

/** Writes a draft into a query string that `fromParams` reads back. */
export function toParams(draft: Draft): URLSearchParams {
  const params = new URLSearchParams();
  if ("last" in draft.range) {
    params.set("last", draft.range.last);
  } else {
    params.set("from", draft.range.from);
    params.set("to", draft.range.to);
  }
  if (draft.classUid !== null) {
    params.set("class", String(draft.classUid));
  }
  for (const filter of draft.filters) {
    params.append("f", `${filter.path}|${filter.op}|${filter.value}`);
  }
  return params;
}

/**
 * A value as the API takes it: a number or a boolean where the text is one
 * and the attribute is not text, a list for `in`, nothing for `exists`.
 */
export function apiValue(filter: DraftFilter, holdsText: boolean): Scalar | Scalar[] | undefined {
  if (filter.op === "exists" || filter.op === "missing") {
    return undefined;
  }
  const one = (text: string): Scalar => {
    const trimmed = text.trim();
    if (!holdsText) {
      if (trimmed === "true" || trimmed === "false") {
        return trimmed === "true";
      }
      // Decimal only: Number() would also read `0x10` and `1e3`.
      if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
        return Number(trimmed);
      }
    }
    return text;
  };
  if (filter.op === "in") {
    return filter.value
      .split(",")
      .map((part) => part.trim())
      .filter((part) => part !== "")
      .map(one);
  }
  return one(filter.value);
}

/** The search a draft asks for, at `now`. */
export function toSearch(
  draft: Draft,
  holdsText: (path: string) => boolean,
  now: Date = new Date(),
): Search {
  let from: string;
  let to: string;
  if ("last" in draft.range) {
    const span = LAST[draft.range.last] ?? LAST["24h"] ?? 0;
    to = now.toISOString();
    from = new Date(now.getTime() - span).toISOString();
  } else {
    from = draft.range.from;
    to = draft.range.to;
  }
  const filters: Filter[] = draft.filters
    .filter((filter) => filter.path.trim() !== "")
    .map((filter) => {
      const value = apiValue(filter, holdsText(filter.path));
      return value === undefined
        ? { path: filter.path.trim(), op: filter.op }
        : { path: filter.path.trim(), op: filter.op, value };
    });
  return {
    from,
    to,
    ...(draft.classUid !== null ? { classes: [draft.classUid] } : {}),
    ...(filters.length > 0 ? { filters } : {}),
    limit: 200,
  };
}
