// The goliath API, as docs/adr/0016-event-search.md defines it.

export type Op =
  | "equals"
  | "not_equals"
  | "contains"
  | "starts_with"
  | "ends_with"
  | "in"
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "exists"
  | "missing";

export type Scalar = string | number | boolean;

export interface Filter {
  path: string;
  op: Op;
  value?: Scalar | Scalar[];
}

export interface Search {
  from: string;
  to: string;
  classes?: number[];
  filters?: Filter[];
  limit?: number;
  after?: string;
}

/** An OCSF event, as normalized. */
export type OcsfEvent = { [key: string]: unknown };

export interface Found {
  at: string;
  class_uid: number;
  source: string;
  kind: string;
  event: OcsfEvent;
}

export interface Page {
  events: Found[];
  next: string | null;
}

export interface Issue {
  target: string;
  source: string;
  reason: string;
}

export interface Stored extends Found {
  source_version: number;
  issues: Issue[];
}

export interface ClassInfo {
  uid: number;
  name: string;
}

/** What an attribute holds, as far as a search compares it. */
export type Holds = "text" | "integer" | "number" | "time" | "boolean" | "object" | "any";

export interface PathInfo {
  path: string;
  holds: Holds;
  values?: number[];
}

/** A refusal or failure the API reported, with its message for people. */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const TOKEN_KEY = "goliath.token";

/** The token for this tab, if one was given. Kept for the session only. */
export function token(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(value: string | null): void {
  try {
    if (value) {
      sessionStorage.setItem(TOKEN_KEY, value);
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
    }
  } catch {
    // Storage may be unavailable; the token then lasts until reload.
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const bearer = token();
  if (bearer) {
    headers.set("Authorization", `Bearer ${bearer}`);
  }
  if (init.body) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`/api/v1${path}`, { ...init, headers });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message =
      body && typeof body === "object" && "error" in body && typeof body.error === "string"
        ? body.error
        : `the API answered ${response.status}`;
    throw new ApiError(response.status, message);
  }
  return body as T;
}

export function search(query: Search, signal?: AbortSignal): Promise<Page> {
  return request<Page>("/search", {
    method: "POST",
    body: JSON.stringify(query),
    ...(signal ? { signal } : {}),
  });
}

export function event(at: string): Promise<Stored> {
  return request<Stored>(`/events/${encodeURIComponent(at)}`);
}

export async function classes(): Promise<ClassInfo[]> {
  const body = await request<{ classes: ClassInfo[] }>("/schema/classes");
  return body.classes;
}

export async function paths(classUid: number): Promise<PathInfo[]> {
  const body = await request<{ paths: PathInfo[] }>(`/schema/classes/${classUid}/paths`);
  return body.paths;
}

/** The operators that apply to what an attribute holds. */
export function operators(holds: Holds): Op[] {
  switch (holds) {
    case "text":
      return [
        "contains",
        "equals",
        "not_equals",
        "starts_with",
        "ends_with",
        "in",
        "exists",
        "missing",
      ];
    case "integer":
    case "number":
    case "time":
      return ["equals", "not_equals", "gt", "gte", "lt", "lte", "in", "exists", "missing"];
    case "boolean":
      return ["equals", "not_equals", "exists", "missing"];
    case "object":
      return ["exists", "missing"];
    case "any":
      return [
        "contains",
        "equals",
        "not_equals",
        "starts_with",
        "ends_with",
        "gt",
        "lt",
        "exists",
        "missing",
      ];
  }
}

/** A value and how many events hold it. */
export interface Frequent {
  key: string;
  count: number;
}

/** Events in one step of an overview, by a key such as `severity_id` or host. */
export interface Step {
  at: number;
  counts: Record<string, number>;
}

export interface Overview {
  from: number;
  to: number;
  step_ms: number;
  total: number;
  dead_letters: number;
  series: Step[];
  classes: Frequent[];
  sources: Frequent[];
  hosts: Frequent[];
  /** The events of `hosts` by step, keyed by host. */
  host_series: Step[];
  users: Frequent[];
}

export interface Arrivals {
  /** The server's clock, in milliseconds since the epoch. */
  now: number;
  seconds: { at: number; count: number }[];
}

export function overview(from: string, to: string, signal?: AbortSignal): Promise<Overview> {
  return request<Overview>("/overview", {
    method: "POST",
    body: JSON.stringify({ from, to }),
    ...(signal ? { signal } : {}),
  });
}

export function arrivals(signal?: AbortSignal): Promise<Arrivals> {
  return request<Arrivals>("/arrivals", signal ? { signal } : {});
}

/** What a source's numbers say; see docs/adr/0019-source-health.md. */
export type Status = "rejecting" | "waiting" | "silent" | "low" | "high" | "learning" | "ok";

/** The health of one source. */
export interface SourceHealth {
  source: string;
  status: Status;
  /** When its last event was received, in milliseconds since the epoch. */
  last_event: number | null;
  /** The start of the last complete hour, in milliseconds since the epoch. */
  hour: number;
  /** Its events in that hour. */
  last_hour: number;
  /** The median of its events in the same hour of the seven days before. */
  baseline: number | null;
  silent_after_minutes: number;
  dead_letters: {
    last_hour: number;
    /** The last 24 complete hours, by stage. */
    last_day: Record<string, number>;
    last: number | null;
  };
}

export interface Sources {
  /** The server's clock, in milliseconds since the epoch. */
  now: number;
  /** The sources needing attention first. */
  sources: SourceHealth[];
}

export function sources(signal?: AbortSignal): Promise<Sources> {
  return request<Sources>("/sources", signal ? { signal } : {});
}

/** How well a thing is going, as the platform judges it. */
export type Standing = "ok" | "degraded" | "failing";

/** The answer to one question about one thing a role does. */
export interface Condition {
  role: string;
  /** The question, such as `storing` or `keeping_up:normalized`. */
  type: string;
  status: Standing;
  /** A word for machines. */
  reason: string;
  /** A sentence for people. */
  message: string;
  /** When the status began, in milliseconds since the epoch. */
  since: number;
}

/** One process that runs a role. */
export interface Instance {
  instance: string;
  /** Whether its newest report is younger than a minute. */
  reporting: boolean;
  version: string;
  started: number;
  last_report: number;
  conditions: Condition[];
}

/** One role, judged from the processes that run it. */
export interface RoleHealth {
  role: string;
  status: Standing;
  reason: string;
  message: string;
  reporting: number;
  /** Processes that ran it at once within the last day. */
  expected: number;
  /** Starts of a process that runs it, in the last ten minutes. */
  starts: number;
  instances: Instance[];
}

/** What one reader of one topic has still to read. */
export interface Flow {
  topic: string;
  reader: string;
  backlog: number;
}

/** A time through which a condition's status held. */
export interface Change {
  instance: string;
  role: string;
  kind: string;
  status: Standing;
  reason: string;
  message: string;
  since: number;
  seen: number;
}

export interface PlatformHealth {
  /** The server's clock, in milliseconds since the epoch. */
  now: number;
  /** Whether the store answered the question. */
  store: "answers" | "silent";
  platform: {
    status: Standing;
    reason: string;
    message: string;
    newest_report: number | null;
    /** The worst first. */
    roles: RoleHealth[];
    /** The longest backlog first. */
    flows: Flow[];
    /** The newest first. */
    changes: Change[];
  };
}

export function platform(signal?: AbortSignal): Promise<PlatformHealth> {
  return request<PlatformHealth>("/platform", signal ? { signal } : {});
}
