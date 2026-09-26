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
