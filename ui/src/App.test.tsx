import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { Found, Search } from "./api";

const LAUNCH: Found = {
  at: `1790330400000-${"ab".repeat(16)}`,
  class_uid: 1007,
  source: "sysmon",
  kind: "process_creation",
  event: {
    time: 1790330400000,
    class_uid: 1007,
    device: { hostname: "ws-7" },
    actor: { user: { name: "alice" } },
    process: { cmd_line: "powershell -enc AAAA", pid: 4242 },
    observables: [{ value: "x" }],
  },
};

interface Call {
  path: string;
  body: Search | null;
  authorization: string | null;
}

let calls: Call[] = [];
let requireToken: string | null = null;

function reply(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

beforeEach(() => {
  calls = [];
  requireToken = null;
  sessionStorage.clear();
  window.history.replaceState(null, "", "/");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const path = input.replace("/api/v1", "");
      const headers = new Headers(init?.headers);
      const body = init?.body ? (JSON.parse(String(init.body)) as Search) : null;
      calls.push({ path, body, authorization: headers.get("authorization") });
      if (requireToken && headers.get("authorization") !== `Bearer ${requireToken}`) {
        return reply(401, { error: "a valid bearer token is needed" });
      }
      if (path === "/schema/classes") {
        return reply(200, { classes: [{ uid: 1007, name: "process_activity" }] });
      }
      if (path.startsWith("/schema/classes/")) {
        return reply(200, { paths: [{ path: "process.cmd_line", holds: "text" }] });
      }
      if (path === "/search") {
        return reply(200, { events: [LAUNCH], next: null });
      }
      if (path.startsWith("/events/")) {
        return reply(200, { ...LAUNCH, source_version: 1, issues: [] });
      }
      return reply(404, { error: "no such route" });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>,
  );
}

describe("the search view", () => {
  it("shows what a search finds, one row an event", async () => {
    show();
    expect(await screen.findByText("powershell -enc AAAA")).toBeInTheDocument();
    expect(screen.getByText("ws-7")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("Process Activity")).toBeInTheDocument();
    const searched = calls.find((call) => call.path === "/search");
    expect(searched?.body?.limit).toBe(200);
  });

  it("opens an event, and turns a value into a filter", async () => {
    const user = userEvent.setup();
    show();
    await user.click(await screen.findByText("powershell -enc AAAA"));
    expect(await screen.findByText(/definition version 1/)).toBeInTheDocument();
    // Values inside lists cannot be searched, so they offer no filter.
    expect(screen.queryByLabelText("Filter on observables.value")).not.toBeInTheDocument();

    await user.click(screen.getByLabelText("Filter on process.pid"));
    await waitFor(() => {
      const last = calls.filter((call) => call.path === "/search").at(-1);
      expect(last?.body?.filters).toEqual([{ path: "process.pid", op: "equals", value: 4242 }]);
    });
    expect(window.location.search).toContain("f=process.pid%7Cequals%7C4242");
  });

  it("asks for a token when the API wants one, and sends it", async () => {
    requireToken = "t".repeat(32);
    const user = userEvent.setup();
    show();
    await user.type(await screen.findByLabelText("Token"), requireToken);
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText("powershell -enc AAAA")).toBeInTheDocument();
    expect(calls.at(-1)?.authorization).toBe(`Bearer ${requireToken}`);
  });

  it("sends the filters written in the search bar", async () => {
    const user = userEvent.setup();
    show();
    await screen.findByText("powershell -enc AAAA");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    await user.type(screen.getByLabelText("Attribute"), "process.cmd_line");
    await user.type(screen.getByLabelText("Value"), "-enc");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => {
      const last = calls.filter((call) => call.path === "/search").at(-1);
      expect(last?.body?.filters).toEqual([
        { path: "process.cmd_line", op: "contains", value: "-enc" },
      ]);
    });
  });
});
