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

const OVERVIEW = {
  from: 1790326800000,
  to: 1790330400000,
  step_ms: 30000,
  total: 1234,
  dead_letters: 2,
  series: [{ at: 1790330370000, counts: { "1": 1200, "4": 34 } }],
  classes: [{ key: "1007", count: 1234 }],
  sources: [{ key: "sysmon", count: 1234 }],
  hosts: [{ key: "ws-7", count: 900 }],
  host_series: [{ at: 1790330370000, counts: { "ws-7": 900 } }],
  users: [{ key: "alice", count: 800 }],
};

const SOURCES = {
  now: 1790598600000,
  sources: [
    {
      source: "zeek",
      status: "silent",
      last_event: 1790588000000,
      hour: 1790593200000,
      last_hour: 0,
      baseline: 1500,
      silent_after_minutes: 60,
      dead_letters: { last_hour: 0, last_day: {}, last: null },
    },
    {
      source: "sysmon",
      status: "ok",
      last_event: 1790598590000,
      hour: 1790593200000,
      last_hour: 12000,
      baseline: 11000,
      silent_after_minutes: 60,
      dead_letters: { last_hour: 3, last_day: { decoding: 5 }, last: 1790598000000 },
    },
  ],
};

const PLATFORM = {
  now: 1790598600000,
  store: "answers",
  platform: {
    status: "failing",
    reason: "writer:store_refused",
    message: "The store refused the last batch, which is held and tried again.",
    newest_report: 1790598590000,
    roles: [
      {
        role: "writer",
        status: "failing",
        reason: "store_refused",
        message: "The store refused the last batch, which is held and tried again.",
        reporting: 1,
        expected: 2,
        starts: 0,
        instances: [
          {
            instance: "writer-0",
            reporting: true,
            version: "0.1.0",
            started: 1790591400000,
            last_report: 1790598590000,
            conditions: [
              {
                role: "writer",
                type: "keeping_up:normalized",
                status: "degraded",
                reason: "backlog_grows",
                message: "The backlog of `normalized` grew.",
                since: 1790598300000,
              },
            ],
          },
          {
            instance: "writer-1",
            reporting: false,
            version: "0.1.0",
            started: 1790591400000,
            last_report: 1790598000000,
            conditions: [],
          },
        ],
      },
    ],
    flows: [
      { topic: "normalized", reader: "writer", backlog: 4200 },
      { topic: "findings", reader: "writer", backlog: 0 },
    ],
    changes: [
      {
        instance: "writer-0",
        role: "writer",
        kind: "storing",
        status: "failing",
        reason: "store_refused",
        message: "The store refused the last batch.",
        since: 1790598480000,
        seen: 1790598590000,
      },
    ],
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
  window.history.replaceState(null, "", "/?view=search");
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
      if (path === "/overview") {
        return reply(200, OVERVIEW);
      }
      if (path === "/arrivals") {
        return reply(200, { now: 1790330460000, seconds: [{ at: 1790330455000, count: 12 }] });
      }
      if (path === "/sources") {
        return reply(200, SOURCES);
      }
      if (path === "/platform") {
        return reply(200, PLATFORM);
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

describe("the overview", () => {
  it("opens by default and shows what the stored events add up to", async () => {
    window.history.replaceState(null, "", "/");
    show();
    // Each appears in a chart's legend or list and in the recent events.
    await waitFor(() => {
      expect(screen.getByText("powershell -enc AAAA")).toBeInTheDocument();
    });
    expect(screen.getAllByText("ws-7").length).toBeGreaterThan(1);
    expect(screen.getAllByText("alice").length).toBeGreaterThan(1);
    expect(screen.getAllByText("Process Activity").length).toBeGreaterThan(1);
    const asked = calls.find((call) => call.path === "/overview");
    expect(asked?.body).toMatchObject({ from: expect.any(String), to: expect.any(String) });
    // The recent events table asks for Medium and above.
    await waitFor(() => {
      const recent = calls.find((call) => call.path === "/search");
      expect(recent?.body?.filters).toEqual([{ path: "severity_id", op: "gte", value: 3 }]);
    });
  });

  it("asks for another range when one is picked", async () => {
    window.history.replaceState(null, "", "/");
    const user = userEvent.setup();
    show();
    await screen.findAllByText("ws-7");
    await user.selectOptions(screen.getByLabelText("Time range"), "Last hour");
    await waitFor(() => {
      const spans = calls
        .filter((call) => call.path === "/overview" && call.body)
        .map((call) => {
          const body = call.body as unknown as { from: string; to: string };
          return Date.parse(body.to) - Date.parse(body.from);
        });
      expect(spans).toContain(3_600_000);
    });
  });
});

describe("source health", () => {
  it("lists the sources, the ones needing attention first", async () => {
    window.history.replaceState(null, "", "/?view=sources");
    show();
    const silent = await screen.findByText("Silent");
    expect(silent.closest("span")).toHaveAttribute("title", "No event for over 60 minutes.");
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows.map((row) => row.querySelector("td")?.textContent)).toEqual(["zeek", "sysmon"]);
    expect(screen.getByText("2 h ago")).toBeInTheDocument();
    expect(screen.getByText("just now")).toBeInTheDocument();
    expect(screen.getByTitle("decoding 5")).toHaveTextContent("5");
  });
});

describe("platform health", () => {
  it("says what is wrong, which role, and what its processes say", async () => {
    window.history.replaceState(null, "", "/?view=platform");
    show();
    // The verdict, with the reason of the worst role.
    expect(
      await screen.findAllByText(
        "The store refused the last batch, which is held and tried again.",
      ),
    ).toHaveLength(2);
    expect(screen.getByText(/The store answers, newest report just now/)).toBeInTheDocument();
    // The role, by how many report.
    expect(screen.getByText("1 of 2")).toBeInTheDocument();
    // A condition: the question, what it is about, how long, and why.
    const condition = screen.getByText("Keeping up with").closest("td");
    expect(condition).toHaveTextContent(
      "Keeping up with normalized for 5 min. The backlog of `normalized` grew.",
    );
    // A process that stopped reporting.
    expect(screen.getByText("Gone")).toBeInTheDocument();
    expect(screen.getByText("Last report 10 min ago.")).toBeInTheDocument();
    // Where records wait, and what changed.
    expect(screen.getByText("4,200")).toBeInTheDocument();
    expect(screen.getByText("Storing events")).toBeInTheDocument();
    expect(screen.getByText("2 min ago")).toBeInTheDocument();
  });
});
