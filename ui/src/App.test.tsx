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

const MATCH: Found = {
  at: `1790330400000-${"cd".repeat(16)}`,
  class_uid: 2004,
  source: "goliath-intel",
  kind: "indicator_match",
  event: {
    time: 1790330400000,
    class_uid: 2004,
    severity_id: 4,
    confidence_score: 95,
    is_alert: true,
    finding_info: { title: "Indicator match: domain c2.bad.example.com" },
    evidences: [
      {
        uid: "ab".repeat(16),
        name: "dst_endpoint.hostname",
        data: { class_uid: 1007, time: 1790330400000, value: "c2.bad.example.com" },
      },
    ],
    enrichments: [
      {
        name: "hostname",
        value: "ws-7",
        type: "asset",
        provider: "cmdb",
        data: { owner: "alice" },
      },
    ],
    unmapped: {
      indicator_kind: "domain",
      indicator_value: "c2.bad.example.com",
      assertions: [{ feed: "threatfox", version: "7", confidence: 95 }],
    },
  },
};

interface Call {
  path: string;
  body: Search | null;
  authorization: string | null;
}

const SID = "user:sid:s-1-5-21-1-2-3-1104";

const ENTITY = {
  asked: "user:name:corp\\adam",
  entity: SID,
  kind: "user",
  provisional: false,
  shared: false,
  alias_of: [],
  identifiers: [
    {
      identifier: SID,
      form: "sid",
      strong: true,
      standing: "member",
      via: null,
      rule: null,
      said: null,
      events: 0,
      first_seen: 0,
      last_seen: 0,
    },
    {
      identifier: "user:name:corp\\adam",
      form: "name",
      strong: true,
      standing: "member",
      via: SID,
      rule: "user",
      said: null,
      events: 41,
      first_seen: 1790330400000,
      last_seen: 1790334000000,
    },
  ],
};

const NEIGHBOURS = {
  entity: SID,
  kind: "user",
  identifiers: [SID, "user:name:corp\\adam"],
  from: 1790326800000,
  to: 1790413200000,
  degree: 2,
  limit: 100,
  neighbours: [
    {
      entity: "host:name:dc-1.corp.example",
      kind: "host",
      direction: "out",
      link: "logged_on_to",
      events: 5,
      first_seen: 1790330460000,
      last_seen: 1790330520005,
    },
    {
      entity: "address:ip:10.0.0.5",
      kind: "address",
      direction: "in",
      link: "connected_to",
      events: 2,
      first_seen: 1790330460000,
      last_seen: 1790330470000,
    },
  ],
};

const PATH = {
  source: SID,
  target: "host:name:files.corp.example",
  found: true,
  complete: true,
  most: 4,
  hub_over: 100,
  through_hubs: false,
  path: [
    { entity: SID, kind: "user" },
    { entity: "host:name:ws-7.corp.example", kind: "host" },
    { entity: "host:name:files.corp.example", kind: "host" },
  ],
  hops: [
    {
      from: SID,
      to: "host:name:ws-7.corp.example",
      links: [
        {
          src: SID,
          dst: "host:name:ws-7.corp.example",
          link: "logged_on_to",
          events: 3,
          first_seen: 1790330460000,
          last_seen: 1790330520000,
        },
      ],
    },
    {
      from: "host:name:ws-7.corp.example",
      to: "host:name:files.corp.example",
      links: [
        {
          src: "host:name:files.corp.example",
          dst: "host:name:ws-7.corp.example",
          link: "connected_to",
          events: 7,
          first_seen: 1790330460000,
          last_seen: 1790330520000,
        },
      ],
    },
  ],
  hubs: [{ entity: "host:name:dc-1.corp.example", kind: "host", degree: 412 }],
};

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
      if (path === "/findings") {
        return reply(200, {
          findings: [MATCH],
          next: null,
          total: 3,
          severities: { "4": 1, "2": 2 },
        });
      }
      if (path === "/entity") {
        return reply(200, ENTITY);
      }
      if (path === "/entity/neighbours") {
        return reply(200, NEIGHBOURS);
      }
      if (path === "/entity/path") {
        // Nothing is joined to the name read as a domain.
        const target = (body as unknown as { target: string }).target;
        return reply(
          200,
          target.startsWith("domain:")
            ? { ...PATH, target, found: false, path: null, hops: null, hubs: [] }
            : PATH,
        );
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

describe("the queue of findings", () => {
  it("shows what was found, and what one finding says beside it", async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, "", "/?view=findings");
    show();
    // The queue, with how many of each severity the range holds.
    const row = (await screen.findByText("Indicator match: domain")).closest("tr");
    expect(row).toHaveTextContent("High");
    expect(row).toHaveTextContent("threatfox");
    expect(screen.getByRole("button", { name: /Low\s*2/ })).toBeInTheDocument();

    // The panel: why, who and what, and the event it was made of.
    await user.click(screen.getByText("Indicator match: domain"));
    const panel = screen.getByRole("complementary", { name: "Finding" });
    expect(panel).toHaveTextContent("dst_endpoint.hostname of Process Activity");
    expect(panel).toHaveTextContent("hostname ws-7 · asset from cmdb");
    expect(panel).toHaveTextContent("owner");
    expect(await screen.findByText("powershell -enc AAAA")).toBeInTheDocument();
    expect(calls.some((call) => call.path === `/events/1790330400000-${"ab".repeat(16)}`)).toBe(
      true,
    );
  });

  it("asks again for the severities chosen, and for a value from its menu", async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, "", "/?view=findings");
    show();
    await user.click(await screen.findByRole("button", { name: /High\s*1/ }));
    await waitFor(() =>
      expect(
        calls.some((call) => call.path === "/findings" && "severities" in (call.body ?? {})),
      ).toBe(true),
    );
    const chosen = calls.findLast((call) => call.path === "/findings")?.body as unknown as {
      severities: number[];
    };
    expect(chosen.severities).toEqual([4]);

    const value = (await screen.findAllByRole("button", { name: "c2.bad.example.com" }))[0];
    await user.click(value as HTMLElement);
    await user.click(screen.getByRole("menuitem", { name: "Show only findings of it" }));
    await waitFor(() =>
      expect(calls.findLast((call) => call.path === "/findings")?.body?.filters).toEqual([
        { path: "unmapped.indicator_value", op: "equals", value: "c2.bad.example.com" },
      ]),
    );
    expect(screen.getByTitle("Remove this filter")).toHaveTextContent(
      "value is c2.bad.example.com",
    );
  });

  it("leads from a value to the events that hold it", async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, "", "/?view=findings");
    show();
    const named = (await screen.findAllByRole("button", { name: "c2.bad.example.com" }))[0];
    await user.click(named as HTMLElement);
    await user.click(screen.getByRole("menuitem", { name: "Show events that hold it" }));
    await waitFor(() =>
      expect(calls.findLast((call) => call.path === "/search")?.body).toMatchObject({
        classes: [1007],
        filters: [{ path: "dst_endpoint.hostname", op: "equals", value: "c2.bad.example.com" }],
      }),
    );
    expect(screen.getByRole("tab", { name: "Events" })).toHaveAttribute("aria-selected", "true");
  });
});

describe("the entity view", () => {
  it("shows what an entity is known by, and what it was seen with", async () => {
    window.history.replaceState(null, "", "/?view=entity&entity=CORP\\Adam");
    show();
    // The value is asked for as the identifier its form says.
    await waitFor(() =>
      expect(calls.find((call) => call.path === "/entity")?.body).toEqual({
        identifier: "user:name:corp\\adam",
      }),
    );
    expect(await screen.findByRole("heading", { name: "s-1-5-21-1-2-3-1104" })).toBeInTheDocument();
    const why = (await screen.findByText("rule user", { exact: false })).closest("tr");
    expect(why).toHaveTextContent(`seen with ${SID}`);
    expect(why).toHaveTextContent("41");

    const row = (await screen.findByRole("cell", { name: /logged on to/ })).closest("tr");
    expect(row).toHaveTextContent("dc-1.corp.example");
    expect(screen.getByRole("cell", { name: /connected from/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "2 neighbours" })).toBeInTheDocument();
  });

  it("asks for the kinds of link chosen, and opens a neighbour", async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, "", `/?view=entity&entity=${SID}`);
    show();
    await user.click(await screen.findByRole("button", { name: "logged on to" }));
    await waitFor(() =>
      expect(calls.findLast((call) => call.path === "/entity/neighbours")?.body).toMatchObject({
        identifier: SID,
        links: ["logged_on_to"],
        limit: 100,
      }),
    );

    const named = (await screen.findAllByRole("button", { name: "10.0.0.5" }))[0];
    await user.click(named as HTMLElement);
    await waitFor(() =>
      expect(calls.findLast((call) => call.path === "/entity")?.body).toEqual({
        identifier: "address:ip:10.0.0.5",
      }),
    );
    expect(window.location.search).toContain("entity=address%3Aip%3A10.0.0.5");
  });

  it("finds a path to another entity, and says what it did not go through", async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, "", `/?view=entity&entity=${SID}`);
    show();
    await user.type(await screen.findByLabelText("The other entity"), "files.corp.example");
    await user.click(screen.getByRole("button", { name: "Find" }));
    // A name with dots may be a domain or a machine: each is asked for,
    // and the one that has a path is shown.
    await waitFor(() =>
      expect(
        calls
          .filter((call) => call.path === "/entity/path")
          .map((call) => (call.body as unknown as { target: string }).target),
      ).toEqual(["domain:name:files.corp.example", "host:name:files.corp.example"]),
    );
    const way = (await screen.findByText("2 links, the fewest.")).closest("section");
    // Each link reads along the path, whichever end acted.
    expect(way).toHaveTextContent("logged on to 3");
    expect(way).toHaveTextContent("connected from 7");
    expect(way).toHaveTextContent("Not gone through:");
    expect(way).toHaveTextContent("412 neighbours");
    expect(window.location.search).toContain("path=files.corp.example");

    await user.click(screen.getByRole("button", { name: "through hubs" }));
    await waitFor(() =>
      expect(calls.findLast((call) => call.path === "/entity/path")?.body).toMatchObject({
        through_hubs: true,
      }),
    );
  });

  it("is reached from the value a finding names", async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, "", "/?view=findings");
    show();
    const named = (await screen.findAllByRole("button", { name: "c2.bad.example.com" }))[0];
    await user.click(named as HTMLElement);
    await user.click(screen.getByRole("menuitem", { name: "Open its entity" }));
    await waitFor(() =>
      expect(calls.findLast((call) => call.path === "/entity")?.body).toEqual({
        identifier: "domain:name:c2.bad.example.com",
      }),
    );
    expect(screen.getByRole("tab", { name: "Entities" })).toHaveAttribute("aria-selected", "true");
    // A name with dots may be a machine: the other reading is offered.
    await user.click(screen.getByRole("button", { name: "as a host" }));
    await waitFor(() =>
      expect(calls.findLast((call) => call.path === "/entity")?.body).toEqual({
        identifier: "host:name:c2.bad.example.com",
      }),
    );
  });
});
