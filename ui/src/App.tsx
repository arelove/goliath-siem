import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useMemo, useState } from "react";
import type { Scalar, Search } from "./api";
import { ApiError, classes, paths, search, token } from "./api";
import { EventDetail } from "./components/EventDetail";
import { Mark } from "./components/Mark";
import { Results } from "./components/Results";
import { SearchBar } from "./components/SearchBar";
import { TokenPrompt } from "./components/TokenPrompt";
import { Overview } from "./Overview";
import { Platform } from "./Platform";
import type { Draft } from "./query";
import { fromParams, toParams, toSearch } from "./query";
import { Sources } from "./Sources";
import { className } from "./summary";

function unauthorized(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401;
}

type View = "overview" | "search" | "sources" | "platform";

/** Ranges the dashboard offers, each ending now. */
const RANGES = [
  { label: "Last 15 minutes", ms: 15 * 60_000 },
  { label: "Last hour", ms: 3_600_000 },
  { label: "Last 6 hours", ms: 6 * 3_600_000 },
  { label: "Last 24 hours", ms: 24 * 3_600_000 },
  { label: "Last 7 days", ms: 7 * 24 * 3_600_000 },
];

type Theme = "dark" | "light";
const THEME_KEY = "goliath.theme";

/** The theme chosen before, dark unless light was. */
function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function applyTheme(theme: Theme): Theme {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    // Storage may be unavailable; the choice then lasts until reload.
  }
  return theme;
}

function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
      <circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" strokeWidth="2" />
      <path
        d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
      <path
        d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function viewOf(params: URLSearchParams): View {
  const view = params.get("view");
  return view === "search" || view === "sources" || view === "platform" ? view : "overview";
}

const TABS: Record<View, { tab: string; section: string }> = {
  overview: { tab: "Dashboard", section: "Security overview" },
  search: { tab: "Events", section: "Event search" },
  sources: { tab: "Sources", section: "Source health" },
  platform: { tab: "Platform", section: "Platform health" },
};

export function App() {
  const client = useQueryClient();
  const [draft, setDraft] = useState<Draft>(() =>
    fromParams(new URLSearchParams(window.location.search)),
  );
  const [selected, setSelected] = useState<string | null>(null);
  const [view, setView] = useState<View>(() => viewOf(new URLSearchParams(window.location.search)));
  const [overviewError, setOverviewError] = useState<unknown>(null);
  const [span, setSpan] = useState(24 * 3_600_000);
  const [theme, setTheme] = useState(currentTheme);
  const show = (next: View) => {
    setView(next);
    const params = new URLSearchParams(window.location.search);
    params.set("view", next);
    window.history.replaceState(null, "", `?${params.toString()}`);
  };

  const classList = useQuery({ queryKey: ["classes"], queryFn: classes, staleTime: Infinity });
  const pathList = useQuery({
    queryKey: ["paths", draft.classUid],
    queryFn: () => paths(draft.classUid ?? 0),
    enabled: draft.classUid !== null,
    staleTime: Infinity,
  });
  const names = useMemo(
    () => new Map((classList.data ?? []).map((info) => [info.uid, className(info.name)])),
    [classList.data],
  );
  const holdsText = useCallback(
    (path: string) => {
      const holds = pathList.data?.find((info) => info.path === path)?.holds;
      return holds === undefined ? false : holds === "text";
    },
    [pathList.data],
  );

  // The search runs as submitted; editing the draft does not rerun it.
  const [submitted, setSubmitted] = useState<Search>(() => toSearch(draft, () => false));
  const results = useInfiniteQuery({
    queryKey: ["search", submitted],
    queryFn: ({ pageParam, signal }) =>
      search(pageParam ? { ...submitted, after: pageParam } : submitted, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next ?? undefined,
    enabled: view === "search",
  });
  const events = useMemo(
    () => results.data?.pages.flatMap((page) => page.events) ?? [],
    [results.data],
  );

  const run = (next: Draft) => {
    setDraft(next);
    setSubmitted(toSearch(next, holdsText));
    setSelected(null);
    const params = toParams(next);
    params.set("view", "search");
    window.history.replaceState(null, "", `?${params.toString()}`);
  };

  const addFilter = (path: string, value: Scalar) =>
    run({ ...draft, filters: [...draft.filters, { path, op: "equals", value: String(value) }] });

  const loadMore = useCallback(() => {
    void results.fetchNextPage();
  }, [results.fetchNextPage]);

  const locked = [results.error, classList.error, pathList.error, overviewError].some(unauthorized);
  if (locked) {
    return (
      <main className="app locked">
        <TokenPrompt
          rejected={token() !== null}
          onDone={() => {
            setOverviewError(null);
            void client.resetQueries();
          }}
        />
      </main>
    );
  }

  return (
    <main className="app">
      <header className="topbar">
        <span className="brand">
          <Mark />
          goliath
        </span>
        <span className="section">{TABS[view].section}</span>
        <button
          type="button"
          className="icon"
          aria-label={theme === "dark" ? "Light theme" : "Dark theme"}
          title={theme === "dark" ? "Light theme" : "Dark theme"}
          onClick={() => setTheme(applyTheme(theme === "dark" ? "light" : "dark"))}
        >
          {theme === "dark" ? <SunIcon /> : <MoonIcon />}
        </button>
      </header>
      <nav className="subbar">
        <div className="tabs" role="tablist">
          {(["overview", "search", "sources", "platform"] as const).map((name) => (
            <button
              key={name}
              type="button"
              role="tab"
              aria-selected={view === name}
              className={view === name ? "tab active" : "tab"}
              onClick={() => show(name)}
            >
              {TABS[name].tab}
            </button>
          ))}
        </div>
        {view === "overview" && (
          <select
            aria-label="Time range"
            value={span}
            onChange={(event) => setSpan(Number(event.target.value))}
          >
            {RANGES.map((range) => (
              <option key={range.ms} value={range.ms}>
                {range.label}
              </option>
            ))}
          </select>
        )}
      </nav>
      {view === "platform" ? (
        <Platform onError={setOverviewError} />
      ) : view === "sources" ? (
        <Sources onError={setOverviewError} />
      ) : view === "overview" ? (
        <Overview
          span={span}
          className={(uid) => names.get(Number(uid)) ?? `Class ${uid}`}
          onError={setOverviewError}
          onOpen={(at) => {
            setSelected(at);
            show("search");
          }}
        />
      ) : (
        searchView()
      )}
    </main>
  );

  function searchView() {
    return (
      <>
        <div className="searchbar">
          <SearchBar
            draft={draft}
            classes={classList.data ?? []}
            paths={pathList.data ?? []}
            searching={results.isFetching && !results.isFetchingNextPage}
            onChange={setDraft}
            onSubmit={() => run(draft)}
          />
        </div>
        {results.error && <p className="error banner">{results.error.message}</p>}
        <div className={selected ? "body split" : "body"}>
          {results.isPending ? (
            <p className="note">Searching</p>
          ) : events.length === 0 && !results.error ? (
            <p className="note">No events match.</p>
          ) : (
            <Results
              events={events}
              names={names}
              hasMore={results.hasNextPage}
              loadingMore={results.isFetchingNextPage}
              selected={selected}
              onMore={loadMore}
              onSelect={setSelected}
            />
          )}
          {selected && (
            <EventDetail
              at={selected}
              className={
                names.get(events.find((found) => found.at === selected)?.class_uid ?? -1) ?? "Event"
              }
              onFilter={addFilter}
              onClose={() => setSelected(null)}
            />
          )}
        </div>
      </>
    );
  }
}
