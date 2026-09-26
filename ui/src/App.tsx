import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useMemo, useState } from "react";
import type { Scalar, Search } from "./api";
import { ApiError, classes, paths, search, token } from "./api";
import { EventDetail } from "./components/EventDetail";
import { Results } from "./components/Results";
import { SearchBar } from "./components/SearchBar";
import { TokenPrompt } from "./components/TokenPrompt";
import type { Draft } from "./query";
import { fromParams, toParams, toSearch } from "./query";
import { className } from "./summary";

function unauthorized(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401;
}

export function App() {
  const client = useQueryClient();
  const [draft, setDraft] = useState<Draft>(() =>
    fromParams(new URLSearchParams(window.location.search)),
  );
  const [selected, setSelected] = useState<string | null>(null);

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
  });
  const events = useMemo(
    () => results.data?.pages.flatMap((page) => page.events) ?? [],
    [results.data],
  );

  const run = (next: Draft) => {
    setDraft(next);
    setSubmitted(toSearch(next, holdsText));
    setSelected(null);
    window.history.replaceState(null, "", `?${toParams(next).toString()}`);
  };

  const addFilter = (path: string, value: Scalar) =>
    run({ ...draft, filters: [...draft.filters, { path, op: "equals", value: String(value) }] });

  const loadMore = useCallback(() => {
    void results.fetchNextPage();
  }, [results.fetchNextPage]);

  const locked = [results.error, classList.error, pathList.error].some(unauthorized);
  if (locked) {
    return (
      <main className="app locked">
        <TokenPrompt
          rejected={token() !== null}
          onDone={() => {
            void client.resetQueries();
          }}
        />
      </main>
    );
  }

  return (
    <main className="app">
      <header className="top">
        <h1>Goliath</h1>
        <SearchBar
          draft={draft}
          classes={classList.data ?? []}
          paths={pathList.data ?? []}
          searching={results.isFetching && !results.isFetchingNextPage}
          onChange={setDraft}
          onSubmit={() => run(draft)}
        />
      </header>
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
    </main>
  );
}
