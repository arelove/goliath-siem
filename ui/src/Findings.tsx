import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import type { Filter, Scalar } from "./api";
import { event, findings } from "./api";
import { Tree } from "./components/EventDetail";
import type { Way } from "./components/ValueMenu";
import { ValueMenu } from "./components/ValueMenu";
import type { Finding } from "./finding";
import { LEVELS, level, read, sameValue } from "./finding";
import { when } from "./summary";

/** Events to look for, from something a finding names. */
export interface Lead {
  from: string;
  to: string;
  classUid: number | null;
  path: string;
  value: Scalar;
}

interface Props {
  /** The range, ending now, in milliseconds. */
  span: number;
  /** A readable name for a class. */
  className: (uid: number) => string;
  /** Reports a failure, so that a refused token can be asked for again. */
  onError: (error: unknown) => void;
  /** Opens the events view on what a finding names. */
  onEvents: (lead: Lead) => void;
  /** Opens the entity a value names. */
  onEntity: (value: string) => void;
}

const number = new Intl.NumberFormat();

/** A filter of the queue as its chip says it. */
function said(filter: Filter): string {
  const name = filter.path === "unmapped.indicator_value" ? "value" : filter.path;
  return `${name} ${filter.op === "not_equals" ? "is not" : "is"} ${String(filter.value)}`;
}

function Severity({ id }: { id: number }) {
  const shown = level(id);
  return (
    <span className={`status sev ${shown.tone}`}>
      <span className="pip" />
      {shown.name}
    </span>
  );
}

/**
 * The queue: what was found in the range, the most severe first and then
 * the newest, and beside it what one finding says. See "From a finding to
 * a decision" in docs/adr/0024-interface.md.
 */
export function Findings({ span, className, onError, onEvents, onEntity }: Props) {
  const [severities, setSeverities] = useState<number[]>([]);
  const [filters, setFilters] = useState<Filter[]>([]);
  // The finding that is open is in the address, so that a link opens it.
  const [selected, setSelected] = useState<string | null>(() =>
    new URLSearchParams(window.location.search).get("finding"),
  );
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("view") !== "findings") {
      return;
    }
    if (selected) {
      params.set("finding", selected);
    } else {
      params.delete("finding");
    }
    window.history.replaceState(null, "", `?${params.toString()}`);
  }, [selected]);
  const [asked, setAsked] = useState(0);
  // One range for every page of the queue: a page asked for later must not
  // be of another range. `asked` is named so that asking again moves it.
  // biome-ignore lint/correctness/useExhaustiveDependencies: see above
  const range = useMemo(() => {
    const to = new Date();
    return { from: new Date(to.getTime() - span).toISOString(), to: to.toISOString() };
  }, [span, asked]);

  const queue = useInfiniteQuery({
    queryKey: ["findings", range, severities, filters],
    queryFn: ({ pageParam, signal }) =>
      findings(
        {
          ...range,
          ...(severities.length > 0 ? { severities } : {}),
          ...(filters.length > 0 ? { filters } : {}),
          ...(pageParam ? { after: pageParam } : {}),
        },
        signal,
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next ?? undefined,
    placeholderData: keepPreviousData,
  });
  useEffect(() => {
    if (queue.error) {
      onError(queue.error);
    }
  }, [queue.error, onError]);

  const rows = useMemo(
    () => queue.data?.pages.flatMap((page) => page.findings.map(read)) ?? [],
    [queue.data],
  );
  const first = queue.data?.pages[0];
  const open = rows.find((row) => row.at === selected) ?? null;

  const toggle = (id: number) => {
    setSelected(null);
    setSeverities(
      severities.includes(id) ? severities.filter((one) => one !== id) : [...severities, id],
    );
  };
  const narrow = (filter: Filter) => {
    setSelected(null);
    setFilters([
      ...filters.filter((one) => one.path !== filter.path || one.op !== filter.op),
      filter,
    ]);
  };
  const move = (by: number) => {
    const index = rows.findIndex((row) => row.at === selected);
    const next = rows[Math.min(rows.length - 1, Math.max(0, index + by))];
    if (next) {
      setSelected(next.at);
    }
  };

  /** What the queue can do with the value a finding names. */
  const ways = (finding: Finding): Way[] => [
    {
      label: "Show only findings of it",
      run: () => narrow({ path: "unmapped.indicator_value", op: "equals", value: finding.value }),
    },
    {
      label: "Hide findings of it",
      run: () =>
        narrow({ path: "unmapped.indicator_value", op: "not_equals", value: finding.value }),
    },
    ...(finding.evidence.path
      ? [
          {
            label: "Show events that hold it",
            run: () =>
              onEvents({
                ...range,
                classUid: finding.evidence.classUid,
                path: finding.evidence.path,
                value: finding.value,
              }),
          },
        ]
      : []),
    { label: "Open its entity", run: () => onEntity(finding.value) },
  ];

  return (
    <div className="queue">
      <div className="queue-bar">
        <span className="queue-total">
          {first ? number.format(first.total) : ""}
          <span className="caption"> {first?.total === 1 ? "finding" : "findings"}</span>
        </span>
        <fieldset className="chips">
          <legend className="hidden">Severities shown</legend>
          {LEVELS.map((entry) => {
            const count = first?.severities[String(entry.id)] ?? 0;
            // A severity nothing has is not offered, unless it is chosen.
            if (count === 0 && !severities.includes(entry.id) && entry.id !== 5 && entry.id !== 4) {
              return null;
            }
            return (
              <button
                type="button"
                key={entry.id}
                className={`chip ${entry.tone}`}
                aria-pressed={severities.includes(entry.id)}
                onClick={() => toggle(entry.id)}
              >
                <span className="pip" />
                {entry.name}
                <span className="chip-count">{number.format(count)}</span>
              </button>
            );
          })}
        </fieldset>
        {filters.map((filter) => (
          <button
            type="button"
            key={`${filter.path}|${filter.op}`}
            className="chip filter-chip"
            title="Remove this filter"
            onClick={() => setFilters(filters.filter((one) => one !== filter))}
          >
            <span className="mono">{said(filter)}</span>
            <span aria-hidden="true">×</span>
          </button>
        ))}
        <button type="button" className="quiet again" onClick={() => setAsked(asked + 1)}>
          {queue.isFetching && !queue.isFetchingNextPage ? "Reading" : "Refresh"}
        </button>
      </div>
      {queue.error && <p className="error banner">{queue.error.message}</p>}
      <div className={open ? "body split" : "body"}>
        <section
          className="results sources findings"
          aria-label="Findings"
          // biome-ignore lint/a11y/noNoninteractiveTabindex: the queue is worked by keyboard
          tabIndex={0}
          onKeyDown={(pressed) => {
            if (pressed.key === "ArrowDown" || pressed.key === "j") {
              pressed.preventDefault();
              move(1);
            } else if (pressed.key === "ArrowUp" || pressed.key === "k") {
              pressed.preventDefault();
              move(-1);
            } else if (pressed.key === "Escape") {
              setSelected(null);
            }
          }}
        >
          {queue.isPending ? (
            <p className="note">Reading the queue</p>
          ) : rows.length === 0 ? (
            !queue.error && <Nothing narrowed={severities.length > 0 || filters.length > 0} />
          ) : (
            <>
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Time</th>
                    <th>Finding</th>
                    <th>Value</th>
                    <th>Asserted by</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr
                      key={row.at}
                      className={row.at === selected ? "selected" : undefined}
                      aria-selected={row.at === selected}
                      onClick={() => setSelected(row.at === selected ? null : row.at)}
                    >
                      <td>
                        <Severity id={row.severity} />
                      </td>
                      <td className="mono">{when(row.time).slice(0, 19)}</td>
                      <td className="what">
                        {row.kind ? `Indicator match: ${row.kind}` : row.title}
                        {row.suppressed && <span className="muted"> · suppressed</span>}
                      </td>
                      <td>{row.value && <ValueMenu value={row.value} ways={ways(row)} />}</td>
                      <td>{row.assertions.map((one) => one.feed).join(", ")}</td>
                      <td className="count">{row.confidence ?? ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {queue.hasNextPage ? (
                <p className="note">
                  <button
                    type="button"
                    disabled={queue.isFetchingNextPage}
                    onClick={() => void queue.fetchNextPage()}
                  >
                    {queue.isFetchingNextPage ? "Reading" : "Show more"}
                  </button>
                </p>
              ) : (
                <p className="note">{number.format(rows.length)} shown, which is all</p>
              )}
            </>
          )}
        </section>
        {open && (
          <Panel
            finding={open}
            others={sameValue(rows, open)}
            ways={ways(open)}
            className={className}
            onSelect={setSelected}
            onEntity={onEntity}
            onEvents={(path, value) =>
              onEvents({ ...range, classUid: open.evidence.classUid, path, value })
            }
            onClose={() => setSelected(null)}
          />
        )}
      </div>
    </div>
  );
}

/** An empty queue says why it is empty, and what would fill it. */
function Nothing({ narrowed }: { narrowed: boolean }) {
  return narrowed ? (
    <p className="note">No finding in this range is left by what is chosen above.</p>
  ) : (
    <div className="note nothing">
      <p>No findings in this range.</p>
      <p>
        A finding is made when an event names an address, a domain, or a file that an indicator feed
        asserts. The Platform view says whether the feeds are current, and Sources whether events
        arrive.
      </p>
    </div>
  );
}

interface PanelProps {
  finding: Finding;
  /** Other findings of the queue that name the same value. */
  others: Finding[];
  ways: Way[];
  className: (uid: number) => string;
  onSelect: (at: string) => void;
  onEvents: (path: string, value: Scalar) => void;
  onEntity: (value: string) => void;
  onClose: () => void;
}

function Panel({
  finding,
  others,
  ways,
  className,
  onSelect,
  onEvents,
  onEntity,
  onClose,
}: PanelProps) {
  const source = useQuery({
    queryKey: ["event", finding.evidence.at],
    queryFn: () => event(finding.evidence.at ?? ""),
    enabled: finding.evidence.at !== null,
    retry: false,
  });
  return (
    <aside className="detail finding" aria-label="Finding">
      <header>
        <h2>
          <Severity id={finding.severity} /> {finding.title}
        </h2>
        <button type="button" className="quiet" aria-label="Close" onClick={onClose}>
          ×
        </button>
      </header>
      <p className="meta">
        {when(finding.time)}
        {finding.confidence !== null && ` · confidence ${finding.confidence}`}
      </p>

      <section>
        <h3>What was found and why</h3>
        {finding.suppressed && <p className="suppressed">Not an alert. {finding.suppressed}</p>}
        <dl className="facts">
          <dt>{finding.kind || "Value"}</dt>
          <dd>{finding.value && <ValueMenu value={finding.value} ways={ways} />}</dd>
          {finding.evidence.path && (
            <>
              <dt>Held by</dt>
              <dd>
                <span className="mono">{finding.evidence.path}</span>
                {finding.evidence.classUid !== null && (
                  <span className="muted"> of {className(finding.evidence.classUid)}</span>
                )}
              </dd>
            </>
          )}
        </dl>
        {finding.assertions.length > 0 && (
          <table className="asserted">
            <thead>
              <tr>
                <th>Feed</th>
                <th>Confidence</th>
                <th>Version</th>
                <th>First seen</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {finding.assertions.map((one) => (
                <tr key={`${one.feed}|${one.version}`}>
                  <td className="mono">{one.feed}</td>
                  <td className="count">{one.confidence ?? ""}</td>
                  <td className="mono">{one.version}</td>
                  <td>{when(one.firstSeen).slice(0, 10)}</td>
                  <td>{when(one.lastSeen).slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section>
        <h3>Who and what</h3>
        {finding.enrichments.length === 0 ? (
          <p className="muted">
            The site's lists say nothing of what this event names. Context comes from the lists a
            detector is given.
          </p>
        ) : (
          finding.enrichments.map((entry) => (
            <div className="known" key={`${entry.name}|${entry.value}|${entry.provider}`}>
              <p>
                <span className="muted">{entry.name}</span>{" "}
                <ValueMenu
                  value={entry.value}
                  ways={[{ label: "Open its entity", run: () => onEntity(entry.value) }]}
                />
                <span className="muted">
                  {" "}
                  · {entry.type} from {entry.provider}
                </span>
              </p>
              <dl className="facts">
                {entry.data.map(([key, value]) => (
                  <Fact key={key} name={key} value={value} />
                ))}
              </dl>
            </div>
          ))
        )}
      </section>

      <section>
        <h3>What else</h3>
        {others.length === 0 ? (
          <p className="muted">No other finding in the queue names this value.</p>
        ) : (
          <ul className="others">
            {others.slice(0, 20).map((other) => (
              <li key={other.at}>
                <button type="button" className="quiet" onClick={() => onSelect(other.at)}>
                  <Severity id={other.severity} />
                  <span className="mono">{when(other.time).slice(0, 19)}</span>
                </button>
              </li>
            ))}
            {others.length > 20 && <li className="muted">and {others.length - 20} more</li>}
          </ul>
        )}
      </section>

      <section>
        <h3>The event</h3>
        {finding.evidence.at === null ? (
          <p className="muted">The finding does not say which event it was made of.</p>
        ) : source.isPending ? (
          <p className="muted">Reading the event</p>
        ) : source.error ? (
          <p className="muted">
            The event is not stored where the finding says: it may have aged out, or its time was
            not its own. {source.error.message}
          </p>
        ) : (
          <>
            <p className="meta">
              {source.data.source} {source.data.kind} · {className(source.data.class_uid)}
            </p>
            <Tree value={source.data.event} path="" inList={false} onFilter={onEvents} />
          </>
        )}
      </section>

      <section>
        <h3>The decision</h3>
        <p className="muted">
          A decision needs a place to be kept, which comes with cases. Until then the queue has no
          status of its own.
        </p>
      </section>
    </aside>
  );
}

function Fact({ name, value }: { name: string; value: string }) {
  return (
    <>
      <dt>{name}</dt>
      <dd className="mono">{value}</dd>
    </>
  );
}
