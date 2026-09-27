import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { arrivals, overview } from "./api";
import { Counter } from "./charts/Counter";
import { SEVERITIES } from "./charts/canvas";
import { Donut } from "./charts/Donut";
import { LiveChart } from "./charts/LiveChart";
import { StackedArea } from "./charts/StackedArea";
import { TopList } from "./charts/TopList";

/** Ranges the overview offers, each ending now. */
const RANGES = [
  { label: "15 min", ms: 15 * 60_000 },
  { label: "1 hour", ms: 3_600_000 },
  { label: "6 hours", ms: 6 * 3_600_000 },
  { label: "24 hours", ms: 24 * 3_600_000 },
  { label: "7 days", ms: 7 * 24 * 3_600_000 },
];

/** Severities from High up, as OCSF numbers them. */
const SEVERE = ["4", "5", "6"];

interface Props {
  /** A readable name for a class, by its uid as text. */
  className: (uid: string) => string;
  /** Whether the API refused the token, to ask for another. */
  onError: (error: unknown) => void;
}

/**
 * What the stored events add up to: a live rate, counts by severity over
 * time, and the most frequent classes, sources, hosts, and users.
 */
export function Overview({ className, onError }: Props) {
  const [span, setSpan] = useState(3_600_000);
  const summary = useQuery({
    queryKey: ["overview", span],
    queryFn: ({ signal }) => {
      const to = new Date();
      const from = new Date(to.getTime() - span);
      return overview(from.toISOString(), to.toISOString(), signal);
    },
    refetchInterval: 5000,
    placeholderData: keepPreviousData,
  });
  const live = useQuery({
    queryKey: ["arrivals"],
    queryFn: ({ signal }) => arrivals(signal),
    refetchInterval: 1000,
  });
  useEffect(() => {
    if (summary.error) {
      onError(summary.error);
    }
  }, [summary.error, onError]);

  const data = summary.data;
  const bySeverity = new Map<string, number>();
  for (const step of data?.series ?? []) {
    for (const [id, count] of Object.entries(step.counts)) {
      bySeverity.set(id, (bySeverity.get(id) ?? 0) + count);
    }
  }
  const severe = SEVERE.reduce((sum, id) => sum + (bySeverity.get(id) ?? 0), 0);
  // The last five complete seconds; the current one is still arriving.
  const seconds = live.data?.seconds ?? [];
  const now = Math.floor((live.data?.now ?? 0) / 1000) * 1000;
  const recent = seconds
    .filter((second) => second.at < now - 1000 && second.at >= now - 6000)
    .reduce((sum, second) => sum + second.count, 0);

  return (
    <div className="overview">
      <div className="toolbar">
        <fieldset className="ranges">
          <legend className="hidden">Time range</legend>
          {RANGES.map((range) => (
            <button
              key={range.ms}
              type="button"
              className={range.ms === span ? "range active" : "range"}
              onClick={() => setSpan(range.ms)}
            >
              {range.label}
            </button>
          ))}
        </fieldset>
        <span className={summary.isFetching ? "sync busy" : "sync"} title="Refreshes every 5 s" />
      </div>
      {summary.error && <p className="error banner">{summary.error.message}</p>}

      <section className="tiles">
        <div className="tile">
          <h3>Events</h3>
          <p className="figure">
            <Counter value={data?.total ?? 0} />
          </p>
        </div>
        <div className="tile">
          <h3>High and above</h3>
          <p className="figure severe">
            <Counter value={severe} />
          </p>
        </div>
        <div className="tile">
          <h3>Dead letters</h3>
          <p className={data?.dead_letters ? "figure warn" : "figure"}>
            <Counter value={data?.dead_letters ?? 0} />
          </p>
        </div>
        <div className="tile">
          <h3>Stored now</h3>
          <p className="figure">
            <Counter value={Math.round(recent / 5)} ms={700} />
            <small> /s</small>
          </p>
        </div>
      </section>

      <div className="grid">
        <LiveChart arrivals={live.data} />
        <section className="panel wide">
          <header>
            <h2>Events by severity</h2>
            <ul className="legend inline">
              {SEVERITIES.filter((severity) => bySeverity.has(severity.id)).map((severity) => (
                <li key={severity.id}>
                  <span className="swatch" style={{ background: severity.color }} />
                  {severity.name}
                </li>
              ))}
            </ul>
          </header>
          <StackedArea overview={data} live />
        </section>
        <Donut title="Classes" entries={data?.classes ?? []} label={className} />
        <Donut title="Sources" entries={data?.sources ?? []} />
        <TopList title="Top hosts" entries={data?.hosts ?? []} />
        <TopList title="Top users" entries={data?.users ?? []} />
      </div>
    </div>
  );
}
