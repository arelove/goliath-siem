import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { arrivals, overview } from "./api";
import { Counter } from "./charts/Counter";
import { PALETTE, per, SEVERITIES } from "./charts/canvas";
import { Donut } from "./charts/Donut";
import { LiveChart } from "./charts/LiveChart";
import { SeriesChart } from "./charts/SeriesChart";
import { TopList } from "./charts/TopList";
import { Card, Legend } from "./components/Card";
import { RecentEvents } from "./components/RecentEvents";

/** Severities from High up, as OCSF numbers them. */
const SEVERE = ["4", "5", "6"];

interface Props {
  /** The range, ending now, in milliseconds. */
  span: number;
  /** A readable name for a class, by its uid as text. */
  className: (uid: string) => string;
  /** Reports a failure, so that a refused token can be asked for again. */
  onError: (error: unknown) => void;
  /** Opens an event in the events view. */
  onOpen: (at: string) => void;
}

/**
 * What the stored events add up to: headline counts, counts by severity and
 * by host over time, the most frequent classes, hosts, and users, the live
 * rate, and the newest events that matter.
 */
export function Overview({ span, className, onError, onOpen }: Props) {
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
  const rate = useRef<HTMLSpanElement>(null);

  const data = summary.data;
  const bySeverity = new Map<string, number>();
  for (const step of data?.series ?? []) {
    for (const [id, count] of Object.entries(step.counts)) {
      bySeverity.set(id, (bySeverity.get(id) ?? 0) + count);
    }
  }
  const severe = SEVERE.reduce((sum, id) => sum + (bySeverity.get(id) ?? 0), 0);
  const severities = SEVERITIES.filter((severity) => bySeverity.has(severity.key));
  const hosts = (data?.hosts ?? []).map((entry, index) => ({
    key: entry.key,
    name: entry.key,
    color: PALETTE[index % PALETTE.length] ?? "#9aa5b5",
    count: entry.count,
  }));
  const range = {
    from: data?.from ?? Date.now() - span,
    to: data?.to ?? Date.now(),
    step: data?.step_ms ?? 60_000,
  };
  const caption = `time per ${per(range.step)}`;

  return (
    <div className="overview">
      {summary.error && <p className="error banner">{summary.error.message}</p>}
      <section className="card figures">
        <div>
          <h3>Events</h3>
          <p className="figure">
            <Counter value={data?.total ?? 0} />
          </p>
        </div>
        <div>
          <h3>High and above</h3>
          <p className="figure severe">
            <Counter value={severe} />
          </p>
        </div>
        <div>
          <h3>Dead letters</h3>
          <p className={data?.dead_letters ? "figure severe" : "figure"}>
            <Counter value={data?.dead_letters ?? 0} />
          </p>
        </div>
        <div>
          <h3>Stored now, per second</h3>
          <p className="figure">
            <span ref={rate}>0</span>
          </p>
        </div>
      </section>

      <div className="rows">
        <Card
          className="span-2"
          title="Events by severity"
          axis="Count"
          caption={caption}
          legend={
            <Legend
              items={severities.map((severity) => ({
                ...severity,
                count: bySeverity.get(severity.key) ?? 0,
              }))}
            />
          }
        >
          <SeriesChart steps={data?.series} layers={SEVERITIES} kind="area" live {...range} />
        </Card>
        <Card title="Classes">
          <Donut entries={data?.classes ?? []} label={className} />
        </Card>

        <Card title="Top 5 hosts">
          <Donut entries={data?.hosts ?? []} />
        </Card>
        <Card
          className="span-2"
          title="Events by host, top 5"
          axis="Count"
          caption={caption}
          legend={<Legend items={hosts} />}
        >
          <SeriesChart steps={data?.host_series} layers={hosts} kind="bars" live {...range} />
        </Card>

        <Card className="span-2" title="Events stored, last two minutes" axis="Events/s">
          <LiveChart arrivals={live.data} rate={rate} />
        </Card>
        <TopList title="Top users" entries={data?.users ?? []} />
      </div>

      <RecentEvents from={range.from} to={range.to} className={className} onOpen={onOpen} />
    </div>
  );
}
