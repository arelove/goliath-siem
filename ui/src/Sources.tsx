import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { sources } from "./api";
import { ago, STATUSES, stages } from "./health";

interface Props {
  /** Reports a failure, so that a refused token can be asked for again. */
  onError: (error: unknown) => void;
}

const number = new Intl.NumberFormat();

/**
 * Every source, the ones needing attention first: when it last sent, its
 * last hour against the same hour of its week, and what it sent that could
 * not be read.
 */
export function Sources({ onError }: Props) {
  const health = useQuery({
    queryKey: ["sources"],
    queryFn: ({ signal }) => sources(signal),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
  });
  useEffect(() => {
    if (health.error) {
      onError(health.error);
    }
  }, [health.error, onError]);
  const data = health.data;

  return (
    <div className="overview">
      <section className="card sources">
        <header>
          <h2>Sources</h2>
          <span className="caption">
            The last complete hour, against the same hour of the seven days before
          </span>
        </header>
        {health.error ? (
          <p className="note error">{health.error.message}</p>
        ) : !data ? (
          <p className="note">Loading</p>
        ) : data.sources.length === 0 ? (
          <p className="note">No source is configured or has sent anything.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Status</th>
                <th>Last event</th>
                <th>Last hour</th>
                <th>Usual for the hour</th>
                <th>Dead letters, hour</th>
                <th>Dead letters, day</th>
              </tr>
            </thead>
            <tbody>
              {data.sources.map((source) => {
                const status = STATUSES[source.status];
                const day = Object.values(source.dead_letters.last_day).reduce(
                  (sum, count) => sum + count,
                  0,
                );
                return (
                  <tr key={source.source}>
                    <td className="mono">{source.source}</td>
                    <td>
                      <span
                        className={`status ${status.tone}`}
                        title={
                          source.status === "silent"
                            ? `No event for over ${source.silent_after_minutes} minutes.`
                            : status.meaning
                        }
                      >
                        <span className="dot" />
                        {status.label}
                      </span>
                    </td>
                    <td title={source.last_event ? new Date(source.last_event).toString() : ""}>
                      {ago(source.last_event, data.now)}
                    </td>
                    <td className="count">{number.format(source.last_hour)}</td>
                    <td className="count">
                      {source.baseline === null ? "not yet" : number.format(source.baseline)}
                    </td>
                    <td className="count">{number.format(source.dead_letters.last_hour)}</td>
                    <td className="count" title={stages(source.dead_letters.last_day)}>
                      {number.format(day)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
