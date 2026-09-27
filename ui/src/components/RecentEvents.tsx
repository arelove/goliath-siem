import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { search } from "../api";
import { SEVERITIES } from "../charts/canvas";
import { summarize, when } from "../summary";

interface Props {
  from: number;
  to: number;
  /** A readable name for a class, by its uid as text. */
  className: (uid: string) => string;
  /** Opens an event, by the `at` a search returned. */
  onOpen: (at: string) => void;
}

/** Severities the table can start from, as OCSF numbers them. */
const FLOORS = [
  { value: 3, label: "Medium and above" },
  { value: 4, label: "High and above" },
  { value: 0, label: "All events" },
];

/** The newest events in the range, from a chosen severity up. */
export function RecentEvents({ from, to, className, onOpen }: Props) {
  const [floor, setFloor] = useState(3);
  const recent = useQuery({
    queryKey: ["recent", from, to, floor],
    queryFn: ({ signal }) =>
      search(
        {
          from: new Date(from).toISOString(),
          to: new Date(to).toISOString(),
          ...(floor > 0
            ? { filters: [{ path: "severity_id", op: "gte" as const, value: floor }] }
            : {}),
          limit: 10,
        },
        signal,
      ),
    placeholderData: keepPreviousData,
  });
  const events = recent.data?.events ?? [];

  return (
    <section className="card recent">
      <header>
        <h2>Recent events</h2>
        <select
          aria-label="Severity"
          value={floor}
          onChange={(event) => setFloor(Number(event.target.value))}
        >
          {FLOORS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </header>
      {recent.error ? (
        <p className="note error">{recent.error.message}</p>
      ) : events.length === 0 ? (
        <p className="note">{recent.isPending ? "Loading" : "No events in this range."}</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Host</th>
              <th>Actor</th>
              <th>Class</th>
              <th>Severity</th>
              <th>Event</th>
            </tr>
          </thead>
          <tbody>
            {events.map((found) => {
              const summary = summarize(found.event);
              const severity = SEVERITIES.find(
                (entry) => entry.key === String(found.event.severity_id ?? ""),
              );
              return (
                <tr key={found.at} onClick={() => onOpen(found.at)}>
                  <td className="mono">{when(found.event.time)}</td>
                  <td>{summary.host}</td>
                  <td>{summary.actor}</td>
                  <td>{className(String(found.class_uid))}</td>
                  <td>
                    {severity && (
                      <span className="level">
                        <span className="dot" style={{ background: severity.color }} />
                        {severity.name}
                      </span>
                    )}
                  </td>
                  <td className="mono what" title={summary.what}>
                    {summary.what}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
