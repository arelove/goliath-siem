import type { Frequent } from "../api";
import { compact } from "./canvas";

interface Props {
  title: string;
  entries: Frequent[];
  /** Called with a value to look for its events. */
  onPick?: (key: string) => void;
}

/** The most frequent values, as bars that grow and shrink with each fetch. */
export function TopList({ title, entries, onPick }: Props) {
  const most = Math.max(1, ...entries.map((entry) => entry.count));
  return (
    <section className="panel toplist">
      <h2>{title}</h2>
      {entries.length === 0 ? (
        <p className="note">Nothing in this range.</p>
      ) : (
        <ol>
          {entries.map((entry) => (
            <li key={entry.key}>
              <button
                type="button"
                className="bar-row"
                disabled={!onPick}
                onClick={() => onPick?.(entry.key)}
              >
                <span className="name" title={entry.key}>
                  {entry.key}
                </span>
                <span className="count">{compact(entry.count)}</span>
                <span className="bar" style={{ width: `${(entry.count / most) * 100}%` }} />
              </button>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
