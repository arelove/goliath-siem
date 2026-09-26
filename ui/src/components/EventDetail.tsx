import { useQuery } from "@tanstack/react-query";
import type { Scalar } from "../api";
import { event } from "../api";
import { when } from "../summary";

interface Props {
  at: string;
  className: string;
  onFilter: (path: string, value: Scalar) => void;
  onClose: () => void;
}

export function EventDetail({ at, className, onFilter, onClose }: Props) {
  const stored = useQuery({ queryKey: ["event", at], queryFn: () => event(at) });
  return (
    <aside className="detail" aria-label="Event">
      <header>
        <h2>{className}</h2>
        <button type="button" className="quiet" aria-label="Close" onClick={onClose}>
          ×
        </button>
      </header>
      {stored.isPending && <p className="note">Loading</p>}
      {stored.error && <p className="error">{stored.error.message}</p>}
      {stored.data && (
        <>
          <p className="meta">
            {when(stored.data.event.time)} · {stored.data.source} {stored.data.kind} · definition
            version {stored.data.source_version}
          </p>
          {stored.data.issues.length > 0 && (
            <section className="issues">
              <h3>Normalization issues</h3>
              <ul>
                {stored.data.issues.map((issue) => (
                  <li key={issue.target}>
                    <code>{issue.target}</code> from <code>{issue.source}</code>: {issue.reason}
                  </li>
                ))}
              </ul>
            </section>
          )}
          <Tree value={stored.data.event} path="" inList={false} onFilter={onFilter} />
        </>
      )}
    </aside>
  );
}

interface TreeProps {
  value: unknown;
  path: string;
  inList: boolean;
  onFilter: (path: string, value: Scalar) => void;
}

/** The event as a tree; a value outside lists can become a filter. */
function Tree({ value, path, inList, onFilter }: TreeProps) {
  if (value !== null && typeof value === "object") {
    const entries = Array.isArray(value)
      ? value.map((item, index) => [String(index), item] as const)
      : Object.entries(value as Record<string, unknown>);
    return (
      <ul className="tree">
        {entries.map(([key, child]) => {
          const childPath = Array.isArray(value) ? path : path ? `${path}.${key}` : key;
          return (
            <li key={key}>
              <span className="key">{key}</span>
              <Tree
                value={child}
                path={childPath}
                inList={inList || Array.isArray(value)}
                onFilter={onFilter}
              />
            </li>
          );
        })}
      </ul>
    );
  }
  const scalar: Scalar | null =
    typeof value === "string" || typeof value === "number" || typeof value === "boolean"
      ? value
      : null;
  return (
    <span className="leaf">
      <span className="mono">{scalar === null ? "null" : String(scalar)}</span>
      {scalar !== null && !inList && (
        <button
          type="button"
          className="quiet add"
          title={`Search for ${path} = ${String(scalar)}`}
          aria-label={`Filter on ${path}`}
          onClick={() => onFilter(path, scalar)}
        >
          +
        </button>
      )}
    </span>
  );
}
