import type { Holds, Op, PathInfo } from "../api";
import { operators } from "../api";
import type { DraftFilter } from "../query";

const LABELS: Record<Op, string> = {
  equals: "is",
  not_equals: "is not",
  contains: "contains",
  starts_with: "starts with",
  ends_with: "ends with",
  in: "is one of",
  gt: ">",
  gte: "≥",
  lt: "<",
  lte: "≤",
  exists: "exists",
  missing: "is missing",
};

interface Props {
  filter: DraftFilter;
  paths: PathInfo[];
  listId: string;
  onChange: (filter: DraftFilter) => void;
  onRemove: () => void;
}

export function FilterRow({ filter, paths, listId, onChange, onRemove }: Props) {
  const holds: Holds = paths.find((info) => info.path === filter.path)?.holds ?? "any";
  const ops = operators(holds);
  const takesValue = filter.op !== "exists" && filter.op !== "missing";
  return (
    <div className="filter">
      <input
        className="path"
        aria-label="Attribute"
        placeholder="process.cmd_line"
        list={listId}
        value={filter.path}
        spellCheck={false}
        onChange={(change) => onChange({ ...filter, path: change.target.value })}
      />
      <select
        aria-label="Comparison"
        value={ops.includes(filter.op) ? filter.op : (ops[0] ?? "equals")}
        onChange={(change) => onChange({ ...filter, op: change.target.value as Op })}
      >
        {ops.map((op) => (
          <option key={op} value={op}>
            {LABELS[op]}
          </option>
        ))}
      </select>
      {takesValue && (
        <input
          className="value"
          aria-label="Value"
          placeholder={
            filter.op === "in" ? "a, b, c" : holds === "time" ? "2026-09-25T08:00:00Z" : ""
          }
          value={filter.value}
          spellCheck={false}
          onChange={(change) => onChange({ ...filter, value: change.target.value })}
        />
      )}
      <button type="button" className="quiet" aria-label="Remove filter" onClick={onRemove}>
        ×
      </button>
    </div>
  );
}
