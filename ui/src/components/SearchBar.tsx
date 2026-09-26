import type { ClassInfo, PathInfo } from "../api";
import type { Draft } from "../query";
import { LAST } from "../query";
import { className } from "../summary";
import { FilterRow } from "./FilterRow";

interface Props {
  draft: Draft;
  classes: ClassInfo[];
  paths: PathInfo[];
  searching: boolean;
  onChange: (draft: Draft) => void;
  onSubmit: () => void;
}

const PATHS_LIST = "goliath-paths";

export function SearchBar({ draft, classes, paths, searching, onChange, onSubmit }: Props) {
  const range = "last" in draft.range ? draft.range.last : "custom";
  return (
    <form
      className="search"
      onSubmit={(submit) => {
        submit.preventDefault();
        onSubmit();
      }}
    >
      <div className="line">
        <select
          aria-label="Time range"
          value={range}
          onChange={(change) => {
            const value = change.target.value;
            if (value === "custom") {
              const to = new Date();
              const from = new Date(to.getTime() - (LAST["24h"] ?? 0));
              onChange({ ...draft, range: { from: from.toISOString(), to: to.toISOString() } });
            } else {
              onChange({ ...draft, range: { last: value } });
            }
          }}
        >
          {Object.keys(LAST).map((last) => (
            <option key={last} value={last}>
              Last {last}
            </option>
          ))}
          <option value="custom">Between</option>
        </select>
        {"from" in draft.range && (
          <>
            <input
              aria-label="From"
              className="time"
              value={draft.range.from}
              onChange={(change) =>
                onChange({
                  ...draft,
                  range: { ...draft.range, from: change.target.value } as Draft["range"],
                })
              }
            />
            <input
              aria-label="To"
              className="time"
              value={draft.range.to}
              onChange={(change) =>
                onChange({
                  ...draft,
                  range: { ...draft.range, to: change.target.value } as Draft["range"],
                })
              }
            />
          </>
        )}
        <select
          aria-label="Class"
          value={draft.classUid ?? ""}
          onChange={(change) =>
            onChange({
              ...draft,
              classUid: change.target.value === "" ? null : Number(change.target.value),
            })
          }
        >
          <option value="">Every class</option>
          {classes.map((info) => (
            <option key={info.uid} value={info.uid}>
              {className(info.name)} ({info.uid})
            </option>
          ))}
        </select>
        <button
          type="button"
          className="quiet"
          onClick={() =>
            onChange({
              ...draft,
              filters: [...draft.filters, { path: "", op: "contains", value: "" }],
            })
          }
        >
          Add filter
        </button>
        <button type="submit" disabled={searching}>
          {searching ? "Searching" : "Search"}
        </button>
      </div>
      <datalist id={PATHS_LIST}>
        {paths.map((info) => (
          <option key={info.path} value={info.path} />
        ))}
      </datalist>
      {draft.filters.map((filter, index) => (
        <FilterRow
          // Filters have no identity of their own; their place is theirs.
          // biome-ignore lint/suspicious/noArrayIndexKey: see above
          key={index}
          filter={filter}
          paths={paths}
          listId={PATHS_LIST}
          onChange={(changed) =>
            onChange({
              ...draft,
              filters: draft.filters.map((old, at) => (at === index ? changed : old)),
            })
          }
          onRemove={() =>
            onChange({ ...draft, filters: draft.filters.filter((_, at) => at !== index) })
          }
        />
      ))}
    </form>
  );
}
