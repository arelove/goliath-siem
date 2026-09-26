import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef } from "react";
import type { Found } from "../api";
import { summarize, when } from "../summary";

interface Props {
  events: Found[];
  names: Map<number, string>;
  hasMore: boolean;
  loadingMore: boolean;
  selected: string | null;
  onMore: () => void;
  onSelect: (at: string) => void;
}

const ROW = 30;

export function Results({
  events,
  names,
  hasMore,
  loadingMore,
  selected,
  onMore,
  onSelect,
}: Props) {
  const scroller = useRef<HTMLDivElement>(null);
  const rows = useVirtualizer({
    count: events.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW,
    overscan: 20,
    // Before layout, and where there is none, as in tests: a screenful.
    initialRect: { width: 1200, height: 800 },
  });
  const items = rows.getVirtualItems();
  const last = items[items.length - 1];

  // Near the end of what is loaded, load the next page.
  useEffect(() => {
    if (last && last.index >= events.length - 20 && hasMore && !loadingMore) {
      onMore();
    }
  }, [last, events.length, hasMore, loadingMore, onMore]);

  return (
    <div className="results" ref={scroller}>
      <div className="row head">
        <span>Time</span>
        <span>Class</span>
        <span>Host</span>
        <span>Actor</span>
        <span>Event</span>
      </div>
      <div style={{ height: rows.getTotalSize(), position: "relative" }}>
        {items.map((item) => {
          const found = events[item.index];
          if (!found) {
            return null;
          }
          const summary = summarize(found.event);
          return (
            <button
              type="button"
              key={found.at}
              className={found.at === selected ? "row selected" : "row"}
              style={{ transform: `translateY(${item.start}px)`, height: ROW }}
              onClick={() => onSelect(found.at)}
            >
              <span className="mono">{when(found.event.time)}</span>
              <span>{names.get(found.class_uid) ?? found.class_uid}</span>
              <span>{summary.host}</span>
              <span>{summary.actor}</span>
              <span className="mono" title={summary.what}>
                {summary.what}
              </span>
            </button>
          );
        })}
      </div>
      {loadingMore && <p className="note">Loading more</p>}
      {!hasMore && events.length > 0 && <p className="note">{events.length} events, all shown</p>}
    </div>
  );
}
