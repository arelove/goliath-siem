import type { ReactNode } from "react";

interface Props {
  title: string;
  /** Beside the title, such as a live figure. */
  aside?: ReactNode;
  /** The vertical axis's name, written along it. */
  axis?: string;
  /** Under the chart, such as what one step spans. */
  caption?: string;
  /** Beside the chart, on the right. */
  legend?: ReactNode;
  className?: string;
  children: ReactNode;
}

/** A panel of the dashboard: a titled chart, with its axis name and legend. */
export function Card({ title, aside, axis, caption, legend, className, children }: Props) {
  return (
    <section className={className ? `card ${className}` : "card"}>
      <header>
        <h2>{title}</h2>
        {aside}
      </header>
      <div className={legend ? "card-body with-legend" : "card-body"}>
        {axis && <span className="axis-name">{axis}</span>}
        <div className="card-chart">
          {children}
          {caption && <span className="caption">{caption}</span>}
        </div>
        {legend}
      </div>
    </section>
  );
}

/** A legend of named colours, with counts when given. */
export function Legend({
  items,
}: {
  items: { key: string; name: string; color: string; count?: number }[];
}) {
  return (
    <ul className="legend">
      {items.map((item) => (
        <li key={item.key}>
          <span className="dot" style={{ background: item.color }} />
          <span className="name" title={item.name}>
            {item.name}
          </span>
          {item.count !== undefined && (
            <span className="count">{item.count.toLocaleString("en-US")}</span>
          )}
        </li>
      ))}
    </ul>
  );
}
