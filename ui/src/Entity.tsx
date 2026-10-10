import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import type { Held, Neighbour } from "./api";
import { entity, neighbours } from "./api";
import { ValueMenu } from "./components/ValueMenu";
import { candidates, LINK_KINDS, linkName, parts, reads } from "./identifier";
import { when } from "./summary";

interface Props {
  /** The range, ending now, in milliseconds. */
  span: number;
  /** What was asked for: an identifier, or a value that may be one. */
  asked: string;
  /** Opens the entity of an identifier or a value. */
  onOpen: (asked: string) => void;
  /** Reports a failure, so that a refused token can be asked for again. */
  onError: (error: unknown) => void;
}

const number = new Intl.NumberFormat();

/** Neighbours an answer holds unless more are asked for, and at most. */
const FEW = 100;
const MOST = 1000;
/** Neighbours the picture draws: more than these are read in the table. */
const DRAWN = 14;

/** An identifier as a name: its value, with its kind beside it. */
function Name({ identifier, onOpen }: { identifier: string; onOpen: (asked: string) => void }) {
  const named = parts(identifier);
  return (
    <span className="named">
      <span className={`pip ${named?.kind ?? ""}`} />
      <ValueMenu
        value={identifier}
        ways={[{ label: "Open its entity", run: () => onOpen(identifier) }]}
      >
        {named?.value ?? identifier}
      </ValueMenu>
    </span>
  );
}

/**
 * Everything about one user, host, address, domain or file: the
 * identifiers it holds with why each is there, and what it was seen with
 * in the range. See docs/adr/0025-entity-graph.md.
 */
export function Entity({ span, asked, onOpen, onError }: Props) {
  const [written, setWritten] = useState(asked);
  useEffect(() => setWritten(asked), [asked]);
  const options = useMemo(() => candidates(asked), [asked]);
  const [chosen, setChosen] = useState(0);
  // biome-ignore lint/correctness/useExhaustiveDependencies: another value starts from its likeliest kind
  useEffect(() => setChosen(0), [asked]);
  const identifier = options[Math.min(chosen, options.length - 1)];

  return (
    <div className="overview entity">
      <form
        className="entity-bar"
        onSubmit={(sent) => {
          sent.preventDefault();
          onOpen(written.trim());
        }}
      >
        <input
          aria-label="Identifier or value"
          className="mono"
          placeholder="An address, a name, a SID, a hash, or an identifier such as host:name:ws-7"
          value={written}
          onChange={(typed) => setWritten(typed.target.value)}
        />
        <button type="submit">Open</button>
        {options.length > 1 && (
          <fieldset className="chips">
            <legend className="hidden">What the value is</legend>
            {options.map((option, index) => (
              <button
                type="button"
                key={option}
                className="chip"
                aria-pressed={index === chosen}
                onClick={() => setChosen(index)}
              >
                <span className={`pip ${parts(option)?.kind ?? ""}`} />
                as a {parts(option)?.kind}
              </button>
            ))}
          </fieldset>
        )}
      </form>
      {identifier ? (
        <One
          key={identifier}
          identifier={identifier}
          span={span}
          onOpen={onOpen}
          onError={onError}
        />
      ) : (
        <div className="note nothing">
          <p>No entity is open.</p>
          <p>
            An entity is one user, host, address, domain or file, under every identifier the sources
            know it by. Write one above, or open one from the menu of a value.
          </p>
        </div>
      )}
    </div>
  );
}

interface OneProps {
  identifier: string;
  span: number;
  onOpen: (asked: string) => void;
  onError: (error: unknown) => void;
}

function One({ identifier, span, onOpen, onError }: OneProps) {
  const [links, setLinks] = useState<string[]>([]);
  const [limit, setLimit] = useState(FEW);
  const [again, setAgain] = useState(0);
  // biome-ignore lint/correctness/useExhaustiveDependencies: asking again moves the range
  const range = useMemo(() => {
    const to = new Date();
    return { from: new Date(to.getTime() - span).toISOString(), to: to.toISOString() };
  }, [span, again]);

  const known = useQuery({
    queryKey: ["entity", identifier, again],
    queryFn: ({ signal }) => entity(identifier, signal),
  });
  const seen = useQuery({
    queryKey: ["neighbours", identifier, range, links, limit],
    queryFn: ({ signal }) =>
      neighbours({ identifier, ...range, limit, ...(links.length > 0 ? { links } : {}) }, signal),
    placeholderData: keepPreviousData,
  });
  const failed = known.error ?? seen.error;
  useEffect(() => {
    if (failed) {
      onError(failed);
    }
  }, [failed, onError]);

  const name = known.data?.entity ?? identifier;
  const named = parts(name);
  const rows = seen.data?.neighbours ?? [];
  const degree = seen.data?.degree ?? 0;
  const toggle = (link: string) =>
    setLinks(links.includes(link) ? links.filter((one) => one !== link) : [...links, link]);

  return (
    <>
      <header className="entity-head">
        <span className={`status ${named?.kind ?? ""}`}>
          <span className="pip" />
          {named?.kind ?? "entity"}
        </span>
        <h1 className="mono">{named?.value ?? name}</h1>
        <ValueMenu value={name}>{name}</ValueMenu>
        {known.data?.provisional && (
          <span className="status" title="Seen under one weak identifier alone">
            provisional
          </span>
        )}
        {known.data?.shared && (
          <span className="status" title="Claimed by too many to be evidence of any">
            shared
          </span>
        )}
        <button type="button" className="quiet again" onClick={() => setAgain(again + 1)}>
          {known.isFetching || seen.isFetching ? "Reading" : "Refresh"}
        </button>
      </header>
      {failed && <p className="error banner">{failed.message}</p>}
      {known.data && known.data.entity !== known.data.asked && (
        <p className="meta entity-note">
          <span className="mono">{known.data.asked}</span> is one of its identifiers.
        </p>
      )}
      {known.data && known.data.alias_of.length > 0 && (
        <p className="meta entity-note">
          A weak identifier, and another name of{" "}
          {known.data.alias_of.map((other) => (
            <Name key={other} identifier={other} onOpen={onOpen} />
          ))}
        </p>
      )}

      <div className="entity-top">
        <section className="card">
          <header>
            <h2>Identifiers</h2>
            <span className="caption">why each is in it</span>
          </header>
          {known.isPending ? (
            <p className="muted">Reading the entity</p>
          ) : !known.data || known.data.identifiers.length === 0 ? (
            <p className="muted">
              Nothing joins this identifier to another: no source has named it together with a
              second one, so it is an entity of its own.
            </p>
          ) : (
            <div className="sources scroll">
              <table>
                <thead>
                  <tr>
                    <th>Identifier</th>
                    <th>Standing</th>
                    <th>Why</th>
                    <th>Events</th>
                    <th>First seen</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {known.data.identifiers.map((held) => (
                    <tr key={held.identifier}>
                      <td>
                        <ValueMenu value={held.identifier} />
                      </td>
                      <td>
                        {held.standing}
                        {held.strong !== null && (
                          <span className="muted"> · {held.strong ? "strong" : "weak"}</span>
                        )}
                      </td>
                      <td className="reason">
                        <Why held={held} />
                      </td>
                      <td className="count">{held.via ? number.format(held.events) : ""}</td>
                      <td className="count mono">
                        {held.via ? when(held.first_seen).slice(0, 19) : ""}
                      </td>
                      <td className="count mono">
                        {held.via ? when(held.last_seen).slice(0, 19) : ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="card">
          <header>
            <h2>Seen with</h2>
            <span className="caption">
              {rows.length > DRAWN ? `the ${DRAWN} seen most, of ` : ""}
              {number.format(degree)} in the range
            </span>
          </header>
          <Web centre={name} rows={rows} onOpen={onOpen} />
        </section>
      </div>

      <section className="card">
        <header>
          <h2>
            {number.format(degree)} {degree === 1 ? "neighbour" : "neighbours"}
          </h2>
          <fieldset className="chips">
            <legend className="hidden">Kinds of link shown</legend>
            {LINK_KINDS.map((link) => (
              <button
                type="button"
                key={link}
                className="chip"
                aria-pressed={links.includes(link)}
                onClick={() => toggle(link)}
              >
                {linkName(link)}
              </button>
            ))}
          </fieldset>
        </header>
        {seen.isPending ? (
          <p className="muted">Reading what it was seen with</p>
        ) : rows.length === 0 ? (
          <p className="muted">
            {links.length > 0
              ? "No link of the kinds chosen in this range."
              : "It was seen with nothing in this range. A longer range may hold more."}
          </p>
        ) : (
          <>
            <div className="sources scroll">
              <table>
                <thead>
                  <tr>
                    <th>Link</th>
                    <th>Entity</th>
                    <th>Kind</th>
                    <th>Events</th>
                    <th>First seen</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={`${row.entity}|${row.direction}|${row.link}`}>
                      <td>
                        <span className="muted">{row.direction === "in" ? "← " : "→ "}</span>
                        {reads(row.link, row.direction)}
                      </td>
                      <td>
                        <Name identifier={row.entity} onOpen={onOpen} />
                      </td>
                      <td className="muted">{row.kind ?? ""}</td>
                      <td className="count">{number.format(row.events)}</td>
                      <td className="count mono">{when(row.first_seen).slice(0, 19)}</td>
                      <td className="count mono">{when(row.last_seen).slice(0, 19)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="note">
              {rows.length >= limit && limit < MOST ? (
                <button type="button" disabled={seen.isFetching} onClick={() => setLimit(MOST)}>
                  {seen.isFetching ? "Reading" : `Show up to ${number.format(MOST)}`}
                </button>
              ) : rows.length >= limit ? (
                `The ${number.format(rows.length)} seen last. A kind of link or a shorter range shows the rest.`
              ) : (
                `${number.format(rows.length)} shown, which is all`
              )}
            </p>
          </>
        )}
      </section>
    </>
  );
}

/** Why an identifier is in the entity: what it was seen with, or who said. */
function Why({ held }: { held: Held }) {
  if (held.said) {
    return <>a person decided: {held.said}</>;
  }
  if (!held.via) {
    return <span className="muted">names the entity</span>;
  }
  return (
    <>
      seen with <span className="mono">{held.via}</span>
      {held.rule && <span className="muted"> · rule {held.rule}</span>}
    </>
  );
}

interface WebProps {
  centre: string;
  rows: Neighbour[];
  onOpen: (asked: string) => void;
}

/**
 * The entity among what it was seen with most: a picture to read the
 * shape from, with the table under it for the rows.
 */
function Web({ centre, rows, onOpen }: WebProps) {
  const around = useMemo(() => {
    const events = new Map<string, number>();
    for (const row of rows) {
      events.set(row.entity, (events.get(row.entity) ?? 0) + row.events);
    }
    return [...events.entries()]
      .sort((one, other) => other[1] - one[1])
      .slice(0, DRAWN)
      .map(([name, count], index, all) => {
        const angle = (index / all.length) * 2 * Math.PI - Math.PI / 2;
        // Two rings, by turns, so that names side by side do not cover
        // each other.
        const ring = all.length > 8 && index % 2 === 1 ? 0.62 : 1;
        return {
          name,
          count,
          x: 50 + 38 * ring * Math.cos(angle),
          y: 50 + 40 * ring * Math.sin(angle),
        };
      });
  }, [rows]);
  if (around.length === 0) {
    return <p className="muted">Nothing to draw in this range.</p>;
  }
  const most = Math.max(...around.map((one) => one.count));
  return (
    <div className="web">
      <svg className="lines" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        {around.map((one) => (
          <line
            key={one.name}
            x1="50"
            y1="50"
            x2={one.x}
            y2={one.y}
            vectorEffect="non-scaling-stroke"
            strokeWidth={1 + 2 * (Math.log1p(one.count) / Math.log1p(most))}
          />
        ))}
      </svg>
      <span
        className={`node centre ${parts(centre)?.kind ?? ""}`}
        style={{ left: "50%", top: "50%" }}
      >
        <span className="pip" />
        <span className="mono">{parts(centre)?.value ?? centre}</span>
      </span>
      {around.map((one) => (
        <button
          type="button"
          key={one.name}
          className={`node ${parts(one.name)?.kind ?? ""}`}
          style={{ left: `${one.x}%`, top: `${one.y}%` }}
          title={`${one.name}: ${number.format(one.count)} events`}
          onClick={() => onOpen(one.name)}
        >
          <span className="pip" />
          <span className="mono">{parts(one.name)?.value ?? one.name}</span>
        </button>
      ))}
    </div>
  );
}
