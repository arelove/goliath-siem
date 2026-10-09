import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Fragment, useEffect } from "react";
import type { Standing } from "./api";
import { platform } from "./api";
import { ago } from "./health";
import { lasting, question, STANDINGS, shares } from "./standing";

interface Props {
  /** Reports a failure, so that a refused token can be asked for again. */
  onError: (error: unknown) => void;
}

const number = new Intl.NumberFormat();

function Pill({ status, title }: { status: Standing; title?: string }) {
  const shown = STANDINGS[status] ?? STANDINGS.degraded;
  return (
    <span className={`status ${shown.tone}`} title={title}>
      <span className="dot" />
      {shown.label}
    </span>
  );
}

/**
 * The platform itself: whether it is well and why not, each role with the
 * processes that run it and what each says of what it does, where records
 * wait, and what changed lately. See docs/adr/0023-platform-health.md.
 */
export function Platform({ onError }: Props) {
  const health = useQuery({
    queryKey: ["platform"],
    queryFn: ({ signal }) => platform(signal),
    refetchInterval: 15_000,
    placeholderData: keepPreviousData,
  });
  useEffect(() => {
    if (health.error) {
      onError(health.error);
    }
  }, [health.error, onError]);
  const data = health.data;

  if (health.error) {
    return (
      <div className="overview">
        <section className="card">
          <p className="note error">{health.error.message}</p>
        </section>
      </div>
    );
  }
  if (!data) {
    return (
      <div className="overview">
        <section className="card">
          <p className="note">Loading</p>
        </section>
      </div>
    );
  }
  const { now } = data;
  const judged = data.platform;
  const bars = shares(judged.flows);

  return (
    <div className="overview platform">
      <section className={`card verdict ${STANDINGS[judged.status]?.tone ?? "warn"}`}>
        <header>
          <h2>Platform</h2>
          <span className="caption">
            {data.store === "answers" ? "The store answers" : "The store does not answer"}
            {judged.newest_report !== null && `, newest report ${ago(judged.newest_report, now)}`}
          </span>
        </header>
        <div className="verdict-body">
          <Pill status={judged.status} />
          <p>{judged.message}</p>
        </div>
      </section>

      <section className="card sources">
        <header>
          <h2>Roles</h2>
          <span className="caption">
            Each judged by the processes that report, not by their names
          </span>
        </header>
        {judged.roles.length === 0 ? (
          <p className="note">No process has reported.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Role</th>
                <th>Status</th>
                <th>Why</th>
                <th>Reporting</th>
                <th>Starts, 10 min</th>
              </tr>
            </thead>
            <tbody>
              {judged.roles.map((role) => (
                <Fragment key={role.role}>
                  <tr className="role">
                    <td className="mono">{role.role}</td>
                    <td>
                      <Pill status={role.status} title={role.reason} />
                    </td>
                    <td className="why">{role.message}</td>
                    <td className="count">
                      {role.reporting} of {role.expected}
                    </td>
                    <td className="count">{role.starts}</td>
                  </tr>
                  {role.instances.flatMap((instance) =>
                    instance.conditions.length === 0
                      ? [
                          <tr key={instance.instance} className="condition">
                            <td className="mono instance">{instance.instance}</td>
                            <td>
                              {instance.reporting ? (
                                <span className="status quiet">
                                  <span className="dot" />
                                  Reporting
                                </span>
                              ) : (
                                <span className="status bad">
                                  <span className="dot" />
                                  Gone
                                </span>
                              )}
                            </td>
                            <td className="why">
                              {instance.reporting
                                ? `Version ${instance.version}, started ${ago(instance.started, now)}.`
                                : `Last report ${ago(instance.last_report, now)}.`}
                            </td>
                            <td />
                            <td />
                          </tr>,
                        ]
                      : instance.conditions.map((condition) => {
                          const asked = question(condition.type);
                          return (
                            <tr
                              key={`${instance.instance} ${condition.type}`}
                              className="condition"
                            >
                              <td className="instance">
                                <span className="mono">{instance.instance}</span>
                                {!instance.reporting && <span className="gone"> gone</span>}
                              </td>
                              <td>
                                <Pill status={condition.status} title={condition.reason} />
                              </td>
                              <td className="why">
                                <strong>
                                  {asked.asks}
                                  {asked.of !== null && <span className="mono"> {asked.of}</span>}
                                </strong>
                                {" for "}
                                {lasting(condition.since, now)}. {condition.message}
                              </td>
                              <td />
                              <td />
                            </tr>
                          );
                        }),
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card sources flows">
        <header>
          <h2>Flows</h2>
          <span className="caption">What each reader of a topic has still to read</span>
        </header>
        {judged.flows.length === 0 ? (
          <p className="note">No reader has counted a backlog yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Topic</th>
                <th>Reader</th>
                <th>Backlog</th>
                <th>Records</th>
              </tr>
            </thead>
            <tbody>
              {judged.flows.map((flow, index) => (
                <tr key={`${flow.topic} ${flow.reader}`}>
                  <td className="mono">{flow.topic}</td>
                  <td className="mono">{flow.reader}</td>
                  <td className="bar">
                    <span style={{ width: `${Math.round((bars[index] ?? 0) * 100)}%` }} />
                  </td>
                  <td className="count">{number.format(flow.backlog)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card sources">
        <header>
          <h2>Changes</h2>
          <span className="caption">Each time a condition's status held, the newest first</span>
        </header>
        {judged.changes.length === 0 ? (
          <p className="note">No condition has been reported.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Since</th>
                <th>Process</th>
                <th>Role</th>
                <th>Condition</th>
                <th>Status</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {judged.changes.map((change) => {
                const asked = question(change.kind);
                return (
                  <tr key={`${change.instance} ${change.role} ${change.kind} ${change.since}`}>
                    <td title={new Date(change.since).toString()}>{ago(change.since, now)}</td>
                    <td className="mono">{change.instance}</td>
                    <td className="mono">{change.role}</td>
                    <td>
                      {asked.asks}
                      {asked.of !== null && <span className="mono"> {asked.of}</span>}
                    </td>
                    <td>
                      <Pill status={change.status} />
                    </td>
                    <td className="mono">{change.reason}</td>
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
