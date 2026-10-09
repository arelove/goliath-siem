import { describe, expect, it } from "vitest";
import { lasting, question, STANDINGS, shares } from "./standing";

describe("platform health", () => {
  it("reads a condition's type as a question and what it is about", () => {
    expect(question("storing")).toEqual({ asks: "Storing events", of: null });
    expect(question("keeping_up:normalized")).toEqual({
      asks: "Keeping up with",
      of: "normalized",
    });
    // A source's name may hold a colon; only the first divides.
    expect(question("normalizing:a:b")).toEqual({ asks: "Normalizing", of: "a:b" });
    // A type this build does not know is still shown.
    expect(question("store_reachable")).toEqual({ asks: "store reachable", of: null });
  });

  it("says how long a state has lasted", () => {
    const now = Date.UTC(2026, 9, 10, 12, 0);
    expect(lasting(now - 20_000, now)).toBe("20 s");
    expect(lasting(now + 5_000, now)).toBe("0 s");
    expect(lasting(now - 5 * 60_000, now)).toBe("5 min");
    expect(lasting(now - 3 * 3_600_000, now)).toBe("3 h");
    expect(lasting(now - 3 * 24 * 3_600_000, now)).toBe("3 days");
  });

  it("measures each backlog against the longest", () => {
    const flow = (backlog: number) => ({ topic: "t", reader: "r", backlog });
    expect(shares([flow(200), flow(50), flow(0)])).toEqual([1, 0.25, 0]);
    expect(shares([flow(0), flow(0)])).toEqual([0, 0]);
    expect(shares([])).toEqual([]);
  });

  it("has a tone for every standing", () => {
    expect(Object.keys(STANDINGS).sort()).toEqual(["degraded", "failing", "ok"]);
  });
});
