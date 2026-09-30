import { describe, expect, it } from "vitest";
import { ago, STATUSES, stages } from "./health";

describe("source health", () => {
  const now = Date.UTC(2026, 8, 28, 12, 30);

  it("says how long ago a source last sent", () => {
    expect(ago(null, now)).toBe("never");
    expect(ago(now - 20_000, now)).toBe("just now");
    expect(ago(now + 5_000, now)).toBe("just now");
    expect(ago(now - 5 * 60_000, now)).toBe("5 min ago");
    expect(ago(now - 3 * 3_600_000, now)).toBe("3 h ago");
    expect(ago(now - 3 * 24 * 3_600_000, now)).toBe("3 days ago");
  });

  it("lists the stages that had dead letters", () => {
    expect(stages({ normalizing: 4, decoding: 8, framing: 0 })).toBe("decoding 8, normalizing 4");
    expect(stages({})).toBe("");
  });

  it("explains every status", () => {
    for (const status of Object.values(STATUSES)) {
      expect(status.meaning.endsWith(".")).toBe(true);
    }
  });
});
