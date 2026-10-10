import { describe, expect, it } from "vitest";
import type { Found } from "./api";
import { level, read, sameValue } from "./finding";

const UID = "0f".repeat(16);

function found(at: string, event: Record<string, unknown>): Found {
  return { at, class_uid: 2004, source: "goliath-intel", kind: "indicator_match", event };
}

const MATCH = found("1790330400000-aa", {
  time: 1790330400000,
  severity_id: 4,
  confidence_score: 95,
  is_alert: true,
  message: "An indicator names the domain c2.bad.example.com",
  finding_info: { title: "Indicator match: domain c2.bad.example.com" },
  evidences: [
    {
      uid: UID,
      name: "dst_endpoint.hostname",
      data: { class_uid: 4003, time: 1790330400000, value: "c2.bad.example.com" },
    },
  ],
  observables: [{ name: "dst_endpoint.hostname", type_id: 1, value: "c2.bad.example.com" }],
  enrichments: [
    {
      name: "hostname",
      value: "ws-7",
      type: "asset",
      provider: "cmdb",
      data: { owner: "alice", labels: ["finance", "laptop"], source_version: "12" },
    },
  ],
  unmapped: {
    indicator_kind: "domain",
    indicator_value: "c2.bad.example.com",
    assertions: [
      { feed: "threatfox", version: "7", confidence: 95, first_seen: 1790000000, last_seen: null },
    ],
  },
});

describe("a finding as the interface reads it", () => {
  it("names what matched, who asserts it, and the event it was made of", () => {
    const finding = read(MATCH);
    expect(finding).toMatchObject({
      severity: 4,
      kind: "domain",
      value: "c2.bad.example.com",
      confidence: 95,
      suppressed: null,
      evidence: { at: `1790330400000-${UID}`, classUid: 4003, path: "dst_endpoint.hostname" },
    });
    expect(finding.assertions).toEqual([
      {
        feed: "threatfox",
        version: "7",
        confidence: 95,
        firstSeen: 1790000000000,
        lastSeen: null,
      },
    ]);
    expect(finding.enrichments[0]?.data).toEqual([
      ["owner", "alice"],
      ["labels", "finance, laptop"],
      ["source_version", "12"],
    ]);
  });

  it("reads a finding made before the value had a member of its own", () => {
    const event = { ...MATCH.event, unmapped: { indicator_kind: "domain" } };
    expect(read(found("1-bb", event)).value).toBe("c2.bad.example.com");
  });

  it("says why a suppressed finding is not an alert", () => {
    const event = {
      ...MATCH.event,
      is_alert: false,
      status_id: 3,
      severity_id: 1,
      status_detail: "Allowlist partners version 3, entry 2: a partner",
    };
    expect(read(found("1-cc", event)).suppressed).toBe(
      "Allowlist partners version 3, entry 2: a partner",
    );
  });

  it("is not broken by a finding that holds nothing it expects", () => {
    const finding = read(found("1-dd", {}));
    expect(finding).toMatchObject({ severity: 0, title: "Finding", value: "", assertions: [] });
    expect(finding.evidence.at).toBeNull();
    expect(level(finding.severity).name).toBe("Unknown");
  });

  it("finds the other findings of the same value", () => {
    const one = read(MATCH);
    const two = read(found("2-ee", MATCH.event));
    const other = read(found("3-ff", { unmapped: { indicator_value: "198.51.100.7" } }));
    expect(sameValue([one, two, other], one).map((finding) => finding.at)).toEqual(["2-ee"]);
    expect(sameValue([one, two], read(found("4-gg", {})))).toEqual([]);
  });
});
