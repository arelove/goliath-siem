import { describe, expect, it } from "vitest";
import type { Draft } from "./query";
import { apiValue, fromParams, toParams, toSearch } from "./query";

describe("the address keeps a search", () => {
  it("reads back what it wrote", () => {
    const draft: Draft = {
      range: { from: "2026-09-25T00:00:00Z", to: "2026-09-26T00:00:00Z" },
      classUid: 1007,
      filters: [
        { path: "process.cmd_line", op: "contains", value: "a|b" },
        { path: "process.pid", op: "exists", value: "" },
      ],
    };
    expect(fromParams(toParams(draft))).toEqual(draft);
  });

  it("ignores what it does not understand", () => {
    const draft = fromParams(new URLSearchParams("last=9y&class=x&f=a|like|b&f=|equals|c"));
    expect(draft).toEqual({ range: { last: "24h" }, classUid: null, filters: [] });
  });
});

describe("a draft becomes the API's search", () => {
  const now = new Date("2026-09-25T12:00:00Z");

  it("resolves a relative range against now", () => {
    const search = toSearch(
      { range: { last: "1h" }, classUid: null, filters: [] },
      () => true,
      now,
    );
    expect(search).toEqual({
      from: "2026-09-25T11:00:00.000Z",
      to: "2026-09-25T12:00:00.000Z",
      limit: 200,
    });
  });

  it("types values by what the attribute holds", () => {
    const text = (path: string) => path === "user.name";
    const search = toSearch(
      {
        range: { last: "1h" },
        classUid: 3002,
        filters: [
          { path: "user.name", op: "equals", value: "1234" },
          { path: "is_mfa", op: "equals", value: "true" },
          { path: "status_id", op: "in", value: "1, 2," },
          { path: "session", op: "missing", value: "ignored" },
          { path: "  ", op: "equals", value: "dropped" },
        ],
      },
      text,
      now,
    );
    expect(search.classes).toEqual([3002]);
    expect(search.filters).toEqual([
      { path: "user.name", op: "equals", value: "1234" },
      { path: "is_mfa", op: "equals", value: true },
      { path: "status_id", op: "in", value: [1, 2] },
      { path: "session", op: "missing" },
    ]);
  });

  it("keeps text that is not a number as text", () => {
    expect(apiValue({ path: "x", op: "equals", value: "0x10" }, false)).toBe("0x10");
    expect(apiValue({ path: "x", op: "equals", value: "" }, false)).toBe("");
  });
});
