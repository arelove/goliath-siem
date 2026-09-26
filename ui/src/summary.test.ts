import { describe, expect, it } from "vitest";
import { at, className, summarize } from "./summary";

describe("a row's summary", () => {
  it("shows the host, the actor, and what happened", () => {
    expect(
      summarize({
        device: { hostname: "web-1" },
        actor: { user: { name: "root" } },
        process: { cmd_line: "curl http://x" },
        message: "not this",
      }),
    ).toEqual({ host: "web-1", actor: "root", what: "curl http://x" });
  });

  it("falls back through the paths and leaves blanks", () => {
    expect(summarize({ user: { name: "alice" }, src_endpoint: { ip: "203.0.113.9" } })).toEqual({
      host: "203.0.113.9",
      actor: "alice",
      what: "alice",
    });
    expect(summarize({})).toEqual({ host: "", actor: "", what: "" });
  });

  it("reads paths without looking into lists", () => {
    expect(at({ a: { b: 1 } }, "a.b")).toBe(1);
    expect(at({ a: [{ b: 1 }] }, "a.0.b")).toBeUndefined();
    expect(at({ a: null }, "a.b")).toBeUndefined();
  });

  it("names classes as people read them", () => {
    expect(className("process_activity")).toBe("Process Activity");
  });
});
