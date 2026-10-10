import { describe, expect, it } from "vitest";
import { candidates, parts, reads } from "./identifier";

describe("an identifier", () => {
  it("is taken apart, with colons left in its value", () => {
    expect(parts("address:ip:2001:db8::1")).toEqual({
      kind: "address",
      form: "ip",
      value: "2001:db8::1",
    });
    expect(parts("user:name:corp\\adam")?.value).toBe("corp\\adam");
  });

  it("is not read from what is none", () => {
    expect(parts("ws-7.corp.example")).toBeNull();
    expect(parts("thing:name:x")).toBeNull();
    expect(parts("host:name:")).toBeNull();
  });
});

describe("a value", () => {
  it("is the identifier its form says", () => {
    expect(candidates(" 10.0.0.5 ")).toEqual(["address:ip:10.0.0.5"]);
    expect(candidates("2001:db8::1")).toEqual(["address:ip:2001:db8::1"]);
    expect(candidates("S-1-5-21-1-2-3-1104")).toEqual(["user:sid:s-1-5-21-1-2-3-1104"]);
    expect(candidates("AB".repeat(32))).toEqual([`file:hash:${"ab".repeat(32)}`]);
    expect(candidates("adam@corp.example")).toEqual(["user:email:adam@corp.example"]);
    expect(candidates("CORP\\Adam")).toEqual(["user:name:corp\\adam"]);
  });

  it("may be of more than one kind, and an identifier is itself", () => {
    expect(candidates("c2.bad.example.com")).toEqual([
      "domain:name:c2.bad.example.com",
      "host:name:c2.bad.example.com",
    ]);
    expect(candidates("ws-7")).toEqual(["host:name:ws-7", "user:name:ws-7"]);
    expect(candidates("Host:Name:WS-7")).toEqual(["host:name:ws-7"]);
    expect(candidates("  ")).toEqual([]);
  });
});

describe("a link", () => {
  it("reads from either side", () => {
    expect(reads("logged_on_to", "out")).toBe("logged on to");
    expect(reads("logged_on_to", "in")).toBe("logged on from");
    expect(reads("new_kind", "out")).toBe("new_kind");
  });
});
