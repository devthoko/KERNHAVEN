import { describe, expect, it } from "vitest";
import { matchPath } from "./router";

describe("matchPath", () => {
  it("matches static and parameterized paths", () => {
    expect(matchPath("/", "/")).toEqual({});
    expect(matchPath("/jobs", "/jobs")).toEqual({});
    expect(matchPath("/jobs/:id", "/jobs/42")).toEqual({ id: "42" });
    expect(matchPath("/jobs/:id", "/jobs")).toBeNull();
    expect(matchPath("/jobs/:id", "/users/42")).toBeNull();
    expect(matchPath("/jobs/:id", "/jobs/a%2Fb")).toEqual({ id: "a/b" });
  });
});
