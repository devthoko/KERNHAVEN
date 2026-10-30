import { describe, expect, it } from "vitest";
import { areas, currentTab, pathMatches, visibleAreas } from "./navigation";
import type { Permission } from "./types";

describe("navigation", () => {
  it("matches a page and the pages below it, but not look-alike prefixes", () => {
    expect(pathMatches("/", "/")).toBe(true);
    expect(pathMatches("/", "/apps")).toBe(false);
    expect(pathMatches("/apps", "/apps/e2e")).toBe(true);
    expect(pathMatches("/apps", "/appsx")).toBe(false);
  });

  it("picks the most specific tab", () => {
    expect(currentTab(areas, "/apps/store/1/notes")?.tab.label).toBe("App store");
    expect(currentTab(areas, "/apps/notes")?.tab.label).toBe("Installed");
    expect(currentTab(areas, "/containers/abc")?.area.label).toBe("Docker");
    expect(currentTab(areas, "/audit")?.area.label).toBe("Security");
    expect(currentTab(areas, "/nowhere")).toBeNull();
  });

  it("hides pages and whole areas the role may not see", () => {
    const viewer = new Set<Permission>(["apps.read", "containers.read", "jobs.read", "system.read", "alerts.read"]);
    const list = visibleAreas((p) => viewer.has(p));
    const labels = list.map((a) => a.label);
    expect(labels).toEqual(["Home", "Apps", "Monitoring", "Docker", "Jobs"]);
    expect(labels).not.toContain("Users");
    expect(list.find((a) => a.label === "Monitoring")?.tabs.map((t) => t.to)).toEqual(["/monitoring", "/alerts"]);

    const alertsOnly = visibleAreas((p) => p === "alerts.read");
    // The area link leads to the first page the role may open.
    expect(alertsOnly.find((a) => a.label === "Monitoring")?.tabs[0]?.to).toBe("/alerts");
  });

  it("assigns every page to exactly one area", () => {
    const all = areas.flatMap((a) => a.tabs.map((t) => t.to));
    expect(new Set(all).size).toBe(all.length);
  });
});
