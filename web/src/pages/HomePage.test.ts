import { describe, expect, it } from "vitest";
import { isHousekeeping, jobTitle } from "../components/JobBits";
import type { Alert, FileSystemInfo, InstalledApp, Job, ServiceCheck, StorageInventory } from "../lib/types";
import { collectIssues, largestFileSystem } from "./HomePage";

const fs = (over: Partial<FileSystemInfo>): FileSystemInfo => ({
  path: "/dev/x",
  name: "x",
  type: "part",
  fstype: "ext4",
  label: "",
  uuid: "",
  size_bytes: 0,
  fs_size_bytes: 100,
  fs_used_bytes: 10,
  fs_available_bytes: 90,
  mountpoints: [],
  mountable: false,
  ...over,
});

const inventory = (systems: FileSystemInfo[]) => ({ disks: [{ file_systems: systems }] }) as unknown as StorageInventory;

describe("largestFileSystem", () => {
  it("prefers the system root", () => {
    expect(largestFileSystem(inventory([fs({ name: "big", fs_size_bytes: 1000 }), fs({ name: "root", mountpoints: ["/"] })]))?.name).toBe("root");
  });
  it("falls back to the biggest file system and skips unknown sizes", () => {
    expect(largestFileSystem(inventory([fs({ name: "a" }), fs({ name: "b", fs_size_bytes: 500 }), fs({ name: "c", fs_size_bytes: 0, mountpoints: ["/"] })]))?.name).toBe("b");
    expect(largestFileSystem(inventory([]))).toBeNull();
  });
});

describe("collectIssues", () => {
  it("lists failures before warnings before updates", () => {
    const issues = collectIssues({
      alerts: [{ id: 1, severity: "warning", title: "Disk almost full", body: "/ 92 %" } as Alert],
      services: [
        { name: "monitor", label: "Monitor service", status: "down" },
        { name: "proxy", label: "Proxy", status: "not_configured" },
      ] as ServiceCheck[],
      jobs: [{ id: 7, kind: "stacks.deploy", needs_attention: true } as Job, { id: 8, kind: "backup.run", needs_attention: false } as Job],
      apps: [{ name: "notes", status: "deployed", update_available: true, version: "1.0", latest_version: "2.0" } as InstalledApp],
    });
    expect(issues.map((i) => i.title)).toEqual(["Monitor service is down", "Deploy stack (job #7) needs attention", "Disk almost full", "Update for notes"]);
    expect(issues[1]?.to).toBe("/jobs/7");
  });
  it("includes security findings but not info or update findings", () => {
    const issues = collectIssues({
      findings: [
        { severity: "critical", area: "mfa", title: "owner signs in with a password only", link: "/users" },
        { severity: "warning", area: "updates", title: "notes runs 1.0; 2.0 is available", link: "/apps/notes" },
        { severity: "info", area: "updates", title: "old image", link: "/images" },
        { severity: "warning", area: "backup", title: "No backup plan is enabled", link: "" },
      ],
    });
    expect(issues.map((i) => [i.tone, i.title, i.to])).toEqual([
      ["red", "owner signs in with a password only", "/users"],
      ["amber", "No backup plan is enabled", "/security"],
    ]);
  });
  it("is empty when nothing is wrong", () => {
    expect(collectIssues({ alerts: [], services: [{ name: "core", label: "Core", status: "ok" }], jobs: [], apps: [] })).toEqual([]);
  });
});

describe("job names", () => {
  it("names known kinds and spells out unknown ones", () => {
    expect(jobTitle("backup.run")).toBe("Back up");
    expect(jobTitle("maintenance.purge_sessions")).toBe("Purge sessions");
    expect(isHousekeeping("maintenance.tls_renew")).toBe(true);
    expect(isHousekeeping("backup.run")).toBe(false);
  });
});
