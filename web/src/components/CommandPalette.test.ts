import { describe, expect, it } from "vitest";
import { filterCommands, type Command } from "./CommandPalette";

const cmd = (label: string, group: Command["group"], keywords = ""): Command => ({ id: label, label, group, keywords, run: () => {} });

describe("filterCommands", () => {
  const list = [cmd("Docker › Containers", "Pages"), cmd("Security › Audit log", "Pages"), cmd("Open vaultwarden", "Apps", "Vaultwarden"), cmd("Sign out", "Actions", "log out")];

  it("keeps everything for an empty query", () => {
    expect(filterCommands(list, "  ")).toHaveLength(4);
  });
  it("needs every word, in any order and case", () => {
    expect(filterCommands(list, "AUDIT security").map((c) => c.id)).toEqual(["Security › Audit log"]);
    expect(filterCommands(list, "containers audit")).toEqual([]);
  });
  it("searches group names and keywords", () => {
    expect(filterCommands(list, "apps vault").map((c) => c.id)).toEqual(["Open vaultwarden"]);
    expect(filterCommands(list, "log out").map((c) => c.id)).toEqual(["Sign out"]);
  });
});
