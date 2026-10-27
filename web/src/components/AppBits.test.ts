import { describe, expect, it } from "vitest";
import type { AppField } from "../lib/types";
import { changedValues, initialValues } from "./AppBits";

const fields: AppField[] = [
  { name: "PORT", label: "Port", type: "number", default: "8080" },
  { name: "SECRET", label: "Secret", type: "password", generate: "password" },
  { name: "DEBUG", label: "Debug", type: "boolean" },
  { name: "MODE", label: "Mode", type: "select", options: ["a", "b"] },
];

describe("app form values", () => {
  it("starts from defaults and leaves generated secrets empty", () => {
    expect(initialValues(fields)).toEqual({ PORT: "8080", SECRET: "", DEBUG: "false", MODE: "a" });
  });
  it("sends only filled values so the server generates the rest", () => {
    expect(changedValues({ PORT: "8080", SECRET: "", DEBUG: "false" })).toEqual({ PORT: "8080", DEBUG: "false" });
  });
});
