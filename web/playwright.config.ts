import { defineConfig, devices } from "@playwright/test";

// Run through scripts/e2e.sh, which starts a real kernhaven-core with a fresh
// database and passes its URL and setup token.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.KH_BASE_URL ?? "http://localhost:18471",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
